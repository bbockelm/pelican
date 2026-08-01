//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package transfer_records

import (
	"context"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/db"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/metrics"
)

// Table names within the catalog.
const (
	// ArchiveTableName holds completed transfers: append-only, rotated, and the
	// table a collector normally follows.
	ArchiveTableName = "transfers"
	// ActiveTableName holds transfers still running. It is mutable, so a row can
	// be updated as the transfer progresses and removed when it finishes. It
	// gives visibility into what is happening now, and it is what lets a
	// crashed server account for transfers that were in flight (see Reconcile).
	ActiveTableName = "transfers_active"
)

// DefaultMaxBytes bounds the archive when the operator sets no limit. It is a
// deliberate, visible cap rather than unbounded growth: a monitoring store that
// can fill a filesystem is worse than one that forgets.
const DefaultMaxBytes int64 = 1 << 30 // 1 GiB

// Config configures a Store.
type Config struct {
	// Dir is the catalog directory. Required.
	Dir string
	// MaxBytes bounds the archive's sealed segments. Zero uses DefaultMaxBytes.
	MaxBytes int64
	// Identity is stamped onto every record.
	Identity ServerIdentity
	// RotateInterval is the retention-and-reindex cadence. Zero uses one hour,
	// matching htcondordb's default; negative disables the loop.
	RotateInterval time.Duration
	// MaintainInterval is the mutable table's self-tuning cadence. Zero uses 15
	// minutes, matching htcondordb; negative disables the loop.
	MaintainInterval time.Duration
}

// Store is a Pelican server's local transfer history.
type Store struct {
	cat     *db.Catalog
	archive *db.ArchiveTable
	active  *db.DB
	cfg     Config

	appended atomic.Int64
	dropped  atomic.Int64
	nextKey  atomic.Uint64
}

// Open creates or reopens the store beneath cfg.Dir.
func Open(cfg Config) (*Store, error) {
	if cfg.Dir == "" {
		return nil, errors.New("transfer_records: a directory is required")
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}

	cat, err := db.OpenCatalog(cfg.Dir)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open the transfer-record catalog at %s", cfg.Dir)
	}

	archive, ok := cat.ArchiveTable(ArchiveTableName)
	if !ok {
		archive, err = cat.CreateArchiveTable(ArchiveTableName, archiveConfig(cfg.MaxBytes))
		if err != nil {
			_ = cat.Close()
			return nil, errors.Wrap(err, "failed to create the completed-transfer archive")
		}
	}

	active, ok := cat.Table(ActiveTableName)
	if !ok {
		active, err = cat.CreateTable(ActiveTableName)
		if err != nil {
			_ = cat.Close()
			return nil, errors.Wrap(err, "failed to create the in-progress transfer table")
		}
	}

	s := &Store{cat: cat, archive: archive, active: active, cfg: cfg}
	//nolint:gosec // G115: a nanosecond timestamp is positive and the counter only needs to be unique per process
	s.nextKey.Store(uint64(time.Now().UnixNano()))
	return s, nil
}

// archiveConfig describes the archive's indexing and retention.
//
// CompletionDate is a zone attribute so that a time-range query -- the shape a
// collector issues -- prunes whole segments instead of scanning them. Project
// and the server type are categorical because they are the natural ways to slice
// a federation's transfers. Retention is by bytes: the bound an operator can
// size a filesystem against, and one that degrades predictably, since a busy
// server keeps a shorter window rather than overrunning a budget set in days.
func archiveConfig(maxBytes int64) db.ArchiveConfig {
	return db.ArchiveConfig{
		ZoneAttrs:        []string{AttrCompletionDate},
		CategoricalAttrs: []string{AttrProject, AttrServerType, AttrStatus},
		HotAttrs: []string{
			AttrCompletionDate, AttrPath, AttrReadBytes, AttrWriteBytes,
			AttrProject, AttrUserDN, AttrServerName,
		},
		Retention: collections.Retention{MaxBytes: maxBytes},
	}
}

// Catalog exposes the underlying catalog, for mounting a change feed over it.
func (s *Store) Catalog() *db.Catalog { return s.cat }

// Close flushes and closes the store.
func (s *Store) Close() error { return s.cat.Close() }

// Record appends a completed transfer to the archive.
//
// It is the consumer registered with the metrics package, so it runs on the
// goroutine that finished the transfer and must stay cheap: an append to an
// append-only log, with no network and no fsync in the caller's path.
func (s *Store) Record(event metrics.TransferEvent) {
	key := s.newKey()
	ad := recordFromEvent(event, s.cfg.Identity, StatusCompleted, key)
	if err := s.archive.Append(ad); err != nil {
		log.WithError(err).Warn("Failed to record a completed transfer")
		return
	}
	s.appended.Add(1)
	// A transfer that finished is no longer in progress. Delete is keyed, so this
	// is a no-op for a transfer that was never registered as active.
	if _, err := s.active.Delete(key); err != nil {
		log.WithError(err).Debug("Failed to clear an in-progress transfer row")
	}
}

// CompleteActive archives a finished transfer under the key BeginActive
// returned, and clears its in-progress row.
//
// The key is reused deliberately: the archived record and the in-progress row a
// collector may already have seen describe the same transfer, and sharing a key
// is what lets it recognize them as such rather than double-counting.
func (s *Store) CompleteActive(key string, event metrics.TransferEvent) {
	ad := recordFromEvent(event, s.cfg.Identity, StatusCompleted, key)
	if err := s.archive.Append(ad); err != nil {
		log.WithError(err).Warn("Failed to record a completed transfer")
		return
	}
	s.appended.Add(1)
	if _, err := s.active.Delete(key); err != nil {
		log.WithError(err).Debug("Failed to clear an in-progress transfer row")
	}
}

// EachArchived calls fn for every record in the archive, newest first. It is an
// introspection helper -- a collector follows the change feed instead.
func (s *Store) EachArchived(fn func(*classad.ClassAd)) error {
	seq, err := s.archive.Query("true")
	if err != nil {
		return errors.Wrap(err, "failed to query the transfer archive")
	}
	for ad := range seq {
		fn(ad)
	}
	return nil
}

// BeginActive registers a transfer as in progress and returns its key, which
// UpdateActive and CompleteActive take.
//
// The in-progress table is deliberately separate from the archive: the archive
// is append-only and must stay that way for a collector's cursor to be
// meaningful, whereas a running transfer's row changes as it goes.
func (s *Store) BeginActive(event metrics.TransferEvent) string {
	key := s.newKey()
	ad := recordFromEvent(event, s.cfg.Identity, StatusActive, key)
	if err := s.active.Put(key, ad); err != nil {
		log.WithError(err).Debug("Failed to register an in-progress transfer")
	}
	return key
}

// UpdateActive refreshes an in-progress transfer's counters.
func (s *Store) UpdateActive(key string, event metrics.TransferEvent) {
	ad := recordFromEvent(event, s.cfg.Identity, StatusActive, key)
	if err := s.active.Put(key, ad); err != nil {
		log.WithError(err).Debug("Failed to update an in-progress transfer")
	}
}

// Reconcile moves any rows left in the in-progress table into the archive as
// abandoned, and is called once at startup.
//
// Rows can only be left there by a server that stopped while transfers were
// running. Recording them as abandoned is the honest outcome: the server cannot
// know whether they finished, and either discarding them or writing them as
// completed would misreport what happened. It returns how many were reconciled.
func (s *Store) Reconcile() (int, error) {
	keys := s.active.Keys()
	if len(keys) == 0 {
		return 0, nil
	}
	reconciled := 0
	for _, key := range keys {
		ad, ok := s.active.LookupClassAd(key)
		if !ok {
			continue
		}
		ad.InsertAttrString(AttrStatus, StatusAbandoned)
		if err := s.archive.Append(ad); err != nil {
			return reconciled, errors.Wrap(err, "failed to archive an abandoned transfer")
		}
		if _, err := s.active.Delete(key); err != nil {
			return reconciled, errors.Wrap(err, "failed to clear an abandoned transfer")
		}
		reconciled++
	}
	log.Warnf("Recovered %d transfer(s) that were in progress when the server last stopped; "+
		"they are recorded as abandoned", reconciled)
	return reconciled, nil
}

// Stats reports the store's counters, for the daemon's metrics.
type Stats struct {
	Appended        int64
	DroppedByRotate int64
	ActiveCount     int
	ArchiveCount    int
}

// Stats returns a snapshot of the store's counters.
func (s *Store) Stats() Stats {
	return Stats{
		Appended:        s.appended.Load(),
		DroppedByRotate: s.dropped.Load(),
		ActiveCount:     s.active.Len(),
		ArchiveCount:    s.archive.Count(),
	}
}

// RunMaintenance runs the store's background maintenance until ctx is cancelled.
//
// Two loops at different cadences, mirroring htcondordb. Rotation and reindexing
// go together on the slower one -- rotation is what creates the newly sealed
// segments that reindexing then covers -- while the mutable table's self-tuning
// runs on its own. They are deliberately not merged: the archive's pass is cheap
// and must run reliably, whereas self-tuning is the expensive one.
func (s *Store) RunMaintenance(ctx context.Context) {
	rotate := s.cfg.RotateInterval
	if rotate == 0 {
		rotate = time.Hour
	}
	maintain := s.cfg.MaintainInterval
	if maintain == 0 {
		maintain = 15 * time.Minute
	}

	if rotate > 0 {
		go s.loop(ctx, rotate, s.rotateOnce)
	}
	if maintain > 0 {
		go s.loop(ctx, maintain, func() {
			// Self-tuning applies to the mutable table; the archive's index spec
			// is fixed and its own pass handles reindexing.
			s.active.Maintain(db.MaintainOptions{HotTopN: 16})
		})
	}
}

func (s *Store) loop(ctx context.Context, every time.Duration, fn func()) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}

// rotateOnce enforces retention and then indexes whatever rotation sealed.
func (s *Store) rotateOnce() {
	dropped, err := s.archive.Rotate(float64(time.Now().Unix()))
	if err != nil {
		log.WithError(err).Warn("Failed to rotate the transfer archive")
	} else if dropped > 0 {
		s.dropped.Add(int64(dropped))
		log.Infof("Dropped %d transfer-archive segment(s) to stay within the size limit", dropped)
	}
	s.archive.Reindex()
}

// newKey returns a key unique within this process's lifetime. It seeds from the
// wall clock so that keys from successive runs of the server do not collide in a
// collector's view.
func (s *Store) newKey() string {
	return "xfer-" + strconv.FormatUint(s.nextKey.Add(1), 36)
}

// shared holds the process's store, so a component constructed before the
// modules launch can reach it once it exists.
var shared atomic.Pointer[Store]

// SetShared publishes the process's store, or clears it when s is nil.
//
// This exists for one ordering problem. A server's transfer-record store is
// created while the modules launch, but something built earlier may need to
// serve from it -- the HTCondor command port is assembled before
// LaunchModules runs. Rather than reorder startup around one optional feature,
// the store is published here and looked up when a request actually arrives.
//
// Callers must clear it on shutdown, or a later lookup would hand out a closed
// store.
func SetShared(s *Store) {
	shared.Store(s)
}

// Shared returns the process's transfer-record store, or nil when recording is
// disabled or has not started yet. A caller reaching this on a request path
// should treat nil as "not available" rather than as an error in itself.
func Shared() *Store {
	return shared.Load()
}
