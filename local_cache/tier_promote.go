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

package local_cache

// Promotion from cold tiering targets.
//
// A cold target (TierTargetConfig.Cold) is storage that is larger but slower
// than the cache's local disks.  Local storage is the hot tier: an object
// reaches a cold target only when watermark eviction would otherwise delete it
// (see tierUploader.offerDemotion), and a read of an object there brings it
// back.  This file is the "brings it back" half.
//
// Promotion builds no copy machinery of its own.  It reuses what fills a
// partly cached object from its origin:
//
//  1. The first read moves the object's metadata to a local directory in one
//     transaction (CacheDB.PromoteObject): a fresh data key, an empty block
//     bitmap, and a ColdCopy recording the copy the cold target holds.  From
//     then on the object is an ordinary local object that is missing blocks,
//     and every reader goes through the normal RangeReader -- encryption,
//     the shared block state, pins and auto-repair all apply unchanged.
//  2. A reader that needs a missing block starts a background fill, as for
//     any partly cached object (PersistentCache.startFill); for a promoted
//     object the fill copies from the cold copy instead of the origin
//     (tierPromoter.startFill).  It is registered on the object's shared
//     block state like any fill, so other readers wait for it rather than
//     copy the same blocks, a reader's WaitForCompletion waits for its
//     verdict, it pins the object and registers with the cache's shutdown
//     gate, and it stops once no reader has been open for the prefetch
//     timeout.  A copy that fails in a way that condemns what it wrote
//     condemns the object before its readers are woken.  When the copy
//     cannot supply a block -- the cold copy is gone, changed, or its target
//     is down -- readers fall back to the origin.
//  3. A read of the whole object also starts a background copy of the rest
//     (runBackground), which finishes even if every client goes away and is
//     recorded with a PrefixTierPromote intent so a restart resumes it.  It
//     advances through the object as a series of fills of at most
//     tierPromoteSegment blocks; a range read copies only the range it reads.
//
// The cold copy is kept after the promotion finishes.  Two copies cost room on
// the cold target, but at most the size of local storage, which is the small
// tier by definition; in exchange, evicting the object again costs nothing --
// eviction just points it back at the copy (demoteToColdCopyInTxn) -- and
// readers that were being served from the cold copy when the promotion began
// are never broken.  It also means an object moves between tiers only because
// a client read it or eviction needed the room, so there is no ping-pong: a
// promoted object is never eligible for upload (tierUploader.eligible).
//
// Every read of the cold copy is pinned to the copy recorded when it was
// uploaded, as for proxied reads.  A copy that no longer matches is dropped
// (StorageManager.dropColdCopy) and the object's remaining blocks are fetched
// from the origin instead.

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

const (
	// tierPromoteBackgroundFills bounds how many whole-object background
	// copies run at once.  Readers are never held up by it: a reader that
	// needs a block no copy is writing starts a fill of its own.
	tierPromoteBackgroundFills = 4
	// tierPromoteSegment is the most blocks the background copy registers
	// as one fill.  A reader waits for a fill that covers its block, without
	// a bound; that is cheap for a fill a reader started, which is bounded
	// by the range that reader asked for, but the background copy covers
	// the whole object.  So it advances a segment at a time: a reader whose
	// block is in the segment being copied waits for at most the rest of
	// that segment, and one further ahead -- a range read from the middle
	// of a large object -- fills its range directly.  Consecutive segments
	// share one read of the cold copy.
	tierPromoteSegment = (4 << 20) / BlockDataSize
	// tierPromoteCopyBuffer is the most a copy reads from the cold copy at a
	// time.
	tierPromoteCopyBuffer = 256 << 10
)

// errPromotionDeclined reports that an object on a cold target is to be served
// from there rather than promoted.
var errPromotionDeclined = errors.New("promotion declined")

// errPromotionStale reports that the local life of the object a copy was
// filling has ended (it was demoted, deleted, or promoted again).
var errPromotionStale = errors.New("the object is no longer the local copy being promoted")

// errColdCopyUnavailable reports that a promoted object's cold copy cannot be
// copied from: it was dropped (found changed or missing), its target is no
// longer configured, or the target is down.
var errColdCopyUnavailable = errors.New("the object's cold copy is not available")

// errColdCopyShort reports a cold copy that ended before its recorded size.
var errColdCopyShort = errors.New("the cold copy ended before its recorded size")

// tierPromoter brings objects on cold tiering targets back to local storage.
type tierPromoter struct {
	pc       *PersistentCache
	db       *CacheDB
	storage  *StorageManager
	eviction *EvictionManager
	// ctx is what every copy runs under; Close cancels it.
	ctx context.Context

	// flips makes concurrent first reads of one object share a promotion.
	flips singleflight.Group
	// fillSem bounds concurrent background copies.
	fillSem chan struct{}

	// mu guards background.
	mu sync.Mutex
	// background holds, for each object with a background copy running or
	// queued, the data key of the local life that copy is for.
	background map[InstanceHash][]byte
}

// coldSource is the cold copy a promoted object is filled from, as recorded
// when a copy started, and the local life of the object it fills.
//
// A copy belongs to one local life of its object, identified by the data key
// PromoteObject gave it (generation).  If the object is demoted, deleted or
// promoted again, a copy still queued or running for the old life stops
// before writing anything more.
type coldSource struct {
	hash       InstanceHash
	generation []byte
	target     *tierTarget
	expect     TierObjectInfo
	size       int64
	lastBlock  uint32
}

// newTierPromoter creates the promoter of pc, whose copies run under ctx
// (pc.downloadCtx, which Close cancels, or for a test a context derived from
// it).
func newTierPromoter(pc *PersistentCache, ctx context.Context) *tierPromoter {
	p := &tierPromoter{
		pc:         pc,
		db:         pc.db,
		storage:    pc.storage,
		eviction:   pc.eviction,
		ctx:        ctx,
		fillSem:    make(chan struct{}, tierPromoteBackgroundFills),
		background: make(map[InstanceHash][]byte),
	}
	// Resume interrupted background copies.  Off the startup path, like the
	// uploader's recovery: it can touch every intent, and serving does not
	// depend on it -- an unfinished promotion is filled on demand anyway.
	pc.goWhileOpen(p.recover)
	return p
}

// promoteForRead decides how a read of an object resident on a tiering
// target is served.  For a cold target it promotes the object to local
// storage, updates res to the promoted metadata and returns true, after which
// the caller serves it like any local object.  It returns false -- serve it
// from the target -- for an ordinary target, or when promotion is declined
// or fails; a proxied read of a cold object is always possible, since its
// cold copy outlives the promotion.
//
// whole says the read is for the entire object, which starts a background
// copy of the rest; see the package comment above.
func (pc *PersistentCache) promoteForRead(res *objectResolution, whole bool) bool {
	target := pc.storage.getTierTarget(res.meta.StorageID)
	if pc.promoter == nil || target == nil || !target.cfg.Cold {
		return false
	}
	meta, err := pc.promoter.promote(res.instanceHash, target, whole)
	if err != nil {
		if !errors.Is(err, errPromotionDeclined) {
			log.Warnf("Failed to promote %s from cold tiering target %s; serving it from there: %v",
				res.instanceHash, target.DisplayURL(), err)
			recordTierPromotion(target, tierPromotionError)
		} else {
			log.Debugf("Serving %s from cold tiering target %s: %v", res.instanceHash, target.DisplayURL(), err)
			recordTierPromotion(target, tierPromotionDeclined)
		}
		return false
	}
	res.meta = meta
	return true
}

// partlyPromoted reports whether an object promoted from a cold target is
// still missing blocks.  A fully promoted object is an ordinary local one,
// read without any of the promotion machinery.  If its block state cannot
// be read it is treated as partly promoted, which is the path that copes.
func (pc *PersistentCache) partlyPromoted(res *objectResolution) bool {
	if res.meta == nil || res.meta.ColdCopy == nil {
		return false
	}
	bs, err := pc.storage.GetSharedBlockState(res.instanceHash)
	return err != nil || bs.GetCardinality() < uint64(CalculateBlockCount(res.meta.ContentLength))
}

// finishPromotionForWholeRead starts the background copy of a partly
// promoted object -- one an earlier range read left partly local -- when it
// is read whole, so that, as for a first whole read, the rest is copied even
// if the client leaves.
func (pc *PersistentCache) finishPromotionForWholeRead(res *objectResolution, whole bool) {
	if whole && pc.promoter != nil && pc.partlyPromoted(res) {
		pc.promoter.startBackgroundFill(res.instanceHash, res.meta)
	}
}

// promote moves an object resident on cold target back to local storage and
// returns its new metadata.  Concurrent callers for one object share one
// promotion.
func (p *tierPromoter) promote(hash InstanceHash, target *tierTarget, whole bool) (*CacheMetadata, error) {
	v, err, _ := p.flips.Do(string(hash), func() (any, error) {
		return p.flip(hash, target)
	})
	if err != nil {
		return nil, err
	}
	meta := v.(*CacheMetadata)
	if whole {
		p.startBackgroundFill(hash, meta)
	}
	return meta, nil
}

// flip performs the metadata half of a promotion: it picks a local directory,
// charges it, creates the local file and commits CacheDB.PromoteObject.
func (p *tierPromoter) flip(hash InstanceHash, target *tierTarget) (*CacheMetadata, error) {
	meta, err := p.storage.GetMetadata(hash)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}
	if meta.StorageID != target.id {
		// Promoted (or otherwise moved) since the caller looked.
		if meta.ColdCopy != nil && !p.storage.IsTiered(meta.StorageID) {
			return meta, nil
		}
		return nil, errors.Wrap(errPromotionDeclined, "object moved while being promoted")
	}
	// An upload that demoted this object may still be waiting for a reader
	// to let go of its old local copy before deleting it.  That copy's files
	// sit where the promoted copy would go.
	if intent, err := p.db.GetTierUploadIntent(hash); err != nil || intent != nil {
		return nil, errors.Wrap(errPromotionDeclined, "its previous local copy has not been released yet")
	}

	fileSize := CalculateFileSize(meta.ContentLength)
	sid := p.eviction.ChooseDiskStorage()
	if p.storage.IsTiered(sid) {
		return nil, errors.Wrap(errPromotionDeclined, "no local storage directory to promote into")
	}
	// Reserve the room in eviction's accounting first, atomically, so that
	// a burst of promotions cannot together push the directory past its
	// maximum -- where eviction stops demoting and starts deleting.
	if !p.eviction.reserveForPromotion(sid, fileSize) {
		return nil, errors.Wrapf(errPromotionDeclined, "local storage has no room for a %d-byte object", fileSize)
	}

	// Charge first, as an upload does: a crash between here and the commit
	// over-counts until the next usage reconciliation, never under-counts.
	if err := p.db.AddUsage(sid, meta.NamespaceID, fileSize); err != nil {
		p.eviction.NoteUsageDecrease(sid, fileSize)
		return nil, errors.Wrap(err, "failed to charge local storage")
	}
	refund := func() {
		if err := p.db.AddUsage(sid, meta.NamespaceID, -fileSize); err != nil {
			log.Warnf("Failed to refund local storage for %s: %v", hash, err)
		}
		p.eviction.NoteUsageDecrease(sid, fileSize)
	}

	encMgr := p.db.GetEncryptionManager()
	dek, err := encMgr.GenerateDataKey()
	if err != nil {
		refund()
		return nil, errors.Wrap(err, "failed to generate a data key")
	}
	wrapped, err := encMgr.EncryptDataKey(dek)
	if err != nil {
		refund()
		return nil, errors.Wrap(err, "failed to wrap the data key")
	}

	path := p.storage.getObjectPathForDir(sid, hash)
	file, err := createFile(path)
	if err != nil {
		refund()
		return nil, errors.Wrap(err, "failed to create the local file")
	}
	err = file.Truncate(fileSize)
	file.Close()
	if err != nil {
		_ = os.Remove(path)
		refund()
		return nil, errors.Wrap(err, "failed to allocate the local file")
	}

	// Drop anything cached about the object's previous local life before
	// the new key and bitmap become visible, and again after, so no reader
	// pairs the new metadata with stale state.
	p.storage.invalidateObjectCaches(hash, 1)
	promoted, err := p.db.PromoteObject(hash, target.id, sid, wrapped)
	p.storage.invalidateObjectCaches(hash, 1)
	if err != nil {
		_ = os.Remove(path)
		refund()
		return nil, errors.Wrap(err, "failed to record the promotion")
	}
	// A block-state load that began before the commit could still cache the
	// cold-resident view of the object -- no bitmap and Completed, which
	// reads as every block present.  A promoted object starts with none.
	if bs, err := p.storage.GetSharedBlockState(hash); err == nil && bs.GetCardinality() != 0 {
		p.storage.InvalidateSharedBlockState(hash)
	}
	recordTierPromotion(target, tierPromotionStarted)
	log.Debugf("Promoting %s (%d bytes) from cold tiering target %s to storage %d",
		hash, meta.ContentLength, target.DisplayURL(), sid)
	return promoted, nil
}

// sourceFor returns the cold copy a promoted object's missing blocks are to be
// copied from.  It fails with errPromotionStale when the object is not on
// local storage (or not at all), and with errColdCopyUnavailable when it has
// no cold copy to copy from: none is recorded, the copy's target is no longer
// configured, or its liveness probe says it is down -- readers then fill from
// the origin, rather than try a target known to be unreachable for every
// block they read.
func (p *tierPromoter) sourceFor(hash InstanceHash) (*coldSource, error) {
	meta, err := p.storage.GetMetadata(hash)
	if err != nil {
		return nil, err
	}
	if meta == nil || !p.storage.isLocalDir(meta.StorageID) || meta.ContentLength <= 0 {
		return nil, errPromotionStale
	}
	if meta.ColdCopy == nil {
		return nil, errColdCopyUnavailable
	}
	target := p.storage.getTierTarget(meta.ColdCopy.StorageID)
	if target == nil {
		return nil, errors.Wrap(errColdCopyUnavailable, "its target is no longer configured")
	}
	if !target.healthy.Load() {
		return nil, errors.Wrapf(errColdCopyUnavailable, "cold tiering target %s is down", target.DisplayURL())
	}
	return &coldSource{
		hash:       hash,
		generation: meta.DataKey,
		target:     target,
		expect:     meta.ColdCopy.Remote,
		size:       meta.ContentLength,
		lastBlock:  CalculateBlockCount(meta.ContentLength) - 1,
	}, nil
}

// check reports whether the object is still in the local life src was taken
// from (errPromotionStale if not), with the cold copy it recorded then
// (errColdCopyUnavailable if not).
func (p *tierPromoter) check(src *coldSource) error {
	meta, err := p.storage.GetMetadata(src.hash)
	if err != nil {
		return err
	}
	if meta == nil || !p.storage.isLocalDir(meta.StorageID) || !bytes.Equal(meta.DataKey, src.generation) {
		return errPromotionStale
	}
	if meta.ColdCopy == nil || meta.ColdCopy.StorageID != src.target.id {
		return errColdCopyUnavailable
	}
	return nil
}

// startFill starts a fill of a promoted object from its cold copy, for a
// reader that needs a block that nothing is writing; see
// PersistentCache.startFill, whose rules it follows and whose results it
// returns.  handled is false when the object has no cold copy to copy from;
// the caller then fills from the origin.
func (p *tierPromoter) startFill(hash InstanceHash, state *ObjectBlockState, block, last uint32, overDownload bool) (handled, covered bool, started <-chan struct{}) {
	src, err := p.sourceFor(hash)
	if err != nil {
		log.Debugf("Not copying %s from its cold copy: %v", hash, err)
		return false, false, nil
	}
	fill := state.beginFill(block, min(last, src.lastBlock), overDownload)
	if fill == nil {
		// Already written, or something else is writing it.
		return true, true, nil
	}
	log.Debugf("Copying blocks %d-%d of %s from cold tiering target %s", fill.start, fill.end, hash, src.target.DisplayURL())
	launched := p.pc.goFill(hash, state, fill, func() {
		// Like a fill from the origin, a reader's copy goes on while any
		// reader of the object is open, and stops once none has been for
		// the prefetch timeout.
		ctx, cancel := context.WithCancelCause(p.ctx)
		defer cancel(nil)
		stopWatching := cancelWhenIdle(ctx, cancel, state, fillIdleTimeout())
		defer stopWatching()
		stream := p.openStream(ctx, src)
		defer stream.Close()
		if err := p.copyFill(ctx, src, stream, state, fill); err != nil {
			logCopyStop(src, fill, err)
		}
	})
	if !launched {
		return true, false, nil
	}
	return true, true, fill.done
}

// cancelWhenIdle cancels ctx, with errPrefetchIdle, once no reader of the
// object has been open for timeout -- the rule BlockFetcherV2 applies to a
// fill from the origin -- and returns the function that stops watching.
func cancelWhenIdle(ctx context.Context, cancel context.CancelCauseFunc, state *ObjectBlockState, timeout time.Duration) (stop func()) {
	started := time.Now()
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		ticker := time.NewTicker(idleCheckInterval(timeout))
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				open, last := state.readerActivity()
				if open {
					continue
				}
				if started.After(last) {
					last = started
				}
				if time.Since(last) > timeout {
					cancel(errPrefetchIdle)
					return
				}
			}
		}
	}()
	return func() {
		close(done)
		<-exited
	}
}

// openStream opens a read of src's cold copy, pinned to the copy recorded
// when it was uploaded.  A copy found changed is dropped, so that what the
// object still lacks comes from the origin.
func (p *tierPromoter) openStream(ctx context.Context, src *coldSource) *tierObjectStream {
	stream := newTierObjectStream(ctx, src.target, src.hash, src.size)
	expect := src.expect
	stream.expect = &expect
	stream.onChanged = func() {
		tierChangedObjectsTotal.WithLabelValues(src.target.metricLabel(), tierChangeSeenOnRead).Inc()
		if _, err := p.storage.dropColdCopy(src.hash, src.target.id); err != nil {
			log.Warnf("Failed to drop the changed cold copy of %s: %v", src.hash, err)
		}
	}
	return stream
}

// coldStopKeepsData reports whether a copy from a cold copy that ended in err
// left whole blocks fit to keep: the cases transferStopKeepsData accepts for a
// transfer from the origin -- among them the cache's own idle cancel and
// shutdown -- plus the target failing to deliver the copy (unreachable,
// failing every read, or no longer holding it).  Every read of the cold copy
// is pinned to the copy that was uploaded, so the bytes it did deliver are
// that copy's.
func coldStopKeepsData(err error) bool {
	var readErr *tierReadError
	return errors.As(err, &readErr) || errors.Is(err, errColdCopyUnavailable) || transferStopKeepsData(err)
}

// copyFill copies the blocks of fill from the cold copy through stream, and
// ends its writer according to how the copy went, by the rules a fill from
// the origin follows (see endWrite and BlockFetcherV2.dropIfCondemned):
//
//   - a copy that completes closes the writer;
//   - one stopped for a reason that says nothing against its bytes (see
//     coldStopKeepsData) keeps the whole blocks it wrote (StopEarly);
//   - one whose object left local storage, or began another local life,
//     publishes nothing more (Abort): what it has not yet published belongs
//     to a life that has ended;
//   - anything else -- the cold copy ending before its recorded size, or a
//     failure to write locally -- publishes nothing more, and if it wrote
//     anything condemns the object: its readers are told why, and it is
//     dropped, kept cold copy and all, so that the next read fetches it from
//     the origin.
//
// The caller ends the fill afterwards, so the readers waiting for it are
// woken only once that verdict is in.
func (p *tierPromoter) copyFill(ctx context.Context, src *coldSource, stream *tierObjectStream, state *ObjectBlockState, fill *blockFill) error {
	// Checked after the object was pinned: once pinned it cannot be demoted,
	// but it may have been before, and a deletion does not wait for pins.
	// Writing after that would put an object-sized file on local storage
	// that nothing accounts for.
	if err := p.check(src); err != nil {
		return err
	}
	start := int64(fill.start) * BlockDataSize
	end := min(int64(fill.end+1)*BlockDataSize, src.size)
	if _, err := stream.Seek(start, io.SeekStart); err != nil {
		return err
	}
	bw, err := p.storage.NewBlockWriter(src.hash, fill.start, nil, nil)
	if err != nil {
		return errors.Wrap(err, "failed to open the local copy for writing")
	}
	w := &coldFillWriter{
		bw:        bw,
		lastFlush: time.Now(),
		bytes:     tierPromotedBytesTotal.WithLabelValues(src.target.metricLabel()),
	}
	err = copyColdRange(ctx, w, stream, end-start)
	switch {
	case err == nil:
		if err := bw.Close(); err != nil {
			return errors.Wrap(err, "failed to finish writing the local copy")
		}
	case errors.Is(err, errPromotionStale):
		bw.Abort()
	case coldStopKeepsData(err):
		bw.StopEarly()
	default:
		bw.Abort()
		if w.written > 0 {
			log.Warnf("Copying %s back from cold tiering target %s failed after writing part of it (%v); dropping the object so that it is fetched again",
				src.hash, src.target.DisplayURL(), err)
			state.condemn(err)
			if err := p.storage.Delete(src.hash); err != nil {
				log.Warnf("Failed to drop %s: %v", src.hash, err)
			}
		}
	}
	return err
}

// copyColdRange copies n bytes from src to dst, stopping with ctx's cause once
// ctx is done.
func copyColdRange(ctx context.Context, dst io.Writer, src io.Reader, n int64) error {
	buf := make([]byte, min(n, tierPromoteCopyBuffer))
	for n > 0 {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		r, err := src.Read(buf[:min(int64(len(buf)), n)])
		if r > 0 {
			if _, werr := dst.Write(buf[:r]); werr != nil {
				return werr
			}
			n -= int64(r)
		}
		switch {
		case err == nil:
		case ctx.Err() != nil:
			// A read cut off by the cancel reports the cancel's reason.
			return context.Cause(ctx)
		case errors.Is(err, io.EOF):
			if n > 0 {
				return errColdCopyShort
			}
		default:
			return err
		}
	}
	return nil
}

// coldFillWriter feeds a copy's bytes to its BlockWriter.
type coldFillWriter struct {
	bw        *BlockWriter
	written   int64
	lastFlush time.Time
	bytes     interface{ Add(float64) }
}

func (w *coldFillWriter) Write(b []byte) (int, error) {
	n, err := w.bw.Write(b)
	w.written += int64(n)
	w.bytes.Add(float64(n))
	if err != nil {
		return n, errors.Wrap(err, "failed to write blocks")
	}
	// Publish what has arrived now and then, as a fill from the origin
	// does, so that the readers of a slow copy are not held up for a whole
	// write batch.
	if time.Since(w.lastFlush) >= ETAUpdateInterval {
		if err := w.bw.Flush(); err != nil {
			return n, errors.Wrap(err, "failed to flush blocks")
		}
		w.lastFlush = time.Now()
	}
	return n, nil
}

// logCopyStop logs a copy from a cold copy that ended early.
func logCopyStop(src *coldSource, fill *blockFill, err error) {
	if errors.Is(err, errPromotionStale) || errors.Is(err, errPrefetchIdle) || errors.Is(err, context.Canceled) {
		log.Debugf("Copy of blocks %d-%d of %s from its cold copy stopped: %v", fill.start, fill.end, src.hash, err)
		return
	}
	log.Warnf("Copy of blocks %d-%d of %s from cold tiering target %s ended early (%v); what is still missing comes from the origin",
		fill.start, fill.end, src.hash, src.target.DisplayURL(), err)
}

// startBackgroundFill copies the rest of a promoted object in the background,
// unless that is already under way.  The copy runs to the end even if every
// reader leaves, and a PrefixTierPromote intent lets a restart resume it.
func (p *tierPromoter) startBackgroundFill(hash InstanceHash, meta *CacheMetadata) {
	if meta == nil || meta.ColdCopy == nil || meta.ContentLength <= 0 {
		return
	}
	if bs, err := p.storage.GetSharedBlockState(hash); err == nil &&
		bs.GetCardinality() >= uint64(CalculateBlockCount(meta.ContentLength)) {
		return // every block is local already
	}
	generation := meta.DataKey
	p.mu.Lock()
	if running, ok := p.background[hash]; ok && bytes.Equal(running, generation) {
		p.mu.Unlock()
		return
	}
	// A copy left over from an earlier local life of the object stops at its
	// next check; this one is for the current life.
	p.background[hash] = generation
	p.mu.Unlock()
	finish := func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if running, ok := p.background[hash]; ok && bytes.Equal(running, generation) {
			delete(p.background, hash)
		}
	}

	if err := p.db.SetTierPromoteIntent(hash); err != nil {
		log.Warnf("Failed to record the background promotion of %s; a restart will not resume it: %v", hash, err)
	}
	if !p.pc.goWhileOpen(func() {
		defer finish()
		p.runBackground(hash, generation)
	}) {
		finish() // closing: the intent stays, and the next start resumes the copy
	}
}

// runBackground runs a background copy of the local life of an object that
// generation identifies, once a slot is free, and settles its intent.
func (p *tierPromoter) runBackground(hash InstanceHash, generation []byte) {
	select {
	case p.fillSem <- struct{}{}:
	case <-p.ctx.Done():
		return // keep the intent; the next start resumes the copy
	}
	defer func() { <-p.fillSem }()
	// The copy outlives the read that started it, so it pins the object
	// itself: eviction must not demote it while blocks are still being
	// written.
	unpin := p.storage.PinObject(hash)
	defer unpin()

	src, err := p.sourceFor(hash)
	if err == nil && !bytes.Equal(src.generation, generation) {
		err = errPromotionStale
	}
	if err == nil {
		err = p.copyAll(src)
	}
	complete, completeErr := p.storage.IsComplete(hash)
	switch {
	case errors.Is(err, errPromotionStale):
		// The object left local storage (or started a new local life)
		// while the copy waited or ran; whatever ended it took the intent
		// with it.
		log.Debugf("Background promotion of %s abandoned: %v", hash, err)
		return
	case completeErr == nil && complete:
		if src != nil {
			recordTierPromotion(src.target, tierPromotionCompleted)
			log.Debugf("Promotion of %s from %s is complete", hash, src.target.DisplayURL())
		}
	case p.ctx.Err() != nil:
		return // shutting down; keep the intent so the copy resumes
	default:
		// The object stays partly local, which is a valid state: the rest
		// is fetched as it is read, and eviction can still demote it.
		if src != nil {
			recordTierPromotion(src.target, tierPromotionFailed)
		}
		log.Warnf("Background promotion of %s stopped short: %v", hash, err)
	}
	if err := p.db.DeleteTierPromoteIntent(hash); err != nil {
		log.Warnf("Failed to clear the promotion intent for %s: %v", hash, err)
	}
}

// copyAll copies every block of src's object that is still missing, as a
// series of fills of at most tierPromoteSegment blocks (see there).  Blocks
// another fill is already writing -- a reader's -- are left to it: the copy
// waits for that fill to end and then carries on from the same place, copying
// whatever it left missing.
func (p *tierPromoter) copyAll(src *coldSource) error {
	stream := p.openStream(p.ctx, src)
	defer stream.Close()
	for pos := uint32(0); ; {
		if p.ctx.Err() != nil {
			return context.Cause(p.ctx)
		}
		state, err := p.storage.GetSharedBlockState(src.hash)
		if err != nil {
			return err
		}
		if err := state.Condemned(); err != nil {
			return err
		}
		block, missing := state.firstMissing(pos, src.lastBlock)
		if !missing {
			return nil
		}
		last := uint32(min(uint64(block)+tierPromoteSegment-1, uint64(src.lastBlock)))
		// overDownload: a promoted object has no whole-object download, and
		// if it had, this copy would not wait for it.
		fill := state.beginFill(block, last, true)
		if fill == nil {
			if done := state.fillOver(block); done != nil {
				select {
				case <-done:
				case <-p.ctx.Done():
					return context.Cause(p.ctx)
				}
			}
			pos = block
			continue
		}
		err = p.copyFill(p.ctx, src, stream, state, fill)
		state.endFill(fill)
		if err != nil {
			return err
		}
		pos = fill.end + 1
	}
}

// recover resumes the background copies a previous process left unfinished.
// An intent whose object has since been deleted, demoted or finished is
// simply dropped.
func (p *tierPromoter) recover() {
	hashes, err := p.db.ListTierPromoteIntents()
	if err != nil {
		log.Warnf("Failed to list interrupted promotions: %v", err)
		return
	}
	for _, hash := range hashes {
		if p.ctx.Err() != nil {
			return
		}
		meta, err := p.storage.GetMetadata(hash)
		if err != nil {
			log.Warnf("Failed to load metadata for interrupted promotion %s: %v", hash, err)
			continue
		}
		resumable := meta != nil && meta.ColdCopy != nil && p.storage.isLocalDir(meta.StorageID) &&
			p.storage.getTierTarget(meta.ColdCopy.StorageID) != nil
		if resumable {
			if complete, err := p.storage.IsComplete(hash); err == nil && !complete {
				log.Debugf("Resuming the promotion of %s", hash)
				p.startBackgroundFill(hash, meta)
				continue
			}
		}
		if err := p.db.DeleteTierPromoteIntent(hash); err != nil {
			log.Warnf("Failed to clear the promotion intent for %s: %v", hash, err)
		}
	}
}
