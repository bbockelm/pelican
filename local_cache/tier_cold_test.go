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

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// These tests use the in-memory blob driver, so like tier_backend_test.go
// they need no external service and run on every platform.

// countingBackend counts what the cache asks of a tier backend, so a test can
// tell whether bytes moved between tiers.
type countingBackend struct {
	TierBackend
	puts  atomic.Int64
	opens atomic.Int64
}

func (b *countingBackend) Put(ctx context.Context, key, contentType string, size int64, body io.Reader) (TierObjectInfo, error) {
	b.puts.Add(1)
	return b.TierBackend.Put(ctx, key, contentType, size, body)
}

func (b *countingBackend) OpenRange(ctx context.Context, key string, offset int64, expect *TierObjectInfo) (io.ReadCloser, error) {
	b.opens.Add(1)
	return b.TierBackend.OpenRange(ctx, key, offset, expect)
}

// coldTestData returns n bytes with a pattern that makes misplaced blocks
// show up as mismatches.
func coldTestData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte((i*7 + i/4093) % 251)
	}
	return data
}

// coldEnvConfig is a cold in-memory target.
func coldEnvConfig() TierTargetConfig {
	return TierTargetConfig{ProviderURL: "mem://", Prefix: "cold", MaxSize: 1 << 30, Cold: true}
}

// storeLRUObject stores a completed local object and gives it an LRU entry,
// which eviction needs to find it.  Objects stored one after another are
// ordered oldest first.
func storeLRUObject(t *testing.T, ctx context.Context, env *tierTestEnv, hash InstanceHash, data []byte, nsID NamespaceID) {
	t.Helper()
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, nsID)
	require.NoError(t, env.eviction.RecordAccess(hash))
}

// drainDemotions runs the uploads eviction queued, as the upload workers
// would.
func drainDemotions(t *testing.T, ctx context.Context, u *tierUploader) int {
	t.Helper()
	n := 0
	for {
		select {
		case hash := <-u.queue:
			require.NoError(t, u.processObject(ctx, hash))
			u.settleDemotion(hash)
			n++
		default:
			return n
		}
	}
}

// TestColdTierDemotesOnEviction checks the demotion half of cold tiering:
// local storage is the hot tier, nothing is uploaded when it completes, and
// watermark eviction moves the least recently used objects to the cold
// target instead of deleting them -- except objects too small to be worth it,
// and anything at all when no cold target can take it, which are deleted so
// that local space is always reclaimed.
func TestColdTierDemotesOnEviction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnvWith(t, ctx, coldEnvConfig(),
		EvictionDirConfig{MaxSize: 64 * 1024, HighWaterPercentage: 90, LowWaterPercentage: 50})
	require.True(t, env.uploader.cold)
	backend := &countingBackend{TierBackend: env.target.backend}
	env.target.backend = backend
	nsID := NamespaceID(1)

	small := InstanceHash(fmt.Sprintf("%064d", 1))
	large := []InstanceHash{InstanceHash(fmt.Sprintf("%064d", 2)), InstanceHash(fmt.Sprintf("%064d", 3)), InstanceHash(fmt.Sprintf("%064d", 4))}
	storeLRUObject(t, ctx, env, small, coldTestData(500), nsID)
	payloads := make(map[InstanceHash][]byte)
	for i, h := range large {
		payloads[h] = coldTestData(20*1024 + i)
		storeLRUObject(t, ctx, env, h, payloads[h], nsID)
	}
	env.eviction.recalculateDirUsage()
	label := env.target.metricLabel()
	uploaded := testutil.ToFloat64(tierDemotionsTotal.WithLabelValues(label, tierDemotedByUpload))

	// Completing objects uploads nothing: cold targets are not tiered to on
	// completion.
	assert.Zero(t, backend.puts.Load())

	env.eviction.checkAndEvict()

	// The small object is below the tiering threshold and was deleted.
	meta, err := env.storage.GetMetadata(small)
	require.NoError(t, err)
	assert.Nil(t, meta, "an object below the tiering threshold is deleted, not demoted")

	// The two least recently used large objects were queued, and eviction
	// counted them as freed: the pass stopped there.
	assert.Positive(t, env.uploader.pendingDemotionBytes(env.diskID))
	require.Equal(t, 2, drainDemotions(t, ctx, env.uploader))
	assert.Zero(t, env.uploader.pendingDemotionBytes(env.diskID), "settled demotions are no longer pending")
	assert.Equal(t, uploaded+2, testutil.ToFloat64(tierDemotionsTotal.WithLabelValues(label, tierDemotedByUpload)))

	for i, h := range large {
		meta, err := env.storage.GetMetadata(h)
		require.NoError(t, err)
		require.NotNil(t, meta, "a demoted object is kept")
		if i == 2 {
			assert.Equal(t, env.diskID, meta.StorageID, "the most recently used object stays local")
			continue
		}
		assert.Equal(t, env.tierID, meta.StorageID, "object %d should be on the cold target", i)
		require.NotNil(t, meta.Remote)
		_, statErr := os.Stat(env.storage.getObjectPathForDir(env.diskID, h))
		assert.True(t, os.IsNotExist(statErr), "the local copy of a demoted object is released")

		rc, err := env.target.openStream(ctx, h, 0, meta.Remote)
		require.NoError(t, err)
		got, err := io.ReadAll(rc)
		rc.Close()
		require.NoError(t, err)
		assert.True(t, bytes.Equal(payloads[h], got), "the cold target holds the object's bytes")
	}
	diskUsage, err := env.db.GetUsage(env.diskID, nsID)
	require.NoError(t, err)
	assert.Equal(t, CalculateFileSize(int64(len(payloads[large[2]]))), diskUsage)
	tierUsage, err := env.db.GetUsage(env.tierID, nsID)
	require.NoError(t, err)
	assert.Equal(t, CalculateFileSize(int64(len(payloads[large[0]])))+CalculateFileSize(int64(len(payloads[large[1]]))), tierUsage)

	// With no healthy cold target, eviction deletes rather than wait.
	env.target.healthy.Store(false)
	last := InstanceHash(fmt.Sprintf("%064d", 5))
	storeLRUObject(t, ctx, env, last, coldTestData(40*1024), nsID)
	env.eviction.recalculateDirUsage()
	env.eviction.checkAndEvict()
	assert.Zero(t, drainDemotions(t, ctx, env.uploader))
	meta, err = env.storage.GetMetadata(large[2])
	require.NoError(t, err)
	assert.Nil(t, meta, "with no cold target to take it, the object is deleted")
}

// TestColdTierDeletesPastTheHardLimit checks that demotion, whose space is
// only freed when an upload finishes, is not relied on once local storage is
// already over its maximum: such a pass deletes.
func TestColdTierDeletesPastTheHardLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnvWith(t, ctx, coldEnvConfig(),
		EvictionDirConfig{MaxSize: 32 * 1024, HighWaterPercentage: 90, LowWaterPercentage: 50})
	nsID := NamespaceID(1)
	hashes := []InstanceHash{InstanceHash(fmt.Sprintf("%064d", 11)), InstanceHash(fmt.Sprintf("%064d", 12))}
	for _, h := range hashes {
		storeLRUObject(t, ctx, env, h, coldTestData(20*1024), nsID)
	}
	env.eviction.recalculateDirUsage()
	env.eviction.checkAndEvict()
	assert.Zero(t, drainDemotions(t, ctx, env.uploader), "nothing is demoted from storage over its hard limit")
	meta, err := env.storage.GetMetadata(hashes[0])
	require.NoError(t, err)
	assert.Nil(t, meta)
}

// TestColdTierRecoveryDoesNotRequeue checks that crash recovery of an upload
// that never committed leaves a cold-tier object local: it was being demoted
// because eviction needed the room, and eviction will offer it again if it
// still does.  (An ordinary target would re-queue it.)
func TestColdTierRecoveryDoesNotRequeue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnvWith(t, ctx, coldEnvConfig(), EvictionDirConfig{MaxSize: 1 << 30})
	hash := InstanceHash(fmt.Sprintf("%064d", 21))
	data := coldTestData(8 * 1024)
	storeLRUObject(t, ctx, env, hash, data, 1)
	require.NoError(t, env.db.SetTierUploadIntent(hash, &TierUploadIntent{
		TargetStorageID:   env.tierID,
		OriginalStorageID: env.diskID,
		Key:               env.target.objectKey(hash),
		Size:              int64(len(data)),
		NamespaceID:       1,
		StartedAt:         time.Now(),
	}))
	require.NoError(t, env.uploader.recover(ctx))
	assert.Empty(t, env.uploader.queue, "recovery must not demote an object nothing asked to demote")
	intent, err := env.db.GetTierUploadIntent(hash)
	require.NoError(t, err)
	assert.Nil(t, intent)
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Equal(t, env.diskID, meta.StorageID)
}

// TestColdTierConfig checks the Cold key and the rule that cold and ordinary
// targets are not mixed.
func TestColdTierConfig(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Cache_TieringTargets.Set([]interface{}{
		map[string]interface{}{"ProviderURL": "mem://a", "MaxSize": "1GB", "Cold": true},
		map[string]interface{}{"ProviderURL": "mem://b", "MaxSize": "1GB", "Cold": true},
	}))
	cfgs, err := ParseTierTargetsConfig()
	require.NoError(t, err)
	require.Len(t, cfgs, 2)
	assert.True(t, cfgs[0].Cold)
	assert.True(t, cfgs[1].Cold)

	require.NoError(t, param.Cache_TieringTargets.Set([]interface{}{
		map[string]interface{}{"ProviderURL": "mem://a", "MaxSize": "1GB", "Cold": true},
		map[string]interface{}{"ProviderURL": "mem://b", "MaxSize": "1GB"},
	}))
	_, err = ParseTierTargetsConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Cold")
}

// coldCacheEnv is a whole PersistentCache with one cold in-memory target,
// for exercising promotion through the real read path.
type coldCacheEnv struct {
	pc     *PersistentCache
	ctx    context.Context
	egrp   *errgroup.Group
	tierID StorageID
	diskID StorageID
	target *tierTarget
	srv    *httptest.Server
	// backend is the target's backend, through which faults are injected.
	backend *faultyBackend
}

// faultyBackend wraps a tier backend so a test can make it go down part-way
// through a read, and count its reads.  It is installed when the backend is
// opened (wrapTierBackendForTest), before anything else can use it, and is
// configured through atomics, so tests can change it while the cache runs.
type faultyBackend struct {
	TierBackend
	opens atomic.Int64
	// budget, when non-negative, is how many more bytes the backend serves
	// before it goes down: the read in progress then fails -- or, with stall
	// set, blocks until its context ends -- and later opens fail.
	budget atomic.Int64
	stall  atomic.Bool
	// resume, when set with stall, ends a stall when it is closed: the
	// backend then serves without a budget again.
	resume atomic.Pointer[chan struct{}]
	// resets makes reads fail at once, while opens still succeed: that many
	// of them when positive, every one when negative.
	resets atomic.Int64
	// served is signalled when the budget runs out.
	served chan struct{}
	// hold, while set, blocks every read of a body opened at offset holdAt
	// (of any body, when holdAt is negative) until it is closed or the
	// read's context ends; held is signalled when a read starts to wait.
	hold   atomic.Pointer[chan struct{}]
	holdAt atomic.Int64
	held   chan struct{}
}

func newFaultyBackend(inner TierBackend) *faultyBackend {
	b := &faultyBackend{TierBackend: inner, served: make(chan struct{}, 16), held: make(chan struct{}, 16)}
	b.budget.Store(-1)
	b.holdAt.Store(-1)
	return b
}

// goDownAfter makes the backend fail once n more bytes have been read.
func (b *faultyBackend) goDownAfter(n int64) { b.budget.Store(n) }

// recover brings the backend back.
func (b *faultyBackend) recover() { b.budget.Store(-1) }

func (b *faultyBackend) OpenRange(ctx context.Context, key string, offset int64, expect *TierObjectInfo) (io.ReadCloser, error) {
	b.opens.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b.budget.Load() == 0 {
		return nil, errors.New("injected: target unreachable")
	}
	rc, err := b.TierBackend.OpenRange(ctx, key, offset, expect)
	if err != nil {
		return nil, err
	}
	return &faultyReader{ReadCloser: rc, b: b, ctx: ctx, offset: offset}, nil
}

type faultyReader struct {
	io.ReadCloser
	b      *faultyBackend
	ctx    context.Context
	offset int64 // where the body starts
}

func (r *faultyReader) Read(p []byte) (int, error) {
	if hold := r.b.hold.Load(); hold != nil {
		if at := r.b.holdAt.Load(); at < 0 || at == r.offset {
			select {
			case r.b.held <- struct{}{}:
			default:
			}
			select {
			case <-*hold:
			case <-r.ctx.Done():
				return 0, r.ctx.Err()
			}
		}
	}
	if n := r.b.resets.Load(); n != 0 {
		if n > 0 {
			r.b.resets.Add(-1)
		}
		return 0, errors.New("injected: connection reset")
	}
	left := r.b.budget.Load()
	if left == 0 {
		select {
		case r.b.served <- struct{}{}:
		default:
		}
		if r.b.stall.Load() {
			var resume <-chan struct{}
			if ch := r.b.resume.Load(); ch != nil {
				resume = *ch
			}
			select {
			case <-r.ctx.Done():
				return 0, r.ctx.Err()
			case <-resume:
				r.b.budget.Store(-1)
				return r.Read(p)
			}
		}
		return 0, errors.New("injected: connection reset")
	}
	if left > 0 && int64(len(p)) > left {
		p = p[:left]
	}
	n, err := r.ReadCloser.Read(p)
	if left > 0 {
		r.b.budget.Add(-int64(n))
	}
	return n, err
}

func newColdCache(t *testing.T, diskMax uint64) *coldCacheEnv {
	t.Helper()
	return newColdCacheWith(t, diskMax,
		map[string]interface{}{"ProviderURL": "mem://", "Prefix": "cold", "MaxSize": "1GB", "Cold": true})
}

// newColdCacheWith is newColdCache with a chosen Cache.TieringTargets entry.
func newColdCacheWith(t *testing.T, diskMax uint64, target map[string]interface{}) *coldCacheEnv {
	t.Helper()
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(context.Background())
	egrp, _ := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})

	// Stub federation so NewPersistentCache resolves offline.
	config.SetFederation(pelican_url.FederationDiscovery{
		DiscoveryEndpoint: "https://cache.example:8443",
		DirectorEndpoint:  "https://cache.example:8443",
	})
	require.NoError(t, param.Cache_TieringTargets.Set([]interface{}{target}))
	require.NoError(t, param.Cache_TieringThreshold.Set("1KB"))

	var backend *faultyBackend
	wrapTierBackendForTest = func(inner TierBackend) TierBackend {
		backend = newFaultyBackend(inner)
		return backend
	}
	t.Cleanup(func() { wrapTierBackendForTest = nil })

	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir, MaxSize: diskMax}},
		DeferConfig: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	require.NotNil(t, pc.promoter, "a cold target should wire the promoter")
	require.NoError(t, pc.ac.updateConfig([]server_structs.NamespaceAd{{
		Path: "/test",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	}}))

	wrapTierBackendForTest = nil
	require.NotNil(t, backend)
	env := &coldCacheEnv{pc: pc, ctx: ctx, egrp: egrp, backend: backend}
	for id := range pc.storage.tierTargets {
		env.tierID = id
	}
	for id := range pc.storage.GetDirs() {
		env.diskID = id
	}
	env.target = pc.storage.getTierTarget(env.tierID)
	require.False(t, env.target.canRedirect, "a cold target never redirects")
	env.srv = httptest.NewServer(http.HandlerFunc(pc.serveObject))
	t.Cleanup(env.srv.Close)
	return env
}

// putColdObject caches an object at path and demotes it to the cold target,
// as eviction would.
func (e *coldCacheEnv) putColdObject(t *testing.T, path string, data []byte) InstanceHash {
	t.Helper()
	pc := e.pc
	normalized := pc.normalizePath(path)
	objectHash := pc.db.ObjectHash(normalized)
	etag := "etag-" + path
	hash := pc.db.InstanceHash(etag, objectHash)
	storeTestObject(t, e.ctx, pc.storage, hash, data, e.diskID, pc.getNamespaceID(path))
	meta, err := pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	meta.ETag = etag
	meta.SourceURL = normalized
	meta.LastValidated = time.Now()
	meta.CCMaxAge = 3600
	require.NoError(t, pc.storage.SetMetadata(hash, meta))
	require.NoError(t, pc.db.SetLatestETag(objectHash, etag, time.Now()))

	require.NoError(t, pc.tierUploader.processObject(e.ctx, hash))
	meta, err = pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.Equal(t, e.tierID, meta.StorageID, "the object should be on the cold target")
	return hash
}

// get fetches path through the cache's HTTP handler.
func (e *coldCacheEnv) get(t *testing.T, path, rangeHeader string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	require.NoError(t, err)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

// waitPromoted waits until every block of the object is local and nothing is
// still writing it.
func (e *coldCacheEnv) waitPromoted(t *testing.T, hash InstanceHash) *CacheMetadata {
	t.Helper()
	require.Eventually(t, func() bool {
		complete, err := e.pc.storage.IsComplete(hash)
		return err == nil && complete && !e.pc.storage.IsObjectPinned(hash)
	}, 20*time.Second, 20*time.Millisecond, "the promotion should complete")
	meta, err := e.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	return meta
}

func (e *coldCacheEnv) usage(t *testing.T, sid StorageID, path string) int64 {
	t.Helper()
	u, err := e.pc.db.GetUsage(sid, e.pc.getNamespaceID(path))
	require.NoError(t, err)
	return u
}

// TestColdTierPromotesOnRead checks the promotion half: a whole-object read of
// an object on a cold target is served through the cache and brings the object
// back to local storage, keeping the cold copy; later reads are local.
func TestColdTierPromotesOnRead(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/whole.bin"
	data := coldTestData(3<<20 + 777)
	hash := env.putColdObject(t, path, data)
	before, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	fileSize := CalculateFileSize(int64(len(data)))
	assert.Zero(t, env.usage(t, env.diskID, path))
	assert.Equal(t, fileSize, env.usage(t, env.tierID, path))

	label := env.target.metricLabel()
	promotions := func(result string) float64 {
		return testutil.ToFloat64(tierPromotionsTotal.WithLabelValues(label, result))
	}
	promotedBytes := func() float64 { return testutil.ToFloat64(tierPromotedBytesTotal.WithLabelValues(label)) }
	proxied := func() float64 { return testutil.ToFloat64(tierRequestsTotal.WithLabelValues(label, tierServedByProxy)) }
	started, completed, copied, proxies := promotions(tierPromotionStarted), promotions(tierPromotionCompleted), promotedBytes(), proxied()

	status, body := env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	require.True(t, bytes.Equal(data, body), "the promoted read must return the object's bytes")

	meta := env.waitPromoted(t, hash)
	assert.Equal(t, env.diskID, meta.StorageID)
	require.NotNil(t, meta.ColdCopy, "the cold copy is kept")
	assert.Equal(t, env.tierID, meta.ColdCopy.StorageID)
	assert.Equal(t, *before.Remote, meta.ColdCopy.Remote)
	assert.Nil(t, meta.Remote)
	assert.True(t, before.Completed.Equal(meta.Completed), "promotion does not change when the content was fetched")

	// Both copies are charged where they are.
	assert.Equal(t, fileSize, env.usage(t, env.diskID, path))
	assert.Equal(t, fileSize, env.usage(t, env.tierID, path))

	assert.Equal(t, started+1, promotions(tierPromotionStarted))
	assert.Equal(t, completed+1, promotions(tierPromotionCompleted))
	assert.GreaterOrEqual(t, promotedBytes()-copied, float64(len(data)))
	assert.Equal(t, proxies, proxied(), "a promoted read is not a proxied one")
	intents, err := env.pc.db.ListTierPromoteIntents()
	require.NoError(t, err)
	assert.Empty(t, intents, "a finished background copy clears its intent")

	// The next read is local: nothing more comes from the cold target.
	copied = promotedBytes()
	status, body = env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	assert.True(t, bytes.Equal(data, body))
	assert.Equal(t, copied, promotedBytes())
	assert.Equal(t, proxies, proxied())
}

// TestColdTierRangeReadPromotesOnlyWhatItReads checks that a range read from
// the middle of a cold object is answered promptly and promotes only the
// blocks around it, and that a later whole read finishes the job.
func TestColdTierRangeReadPromotesOnlyWhatItReads(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/ranged.bin"
	data := coldTestData(6 << 20)
	hash := env.putColdObject(t, path, data)
	label := env.target.metricLabel()
	copied := testutil.ToFloat64(tierPromotedBytesTotal.WithLabelValues(label))

	const start, end = 4000000, 4000999
	status, body := env.get(t, path, fmt.Sprintf("bytes=%d-%d", start, end))
	require.Equal(t, http.StatusPartialContent, status)
	require.True(t, bytes.Equal(data[start:end+1], body), "the range must come back intact")

	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Equal(t, env.diskID, meta.StorageID, "even a range read promotes the object")
	require.NotNil(t, meta.ColdCopy)
	bs, err := env.pc.storage.GetSharedBlockState(hash)
	require.NoError(t, err)
	assert.True(t, bs.ContainsRange(ContentOffsetToBlock(start), ContentOffsetToBlock(end)))
	assert.False(t, bs.Contains(0), "blocks nobody read are not copied")

	// No background copy: the read copied the blocks of its range.
	require.Eventually(t, func() bool { return !env.pc.storage.IsObjectPinned(hash) }, 10*time.Second, 10*time.Millisecond)
	moved := testutil.ToFloat64(tierPromotedBytesTotal.WithLabelValues(label)) - copied
	rangeBlocks := ContentOffsetToBlock(end) - ContentOffsetToBlock(start) + 1
	assert.LessOrEqual(t, moved, float64(rangeBlocks*BlockDataSize))
	complete, err := env.pc.storage.IsComplete(hash)
	require.NoError(t, err)
	assert.False(t, complete)
	intents, err := env.pc.db.ListTierPromoteIntents()
	require.NoError(t, err)
	assert.Empty(t, intents)

	// A whole read completes it, reusing what is already local.
	status, body = env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	require.True(t, bytes.Equal(data, body))
	env.waitPromoted(t, hash)
}

// TestColdTierConcurrentReaders checks that readers racing to promote one
// object all get its bytes and share one promotion.
func TestColdTierConcurrentReaders(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/concurrent.bin"
	data := coldTestData(5<<20 + 123)
	hash := env.putColdObject(t, path, data)
	label := env.target.metricLabel()
	started := testutil.ToFloat64(tierPromotionsTotal.WithLabelValues(label, tierPromotionStarted))
	copied := testutil.ToFloat64(tierPromotedBytesTotal.WithLabelValues(label))

	const readers = 8
	var wg sync.WaitGroup
	results := make([][]byte, readers)
	statuses := make([]int, readers)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rangeHeader := ""
			if i%2 == 1 {
				// Half of them read ranges, from different places.
				rangeHeader = fmt.Sprintf("bytes=%d-%d", i*500000, i*500000+300000)
			}
			req, err := http.NewRequest(http.MethodGet, env.srv.URL+path, nil)
			if err != nil {
				return
			}
			if rangeHeader != "" {
				req.Header.Set("Range", rangeHeader)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			statuses[i] = resp.StatusCode
			results[i], _ = io.ReadAll(resp.Body)
		}(i)
	}
	wg.Wait()
	for i := 0; i < readers; i++ {
		if i%2 == 1 {
			require.Equal(t, http.StatusPartialContent, statuses[i], "reader %d", i)
			assert.True(t, bytes.Equal(data[i*500000:i*500000+300001], results[i]), "reader %d got the wrong bytes", i)
		} else {
			require.Equal(t, http.StatusOK, statuses[i], "reader %d", i)
			assert.True(t, bytes.Equal(data, results[i]), "reader %d got the wrong bytes", i)
		}
	}
	env.waitPromoted(t, hash)
	assert.Equal(t, started+1, testutil.ToFloat64(tierPromotionsTotal.WithLabelValues(label, tierPromotionStarted)),
		"concurrent readers share one promotion")
	// Every copy is a fill registered on the object's block state, and no
	// fill starts on blocks another is writing, so nothing is copied twice.
	assert.LessOrEqual(t, testutil.ToFloat64(tierPromotedBytesTotal.WithLabelValues(label))-copied, float64(len(data)),
		"readers of one object share its copies")
}

// TestColdTierPromotionResumesAfterRestart checks crash recovery: a promotion
// whose background copy was interrupted is resumed by the next process, and an
// intent whose object is gone is discarded.
func TestColdTierPromotionResumesAfterRestart(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/resumed.bin"
	data := coldTestData(2<<20 + 99)
	hash := env.putColdObject(t, path, data)

	// What a process that died right after promoting the object leaves
	// behind: the metadata moved, an empty local copy, and the intent.
	_, err := env.pc.promoter.flip(hash, env.target)
	require.NoError(t, err)
	require.NoError(t, env.pc.db.SetTierPromoteIntent(hash))
	ghost := InstanceHash(fmt.Sprintf("%064d", 99))
	require.NoError(t, env.pc.db.SetTierPromoteIntent(ghost))
	complete, err := env.pc.storage.IsComplete(hash)
	require.NoError(t, err)
	require.False(t, complete)

	// The next process builds a fresh promoter, which recovers.
	newTierPromoter(env.pc, env.pc.downloadCtx)
	env.waitPromoted(t, hash)
	require.Eventually(t, func() bool {
		intents, err := env.pc.db.ListTierPromoteIntents()
		return err == nil && len(intents) == 0
	}, 10*time.Second, 10*time.Millisecond, "both intents should be settled")

	reader, err := env.pc.storage.NewObjectReader(hash)
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	reader.Close()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, got), "the resumed copy must hold the object's bytes")
}

// TestColdTierNoPingPong checks that an object moves between tiers only when a
// client reads it or eviction needs its room: a promoted object is never
// uploaded again, and evicting it just points it back at the copy it kept.
func TestColdTierNoPingPong(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/pingpong.bin"
	data := coldTestData(1<<20 + 5)
	hash := env.putColdObject(t, path, data)
	before, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	label := env.target.metricLabel()
	uploads := func() float64 {
		return testutil.ToFloat64(tierUploadsTotal.WithLabelValues(label, tierUploadSucceeded))
	}
	uploaded := uploads()
	flips := testutil.ToFloat64(tierDemotionsTotal.WithLabelValues(label, tierDemotedToRetainedCopy))
	fileSize := CalculateFileSize(int64(len(data)))
	nsID := env.pc.getNamespaceID(path)

	for round := 0; round < 2; round++ {
		status, body := env.get(t, path, "")
		require.Equal(t, http.StatusOK, status)
		require.True(t, bytes.Equal(data, body))
		meta := env.waitPromoted(t, hash)
		assert.False(t, env.pc.tierUploader.eligible(meta), "a promoted object is never uploaded")
		assert.Equal(t, demoteNo, env.pc.tierUploader.offerDemotion(hash, meta))

		evicted, _, _, err := env.pc.storage.EvictByLRU(env.diskID, nsID, 0, 0)
		require.NoError(t, err)
		require.Len(t, evicted, 1)
		assert.Equal(t, env.tierID, evicted[0].demotedTo)

		meta, err = env.pc.storage.GetMetadata(hash)
		require.NoError(t, err)
		assert.Equal(t, env.tierID, meta.StorageID, "eviction points the object back at its cold copy")
		assert.Equal(t, before.Remote, meta.Remote)
		assert.Nil(t, meta.ColdCopy)
		_, statErr := os.Stat(env.pc.storage.getObjectPathForDir(env.diskID, hash))
		assert.True(t, os.IsNotExist(statErr), "the local copy is released")
		assert.Zero(t, env.usage(t, env.diskID, path))
		assert.Equal(t, fileSize, env.usage(t, env.tierID, path))
		exists, err := env.target.objectExists(env.ctx, hash)
		require.NoError(t, err)
		assert.True(t, exists)
	}
	assert.Equal(t, uploaded, uploads(), "no round trip uploaded anything")
	assert.Equal(t, flips+2, testutil.ToFloat64(tierDemotionsTotal.WithLabelValues(label, tierDemotedToRetainedCopy)))
}

// TestColdTierKeptCopyConsistency checks that the consistency machinery
// treats a promoted object's kept cold copy as the object's: the sweep leaves
// it, the usage recount charges it, and a copy that changed or vanished is
// dropped without losing the local object.
func TestColdTierKeptCopyConsistency(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/kept.bin"
	data := coldTestData(256*1024 + 3)
	hash := env.putColdObject(t, path, data)
	status, body := env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	require.True(t, bytes.Equal(data, body))
	env.waitPromoted(t, hash)
	fileSize := CalculateFileSize(int64(len(data)))

	// The sweep recognizes the kept copy as this cache's.  Without a grace
	// period, so that a just-written copy is not spared for its age alone.
	// (The periodic scans have not started; their first run is minutes away.)
	env.pc.consistency.minAgeForCleanup = 0
	require.NoError(t, env.pc.consistency.RunTierScan(env.ctx))
	exists, err := env.target.objectExists(env.ctx, hash)
	require.NoError(t, err)
	assert.True(t, exists, "the sweep must not treat a kept cold copy as an orphan")

	// The usage recount agrees with what was charged.
	require.NoError(t, env.pc.consistency.RunMetadataScan(env.ctx, nil))
	assert.Equal(t, fileSize, env.usage(t, env.tierID, path))
	assert.Equal(t, fileSize, env.usage(t, env.diskID, path))

	// Overwritten in the bucket: the integrity scan drops the copy, not the
	// object.
	_, err = env.target.backend.Put(env.ctx, env.target.objectKey(hash), "application/octet-stream",
		int64(len(data)), bytes.NewReader(coldTestData(len(data) + 1)[1:]))
	require.NoError(t, err)
	require.NoError(t, env.pc.consistency.RunDataScan(env.ctx, nil))
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Nil(t, meta.ColdCopy, "a changed cold copy is dropped")
	assert.Equal(t, env.diskID, meta.StorageID)
	assert.Zero(t, env.usage(t, env.tierID, path), "the dropped copy is refunded")
	status, body = env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	assert.True(t, bytes.Equal(data, body), "the local object survives")
}

// TestColdTierSweepDropsMissingKeptCopy checks the sweep's half of the above:
// a kept copy deleted from the bucket is forgotten, and the object stays.
func TestColdTierSweepDropsMissingKeptCopy(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/vanished.bin"
	data := coldTestData(64*1024 + 1)
	hash := env.putColdObject(t, path, data)
	status, _ := env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	env.waitPromoted(t, hash)

	require.NoError(t, env.target.backend.Delete(env.ctx, env.target.objectKey(hash)))
	require.NoError(t, env.pc.consistency.RunTierScan(env.ctx))
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "the object is local and must survive its cold copy")
	assert.Nil(t, meta.ColdCopy)
	assert.Zero(t, env.usage(t, env.tierID, path))
}

// TestColdTierDeclinesOversizedPromotion checks that an object too large for
// local storage's eviction headroom is served from the cold target without
// being promoted.
func TestColdTierDeclinesOversizedPromotion(t *testing.T) {
	env := newColdCache(t, 4<<20)
	const path = "/test/cold/huge.bin"
	data := coldTestData(2 << 20) // over the 20% headroom of 4 MiB
	hash := env.putColdObject(t, path, data)
	label := env.target.metricLabel()
	declined := testutil.ToFloat64(tierPromotionsTotal.WithLabelValues(label, tierPromotionDeclined))

	status, body := env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	require.True(t, bytes.Equal(data, body))
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Equal(t, env.tierID, meta.StorageID, "the object stays on the cold target")
	assert.Equal(t, declined+1, testutil.ToFloat64(tierPromotionsTotal.WithLabelValues(label, tierPromotionDeclined)))
}

// promoteForTest moves an object to local storage without reading it, as a
// first read does before any block arrives.
func (e *coldCacheEnv) promoteForTest(t *testing.T, hash InstanceHash) *CacheMetadata {
	t.Helper()
	meta, err := e.pc.promoter.flip(hash, e.target)
	require.NoError(t, err)
	return meta
}

// presentBlocks reports which of an object's blocks are marked downloaded.
func (e *coldCacheEnv) presentBlocks(t *testing.T, hash InstanceHash) []uint32 {
	t.Helper()
	bm, err := e.pc.db.GetBlockState(hash)
	require.NoError(t, err)
	return bm.ToArray()
}

// checkPresentBlocks verifies that every block marked present reads back.
func (e *coldCacheEnv) checkPresentBlocks(t *testing.T, hash InstanceHash, data []byte) {
	t.Helper()
	for _, b := range e.presentBlocks(t, hash) {
		start := int64(b) * BlockDataSize
		end := min(start+BlockDataSize, int64(len(data)))
		got, err := e.pc.storage.ReadBlocks(hash, start, int(end-start))
		require.NoError(t, err, "block %d is marked present but does not read back", b)
		require.True(t, bytes.Equal(data[start:end], got), "block %d holds the wrong bytes", b)
	}
}

// coldFill starts a fill of blocks [first, last] of a promoted object from its
// cold copy, as a reader that needs block first does, and returns the channel
// closed when the fill ends.
func (e *coldCacheEnv) coldFill(t *testing.T, p *tierPromoter, hash InstanceHash, first, last uint32) <-chan struct{} {
	t.Helper()
	state, err := e.pc.storage.GetSharedBlockState(hash)
	require.NoError(t, err)
	handled, covered, started := p.startFill(hash, state, first, last, false)
	require.True(t, handled, "a promoted object with a cold copy fills from it")
	require.True(t, covered)
	require.NotNil(t, started, "the call should have started a fill")
	return started
}

// awaitFill waits for a fill to end.
func awaitFill(t *testing.T, done <-chan struct{}) {
	t.Helper()
	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, 20*time.Second, 5*time.Millisecond, "the fill should end")
}

// TestColdTierFailedCopyLeavesNoTornBlock checks that a copy from the cold copy
// that fails part-way through a block keeps the whole blocks it copied, marks
// nothing else present, and keeps the cold copy: an unreachable target says
// nothing against the bytes it did deliver.
func TestColdTierFailedCopyLeavesNoTornBlock(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/torn.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	env.promoteForTest(t, hash)
	env.backend.goDownAfter(3*BlockDataSize + 100)

	awaitFill(t, env.coldFill(t, env.pc.promoter, hash, 0, 10))
	assert.Equal(t, []uint32{0, 1, 2}, env.presentBlocks(t, hash), "the torn fourth block must not be marked present")
	env.checkPresentBlocks(t, hash, data)
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "a target going down does not condemn the object")
	assert.NotNil(t, meta.ColdCopy, "nor its cold copy")

	// Once the target is back, the rest fills in.
	env.backend.recover()
	awaitFill(t, env.coldFill(t, env.pc.promoter, hash, 3, 10))
	assert.Equal(t, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, env.presentBlocks(t, hash))
	env.checkPresentBlocks(t, hash, data)
}

// TestColdTierCancelledCopyLeavesNoTornBlock is the same for a copy stopped by
// the cache shutting down while a read of the cold copy is stalled mid-block.
func TestColdTierCancelledCopyLeavesNoTornBlock(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/cancelled.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	env.promoteForTest(t, hash)
	env.backend.stall.Store(true)
	env.backend.goDownAfter(3*BlockDataSize + 100)

	// A promoter of its own, so its context can end as a shutdown's would.
	ctx, cancel := context.WithCancel(env.pc.downloadCtx)
	defer cancel()
	p := newTierPromoter(env.pc, ctx)
	done := env.coldFill(t, p, hash, 0, 10)
	<-env.backend.served // the read has stalled mid-block
	cancel()
	awaitFill(t, done)
	assert.Equal(t, []uint32{0, 1, 2}, env.presentBlocks(t, hash), "the torn fourth block must not be marked present")
	env.checkPresentBlocks(t, hash, data)
}

// TestColdTierFetchSurvivesBlockStateReload checks that a read of a promotion
// does not lose track of blocks when the object's shared block state is
// dropped from its cache and reloaded while the promotion is live -- which
// once left it re-reading the cold copy in a loop.
func TestColdTierFetchSurvivesBlockStateReload(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/reload.bin"
	data := coldTestData(2 << 20)
	hash := env.putColdObject(t, path, data)
	p := env.pc.promoter
	for i := 0; i < tierPromoteBackgroundFills; i++ {
		p.fillSem <- struct{}{} // hold the background copy in its queue
	}
	defer func() {
		for i := 0; i < tierPromoteBackgroundFills; i++ {
			<-p.fillSem
		}
	}()
	_, err := p.promote(hash, env.target, true)
	require.NoError(t, err)

	env.pc.storage.blockStates.Delete(hash) // what the TTL does to an idle entry
	env.pc.storage.InvalidateSharedBlockState(hash)

	opens := env.backend.opens.Load()
	status, body := env.get(t, path, "bytes=0-99")
	require.Equal(t, http.StatusPartialContent, status)
	require.True(t, bytes.Equal(data[:100], body))
	assert.LessOrEqual(t, env.backend.opens.Load()-opens, int64(2), "one read of the cold copy should do")
	env.checkPresentBlocks(t, hash, data)
}

// TestColdTierQueuedFillAfterDemotionWritesNothing checks that a background
// copy still waiting for its turn when eviction demotes the object does not
// then write a local file for an object that lives on the cold target.
func TestColdTierQueuedFillAfterDemotionWritesNothing(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/demoted.bin"
	data := coldTestData(1 << 20)
	hash := env.putColdObject(t, path, data)
	require.NoError(t, env.pc.eviction.RecordAccess(hash))
	p := env.pc.promoter
	for i := 0; i < tierPromoteBackgroundFills; i++ {
		p.fillSem <- struct{}{}
	}
	_, err := p.promote(hash, env.target, true)
	require.NoError(t, err)

	evicted, _, _, err := env.pc.storage.EvictByLRU(env.diskID, env.pc.getNamespaceID(path), 0, 0)
	require.NoError(t, err)
	require.Len(t, evicted, 1)
	require.Equal(t, env.tierID, evicted[0].demotedTo)

	for i := 0; i < tierPromoteBackgroundFills; i++ {
		<-p.fillSem
	}
	require.Eventually(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.background) == 0
	}, 10*time.Second, 10*time.Millisecond, "the queued copy should give up")

	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Equal(t, env.tierID, meta.StorageID)
	_, statErr := os.Stat(env.pc.storage.getObjectPathForDir(env.diskID, hash))
	assert.True(t, os.IsNotExist(statErr), "no local file may be written for an object on the cold target")
	assert.Zero(t, env.usage(t, env.diskID, path))

	// A later read promotes it afresh, with nothing left over.
	status, body := env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	require.True(t, bytes.Equal(data, body))
	env.waitPromoted(t, hash)
}

// TestColdTierWholeReadFinishesAPartialPromotion checks that a whole read of
// an object an earlier range read left partly local copies the rest in the
// background, even if the client leaves straight away.
func TestColdTierWholeReadFinishesAPartialPromotion(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/partial.bin"
	data := coldTestData(6 << 20)
	hash := env.putColdObject(t, path, data)
	status, _ := env.get(t, path, "bytes=4000000-4000999")
	require.Equal(t, http.StatusPartialContent, status)
	complete, err := env.pc.storage.IsComplete(hash)
	require.NoError(t, err)
	require.False(t, complete)

	// A whole read whose client hangs up after the first few bytes.
	resp, err := http.Get(env.srv.URL + path)
	require.NoError(t, err)
	buf := make([]byte, 4096)
	_, err = io.ReadFull(resp.Body, buf)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data[:4096], buf))
	resp.Body.Close()

	env.waitPromoted(t, hash)
	reader, err := env.pc.storage.NewObjectReader(hash)
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	reader.Close()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, got))
}

// TestColdTierPromotionStaysUnderTheMaximum checks that a promotion that would
// push local storage past its maximum -- where eviction deletes rather than
// demotes -- is declined, and the object served from the cold target.
func TestColdTierPromotionStaysUnderTheMaximum(t *testing.T) {
	env := newColdCache(t, 4<<20)
	const path = "/test/cold/crowded.bin"
	data := coldTestData(600 << 10) // within the 20% headroom
	hash := env.putColdObject(t, path, data)

	// Fill local storage to just under its maximum with objects eviction
	// cannot touch.
	filler := InstanceHash(fmt.Sprintf("%064d", 77))
	storeTestObject(t, env.ctx, env.pc.storage, filler, coldTestData(3600<<10), env.diskID, NamespaceID(9))
	env.pc.eviction.recalculateDirUsage()

	label := env.target.metricLabel()
	declined := testutil.ToFloat64(tierPromotionsTotal.WithLabelValues(label, tierPromotionDeclined))
	status, body := env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	require.True(t, bytes.Equal(data, body))
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Equal(t, env.tierID, meta.StorageID, "the object stays on the cold target")
	assert.Equal(t, declined+1, testutil.ToFloat64(tierPromotionsTotal.WithLabelValues(label, tierPromotionDeclined)))
}

// TestColdTierPurgeRemovesBothCopies checks that an explicit purge of a
// promoted object (the admin evict API) removes it, including the copy it
// kept on the cold target, and refunds both.
func TestColdTierPurgeRemovesBothCopies(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/purged.bin"
	data := coldTestData(256 << 10)
	hash := env.putColdObject(t, path, data)
	status, _ := env.get(t, path, "")
	require.Equal(t, http.StatusOK, status)
	env.waitPromoted(t, hash)

	require.NoError(t, env.pc.eviction.MarkPurgeFirst(hash))
	evicted, _, _, err := env.pc.storage.EvictByLRU(env.diskID, env.pc.getNamespaceID(path), 0, 0)
	require.NoError(t, err)
	require.Len(t, evicted, 1)
	assert.Zero(t, evicted[0].demotedTo, "a purge deletes rather than demotes")
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, meta)
	exists, err := env.target.objectExists(env.ctx, hash)
	require.NoError(t, err)
	assert.False(t, exists, "the kept copy goes with the object")
	assert.Zero(t, env.usage(t, env.diskID, path))
	assert.Zero(t, env.usage(t, env.tierID, path))
}

// TestColdTierStreamGivesUpOnATargetThatFailsEveryRead checks that a copy from
// a target that accepts every request but fails it at once ends on its own,
// rather than being retried forever, and condemns nothing.
func TestColdTierStreamGivesUpOnATargetThatFailsEveryRead(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/resets.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	env.promoteForTest(t, hash)
	env.backend.resets.Store(-1)

	opens := env.backend.opens.Load()
	awaitFill(t, env.coldFill(t, env.pc.promoter, hash, 0, 0))
	assert.Equal(t, int64(tierStreamBlankRetries+1), env.backend.opens.Load()-opens)
	assert.Empty(t, env.presentBlocks(t, hash))
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.NotNil(t, meta.ColdCopy)
}

// TestColdTierCopyStopsWithItsLastReader checks that a copy a reader started
// stops, keeping the whole blocks it wrote, once no reader of the object has
// been open for the prefetch timeout -- the rule for a fill from the origin --
// rather than wait on a stalled target for ever.
func TestColdTierCopyStopsWithItsLastReader(t *testing.T) {
	env := newColdCache(t, 0)
	require.NoError(t, param.LocalCache_PrefetchTimeout.Set(50*time.Millisecond))
	const path = "/test/cold/abandoned.bin"
	data := coldTestData(64 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	env.promoteForTest(t, hash)
	env.backend.stall.Store(true)
	env.backend.goDownAfter(3*BlockDataSize + 100)

	done := env.coldFill(t, env.pc.promoter, hash, 0, 10) // no reader is open
	<-env.backend.served
	awaitFill(t, done)
	assert.Equal(t, []uint32{0, 1, 2}, env.presentBlocks(t, hash), "an idle stop keeps the whole blocks")
	env.checkPresentBlocks(t, hash, data)
}

// TestColdTierBackgroundCopyOutlivesItsReaders checks the exception to that
// rule: the background copy a whole read starts finishes the promotion after
// every reader has gone, however long ago.
func TestColdTierBackgroundCopyOutlivesItsReaders(t *testing.T) {
	env := newColdCache(t, 0)
	const timeout = 20 * time.Millisecond
	require.NoError(t, param.LocalCache_PrefetchTimeout.Set(timeout))
	const path = "/test/cold/outlived.bin"
	data := coldTestData(1 << 20)
	hash := env.putColdObject(t, path, data)
	gate := make(chan struct{})
	env.backend.hold.Store(&gate)

	// A whole read whose client gives up before a byte has arrived.
	client, _, err := env.pc.GetSeekableReader(env.ctx, path, "", false)
	require.NoError(t, err)
	<-env.backend.held // the background copy is under way, waiting on the target
	require.NoError(t, client.Close())

	// Wait until no reader has been open for well over the timeout.
	state, err := env.pc.storage.GetSharedBlockState(hash)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		open, last := state.readerActivity()
		return !open && !last.IsZero() && time.Since(last) > 10*timeout
	}, 10*time.Second, 5*time.Millisecond, "the reader should go")

	close(gate)
	env.waitPromoted(t, hash)
	reader, err := env.pc.storage.NewObjectReader(hash)
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	reader.Close()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, got))
}

// TestColdTierCloseWaitsForCopies checks that a copy from a cold target is a
// background transfer Close waits for, like a fill from the origin: Close
// stops it and returns only once it has ended, so it cannot outlive the
// database it writes to.
func TestColdTierCloseWaitsForCopies(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/closing.bin"
	hash := env.putColdObject(t, path, coldTestData(64*BlockDataSize))
	env.promoteForTest(t, hash)
	gate := make(chan struct{}) // never opened
	env.backend.hold.Store(&gate)

	done := env.coldFill(t, env.pc.promoter, hash, 0, 10)
	<-env.backend.held
	require.NoError(t, env.pc.Close())
	select {
	case <-done:
	default:
		t.Fatal("Close returned while a copy from the cold target was still running")
	}
}

// TestColdTierRangeReadIsNotHeldUpByTheBackgroundCopy checks that a range read
// far ahead of the background copy is served without waiting for the copy to
// get there: the copy advances a segment at a time, so the range is not
// covered by any fill and the reader fills it directly.
func TestColdTierRangeReadIsNotHeldUpByTheBackgroundCopy(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/far.bin"
	data := coldTestData(12 << 20)
	hash := env.putColdObject(t, path, data)
	gate := make(chan struct{})
	env.backend.holdAt.Store(0) // only the copy from the start of the object
	env.backend.hold.Store(&gate)
	released := false
	release := func() {
		if !released {
			released = true
			close(gate)
		}
	}
	defer release()

	_, err := env.pc.promoter.promote(hash, env.target, true)
	require.NoError(t, err)
	<-env.backend.held // the background copy is under way, held at block 0

	const start, end = 9000000, 9000999
	ctx, cancel := context.WithTimeout(env.ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.srv.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "the range read must not wait for the background copy")
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	require.True(t, bytes.Equal(data[start:end+1], body))

	release()
	env.waitPromoted(t, hash)
}

// TestColdTierShortCopyCondemnsTheObject checks that a cold copy that turns out
// shorter than its record condemns the object, as a fill from the origin that
// fails a verification does: a reader that already served blocks the copy
// wrote learns of it from WaitForCompletion, and the object is dropped, kept
// copy and all, so the next read fetches it afresh.
func TestColdTierShortCopyCondemnsTheObject(t *testing.T) {
	env := newColdCache(t, 0)
	const path = "/test/cold/short.bin"
	data := coldTestData(256 * BlockDataSize)
	hash := env.putColdObject(t, path, data)
	// The copy in the bucket loses its tail.  (S3 would refuse to serve it,
	// since reads are pinned to the uploaded copy; the in-memory driver
	// cannot pin.)
	short := data[:150*BlockDataSize+77]
	_, err := env.target.backend.Put(env.ctx, env.target.objectKey(hash), "application/octet-stream",
		int64(len(short)), bytes.NewReader(short))
	require.NoError(t, err)
	// Pause the copy part-way, once its first batch of blocks is published.
	resume := make(chan struct{})
	env.backend.resume.Store(&resume)
	env.backend.stall.Store(true)
	env.backend.goDownAfter(100 * BlockDataSize)

	// A range-only reader starts no background copy; its own fill covers
	// the object.
	reader, _, err := env.pc.GetSeekableReader(env.ctx, path, "", true)
	require.NoError(t, err)
	defer reader.Close()
	buf := make([]byte, 1000)
	_, err = io.ReadFull(reader, buf)
	require.NoError(t, err, "the blocks the copy wrote before the pause are served")
	require.True(t, bytes.Equal(data[:1000], buf))

	close(resume)
	err = reader.WaitForCompletion(env.ctx)
	require.Error(t, err, "the reader served blocks of a copy that was condemned")
	assert.Contains(t, err.Error(), "dropped")
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, meta, "the object is dropped")
	exists, err := env.target.objectExists(env.ctx, hash)
	require.NoError(t, err)
	assert.False(t, exists, "and its bad cold copy with it")
}

// TestTierStreamRetriesBlips checks the proxy stream on an ordinary (not
// cold) target: a read that fails before producing anything is reopened a
// few times, so transient resets do not fail the client's transfer, but a
// target that fails every read is given up on rather than retried forever.
func TestTierStreamRetriesBlips(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnv(t, ctx)
	backend := newFaultyBackend(env.target.backend)
	env.target.backend = backend // no background goroutines in this env
	hash := InstanceHash(fmt.Sprintf("%064d", 51))
	data := coldTestData(64 * BlockDataSize)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, 1)
	require.NoError(t, env.uploader.processObject(ctx, hash))
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.Equal(t, env.tierID, meta.StorageID)

	read := func() ([]byte, error) {
		stream := newTierObjectStream(ctx, env.target, hash, int64(len(data)))
		stream.expect = meta.Remote
		defer stream.Close()
		return io.ReadAll(stream)
	}

	backend.resets.Store(2) // two resets in a row, then the target recovers
	got, err := read()
	require.NoError(t, err, "transient resets must not fail the read")
	assert.True(t, bytes.Equal(data, got))

	backend.resets.Store(-1)
	opens := backend.opens.Load()
	_, err = read()
	require.Error(t, err, "a target that fails every read must be given up on")
	assert.Equal(t, int64(tierStreamBlankRetries+1), backend.opens.Load()-opens)
}
