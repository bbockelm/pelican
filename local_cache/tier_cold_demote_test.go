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
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/RoaringBitmap/roaring"
	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestColdTierSkipsDemotionOfAnObjectReadSince checks that an object eviction
// queued for demotion is not uploaded after all if it is read while it waits:
// it is hot again, and demoting it would only bring it back.
func TestColdTierSkipsDemotionOfAnObjectReadSince(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnvWith(t, ctx, coldEnvConfig(),
		EvictionDirConfig{MaxSize: 64 * 1024, HighWaterPercentage: 90, LowWaterPercentage: 50})
	nsID := NamespaceID(1)
	hashes := []InstanceHash{InstanceHash(fmt.Sprintf("%064d", 31)), InstanceHash(fmt.Sprintf("%064d", 32)),
		InstanceHash(fmt.Sprintf("%064d", 33))}
	for _, h := range hashes {
		storeLRUObject(t, ctx, env, h, coldTestData(20*1024), nsID)
	}
	env.eviction.recalculateDirUsage()
	env.eviction.checkAndEvict()
	require.Positive(t, env.uploader.pendingDemotionBytes(env.diskID))

	// The oldest is read while its upload waits in the queue.
	require.NoError(t, env.db.UpdateLRU(hashes[0], 0))
	drainDemotions(t, ctx, env.uploader)

	meta, err := env.storage.GetMetadata(hashes[0])
	require.NoError(t, err)
	assert.Equal(t, env.diskID, meta.StorageID, "an object read since it was offered stays local")
	meta, err = env.storage.GetMetadata(hashes[1])
	require.NoError(t, err)
	assert.Equal(t, env.tierID, meta.StorageID, "an untouched one is demoted")
	assert.Zero(t, env.uploader.pendingDemotionBytes(env.diskID))
}

// TestColdTierFullTargetMeansDeletion checks that when the cold target has no
// room, eviction deletes rather than waits.
func TestColdTierFullTargetMeansDeletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := coldEnvConfig()
	cfg.MaxSize = 16 * 1024 // smaller than any object below
	env := newMemTierEnvWith(t, ctx, cfg,
		EvictionDirConfig{MaxSize: 64 * 1024, HighWaterPercentage: 90, LowWaterPercentage: 50})
	nsID := NamespaceID(1)
	hashes := []InstanceHash{InstanceHash(fmt.Sprintf("%064d", 41)), InstanceHash(fmt.Sprintf("%064d", 42)),
		InstanceHash(fmt.Sprintf("%064d", 43))}
	for _, h := range hashes {
		storeLRUObject(t, ctx, env, h, coldTestData(20*1024), nsID)
	}
	env.eviction.recalculateDirUsage()
	env.eviction.checkAndEvict()
	assert.Zero(t, drainDemotions(t, ctx, env.uploader), "nothing fits on the cold target")
	meta, err := env.storage.GetMetadata(hashes[0])
	require.NoError(t, err)
	assert.Nil(t, meta, "with no room on the cold target, the object is deleted")
	diskUsage, err := env.db.GetUsage(env.diskID, nsID)
	require.NoError(t, err)
	assert.LessOrEqual(t, diskUsage, int64(32*1024), "local storage is drained to its low-water mark")
}

// blockStateRow returns the block bitmap the database holds for the object,
// or nil if it holds none.
func blockStateRow(t *testing.T, db *CacheDB, hash InstanceHash) *roaring.Bitmap {
	t.Helper()
	var bm *roaring.Bitmap
	require.NoError(t, db.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(StateKey(hash))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			bm = roaring.New()
			_, err := bm.FromBuffer(append([]byte(nil), val...))
			return err
		})
	}))
	return bm
}

// TestColdTierDemotionFencesALocalWriter checks that demotion ends the local
// life of an object for its writers: a writer of the local copy still running
// when the upload relocates the object -- here an auto-repair rewriting two
// blocks -- writes nothing of it afterwards: no block rows, no completion.
// What such a writer would write belongs to a local life that has ended, and
// would be taken for blocks of whatever local life the object has next.
func TestColdTierDemotionFencesALocalWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnvWith(t, ctx, coldEnvConfig(), EvictionDirConfig{MaxSize: 1 << 30})
	hash := InstanceHash(fmt.Sprintf("%064d", 51))
	data := coldTestData(3*BlockDataSize + 100)
	storeLRUObject(t, ctx, env, hash, data, 1)
	// Just as the upload has read the object, blocks 0 and 1 are found
	// corrupt, and a repair starts rewriting them.
	var bw *BlockWriter
	env.uploader.beforeRelocate = func(h InstanceHash) {
		require.NoError(t, env.db.ClearBlocks(h, []uint32{0, 1}))
		env.storage.InvalidateSharedBlockState(h)
		var err error
		bw, err = env.storage.NewBlockWriter(h, 0, nil, nil)
		require.NoError(t, err)
		_, err = bw.Write(data[:2*BlockDataSize])
		require.NoError(t, err)
	}
	require.NoError(t, env.uploader.processObject(ctx, hash))
	require.NotNil(t, bw)
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.Equal(t, env.tierID, meta.StorageID, "the object was demoted")

	before := blockStateRow(t, env.db, hash)
	require.NotNil(t, before)
	bw.StopEarly() // flushes the blocks it wrote, which completes the object
	assert.Equal(t, before.ToArray(), blockStateRow(t, env.db, hash).ToArray(),
		"a writer of the demoted local copy wrote its blocks, or its completion, after the move")
	assert.Zero(t, env.storage.fences.size(), "no fence may outlive its writers and deletions")
}

// TestColdTierDeferredReleaseKeepsTheFilesOfARefetch checks the release of a
// demoted object's local copy that waited for a reader: if the object is
// deleted and fetched again under the same hash just as the release runs, the
// release must leave the new copy's file alone -- here forced by running the
// deletion and the fetch from the release's own hook.
func TestColdTierDeferredReleaseKeepsTheFilesOfARefetch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnvWith(t, ctx, coldEnvConfig(), EvictionDirConfig{MaxSize: 1 << 30})
	hash := InstanceHash(fmt.Sprintf("%064d", 52))
	data := coldTestData(3*BlockDataSize + 100)
	storeLRUObject(t, ctx, env, hash, data, 1)

	// A reader holds the local copy, so its release is deferred.
	unpin := env.storage.PinObject(hash)
	require.NoError(t, env.uploader.processObject(ctx, hash))
	intent, err := env.db.GetTierUploadIntent(hash)
	require.NoError(t, err)
	require.NotNil(t, intent, "the release waits for the reader")
	unpin()

	path := env.storage.getObjectPathForDir(env.diskID, hash)
	fired := false
	env.uploader.beforeReleaseLocal = func(h InstanceHash) {
		if fired {
			return
		}
		fired = true
		require.NoError(t, env.storage.Delete(h))
		_, err := env.storage.InitDiskStorage(ctx, h, int64(len(data)), env.diskID, 1)
		require.NoError(t, err)
	}
	env.uploader.finishDeferredReleases(ctx)
	require.True(t, fired)

	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, env.diskID, meta.StorageID)
	_, err = os.Stat(path)
	assert.NoError(t, err, "the release of the old local copy deleted the new copy's file")
	intent, err = env.db.GetTierUploadIntent(hash)
	require.NoError(t, err)
	assert.Nil(t, intent, "the intent is settled")
	assert.Zero(t, env.storage.fences.size())
}
