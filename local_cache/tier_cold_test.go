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
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
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
