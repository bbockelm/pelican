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
	"testing"

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
