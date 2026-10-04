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
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TestStorageCapacityMetrics: every storage target the eviction manager
// governs -- local directories and tiering targets alike -- publishes its
// usage, limit and watermarks from startup, follows usage changes, and
// withdraws its series when the manager stops.
func TestStorageCapacityMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnv(t, ctx)

	// Usage recorded before the manager starts must be visible at once,
	// not after the first write.
	require.NoError(t, env.db.ChargeUsage(env.diskID, 1, 1000))

	diskLabels := prometheus.Labels{
		"storage_id": strconv.Itoa(int(env.diskID)),
		"backend":    "posix",
		"path":       filepath.Dir(env.storage.GetDirs()[env.diskID]),
	}
	tierLabels := prometheus.Labels{
		"storage_id": strconv.Itoa(int(env.tierID)),
		"backend":    "tier",
		"path":       env.target.DisplayURL(),
	}

	runCtx, stop := context.WithCancel(ctx)
	egrp, _ := errgroup.WithContext(runCtx)
	env.eviction.Start(runCtx, egrp)

	assert.Equal(t, 1000.0, testutil.ToFloat64(storageUsedBytes.With(diskLabels)))
	assert.Equal(t, float64(1<<30), testutil.ToFloat64(storageLimitBytes.With(diskLabels)))
	assert.Equal(t, float64((1<<30)*90/100), testutil.ToFloat64(storageHighWaterBytes.With(diskLabels)))
	assert.Equal(t, float64((1<<30)*80/100), testutil.ToFloat64(storageLowWaterBytes.With(diskLabels)))

	assert.Equal(t, 0.0, testutil.ToFloat64(storageUsedBytes.With(tierLabels)))
	assert.Equal(t, float64(1<<30), testutil.ToFloat64(storageLimitBytes.With(tierLabels)))

	// A change to the tracked usage is published by the manager's loop.
	env.eviction.NoteUsageIncrease(env.tierID, 4096)
	env.eviction.TriggerEviction()
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(storageUsedBytes.With(tierLabels)) == 4096
	}, 5*time.Second, 10*time.Millisecond)

	// Stopping the manager withdraws its series.
	stop()
	require.NoError(t, egrp.Wait())
	for _, labels := range []prometheus.Labels{diskLabels, tierLabels} {
		assert.False(t, storageUsedBytes.Delete(labels), "used series for %v must be withdrawn", labels)
		assert.False(t, storageLimitBytes.Delete(labels), "limit series for %v must be withdrawn", labels)
	}
}
