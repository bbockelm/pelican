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

package local_cache

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
)

// newMetricsFetcher starts a cache in front of origin, which serves
// /test/obj.bin, of the given size and entity tag, and returns it with a
// fetcher for an empty disk instance of the object -- as a range read of an
// uncached object leaves it -- that goes idle after idleAfter.
func newMetricsFetcher(t *testing.T, origin http.Handler, size int64, etag string, idleAfter time.Duration) (*stubFedCache, *BlockFetcherV2) {
	t.Helper()
	env := newStubFedCache(t, origin)
	pelicanURL := env.pc.normalizePath("/test/obj.bin")
	hash := env.pc.db.InstanceHash(etag, env.pc.db.ObjectHash(pelicanURL))
	var diskID StorageID
	for id := range env.pc.storage.GetDirs() {
		diskID = id
	}
	_, err := env.pc.storage.InitDiskStorage(context.Background(), hash, size, diskID, 1)
	require.NoError(t, err)
	require.NoError(t, env.pc.storage.MergeMetadata(hash, &CacheMetadata{ETag: etag, SourceURL: pelicanURL}))
	bf, err := NewBlockFetcherV2(env.pc.storage, hash, pelicanURL, "", env.pc.fedTokenAsProvider(), env.pc.te,
		BlockFetcherV2Config{PrefetchTimeout: idleAfter})
	require.NoError(t, err)
	t.Cleanup(bf.Close)
	return env, bf
}

// TestFillMetrics checks that every background fill is counted when it
// starts and, by outcome, when it ends, with the bytes it received.
func TestFillMetrics(t *testing.T) {
	const etag = `"v1"`

	t.Run("Completed", func(t *testing.T) {
		_, bf := newMetricsFetcher(t, newVersionedOrigin(1<<20, etag), 1<<20, etag, time.Minute)
		started := counterDelta(cacheFillsStartedTotal)
		completed := counterDelta(cacheFillsEndedTotal.WithLabelValues(string(fillCompleted)))
		ended := counterDelta(allFillEnds()...)
		bytes := counterDelta(cacheFillBytesTotal)

		require.NoError(t, bf.Fill(context.Background(), 0, 1))
		assert.Equal(t, 1.0, started())
		assert.Equal(t, 1.0, completed())
		assert.Equal(t, 1.0, ended())
		assert.Equal(t, float64(2*BlockDataSize), bytes(), "the fill received two blocks")
	})

	t.Run("StoppedEarly", func(t *testing.T) {
		// The origin stalls after the first block, and no reader keeps the
		// fill going, so it goes idle.
		const size = 64 * BlockDataSize
		_, bf := newMetricsFetcher(t, newStallingOrigin(size, BlockDataSize, etag), size, etag, time.Nanosecond)
		stopped := counterDelta(cacheFillsEndedTotal.WithLabelValues(string(fillStoppedEarly)))
		ended := counterDelta(allFillEnds()...)

		require.ErrorIs(t, bf.Fill(context.Background(), 0, 63), errPrefetchIdle)
		assert.Equal(t, 1.0, stopped())
		assert.Equal(t, 1.0, ended())
	})

	t.Run("Condemned", func(t *testing.T) {
		origin := newVersionedOrigin(1<<20, etag)
		_, bf := newMetricsFetcher(t, origin, 1<<20, etag, time.Minute)
		replaced := `"v2"`
		origin.etag.Store(&replaced)
		condemnedFill := counterDelta(cacheFillsEndedTotal.WithLabelValues(string(fillCondemned)))
		ended := counterDelta(allFillEnds()...)
		byFill := counterDelta(cacheObjectsCondemnedTotal.WithLabelValues(string(condemnedByFill), string(condemnVersionChanged)))
		condemned := counterDelta(allCondemned()...)

		require.ErrorIs(t, bf.Fill(context.Background(), 2, 3), client.ErrObjectVersionChanged)
		assert.Equal(t, 1.0, condemnedFill())
		assert.Equal(t, 1.0, ended())
		assert.Equal(t, 1.0, byFill(), "the object must be counted as condemned by a fill")
		assert.Equal(t, 1.0, condemned())
	})

	t.Run("Failed", func(t *testing.T) {
		env, bf := newMetricsFetcher(t, newVersionedOrigin(1<<20, etag), 1<<20, etag, time.Minute)
		// The instance is gone before the fill starts: it fetches nothing.
		require.NoError(t, env.pc.storage.Delete(bf.instanceHash))
		failed := counterDelta(cacheFillsEndedTotal.WithLabelValues(string(fillFailed)))
		ended := counterDelta(allFillEnds()...)
		condemned := counterDelta(allCondemned()...)

		require.ErrorIs(t, bf.Fill(context.Background(), 0, 1), errInstanceDeleted)
		assert.Equal(t, 1.0, failed())
		assert.Equal(t, 1.0, ended())
		assert.Zero(t, condemned(), "a fill that wrote nothing condemns nothing")
	})
}

// TestRangeFetchCondemnsAsRange checks that a reader's own fetch -- not a
// fill -- that finds the object replaced at the origin is counted as
// condemned by a range fetch, and is not counted as a fill.
func TestRangeFetchCondemnsAsRange(t *testing.T) {
	const etag = `"v1"`
	origin := newVersionedOrigin(1<<20, etag)
	_, bf := newMetricsFetcher(t, origin, 1<<20, etag, time.Minute)
	replaced := `"v2"`
	origin.etag.Store(&replaced)
	byRange := counterDelta(cacheObjectsCondemnedTotal.WithLabelValues(string(condemnedByRange), string(condemnVersionChanged)))
	fills := counterDelta(cacheFillsStartedTotal)

	require.ErrorIs(t, bf.FetchBlocks(context.Background(), 0, 1), client.ErrObjectVersionChanged)
	assert.Equal(t, 1.0, byRange())
	assert.Zero(t, fills(), "a reader's own fetch is not a fill")
}

// TestHandOffFailureMetric checks that a download that marked its object as
// downloading and then failed before a fetcher adopted its transfer -- here
// because the object was deleted in that window -- is counted.
func TestHandOffFailureMetric(t *testing.T) {
	const size = 4 << 20
	env := newStubFedCache(t, newStallingOrigin(size, 256<<10, `"v1"`))
	env.pc.beforeHandOff = func(dl *persistentDownload) {
		require.NoError(t, env.pc.storage.Delete(dl.instanceHash))
	}
	failures := counterDelta(cacheDownloadHandOffFailuresTotal)

	_, err := env.pc.Get(context.Background(), "/test/obj.bin", "")
	require.Error(t, err)
	// The count is made as the download returns, which Get need not wait for.
	require.Eventually(t, func() bool { return failures() == 1 }, 10*time.Second, time.Millisecond)
}
