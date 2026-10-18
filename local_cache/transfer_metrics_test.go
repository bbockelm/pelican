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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/error_codes"
)

// counterDelta returns a function reporting how much the sum of the given
// counters has moved since counterDelta was called.  The cache's metrics are
// process-wide, so a test compares before and after rather than reading
// absolute values.
func counterDelta(cs ...prometheus.Collector) func() float64 {
	sum := func() float64 {
		total := 0.0
		for _, c := range cs {
			total += testutil.ToFloat64(c)
		}
		return total
	}
	before := sum()
	return func() float64 { return sum() - before }
}

// Every series of each labelled counter, to watch one as a whole.
func allDownloadStops() []prometheus.Collector {
	var cs []prometheus.Collector
	for _, c := range allDownloadStopCauses {
		for _, o := range allDownloadStopOutcomes {
			cs = append(cs, cacheDownloadStopsTotal.WithLabelValues(string(c), string(o)))
		}
	}
	return cs
}

func allCondemned() []prometheus.Collector {
	var cs []prometheus.Collector
	for _, s := range allCondemnSources {
		for _, r := range allCondemnReasons {
			cs = append(cs, cacheObjectsCondemnedTotal.WithLabelValues(string(s), string(r)))
		}
	}
	return cs
}

func allReadsPastDownload() []prometheus.Collector {
	var cs []prometheus.Collector
	for _, r := range allPastDownloadReasons {
		cs = append(cs, cacheReadsPastDownloadTotal.WithLabelValues(string(r)))
	}
	return cs
}

func allFenceRefusals() []prometheus.Collector {
	var cs []prometheus.Collector
	for _, k := range allFencedWriteKinds {
		cs = append(cs, cacheWriteFenceRefusalsTotal.WithLabelValues(string(k)))
	}
	return cs
}

func allFillEnds() []prometheus.Collector {
	var cs []prometheus.Collector
	for _, o := range allFillOutcomes {
		cs = append(cs, cacheFillsEndedTotal.WithLabelValues(string(o)))
	}
	return cs
}

// TestDownloadStopMetrics checks that the end of a whole-object download
// that did not complete is counted by cause and by whether its data was
// kept, and that a condemned download is counted as condemned, by reason.
func TestDownloadStopMetrics(t *testing.T) {
	trailer := error_codes.NewTransferError(fmt.Errorf("download error after server response started: %w",
		&client.TransferStatusError{Code: 500, Err: errors.New("upstream verification failed")}))
	mismatch := error_codes.NewTransfer_ChecksumMismatchError(&client.ChecksumMismatchError{})
	changed := fmt.Errorf("transfer failed: %w", client.ErrObjectVersionChanged)
	notFound := client.StatusCodeError(404)
	reset := error_codes.NewContact_ConnectionResetError(&client.NetworkResetError{})

	for _, tc := range []struct {
		name        string
		err         error
		closing     bool
		unknownSize bool
		cause       downloadStopCause
		outcome     downloadStopOutcome
		reason      condemnReason // for a condemned download
	}{
		{name: "Idle", err: errAdoptedTransferIdle, cause: downloadStopIdle, outcome: downloadStopKept},
		{name: "Shutdown", err: context.Canceled, closing: true, cause: downloadStopShutdown, outcome: downloadStopKept},
		{name: "Cancelled", err: context.Canceled, cause: downloadStopCancelled, outcome: downloadStopKept},
		{name: "Transport", err: reset, cause: downloadStopTransport, outcome: downloadStopKept},
		{name: "Unreported", err: errAdoptedTransferUnreported, cause: downloadStopUnreported, outcome: downloadStopKept},
		{name: "ChecksumMismatch", err: mismatch, cause: downloadStopError, outcome: downloadStopCondemned, reason: condemnChecksumMismatch},
		{name: "VersionChanged", err: changed, cause: downloadStopError, outcome: downloadStopCondemned, reason: condemnVersionChanged},
		{name: "Trailer", err: trailer, cause: downloadStopError, outcome: downloadStopCondemned, reason: condemnServerReported},
		{name: "Status", err: &notFound, cause: downloadStopError, outcome: downloadStopCondemned, reason: condemnServerReported},
		{name: "Other", err: errors.New("something else"), cause: downloadStopError, outcome: downloadStopCondemned, reason: condemnOther},
		{name: "IdleOfUnknownSize", err: errAdoptedTransferIdle, unknownSize: true,
			cause: downloadStopIdle, outcome: downloadStopCondemned, reason: condemnUnknownSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			size := int64(tornObjectBlocks*BlockDataSize - 17)
			if tc.unknownSize {
				size = -1
			}
			env := newTornBlockEnv(t, size)
			state, err := env.storage.GetSharedBlockState(env.hash)
			require.NoError(t, err)
			pc := &PersistentCache{storage: env.storage, db: env.db}
			pc.closed.Store(tc.closing)
			dl := &persistentDownload{instanceHash: env.hash, completionDone: make(chan struct{})}

			stops := counterDelta(cacheDownloadStopsTotal.WithLabelValues(string(tc.cause), string(tc.outcome)))
			allStops := counterDelta(allDownloadStops()...)
			condemned := counterDelta(allCondemned()...)
			var condemnedHere func() float64
			if tc.reason != "" {
				condemnedHere = counterDelta(cacheObjectsCondemnedTotal.WithLabelValues(string(condemnedByDownload), string(tc.reason)))
			}

			pc.endAdoptedDownload(dl, testWriterFence(t, env.storage, env.hash), state, tc.err)

			assert.Equal(t, 1.0, stops(), "the stop must be counted as %s/%s", tc.cause, tc.outcome)
			assert.Equal(t, 1.0, allStops(), "the stop must be counted once")
			if tc.outcome == downloadStopCondemned {
				assert.Equal(t, 1.0, condemnedHere(), "the download must be counted as condemned for %s", tc.reason)
				assert.Equal(t, 1.0, condemned())
			} else {
				assert.Zero(t, condemned(), "a download whose blocks are kept condemns nothing")
			}
		})
	}
}

// TestCompletedDownloadIsNotAStop checks that a download that completes is
// counted as neither stopped nor condemned.
func TestCompletedDownloadIsNotAStop(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	state, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	pc := &PersistentCache{storage: env.storage, db: env.db}
	dl := &persistentDownload{instanceHash: env.hash, completionDone: make(chan struct{})}
	stops := counterDelta(allDownloadStops()...)
	condemned := counterDelta(allCondemned()...)

	pc.endAdoptedDownload(dl, testWriterFence(t, env.storage, env.hash), state, nil)
	assert.Zero(t, stops())
	assert.Zero(t, condemned())
}

// TestRangeFetchCondemnMetric checks that a reader's own range fetch that
// condemns the object is counted as condemned by a range fetch, and one
// whose failure condemns nothing is not counted.
func TestRangeFetchCondemnMetric(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	bf := &BlockFetcherV2{storage: env.storage, instanceHash: env.hash, meta: meta,
		activeFetches: make(map[fetchKey]*fetchOperation)}
	condemned := counterDelta(allCondemned()...)
	byRange := counterDelta(cacheObjectsCondemnedTotal.WithLabelValues(string(condemnedByRange), string(condemnServerReported)))

	notFound := client.StatusCodeError(404)
	assert.False(t, bf.dropIfCondemned(testWriterFence(t, env.storage, env.hash), &notFound, false, condemnedByRange),
		"a fetch that wrote nothing condemns nothing")
	assert.False(t, bf.dropIfCondemned(testWriterFence(t, env.storage, env.hash), context.Canceled, true, condemnedByRange),
		"a benign stop condemns nothing")
	assert.Zero(t, condemned())

	assert.True(t, bf.dropIfCondemned(testWriterFence(t, env.storage, env.hash), &notFound, true, condemnedByRange))
	assert.Equal(t, 1.0, byRange())
	assert.Equal(t, 1.0, condemned())
}

// TestReadsPastDownloadMetrics checks that a reader that fetches blocks a
// whole-object download has yet to write, rather than wait for it, is
// counted by why: the download was far from them, or late.  A reader whose
// download writes its blocks in time is not counted.
func TestReadsPastDownloadMetrics(t *testing.T) {
	distant := counterDelta(cacheReadsPastDownloadTotal.WithLabelValues(string(pastDistantDownload)))
	late := counterDelta(cacheReadsPastDownloadTotal.WithLabelValues(string(pastLateDownload)))
	all := counterDelta(allReadsPastDownload()...)

	t.Run("Near", func(t *testing.T) {
		obs := NewObjectBlockState(nil)
		obs.SetDownloading()
		defer obs.ClearDownloading()
		obs.SetDownloadETA(func(uint32) time.Time { return time.Now() })
		var overDownloads []bool
		rr := &RangeReader{blockState: obs, end: 100*BlockDataSize - 1}
		rr.startFill = fillStub(&overDownloads, obs)
		go obs.AddRange(0, 9)
		require.NoError(t, returnsWithin(t, func() error { return rr.ensureBlocks(t.Context(), 0, 9) }))
		assert.Zero(t, all(), "a reader that waited for the download is not counted")
	})

	t.Run("Distant", func(t *testing.T) {
		obs := NewObjectBlockState(nil)
		obs.SetDownloading()
		defer obs.ClearDownloading()
		obs.SetDownloadETA(func(uint32) time.Time { return time.Now().Add(time.Hour) })
		var overDownloads []bool
		rr := &RangeReader{blockState: obs, end: 100*BlockDataSize - 1}
		rr.startFill = fillStub(&overDownloads, obs)
		require.NoError(t, returnsWithin(t, func() error { return rr.ensureBlocks(t.Context(), 90, 99) }))
		assert.Equal(t, 1.0, distant(), "one read past the distant download, however many blocks it fills")
		assert.Zero(t, late())
	})

	t.Run("Late", func(t *testing.T) {
		defer func(slack time.Duration) { downloadWaitSlack = slack }(downloadWaitSlack)
		downloadWaitSlack = 50 * time.Millisecond
		obs := NewObjectBlockState(nil)
		obs.SetDownloading()
		defer obs.ClearDownloading()
		obs.SetDownloadETA(func(uint32) time.Time { return time.Now() })
		var overDownloads []bool
		rr := &RangeReader{blockState: obs, end: 100*BlockDataSize - 1}
		rr.startFill = fillStub(&overDownloads, obs)
		before := distant()
		require.NoError(t, returnsWithin(t, func() error { return rr.ensureBlocks(t.Context(), 0, 9) }))
		assert.Equal(t, 1.0, late(), "one read past the late download")
		assert.Equal(t, before, distant())
	})
}

// TestWriteFenceRefusalMetric checks that a writer refused by the write
// fence is counted once, by the kind of its first refused write, however
// many writes it goes on to make; that a writer that was not refused is not
// counted; and that a storage manager that suppresses the cache's metrics
// counts nothing.
func TestWriteFenceRefusalMetric(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	fences := env.storage.fences
	all := counterDelta(allFenceRefusals()...)
	completion := counterDelta(cacheWriteFenceRefusalsTotal.WithLabelValues(string(fencedCompletion)))

	writer := testWriterFence(t, env.storage, env.hash)
	assert.True(t, writer.write(fencedBlocks, func() {}))
	assert.Zero(t, all(), "a write that ran is not a refusal")

	fences.exclude(env.hash)(true)
	assert.False(t, writer.write(fencedCompletion, func() { t.Error("a write after the deletion ran") }))
	assert.False(t, writer.write(fencedBlocks, func() { t.Error("a write after the deletion ran") }))
	assert.Equal(t, 1.0, completion(), "the writer is counted under its first refused write")
	assert.Equal(t, 1.0, all(), "the writer is counted once")

	env.storage.SuppressCacheMetrics()
	suppressed := testWriterFence(t, env.storage, env.hash)
	fences.exclude(env.hash)(true)
	assert.False(t, suppressed.write(fencedBlocks, func() {}))
	assert.Equal(t, 1.0, all(), "a storage manager that is not a cache's counts nothing")
}

// TestFencedOffBlockWriteIsCounted checks the count through a real writer:
// WriteBlocks into an object deleted under it is refused, and counted as a
// refused write of blocks.
func TestFencedOffBlockWriteIsCounted(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	blocks := counterDelta(cacheWriteFenceRefusalsTotal.WithLabelValues(string(fencedBlocks)))
	env.storage.fences.beforeWrite = func(h InstanceHash) {
		require.NoError(t, env.storage.Delete(h))
		env.reinit(t)
	}
	defer func() { env.storage.fences.beforeWrite = nil }()
	require.ErrorIs(t, env.storage.WriteBlocks(env.hash, 0, env.data), errInstanceDeleted)
	assert.Equal(t, 1.0, blocks())
}
