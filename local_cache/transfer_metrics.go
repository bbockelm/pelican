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

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/pelicanplatform/pelican/client"
)

// Metrics of the persistent cache's background transfers: the whole-object
// download a miss starts, the fills that resume a partly cached object, the
// verdicts that condemn an instance's data, and the write fence that keeps
// writers out of a deleted instance.
//
// Every one is counted on an event -- a transfer starting or ending, a
// verdict, a reader deciding not to wait -- never per block or per read, and
// every label takes one of the few values declared below, never anything of
// an object's.  The label values are typed, so a call site cannot pass a
// value the metric does not document.
//
// pstore (an origin's data store) shares the storage layer but runs none of
// these transfers; it suppresses the one metric the storage layer itself
// counts, the write fence's (see StorageManager.SuppressCacheMetrics).

// fillOutcome is how a background fill ended: the "outcome" label of
// cacheFillsEndedTotal.
type fillOutcome string

const (
	fillCompleted    fillOutcome = "completed"     // it wrote every block it was to fetch
	fillStoppedEarly fillOutcome = "stopped_early" // it stopped for a benign reason and kept its whole blocks
	fillCondemned    fillOutcome = "condemned"     // its failure condemned the object, which was dropped
	fillFailed       fillOutcome = "failed"        // it failed having written nothing to condemn
)

// downloadStopCause classifies why a whole-object download ended before
// completing: the "cause" label of cacheDownloadStopsTotal.
type downloadStopCause string

const (
	downloadStopIdle       downloadStopCause = "idle"       // no reader for LocalCache.PrefetchTimeout
	downloadStopShutdown   downloadStopCause = "shutdown"   // the cache was closing
	downloadStopCancelled  downloadStopCause = "cancelled"  // cancelled other than by shutdown
	downloadStopTransport  downloadStopCause = "transport"  // a connection reset, a timeout, a stalled or cut-short body
	downloadStopUnreported downloadStopCause = "unreported" // the transfer client ended without reporting a result
	downloadStopError      downloadStopCause = "error"      // a failure that condemns the data (see transferStopKeepsData)
)

// downloadStopOutcome is what became of a stopped download's data: the
// "outcome" label of cacheDownloadStopsTotal.
type downloadStopOutcome string

const (
	downloadStopKept      downloadStopOutcome = "kept"      // its whole blocks were kept; the object stays partly cached
	downloadStopCondemned downloadStopOutcome = "condemned" // the object was condemned and dropped
)

// condemnSource is which transfer condemned an instance: the "source" label
// of cacheObjectsCondemnedTotal.
type condemnSource string

const (
	condemnedByDownload condemnSource = "download" // the whole-object download of a miss
	condemnedByFill     condemnSource = "fill"     // a background fill of a partly cached object
	condemnedByRange    condemnSource = "range"    // a reader's own range fetch, or a prefetch
)

// condemnReason classifies why an instance was condemned: the "reason"
// label of cacheObjectsCondemnedTotal.
type condemnReason string

const (
	condemnVersionChanged   condemnReason = "version_changed"   // the origin now serves a different version
	condemnChecksumMismatch condemnReason = "checksum_mismatch" // the body did not match its checksum
	condemnServerReported   condemnReason = "server_reported"   // an error status, or a failure in the X-Transfer-Status trailer
	condemnUnknownSize      condemnReason = "unknown_size"      // a download of unknown size stopped early: its blocks cannot be placed
	condemnOther            condemnReason = "other"             // any other failure after part of the body was written
)

// pastDownloadReason is why a reader fetched blocks a whole-object download
// in progress had yet to write instead of waiting for it: the "reason" label
// of cacheReadsPastDownloadTotal.
type pastDownloadReason string

const (
	pastDistantDownload pastDownloadReason = "distant"      // the download was not due to reach them soon
	pastLateDownload    pastDownloadReason = "wait_timeout" // the reader waited, and the download was late
)

// fencedWriteKind is what a writer was writing when the write fence refused
// it: the "kind" label of cacheWriteFenceRefusalsTotal.
type fencedWriteKind string

const (
	fencedBlocks     fencedWriteKind = "blocks"     // blocks, and the rows marking them present
	fencedCompletion fencedWriteKind = "completion" // the record of the object's completion
	fencedFile       fencedWriteKind = "file"       // creating the object's file, or caching its descriptor
	fencedMetadata   fencedWriteKind = "metadata"   // other fields of the object's record, such as its checksums
)

var (
	cacheFillsStartedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_fills_started_total",
		Help: "Background fills started: transfers that fetch a gap of a partly cached object, from the first block a reader needs to the next block present",
	})
	cacheFillsEndedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_fills_ended_total",
		Help: "Background fills ended, by outcome: completed, stopped_early (a benign stop, such as no reader for the idle timeout, " +
			"that kept the whole blocks written), condemned (a failure that dropped the object), or failed (a failure with nothing written to condemn)",
	}, []string{"outcome"})
	cacheFillBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_fill_bytes_total",
		Help: "Bytes background fills received from upstream, counted when each fill ends",
	})

	cacheDownloadStopsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_download_stops_total",
		Help: "Whole-object downloads of a cache miss stored on disk that ended without completing, by cause " +
			"(idle, shutdown, cancelled, transport, unreported, or error -- a failure that condemns the data) and outcome " +
			"(kept: the whole blocks written were kept and the object stays partly cached; condemned: the object was dropped)",
	}, []string{"cause", "outcome"})
	cacheObjectsCondemnedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_objects_condemned_total",
		Help: "Cached objects condemned as bad and dropped by the transfer writing them, by source (download, fill, or range) " +
			"and reason (version_changed, checksum_mismatch, server_reported, unknown_size, or other)",
	}, []string{"source", "reason"})
	cacheReadsPastDownloadTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_reads_past_download_total",
		Help: "Reads that fetched blocks a whole-object download in progress had yet to write, instead of waiting for it, by reason: " +
			"distant (the download was not expected to reach them soon) or wait_timeout (the reader waited and the download was late)",
	}, []string{"reason"})
	cacheWriteFenceRefusalsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_write_fence_refusals_total",
		Help: "Writers refused by the write fence because the object instance they were writing had been deleted (evicted, purged, " +
			"or dropped as bad), counted once per writer, by the kind of its first refused write: blocks, completion, file, or metadata",
	}, []string{"kind"})
	cacheDownloadHandOffFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_download_handoff_failures_total",
		Help: "Whole-object downloads of a cache miss that chose disk storage but failed before their transfer was handed to a block fetcher; " +
			"readers already waiting for them are released",
	})
)

// The values each label takes, every one of which exists from the start, so
// that a rate over a series that has not moved yet reads zero rather than
// nothing.
var (
	allFillOutcomes         = []fillOutcome{fillCompleted, fillStoppedEarly, fillCondemned, fillFailed}
	allDownloadStopCauses   = []downloadStopCause{downloadStopIdle, downloadStopShutdown, downloadStopCancelled, downloadStopTransport, downloadStopUnreported, downloadStopError}
	allDownloadStopOutcomes = []downloadStopOutcome{downloadStopKept, downloadStopCondemned}
	allCondemnSources       = []condemnSource{condemnedByDownload, condemnedByFill, condemnedByRange}
	allCondemnReasons       = []condemnReason{condemnVersionChanged, condemnChecksumMismatch, condemnServerReported, condemnUnknownSize, condemnOther}
	allPastDownloadReasons  = []pastDownloadReason{pastDistantDownload, pastLateDownload}
	allFencedWriteKinds     = []fencedWriteKind{fencedBlocks, fencedCompletion, fencedFile, fencedMetadata}
)

func init() {
	for _, o := range allFillOutcomes {
		cacheFillsEndedTotal.WithLabelValues(string(o))
	}
	for _, c := range allDownloadStopCauses {
		for _, o := range allDownloadStopOutcomes {
			cacheDownloadStopsTotal.WithLabelValues(string(c), string(o))
		}
	}
	for _, s := range allCondemnSources {
		for _, r := range allCondemnReasons {
			cacheObjectsCondemnedTotal.WithLabelValues(string(s), string(r))
		}
	}
	for _, r := range allPastDownloadReasons {
		cacheReadsPastDownloadTotal.WithLabelValues(string(r))
	}
	for _, k := range allFencedWriteKinds {
		cacheWriteFenceRefusalsTotal.WithLabelValues(string(k))
	}
}

// recordFillEnd records the end of a background fill that ended in err (nil
// on success), having received the given number of bytes, and whether its
// failure condemned the object.
func recordFillEnd(err error, condemned bool, bytes int64) {
	outcome := fillFailed
	switch {
	case err == nil:
		outcome = fillCompleted
	case condemned:
		outcome = fillCondemned
	case transferStopKeepsData(err):
		outcome = fillStoppedEarly
	}
	cacheFillsEndedTotal.WithLabelValues(string(outcome)).Inc()
	cacheFillBytesTotal.Add(float64(bytes))
}

// downloadStopCauseOf classifies err, the error a whole-object download
// ended in; closing says whether the cache was shutting down.
func downloadStopCauseOf(err error, closing bool) downloadStopCause {
	switch {
	case errors.Is(err, errAdoptedTransferIdle), errors.Is(err, errPrefetchIdle):
		return downloadStopIdle
	case errors.Is(err, errAdoptedTransferUnreported):
		return downloadStopUnreported
	case !transferStopKeepsData(err):
		return downloadStopError
	case errors.Is(err, context.Canceled):
		// A download runs under the cache's own context, which only the
		// cache's shutdown and the idle stop cancel.
		if closing {
			return downloadStopShutdown
		}
		return downloadStopCancelled
	}
	return downloadStopTransport
}

// recordDownloadStop records a whole-object download that ended in err
// before completing, and whether its data was condemned.
func recordDownloadStop(err error, closing, condemned bool) {
	outcome := downloadStopKept
	if condemned {
		outcome = downloadStopCondemned
	}
	cacheDownloadStopsTotal.WithLabelValues(string(downloadStopCauseOf(err, closing)), string(outcome)).Inc()
}

// condemnReasonOf classifies err, the failure that condemned an instance.
func condemnReasonOf(err error) condemnReason {
	var mismatch *client.ChecksumMismatchError
	var status *client.HttpErrResp
	var code *client.StatusCodeError
	var trailer *client.TransferStatusError
	switch {
	case errors.Is(err, client.ErrObjectVersionChanged):
		return condemnVersionChanged
	case errors.As(err, &mismatch):
		return condemnChecksumMismatch
	case errors.As(err, &status), errors.As(err, &code), errors.As(err, &trailer):
		return condemnServerReported
	}
	return condemnOther
}

// recordCondemned records that a transfer from source condemned the instance
// it was writing, for the given reason.
func recordCondemned(source condemnSource, reason condemnReason) {
	cacheObjectsCondemnedTotal.WithLabelValues(string(source), string(reason)).Inc()
}

// recordReadPastDownload records that a reader fetched blocks a whole-object
// download had yet to write instead of waiting for it.
func recordReadPastDownload(reason pastDownloadReason) {
	cacheReadsPastDownloadTotal.WithLabelValues(string(reason)).Inc()
}
