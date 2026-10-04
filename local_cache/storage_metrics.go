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
	"path/filepath"
	"strconv"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Per-storage capacity metrics: how full each storage directory and tiering
// target is, against the limits eviction works to.  Every storage target the
// eviction manager governs gets a series, labelled with
//
//   - storage_id: the cache's stable ID for the target;
//   - backend:    "posix" for a local directory, "tier" for a tiering target;
//   - path:       the configured directory, or the tiering target's display
//     URL, which never carries credentials (TierTargetConfig.DisplayURL).
//
// The figures are the eviction manager's own in-memory counters, published
// when it starts and on each pass of its loop (every few seconds), so a
// scrape costs nothing and the gauges are right from startup rather than from
// the first write.  The used figure is the same estimate eviction acts on.
//
// Only the eviction manager publishes these, and a pstore origin has none --
// it never evicts and reports its capacity as pelican_pstore_directory_* --
// so a process running both a cache and a pstore origin does not publish the
// pstore's directories under cache names.  When a manager stops, it removes
// its series, so a cache that is torn down and rebuilt in one process (as in
// tests) leaves no stale ones behind.

// Values of the "backend" label on the storage metrics.
const (
	storageBackendPosix = "posix"
	storageBackendTier  = "tier"
)

var (
	storageUsedBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_storage_used_bytes",
		Help: "Bytes the cache has stored on one storage directory or tiering target, as tracked for eviction",
	}, []string{"storage_id", "backend", "path"})
	storageLimitBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_storage_limit_bytes",
		Help: "Maximum bytes the cache stores on one storage directory or tiering target (its MaxSize, " +
			"or the detected filesystem size when none is configured)",
	}, []string{"storage_id", "backend", "path"})
	storageHighWaterBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_storage_high_watermark_bytes",
		Help: "Usage of one storage directory or tiering target above which the cache starts evicting from it",
	}, []string{"storage_id", "backend", "path"})
	storageLowWaterBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_storage_low_watermark_bytes",
		Help: "Usage of one storage directory or tiering target down to which the cache evicts once it has started",
	}, []string{"storage_id", "backend", "path"})
)

// storageGauges is one storage target's set of gauges, resolved once when the
// eviction manager starts so that publishing is a handful of atomic stores.
type storageGauges struct {
	labels prometheus.Labels
	usage  *atomic.Int64
	used   prometheus.Gauge
}

// storageMetricLabels returns the label values for one storage target.
func (em *EvictionManager) storageMetricLabels(id StorageID) prometheus.Labels {
	labels := prometheus.Labels{
		"storage_id": strconv.Itoa(int(id)),
		"backend":    storageBackendPosix,
		"path":       "",
	}
	if em.storage == nil {
		return labels
	}
	if target := em.storage.getTierTarget(id); target != nil {
		labels["backend"] = storageBackendTier
		labels["path"] = target.metricLabel()
	} else if objectsDir, ok := em.storage.dirs[id]; ok {
		// The objects/ subdirectory is an implementation detail; label the
		// directory the operator configured.
		labels["path"] = filepath.Dir(objectsDir)
	}
	return labels
}

// publishStorageMetrics resolves each target's gauges, sets the limit and
// watermark gauges (fixed for the manager's lifetime) and the usage gauges.
// Called once, from Start.
func (em *EvictionManager) publishStorageMetrics() {
	em.storageGauges = make([]storageGauges, 0, len(em.dirIDs))
	for _, id := range em.dirIDs {
		labels := em.storageMetricLabels(id)
		if limits, ok := em.dirLimits[id]; ok {
			storageLimitBytes.With(labels).Set(float64(limits.maxSize))
			storageHighWaterBytes.With(labels).Set(float64(limits.highWater))
			storageLowWaterBytes.With(labels).Set(float64(limits.lowWater))
		}
		em.storageGauges = append(em.storageGauges, storageGauges{
			labels: labels,
			usage:  em.dirUsage[id],
			used:   storageUsedBytes.With(labels),
		})
	}
	em.publishStorageUsage()
}

// publishStorageUsage sets the used gauges from the in-memory counters.
func (em *EvictionManager) publishStorageUsage() {
	for _, g := range em.storageGauges {
		used := g.usage.Load()
		if used < 0 {
			used = 0
		}
		g.used.Set(float64(used))
	}
}

// unpublishStorageMetrics removes exactly the series publishStorageMetrics
// created.
func (em *EvictionManager) unpublishStorageMetrics() {
	for _, g := range em.storageGauges {
		storageUsedBytes.Delete(g.labels)
		storageLimitBytes.Delete(g.labels)
		storageHighWaterBytes.Delete(g.labels)
		storageLowWaterBytes.Delete(g.labels)
	}
}
