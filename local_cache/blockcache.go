/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"strings"

	ristretto "github.com/dgraph-io/ristretto/v2"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// blockCache is the backend-agnostic interface for the plaintext block
// cache.  It stores decrypted blocks (0 < len <= BlockDataSize) keyed by
// the ptCacheKey of (InstanceHash, blockNumber) so that repeated reads can
// skip AES-GCM decryption.
//
// There are two implementations:
//
//   - ristrettoBlockCache: the original in-heap ristretto cache.  Holds its
//     blocks live; the kernel cannot reclaim them under memory pressure.
//   - offHeapBlockCache (Linux only): stores block bytes in an mmap'd arena
//     that is MADV_FREE'd so the kernel may reclaim pages under pressure,
//     degrading to re-decrypt rather than pinning RSS or driving OOM.
type blockCache interface {
	// Get copies the cached block for key into dst and returns the number of
	// bytes copied and true on a hit.  dst must have length >= the cached
	// block's length; callers pass a buffer of at least BlockDataSize.  On a
	// miss it returns (0, false); dst may have been partially overwritten and
	// must be treated as scratch by the caller.
	Get(key uint64, dst []byte) (int, bool)

	// Set stores a copy of val under key.  val must satisfy
	// 0 < len(val) <= BlockDataSize.  The cache copies the bytes in, so the
	// caller may reuse val immediately.
	Set(key uint64, val []byte)

	// Close releases all resources held by the cache.
	Close()

	// directIO reports whether disk reads that feed this cache should use
	// O_DIRECT.  The off-heap backend behaves like the page cache for
	// decrypted blocks, so it bypasses the kernel page cache for the
	// encrypted source data to avoid double-caching ciphertext; the
	// ristretto backend returns false (ordinary buffered I/O).
	directIO() bool
}

// Memory cache backend selectors (param Cache.MemoryCacheBackend /
// LocalCache.MemoryCacheBackend).
const (
	backendRistretto = "ristretto"
	backendOffHeap   = "offheap"
)

// errOffHeapUnsupported is returned by newOffHeapBlockCache on platforms or
// kernels without MADV_FREE support, or when the arena mmap fails.  The
// caller falls back to the ristretto backend.
var errOffHeapUnsupported = errors.New("off-heap block cache unsupported on this platform")

// newBlockCache constructs the plaintext block cache backend named by
// backend with the given byte ceiling.  sizeBytes is the configured size
// (Cache.MemoryCacheSize / LocalCache.MemoryCacheSize); for the off-heap
// backend it is the controller ceiling (c_max), not the operating point.
//
// Returns (nil, nil) when sizeBytes == 0 (cache disabled).  When the
// off-heap backend is requested but unavailable (non-Linux, old kernel, or
// mmap failure) it logs a warning and falls back to ristretto.
func newBlockCache(backend string, sizeBytes uint64) (blockCache, error) {
	if sizeBytes == 0 {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", backendRistretto:
		return newRistrettoBlockCache(sizeBytes)
	case backendOffHeap:
		bc, err := newOffHeapBlockCache(sizeBytes)
		if err != nil {
			log.Warningf("off-heap plaintext block cache unavailable (%v); "+
				"falling back to ristretto backend", err)
			return newRistrettoBlockCache(sizeBytes)
		}
		log.Infof("using off-heap (MADV_FREE) plaintext block cache with %d-byte ceiling", sizeBytes)
		return bc, nil
	default:
		return nil, errors.Errorf("unknown memory cache backend %q (expected %q or %q)",
			backend, backendRistretto, backendOffHeap)
	}
}

// ristrettoBlockCache is the original in-heap plaintext block cache backed
// by ristretto.  Each entry costs BlockDataSize and MaxCost is the
// configured size in bytes.
type ristrettoBlockCache struct {
	c *ristretto.Cache[uint64, []byte]
}

// newRistrettoBlockCache builds a ristretto-backed block cache with a
// MaxCost of sizeBytes.  sizeBytes must be > 0.
func newRistrettoBlockCache(sizeBytes uint64) (blockCache, error) {
	// NumCounters should be ~10x the expected max number of entries.
	numEntries := int64(sizeBytes) / BlockDataSize
	numCounters := numEntries * 10
	if numCounters < 1000 {
		numCounters = 1000
	}
	c, err := ristretto.NewCache(&ristretto.Config[uint64, []byte]{
		NumCounters: numCounters,
		MaxCost:     int64(sizeBytes),
		BufferItems: 64,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create plaintext block cache")
	}
	return &ristrettoBlockCache{c: c}, nil
}

func (r *ristrettoBlockCache) Get(key uint64, dst []byte) (int, bool) {
	v, ok := r.c.Get(key)
	if !ok {
		return 0, false
	}
	return copy(dst, v), true
}

func (r *ristrettoBlockCache) Set(key uint64, val []byte) {
	// ristretto retains the slice it is handed, so copy out of the caller's
	// (reused) buffer.
	entry := make([]byte, len(val))
	copy(entry, val)
	r.c.Set(key, entry, int64(BlockDataSize))
}

func (r *ristrettoBlockCache) Close() {
	r.c.Close()
}

func (r *ristrettoBlockCache) directIO() bool { return false }
