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
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockContent returns deterministic block bytes for a key so that any reader
// can verify a hit returned the correct block (and never another key's bytes).
func blockContent(key uint64, n int) []byte {
	b := make([]byte, n)
	x := key*0x9E3779B97F4A7C15 + 0x1234567
	for i := range b {
		x = x*1099511628211 + uint64(i)
		b[i] = byte(x >> 24)
	}
	return b
}

// backendFactory builds a fresh backend of the given size, skipping the test if
// the backend is unavailable on this platform/kernel.
type backendFactory struct {
	name  string
	build func(tb testing.TB, sizeBytes uint64) blockCache
}

func allBackends() []backendFactory {
	return []backendFactory{
		{
			name: backendRistretto,
			build: func(tb testing.TB, sizeBytes uint64) blockCache {
				c, err := newRistrettoBlockCache(sizeBytes)
				if err != nil {
					tb.Fatalf("ristretto: %v", err)
				}
				return c
			},
		},
		{
			name: backendOffHeap,
			build: func(tb testing.TB, sizeBytes uint64) blockCache {
				c, err := newOffHeapBlockCache(sizeBytes)
				if err != nil {
					tb.Skipf("off-heap backend unavailable: %v", err)
				}
				return c
			},
		},
	}
}

// pollGet retries Get for up to timeout, since admission into the underlying
// ristretto policy is asynchronous for both backends.
func pollGet(c blockCache, key uint64, dst []byte, timeout time.Duration) (int, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if n, ok := c.Get(key, dst); ok {
			return n, true
		}
		if time.Now().After(deadline) {
			return 0, false
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBlockCacheBasic(t *testing.T) {
	for _, bf := range allBackends() {
		t.Run(bf.name, func(t *testing.T) {
			c := bf.build(t, 8<<20) // 8 MiB
			defer c.Close()

			dst := make([]byte, BlockDataSize)

			// Miss on an absent key.
			if _, ok := c.Get(1, dst); ok {
				t.Fatal("expected miss on empty cache")
			}

			// Set a full block and a short (last-block) block.
			full := blockContent(42, BlockDataSize)
			short := blockContent(99, 100)
			c.Set(42, full)
			c.Set(99, short)

			if n, ok := pollGet(c, 42, dst, 2*time.Second); !ok {
				t.Fatal("expected hit for key 42")
			} else if n != BlockDataSize || !bytesEqual(dst[:n], full) {
				t.Fatalf("key 42: wrong content (n=%d)", n)
			}

			if n, ok := pollGet(c, 99, dst, 2*time.Second); !ok {
				t.Fatal("expected hit for key 99")
			} else if n != len(short) || !bytesEqual(dst[:n], short) {
				t.Fatalf("key 99: wrong content (n=%d want %d)", n, len(short))
			}

			// Set copies in: mutating the source afterwards must not corrupt
			// the cached copy.
			src := blockContent(7, BlockDataSize)
			c.Set(7, src)
			if _, ok := pollGet(c, 7, dst, 2*time.Second); !ok {
				t.Fatal("expected hit for key 7")
			}
			for i := range src {
				src[i] = 0
			}
			if n, ok := c.Get(7, dst); ok && !bytesEqual(dst[:n], blockContent(7, BlockDataSize)) {
				t.Fatal("Set did not copy: cached value mutated with source")
			}
		})
	}
}

// TestBlockCacheConcurrentIntegrity is the cross-instance integrity test
// (acceptance §6.2 / §9): many goroutines read and write a shared key space
// while the cache evicts under capacity pressure.  Every successful Get must
// return exactly the block stored for that key — never another key's bytes.
func TestBlockCacheConcurrentIntegrity(t *testing.T) {
	for _, bf := range allBackends() {
		t.Run(bf.name, func(t *testing.T) {
			// Deliberately small so admission/eviction churns slots hard.
			c := bf.build(t, 1<<20) // 1 MiB ~= 256 slots
			defer c.Close()

			const (
				keySpace = 4000
				writers  = 4
				readers  = 8
			)
			dur := 800 * time.Millisecond
			if testing.Short() {
				dur = 150 * time.Millisecond
			}

			var stop atomic.Bool
			var wrong atomic.Uint64
			var hits atomic.Uint64
			var wg sync.WaitGroup

			lengthFor := func(k uint64) int {
				return 1 + int(k%BlockDataSize)
			}

			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func(seed uint64) {
					defer wg.Done()
					rng := rand.New(rand.NewSource(int64(seed)))
					for !stop.Load() {
						k := uint64(rng.Intn(keySpace))
						c.Set(k, blockContent(k, lengthFor(k)))
					}
				}(uint64(w) + 1)
			}

			for r := 0; r < readers; r++ {
				wg.Add(1)
				go func(seed uint64) {
					defer wg.Done()
					rng := rand.New(rand.NewSource(int64(seed) + 100))
					dst := make([]byte, BlockDataSize)
					for !stop.Load() {
						k := uint64(rng.Intn(keySpace))
						n, ok := c.Get(k, dst)
						if !ok {
							continue
						}
						hits.Add(1)
						want := blockContent(k, lengthFor(k))
						if n != len(want) || !bytesEqual(dst[:n], want) {
							wrong.Add(1)
						}
					}
				}(uint64(r) + 1)
			}

			time.Sleep(dur)
			stop.Store(true)
			wg.Wait()

			if wrong.Load() != 0 {
				t.Fatalf("%d reads returned wrong block bytes (hits=%d)", wrong.Load(), hits.Load())
			}
			t.Logf("%s: %d verified hits, 0 wrong-block returns", bf.name, hits.Load())
		})
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- Benchmarks: ristretto vs off-heap ----

func benchBackends(b *testing.B) []backendFactory { return allBackends() }

// BenchmarkBlockCacheGetHit measures the steady-state read hit path (the case
// the cache exists to optimize): a warm working set that fits the cache.
func BenchmarkBlockCacheGetHit(b *testing.B) {
	const size = 64 << 20
	const workingSet = 8000 // * 4080 ~= 32 MiB, fits in 64 MiB
	for _, bf := range benchBackends(b) {
		b.Run(bf.name, func(b *testing.B) {
			c := bf.build(b, size)
			defer c.Close()
			for k := uint64(0); k < workingSet; k++ {
				c.Set(k, blockContent(k, BlockDataSize))
			}
			// Let admission settle.
			time.Sleep(200 * time.Millisecond)

			b.ReportAllocs()
			b.SetBytes(BlockDataSize)
			b.RunParallel(func(pb *testing.PB) {
				dst := make([]byte, BlockDataSize)
				var i uint64
				var hits int
				for pb.Next() {
					k := i % workingSet
					i++
					if _, ok := c.Get(k, dst); ok {
						hits++
					}
				}
				_ = hits
			})
		})
	}
}

// BenchmarkBlockCacheSet measures the write/populate path.
func BenchmarkBlockCacheSet(b *testing.B) {
	const size = 64 << 20
	for _, bf := range benchBackends(b) {
		b.Run(bf.name, func(b *testing.B) {
			c := bf.build(b, size)
			defer c.Close()
			block := blockContent(1, BlockDataSize)
			b.ReportAllocs()
			b.SetBytes(BlockDataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.Set(uint64(i), block)
			}
		})
	}
}

// BenchmarkBlockCacheMixed measures a realistic 90% read / 10% write workload
// over a working set sized to the cache.
func BenchmarkBlockCacheMixed(b *testing.B) {
	const size = 64 << 20
	const workingSet = 12000
	for _, bf := range benchBackends(b) {
		b.Run(bf.name, func(b *testing.B) {
			c := bf.build(b, size)
			defer c.Close()
			for k := uint64(0); k < workingSet; k++ {
				c.Set(k, blockContent(k, BlockDataSize))
			}
			time.Sleep(200 * time.Millisecond)
			b.ReportAllocs()
			b.SetBytes(BlockDataSize)
			b.RunParallel(func(pb *testing.PB) {
				rng := rand.New(rand.NewSource(time.Now().UnixNano()))
				dst := make([]byte, BlockDataSize)
				for pb.Next() {
					k := uint64(rng.Intn(workingSet))
					if rng.Intn(10) == 0 {
						c.Set(k, blockContent(k, BlockDataSize))
					} else {
						c.Get(k, dst)
					}
				}
			})
		})
	}
}
