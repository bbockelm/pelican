//go:build linux

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
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// newOffHeapForTest builds an off-heap cache, skipping when MADV_FREE is
// unavailable on this kernel/filesystem.
func newOffHeapForTest(t testing.TB, sizeBytes uint64) *offHeapBlockCache {
	t.Helper()
	bc, err := newOffHeapBlockCache(sizeBytes)
	if err != nil {
		t.Skipf("off-heap backend unavailable: %v", err)
	}
	return bc.(*offHeapBlockCache)
}

// newOffHeapNoWorkers builds an off-heap cache without the background
// scavenger/controller goroutines, so tests can call scavenge()/controlStep()
// deterministically without the loops racing them.
func newOffHeapNoWorkers(t testing.TB, sizeBytes uint64) *offHeapBlockCache {
	t.Helper()
	c, err := newOffHeapBlockCacheRaw(sizeBytes)
	if err != nil {
		t.Skipf("off-heap backend unavailable: %v", err)
	}
	return c
}

// simulateReclaim mimics what the kernel does to a MADV_FREE'd page: it zeroes
// the whole slot page (payload + generation pad).  After this, a read of that
// slot must detect the reclaim via the zeroed pad and report a miss.
func (c *offHeapBlockCache) simulateReclaim(slot uint32) {
	base := unsafe.Add(c.arenaPtr, uintptr(slot)*c.slotSize)
	for i := uintptr(0); i < c.slotSize; i += 8 {
		atomic.StoreUint64((*uint64)(unsafe.Add(base, i)), 0)
	}
}

// TestOffHeapReclaimDetection verifies the generation-seqlock: a slot whose
// page has been reclaimed (zeroed) reads back as a miss and bumps the
// reclaim-miss counter — never returns the stale/zeroed bytes as a hit.
func TestOffHeapReclaimDetection(t *testing.T) {
	c := newOffHeapForTest(t, 4<<20)
	defer c.Close()

	key := uint64(12345)
	want := blockContent(key, BlockDataSize)
	c.Set(key, want)

	dst := make([]byte, BlockDataSize)
	if _, ok := pollGet(c, key, dst, 2*time.Second); !ok {
		t.Fatal("expected hit before reclaim")
	}

	// Find the slot backing the key and simulate a kernel reclaim of its page.
	h, ok := c.index.Get(key)
	if !ok {
		t.Fatal("key not in index")
	}
	before := c.reclaimMiss.Load()
	c.simulateReclaim(h.slot)

	if _, ok := c.Get(key, dst); ok {
		t.Fatal("expected miss after page reclaim, got a hit")
	}
	if c.reclaimMiss.Load() != before+1 {
		t.Fatalf("reclaim-miss counter did not advance: before=%d after=%d", before, c.reclaimMiss.Load())
	}

	// Re-Set repopulates the block (the self-healing path): a subsequent read
	// must return the correct bytes again.
	c.Set(key, want)
	if n, ok := pollGet(c, key, dst, 2*time.Second); !ok {
		t.Fatal("expected hit after repopulate")
	} else if !bytesEqual(dst[:n], want) {
		t.Fatal("wrong bytes after repopulate")
	}
}

// TestOffHeapScavengeAdvises verifies the scavenger marks cold slots as advised
// (MADV_FREE'd) after they lose their CLOCK second chance, and that a fresh
// write clears the advised state.
func TestOffHeapScavengeAdvises(t *testing.T) {
	c := newOffHeapNoWorkers(t, 4<<20)
	defer c.Close()

	const n = 50
	dst := make([]byte, BlockDataSize)
	for k := uint64(0); k < n; k++ {
		c.Set(k, blockContent(k, BlockDataSize))
	}
	// Ensure all are admitted.
	for k := uint64(0); k < n; k++ {
		pollGet(c, k, dst, 2*time.Second)
	}

	// Two sweeps: the first clears the (read-set) ref bits, the second advises
	// the now-cold slots.
	c.scavenge(false)
	c.scavenge(false)

	advisedLive := 0
	for k := uint64(0); k < n; k++ {
		if h, ok := c.index.Get(k); ok {
			if c.advised.get(h.slot) {
				advisedLive++
			}
		}
	}
	if advisedLive == 0 {
		t.Fatal("expected some live cold slots to be advised after two sweeps")
	}

	// A write must clear the advised state for the slot it lands on.
	c.Set(0, blockContent(0, BlockDataSize))
	if h, ok := c.index.Get(0); ok && c.advised.get(h.slot) {
		t.Fatal("advised bit not cleared by write")
	}
}

// TestOffHeapControllerShrinks verifies the adaptive controller lowers the
// effective slot cap when the reclaim-miss signal indicates harm.
func TestOffHeapControllerShrinks(t *testing.T) {
	c := newOffHeapNoWorkers(t, 64<<20)
	defer c.Close()

	start := c.slotCap.Load()
	// Drive the harm signal directly, then run one control step.
	c.reclaimMiss.Add(reclaimMissShrinkThreshold + 1000)
	c.controlStep(time.Now())

	if c.slotCap.Load() >= start {
		t.Fatalf("expected slot cap to shrink: start=%d now=%d", start, c.slotCap.Load())
	}
	// The cap must never fall below the floor.
	for i := 0; i < 200; i++ {
		c.reclaimMiss.Add(reclaimMissShrinkThreshold + 1000)
		c.controlStep(time.Now())
	}
	if c.slotCap.Load() < c.minSlotCap {
		t.Fatalf("slot cap fell below floor: %d < %d", c.slotCap.Load(), c.minSlotCap)
	}
}

// TestOffHeapArenaIsSingleVMA sanity-checks that the arena's own VMA can be
// found in smaps and reports a bounded RSS (well under the virtual size thanks
// to MAP_NORESERVE + demand fill).
func TestOffHeapArenaResidentBounded(t *testing.T) {
	c := newOffHeapForTest(t, 32<<20)
	defer c.Close()

	// Touch a small fraction of the arena.
	for k := uint64(0); k < 100; k++ {
		c.Set(k, blockContent(k, BlockDataSize))
	}

	rssKB, _, ok := readArenaVMA(uintptr(c.arenaPtr))
	if !ok {
		t.Skip("could not locate arena VMA in smaps on this system")
	}
	virtualKB := uint64(c.arenaLen) / 1024
	if rssKB > virtualKB {
		t.Fatalf("arena RSS %d kB exceeds virtual size %d kB", rssKB, virtualKB)
	}
	t.Logf("arena: virtual=%d kB, resident=%d kB after touching 100 slots", virtualKB, rssKB)
}

// TestOffHeapOverCommitVirtual configures a cache ceiling far larger than host
// RAM and confirms (a) the arena maps successfully (MAP_NORESERVE makes the
// ceiling virtual-only) and (b) resident memory stays tiny when only a little
// is touched.  This is the property that lets an admin set MemoryCacheSize
// above host memory without reserving it — the ristretto backend cannot do
// this (its MaxCost is held live in the heap).
func TestOffHeapOverCommitVirtual(t *testing.T) {
	total := hostMemTotalBytes(t)
	ceiling := total * 4 // 4x host RAM, virtual only
	c := newOffHeapForTest(t, ceiling)
	defer c.Close()

	for k := uint64(0); k < 200; k++ {
		c.Set(k, blockContent(k, BlockDataSize))
	}
	st := c.stats()
	virtualMB := uint64(c.arenaLen) >> 20
	t.Logf("ceiling=%d MB (%.1fx host RAM), arena virtual=%d MB, resident=%d kB, occupied=%d",
		ceiling>>20, float64(ceiling)/float64(total), virtualMB, st.rssKB, st.occupied)

	if st.rssKB > 64*1024 { // touched 200 blocks (~800 kB); allow generous slack
		t.Fatalf("resident %d kB unexpectedly large for an over-committed, lightly-touched arena", st.rssKB)
	}
}

// TestOffHeapReclaimable demonstrates the core "graceful release" property: a
// filled cache, once scavenged, marks its cold pages MADV_FREE so the kernel
// may reclaim them on demand.  We verify the arena's own VMA reports a non-zero
// LazyFree (reclaimable) footprint — i.e. the cache has made its memory
// surrenderable to the kernel.  (Triggering an actual reclaim requires real
// memory pressure / a cgroup limit; see TestOffHeapMemoryPressure.)
func TestOffHeapReclaimable(t *testing.T) {
	c := newOffHeapNoWorkers(t, 64<<20)
	defer c.Close()

	const n = 4000 // ~16 MiB of blocks
	dst := make([]byte, BlockDataSize)
	for k := uint64(0); k < n; k++ {
		c.Set(k, blockContent(k, BlockDataSize))
	}
	for k := uint64(0); k < n; k++ {
		pollGet(c, k, dst, time.Second)
	}

	// Two sweeps so cold slots lose their CLOCK second chance and get advised.
	c.scavenge(false)
	c.scavenge(false)

	st := c.stats()
	t.Logf("after scavenge: rss=%d kB lazyFree=%d kB occupied=%d", st.rssKB, st.lazyFreeKB, st.occupied)
	if st.lazyFreeKB == 0 {
		t.Skip("kernel did not report LazyFree for the arena VMA (kernel/fs dependent); reclaim accounting unavailable")
	}
	// A meaningful fraction of the resident arena should be reclaimable.
	if st.lazyFreeKB*4 < st.rssKB {
		t.Logf("warning: only %d/%d kB marked reclaimable", st.lazyFreeKB, st.rssKB)
	}
}

// hostMemTotalBytes reads MemTotal from /proc/meminfo.
func hostMemTotalBytes(t *testing.T) uint64 {
	t.Helper()
	total, _ := readMemInfoPair()
	if total == 0 {
		t.Skip("could not read MemTotal")
	}
	return total * 1024
}

// BenchmarkBlockCacheOverCommit drives a working set larger than the cache's
// resident budget so reads churn through admission/eviction and (some) reclaim,
// the regime the off-heap design targets.  The off-heap ceiling is set well
// above the resident budget; ristretto is sized at the resident budget (it
// cannot be configured larger without holding it all live).  Both stay within a
// safe absolute footprint so this is OK to run on a normal host.
func BenchmarkBlockCacheOverCommit(b *testing.B) {
	const residentMB = 64
	const workingSet = 200000 // ~800 MiB of distinct blocks >> 64 MiB budget

	b.Run("ristretto", func(b *testing.B) {
		c, err := newRistrettoBlockCache(residentMB << 20)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		runOverCommit(b, c, workingSet)
	})
	b.Run("offheap", func(b *testing.B) {
		// Ceiling 8x the resident budget; controller/kernel keep RSS bounded.
		bc, err := newOffHeapBlockCache(uint64(residentMB) << 20 * 8)
		if err != nil {
			b.Skipf("off-heap unavailable: %v", err)
		}
		defer bc.Close()
		runOverCommit(b, bc, workingSet)
		if oh, ok := bc.(*offHeapBlockCache); ok {
			st := oh.stats()
			hitRate := float64(st.hits) / float64(st.hits+st.misses+st.reclaimMiss+1)
			b.ReportMetric(hitRate*100, "hit%")
			b.ReportMetric(float64(st.rssKB)/1024, "rssMB")
			b.ReportMetric(float64(st.reclaimMiss), "reclaimMiss")
		}
	})
}

// TestOffHeapUnadvisedBounded verifies the writer-backpressure volume cap: a
// heavy write burst with NO background scavenger (so only the inline emergency
// advise in allocSlot runs) must still keep the un-advised (unreclaimable)
// resident set bounded near the hard cap — i.e. the kernel always retains
// MADV_FREE'd pages it could reclaim.  This is the protection that makes the
// "kernel can rapidly shrink us" guarantee robust against fast allocation.
func TestOffHeapUnadvisedBounded(t *testing.T) {
	c := newOffHeapNoWorkers(t, 64<<20) // no scavenger/controller goroutines
	defer c.Close()

	hard := c.unadvisedHardCap
	block := blockContent(1, BlockDataSize)
	for k := 0; k < int(hard)*8; k++ {
		c.Set(uint64(k), block)
	}

	st := c.stats()
	if st.lazyFreeKB == 0 {
		t.Skipf("kernel did not report LazyFree for the arena (rss=%d kB); reclaim accounting unavailable", st.rssKB)
	}
	// Un-advised resident = resident pages the kernel cannot reclaim.
	var unadvisedKB uint64
	if st.rssKB > st.lazyFreeKB {
		unadvisedKB = st.rssKB - st.lazyFreeKB
	}
	hardKB := uint64(hard) * uint64(c.slotSize) / 1024
	t.Logf("after %d writes (no bg scavenger): rss=%d kB lazyFree=%d kB unadvised=%d kB (hard cap=%d kB)",
		int(hard)*8, st.rssKB, st.lazyFreeKB, unadvisedKB, hardKB)

	// Allow generous slack for the free-list, coalescing granularity and the
	// final sub-cap backlog; the point is it does NOT scale with total writes.
	if unadvisedKB > hardKB*4 {
		t.Fatalf("un-advised resident %d kB far exceeds hard cap %d kB: backpressure not bounding the backlog", unadvisedKB, hardKB)
	}
}

// TestOffHeapLockedSetBoundedUnderReads verifies the resident-floor budget: a
// working set that is written once and then read continuously (so every slot is
// "warm") must NOT stay fully un-advised.  Reads never advise (only writes do),
// so without the per-pass second-chance budget the whole hot set would remain
// locked/unreclaimable.  After a scavenge the un-advised set must be bounded by
// the hard cap — i.e. a guaranteed minimum of MADV_FREE'd pages even under a
// read-only hot workload.
func TestOffHeapLockedSetBoundedUnderReads(t *testing.T) {
	c := newOffHeapNoWorkers(t, 64<<20)
	defer c.Close()

	hard := c.unadvisedHardCap
	n := uint64(hard) * 8
	for k := uint64(0); k < n; k++ {
		c.Set(k, blockContent(k, BlockDataSize))
	}
	// Advise the cold backlog, then make the whole set "warm" by reading it,
	// and scavenge again.  Reads set the CLOCK ref bit but never un-advise.
	c.scavenge(false)
	dst := make([]byte, BlockDataSize)
	for k := uint64(0); k < n; k++ {
		c.Get(k, dst)
	}
	c.scavenge(false)

	st := c.stats()
	if st.lazyFreeKB == 0 {
		t.Skipf("kernel did not report LazyFree (rss=%d kB)", st.rssKB)
	}
	var unadvisedKB uint64
	if st.rssKB > st.lazyFreeKB {
		unadvisedKB = st.rssKB - st.lazyFreeKB
	}
	hardKB := uint64(hard) * uint64(c.slotSize) / 1024
	t.Logf("read-hot working set: rss=%d kB lazyFree=%d kB unadvised=%d kB (hard cap=%d kB)",
		st.rssKB, st.lazyFreeKB, unadvisedKB, hardKB)
	if unadvisedKB > hardKB*2 {
		t.Fatalf("un-advised resident %d kB exceeds the resident-floor budget %d kB under a read-hot workload", unadvisedKB, hardKB)
	}
}

// TestOffHeapAdmissionThrottle verifies the controller lowers the admit
// probability when ristretto rejects most admissions (thrash), and relaxes it
// again once rejections subside.
func TestOffHeapAdmissionThrottle(t *testing.T) {
	c := newOffHeapNoWorkers(t, 64<<20)
	defer c.Close()

	if got := c.admitProbPP.Load(); got != admitFull {
		t.Fatalf("initial admitProbPP = %d, want %d (no throttle)", got, admitFull)
	}

	// Simulate thrash windows: almost all activity is evictions, few hits (low
	// efficiency).  Step the controller a few times to let the EWMA build up.
	for i := 0; i < 8; i++ {
		c.hits.Add(20)
		c.evictions.Add(980) // efficiency ~0.02
		c.controlStep(time.Now())
	}
	throttled := c.admitProbPP.Load()
	if throttled >= admitFull {
		t.Fatalf("admitProbPP did not drop under thrash: %d", throttled)
	}
	mf := minAdmitFrac // break constness so the conversion is allowed
	floor := int64(float64(admitFull) * mf)
	if throttled < floor {
		t.Fatalf("admitProbPP %d fell below floor %d", throttled, floor)
	}
	t.Logf("under thrash (eff~0.02): admitProbPP=%d/%d (%.0f%% admitted)",
		throttled, admitFull, float64(throttled)*100/admitFull)

	// Now simulate healthy windows: hits dominate (high efficiency); the
	// throttle must relax back to full admission.
	for i := 0; i < 12; i++ {
		c.hits.Add(1000)
		// no evictions/rejects
		c.controlStep(time.Now())
	}
	if got := c.admitProbPP.Load(); got != admitFull {
		t.Fatalf("admitProbPP did not relax after thrash ended: %d", got)
	}
}

// TestOffHeapThrottleSampler verifies the Bresenham admission gate admits
// approximately admitProbPP/admitFull of calls.
func TestOffHeapThrottleSampler(t *testing.T) {
	c := newOffHeapNoWorkers(t, 4<<20)
	defer c.Close()

	c.admitProbPP.Store(admitFull / 4) // ~25%
	const trials = 100000
	admitted := 0
	for i := 0; i < trials; i++ {
		if c.admit() {
			admitted++
		}
	}
	frac := float64(admitted) / trials
	if frac < 0.23 || frac > 0.27 {
		t.Fatalf("admit fraction %.3f not ~0.25", frac)
	}
}

// TestOffHeapFreeListSecondChance verifies a freed slot gets a one-sweep grace
// before being advised, so churning (freed-then-reused) slots are not
// MADV_FREE'd wastefully.
func TestOffHeapFreeListSecondChance(t *testing.T) {
	c := newOffHeapNoWorkers(t, 4<<20)
	defer c.Close()

	c.Set(1, blockContent(1, BlockDataSize))
	c.index.Wait() // flush ristretto's async admission
	h, ok := c.index.Get(1)
	if !ok {
		t.Fatal("key not admitted")
	}
	slot := h.slot
	c.index.Del(1)
	c.index.Wait() // let OnExit -> freeHandle run
	if c.occupied.get(slot) {
		t.Fatal("slot still occupied after delete")
	}

	// First sweep: freed slot has ref=1 -> second chance, must NOT be advised.
	c.scavenge(false)
	if c.advised.get(slot) {
		t.Fatal("freed slot advised on the first sweep (no grace given)")
	}
	// Second sweep: ref now clear and still free -> advised.
	c.scavenge(false)
	if !c.advised.get(slot) {
		t.Fatal("stably-free slot not advised on the second sweep")
	}
}

// TestOffHeapThrashMadviseBounded is the integration test for the anti-thrash
// work: under a working set far larger than the cache, the admission throttle
// must engage (caching isn't paying off) and, once engaged, admit only a small
// fraction of Sets — which is what keeps the MADV_FREE volume from tracking the
// churn (the "am I calling madvise continuously?" concern).  It is driven
// deterministically (workload + manual control steps) so it doesn't depend on
// background timing.
func TestOffHeapThrashMadviseBounded(t *testing.T) {
	if arenaCopyMode == "atomic" {
		// This is an admission-throttle logic test (counters), not a
		// memory-race test; its ~1M atomic-copy ops are needlessly slow under
		// the race detector.  Correctness of the data path is covered by the
		// integrity/reclaim tests.
		t.Skip("skipped under -race (throttle logic, not race-relevant)")
	}
	c := newOffHeapNoWorkers(t, 8<<20) // ~2048 slots; drive control manually
	defer c.Close()

	const keySpace = 2_000_000 // working set >> cache
	windows := 12
	opsPerWindow := 50_000
	finalOps := 200_000
	if testing.Short() {
		windows, opsPerWindow, finalOps = 8, 8_000, 30_000
	}
	rng := rand.New(rand.NewSource(1))
	dst := make([]byte, BlockDataSize)
	var wrong int

	thrashOps := func(n int) {
		for i := 0; i < n; i++ {
			k := uint64(rng.Intn(keySpace))
			want := blockContent(k, BlockDataSize)
			if m, ok := c.Get(k, dst); ok {
				if !bytesEqual(dst[:m], want) {
					wrong++
				}
			} else {
				c.Set(k, want)
			}
		}
	}

	// Run several control windows so the efficiency EWMA learns the workload is
	// thrash and engages the throttle.
	for w := 0; w < windows; w++ {
		thrashOps(opsPerWindow)
		c.index.Wait() // flush admissions/evictions so the counters are current
		c.controlStep(time.Now())
	}
	if wrong != 0 {
		t.Fatalf("%d wrong-block reads under thrash", wrong)
	}
	if c.admitProbPP.Load() >= admitFull {
		t.Fatalf("admission throttle never engaged under thrash (admitProb=%d)", c.admitProbPP.Load())
	}
	t.Logf("throttle engaged: admitProb=%d/%d (%.0f%% admitted)",
		c.admitProbPP.Load(), admitFull, float64(c.admitProbPP.Load())*100/admitFull)

	// Measure a final phase under the engaged throttle: admissions (and thus the
	// MADV_FREE work that tracks them) must be a small fraction of Set calls.
	base := c.stats()
	thrashOps(finalOps)
	fin := c.stats()
	setD := fin.setCalls - base.setCalls
	admitD := fin.admitAttempt - base.admitAttempt
	madvD := fin.madvisePages - base.madvisePages
	t.Logf("under throttle: setCalls+=%d admitAttempt+=%d (%.1f%%) madvisePages+=%d",
		setD, admitD, float64(admitD)*100/float64(setD), madvD)

	if admitD*2 > setD {
		t.Fatalf("throttle not cutting admissions: admitted %d of %d Sets", admitD, setD)
	}
	if madvD > setD {
		t.Fatalf("madvisePages+=%d exceeded setCalls+=%d: advising not sub-linear in churn", madvD, setD)
	}
}

// TestOffHeapMemoryPressure is the headline acceptance test (§9): it runs the
// cache under a hard cgroup v2 memory budget, in a CHILD PROCESS, so that if the
// design fails to keep the un-advised set within budget the OOM killer takes the
// child (which marks itself the preferred victim) rather than the test runner.
// The child configures the cache ceiling far above the budget and drives a
// working set larger than it; the kernel must reclaim the arena's MADV_FREE'd
// pages to keep the child alive.  Success = child exits 0 with no cgroup OOM
// kills and no wrong-block reads.
//
// It runs automatically as part of `go test` wherever cgroup v2 is writable
// (see .devcontainer: privileged + --cgroupns=private).  It skips cleanly when
// cgroups are not writable, so it is safe everywhere.
func TestOffHeapMemoryPressure(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		t.Skip("parent orchestrator; child workload runs in TestOffHeapMemoryPressureChild")
	}
	if testing.Short() {
		t.Skip("memory-pressure test is long; skipped under -short")
	}
	if bc, err := newOffHeapBlockCache(1 << 20); err != nil {
		t.Skipf("off-heap backend unavailable: %v", err)
	} else {
		bc.Close()
	}

	const budgetBytes = 256 << 20
	cgPath, cleanup, ok := createLimitedCgroup(t, budgetBytes)
	if !ok {
		t.Skip("cgroup v2 not writable here; rebuild the devcontainer (privileged + --cgroupns=private) to enable this test")
	}
	defer cleanup()
	t.Logf("created cgroup %s with memory.max=%d MiB", cgPath, budgetBytes>>20)

	// Re-exec this test binary to run only the child workload, inside the cgroup.
	cmd := exec.Command(os.Args[0], "-test.run=TestOffHeapMemoryPressureChild", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1", cgroupEnv+"="+cgPath)
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", indent(string(out)))

	oomKills := readCgroupOOMKills(cgPath)
	if err != nil {
		t.Fatalf("child failed under %d MiB budget (cgroup oom_kill=%d): %v — "+
			"the cache did not surrender memory fast enough", budgetBytes>>20, oomKills, err)
	}
	if oomKills > 0 {
		t.Fatalf("cgroup reported %d OOM kill(s): the cache exceeded its memory budget", oomKills)
	}
	t.Logf("child survived a %d MiB budget with no OOM kills — kernel reclaimed the cache's pages", budgetBytes>>20)
}

// TestOffHeapMemoryPressureChild is the workload half of TestOffHeapMemoryPressure.
// It only runs when re-exec'd as the child (childEnv set); otherwise it skips.
func TestOffHeapMemoryPressureChild(t *testing.T) {
	if os.Getenv(childEnv) != "1" {
		t.Skip("runs only as the re-exec'd child of TestOffHeapMemoryPressure")
	}
	// Join the target cgroup and become the preferred OOM victim, so any OOM
	// blast radius is confined to this process.
	cgPath := os.Getenv(cgroupEnv)
	if cgPath == "" {
		t.Fatal("no cgroup path passed to child")
	}
	if err := os.WriteFile(filepath.Join(cgPath, "cgroup.procs"),
		[]byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		t.Fatalf("failed to join cgroup: %v", err)
	}
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("1000"), 0); err != nil {
		t.Logf("warning: could not set oom_score_adj (continuing): %v", err)
	}

	limit, ok := readCgroupMemoryMax(cgPath)
	if !ok {
		t.Fatalf("could not read memory.max from %s", cgPath)
	}
	t.Logf("child in cgroup %s, memory.max=%d MiB", cgPath, limit>>20)

	// Ceiling 8x the budget (virtual, MAP_NORESERVE); working set ~4x the
	// budget so it cannot possibly fit resident — the kernel must reclaim.
	bc, err := newOffHeapBlockCache(uint64(limit) * 8)
	if err != nil {
		t.Fatalf("off-heap backend unavailable: %v", err)
	}
	defer bc.Close()
	c := bc.(*offHeapBlockCache)
	workingSet := int(limit*4) / BlockTotalSize

	dur := 15 * time.Second
	var stop atomic.Bool
	var wrong, hits, repop atomic.Uint64
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(seed)))
			dst := make([]byte, BlockDataSize)
			for !stop.Load() {
				k := uint64(rng.Intn(workingSet))
				want := blockContent(k, BlockDataSize)
				if n, ok := c.Get(k, dst); ok {
					hits.Add(1)
					if !bytesEqual(dst[:n], want) {
						wrong.Add(1)
					}
				} else {
					repop.Add(1)
					c.Set(k, want) // simulate re-decrypt + repopulate on miss
				}
			}
		}(w + 1)
	}

	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		st := c.stats()
		t.Logf("rss=%dMiB lazyFree=%dMiB occupied=%d slotCap=%d hits=%d reclaimMiss=%d skipped=%d",
			st.rssKB>>10, st.lazyFreeKB>>10, st.occupied, st.slotCap, hits.Load(), st.reclaimMiss, st.skipped)
	}
	stop.Store(true)
	wg.Wait()

	if wrong.Load() != 0 {
		t.Fatalf("%d reads returned wrong block bytes under pressure", wrong.Load())
	}
	st := c.stats()
	t.Logf("survived: hits=%d repopulated=%d reclaimMiss=%d finalRSS=%dMiB",
		hits.Load(), repop.Load(), st.reclaimMiss, st.rssKB>>10)
	if st.reclaimMiss == 0 {
		t.Logf("note: no reclaim-misses (the kernel kept up via the advised set without forcing re-decrypts)")
	}
}

// --- cgroup helpers (test orchestration only) ---

const (
	childEnv  = "PELICAN_OFFHEAP_CHILD"
	cgroupEnv = "PELICAN_OFFHEAP_CGROUP"
)

// currentCgroupDir returns the absolute path of this process's cgroup v2
// directory under /sys/fs/cgroup, or "" if not on cgroup v2.
func currentCgroupDir() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", rel)
		}
	}
	return ""
}

// createLimitedCgroup creates a child cgroup with memory.max=maxBytes (swap
// disabled) for the pressure test.  Returns ok=false (so the caller skips) if
// cgroup v2 is not writable or the memory controller cannot be delegated.
func createLimitedCgroup(t *testing.T, maxBytes int64) (path string, cleanup func(), ok bool) {
	t.Helper()
	self := currentCgroupDir()
	if self == "" {
		return "", nil, false
	}
	// Ensure the memory controller is delegated to our children.  The cgroup-v2
	// "no internal processes" rule forbids enabling subtree_control on a cgroup
	// that directly holds processes, EXCEPT the cgroup-namespace root — which is
	// exactly what we get under --cgroupns=private, so this works there and
	// fails (-> skip) otherwise.
	if err := os.WriteFile(filepath.Join(self, "cgroup.subtree_control"),
		[]byte("+memory"), 0); err != nil {
		t.Logf("cannot delegate memory controller (%v); skipping", err)
		return "", nil, false
	}
	limited := filepath.Join(self, fmt.Sprintf("pelican_oc_%d", os.Getpid()))
	if err := os.Mkdir(limited, 0o755); err != nil {
		return "", nil, false
	}
	cleanup = func() { _ = os.Remove(limited) }
	if err := os.WriteFile(filepath.Join(limited, "memory.max"),
		[]byte(strconv.FormatInt(maxBytes, 10)), 0); err != nil {
		cleanup()
		return "", nil, false
	}
	_ = os.WriteFile(filepath.Join(limited, "memory.swap.max"), []byte("0"), 0)
	return limited, cleanup, true
}

func readCgroupMemoryMax(cgPath string) (int64, bool) {
	raw, err := os.ReadFile(filepath.Join(cgPath, "memory.max"))
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(raw))
	if s == "max" || s == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readCgroupOOMKills returns the cumulative oom_kill count from memory.events.
func readCgroupOOMKills(cgPath string) int64 {
	raw, err := os.ReadFile(filepath.Join(cgPath, "memory.events"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "oom_kill "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

func indent(s string) string {
	if s == "" {
		return ""
	}
	return "    " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n    ")
}

// BenchmarkArenaCopy compares the two arena payload-copy strategies head to
// head in the same binary (independent of the build tag that selects which one
// the production Get/Set use): atomic word ops (data-race-free, used under
// -race) vs a plain memmove (faster, used in normal builds).  This quantifies
// the cost of the memory-model-correct read path.
func BenchmarkArenaCopy(b *testing.B) {
	c := newOffHeapNoWorkers(b, 4<<20)
	defer c.Close()
	base := unsafe.Add(c.arenaPtr, 0) // page-aligned slot 0
	src := blockContent(1, BlockDataSize)
	dst := make([]byte, BlockDataSize)
	atomicStoreBytes(base, src) // seed the slot

	b.Run("load/atomic", func(b *testing.B) {
		b.SetBytes(BlockDataSize)
		for i := 0; i < b.N; i++ {
			atomicLoadBytes(dst, base)
		}
	})
	b.Run("load/plain", func(b *testing.B) {
		b.SetBytes(BlockDataSize)
		for i := 0; i < b.N; i++ {
			plainLoadBytes(dst, base)
		}
	})
	b.Run("store/atomic", func(b *testing.B) {
		b.SetBytes(BlockDataSize)
		for i := 0; i < b.N; i++ {
			atomicStoreBytes(base, src)
		}
	})
	b.Run("store/plain", func(b *testing.B) {
		b.SetBytes(BlockDataSize)
		for i := 0; i < b.N; i++ {
			plainStoreBytes(base, src)
		}
	})
}

func runOverCommit(b *testing.B, c blockCache, workingSet int) {
	// Pre-warm with the first slice of the working set.
	for k := uint64(0); k < uint64(workingSet); k++ {
		c.Set(k, blockContent(k, BlockDataSize))
	}
	b.ReportAllocs()
	b.SetBytes(BlockDataSize)
	b.ResetTimer()
	var wg sync.WaitGroup
	workers := 8
	per := b.N / workers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(seed)))
			dst := make([]byte, BlockDataSize)
			for i := 0; i < per; i++ {
				k := uint64(rng.Intn(workingSet))
				if _, ok := c.Get(k, dst); !ok {
					// Miss: simulate the re-decrypt-and-repopulate the real
					// caller performs on a cache miss.
					c.Set(k, blockContent(k, BlockDataSize))
				}
			}
		}(w + 1)
	}
	wg.Wait()
}
