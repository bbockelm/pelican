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
	"bufio"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	ristretto "github.com/dgraph-io/ristretto/v2"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// offHeapBlockCache is a Linux-only plaintext block cache that keeps block
// bytes in an mmap'd, MADV_FREE'd arena so the kernel may reclaim them under
// memory pressure (like the page cache) rather than pinning RSS or driving
// OOM.  See reference/06-offheap-block-cache.md for the full design.
//
// Three layers each with one responsibility:
//
//   - ristretto holds the logical index (which keys exist + TinyLFU admission).
//     Its values are pointer-free slotHandles; it never holds block bytes.
//   - The kernel governs physical residency: MADV_FREE'd pages are dropped
//     under real pressure, page-granular, before the OOM killer.
//   - A scavenger marks cold slots reclaimable (MADV_FREE in batches) and an
//     adaptive controller right-sizes the logical capacity to available memory.
//
// A read is a true hit only if the index has the key AND the slot's page was
// not reclaimed.  Reclaim is detected by a per-slot generation tag used as a
// seqlock (§3.2): a reclaimed page reads back all-zero, so the gen written
// into each slot's 16-byte pad reads back as 0 once the kernel drops it.
type offHeapBlockCache struct {
	// index is the authoritative logical map key -> slotHandle.  ristretto
	// admission/eviction drives the logical capacity; OnExit returns slots.
	index *ristretto.Cache[uint64, slotHandle]

	// arena is the mmap'd slab: numSlots contiguous slotSize-byte slots.
	arena    []byte
	arenaPtr unsafe.Pointer // &arena[0], cached for pad pointer math
	arenaLen int

	slotSize     uintptr // one OS page per slot
	padGenOffset uintptr // slotSize-16: offset of the per-slot gen pad
	numSlots     uint32

	// slotGen is the authoritative per-slot generation (the seqlock
	// sequence).  Off-arena so it survives reclaim.  0 means free/invalid;
	// live slots hold the gen of their current occupant.
	slotGen []atomic.Uint32

	// ref is the CLOCK access marker, set on read, cleared by the scavenger
	// hand.  Off-arena so setting it never cancels MADV_FREE.  uint32 per
	// slot (not a packed bit) so concurrent reader/scavenger access is
	// race-free under -race.
	ref []atomic.Uint32

	// occupied marks slots currently holding a live block; advised marks
	// slots currently MADV_FREE'd.  Both are scanned by the scavenger.
	occupied *atomicBitmap
	advised  *atomicBitmap

	genCounter atomic.Uint32

	// free is the LIFO free-slot stack, guarded by freeMu.  occCount mirrors
	// the number of occupied slots (also under freeMu) for the controller.
	freeMu   sync.Mutex
	free     []uint32
	occCount int64

	// slotCap is the controller's effective slot ceiling (the operating
	// point); maxSlotCap is the configured ceiling (c_max), minSlotCap a
	// floor.  growStep is the additive grow increment.
	slotCap    atomic.Int64
	maxSlotCap int64
	minSlotCap int64
	growStep   int64

	// Controller state, owned solely by the control goroutine (and tests).
	ctrlPrevReclaim   uint64
	ctrlPrevHits      uint64
	ctrlPrevEvicts    uint64
	ctrlPrevRejects   uint64
	ctrlEffEWMA       float64 // smoothed cache efficiency = hits/(hits+churn)
	ctrlCooldownUntil time.Time

	// Counters (all internal, free, perfectly attributed).
	hits         atomic.Uint64
	misses       atomic.Uint64
	reclaimMiss  atomic.Uint64 // kernel took a page we wanted: the harm signal
	skipped      atomic.Uint64 // Set dropped because no free slot
	setCalls     atomic.Uint64 // total Set calls
	admitAttempt atomic.Uint64 // Sets that passed the throttle and allocated
	rejects      atomic.Uint64 // ristretto OnReject count (admission declined)
	evictions    atomic.Uint64 // ristretto OnEvict count (admitted then churned out)
	throttled    atomic.Uint64 // Sets skipped by the admission throttle
	madviseCalls atomic.Uint64 // MADV_FREE syscalls issued
	madvisePages atomic.Uint64 // slots advised (pages MADV_FREE'd)

	// Admission throttle state.  admitProbPP is the probability (in parts of
	// admitFull) that a Set is admitted; admitAcc is the Bresenham accumulator
	// that turns it into a cheap, RNG-free per-call decision.
	admitProbPP atomic.Int64
	admitAcc    atomic.Uint64

	// Scavenger state.  scavMu serializes scavenge passes so a writer can run
	// an inline emergency advise concurrently with the background loop without
	// racing the CLOCK hand.  clockHand is owned under scavMu.
	scavMu    sync.Mutex
	clockHand uint32

	// allocsSinceScav counts slot allocations since the last scavenge pass
	// reset it; it is the OOM-exposure proxy (newly-written, not-yet-advised
	// pages).  When it crosses the soft/hard caps, the writer triggers an
	// aggressive scavenge — and at the hard cap performs an inline advise — so
	// the un-advised (unreclaimable) resident set is always bounded and the
	// kernel always has MADV_FREE'd pages to reclaim (§6.1).
	allocsSinceScav  atomic.Int64
	unadvisedHardCap int64 // force an (inline) aggressive advise at this many
	unadvisedSoftCap int64 // signal a background aggressive advise at this many
	emergencyScanCap uint32

	// scavCh requests an out-of-band scavenge; true payload = aggressive.
	scavCh    chan bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// slotHandle is the ristretto value: the authoritative, pointer-free handle
// to a block's bytes.  16-byte struct (4+4+2 padded), never reclaimed.
type slotHandle struct {
	slot   uint32
	gen    uint32
	length uint16
}

// padReserve is the per-slot tail reserved for the generation tag.
const padReserve = 16

// Controller / scavenger tuning.
const (
	scavengeInterval = 2 * time.Second // CLOCK sweep cadence (the decay window)
	controlInterval  = 3 * time.Second // adaptive sizing sample cadence
	growCooldown     = 6 * time.Second // min quiet time after a shrink before growing

	// reclaimMissShrinkThreshold: per-interval reclaim-misses above this are
	// taken as real harm (kernel taking pages we want) -> shrink.
	reclaimMissShrinkThreshold = 64

	// lowMemFraction: shrink when available memory drops below this fraction
	// of total (proactive bound).
	lowMemFraction = 0.10

	// lazyLowPct: when arena RSS is pegged but LazyFree is below this percent
	// of RSS, there are few reclaim candidates -> shrink + aggressive advise.
	lazyLowPct = 5

	shrinkNum = 9 // multiplicative shrink factor 0.9 (asymmetric AI/MD)
	shrinkDen = 10

	// maxUnadvisedBytes is the absolute ceiling on the un-advised
	// (unreclaimable) resident backlog, regardless of cache size, so a large
	// cache still keeps a small OOM-exposure window (§6.1).
	maxUnadvisedBytes = 64 << 20

	// pressureInterval is the fast watcher cadence: it reacts to external
	// memory pressure (PSI / low available memory) far quicker than the AI/MD
	// sizing controller, triggering aggressive advising so the kernel always
	// has reclaim candidates.
	pressureInterval = 250 * time.Millisecond

	// psiSomeAvg10Trigger: a >this %% "some" memory-stall over the last 10s is
	// treated as real pressure -> aggressive advise.
	psiSomeAvg10Trigger = 1.0

	// Admission throttle (anti-thrash).  The signal is cache *efficiency*:
	//   eff = hits / (hits + evictions + rejects)
	// i.e. how often a cached item is re-hit before it is churned out.  It is
	// high during warmup (few evictions) and when the working set fits (hits
	// dominate), and low under thrash (items are evicted/rejected before being
	// hit).  Crucially it is measured among *admitted* items, so it is not
	// corrupted by the throttle itself and can recover when the working set
	// shrinks.  Low efficiency -> admit less, so the cache stops churning (and
	// stops generating wasted MADV_FREE traffic).
	admitFull          = 1024 // admit probability is stored in parts of this
	admitEffLowWater   = 0.05 // efficiency at/below which throttle is maximal
	admitEffHighWater  = 0.30 // efficiency at/above which there is no throttle
	minAdmitFrac       = 0.05 // admit-probability floor (keep sampling to recover)
	reclaimThrottleCap = 0.25 // ceiling on admit prob when reclaim-miss is high
	// Asymmetric smoothing: react fast when efficiency drops (engage quickly to
	// stop churn), recover slowly when it rises (avoid oscillation) — the
	// throttle analogue of fast-shrink/slow-grow.
	effEWMAAlphaDown   = 0.50
	effEWMAAlphaUp     = 0.20
	throttleMinSamples = 100 // min hits+churn/window before trusting the ratio
)

// newOffHeapBlockCache builds the off-heap cache with a byte ceiling of
// sizeBytes (c_max).  Returns errOffHeapUnsupported (so the caller falls back
// to ristretto) if MADV_FREE is unavailable or the arena cannot be mapped.
func newOffHeapBlockCache(sizeBytes uint64) (blockCache, error) {
	c, err := newOffHeapBlockCacheRaw(sizeBytes)
	if err != nil {
		return nil, err
	}
	c.startWorkers()
	return c, nil
}

// newOffHeapBlockCacheRaw builds the cache without starting the background
// scavenger/controller goroutines (tests drive those deterministically).
func newOffHeapBlockCacheRaw(sizeBytes uint64) (*offHeapBlockCache, error) {
	if sizeBytes == 0 {
		return nil, nil
	}
	pageSize := uintptr(unix.Getpagesize())
	if pageSize < 4096 {
		// One block per page requires a page at least as large as a block.
		return nil, errors.Errorf("unexpected page size %d", pageSize)
	}
	slotSize := pageSize
	if uintptr(BlockDataSize)+padReserve > slotSize {
		return nil, errors.Errorf("block size %d + pad does not fit in page %d", BlockDataSize, slotSize)
	}

	// Logical capacity (blocks) from the byte ceiling, plus headroom so the
	// free list never runs dry while ristretto's async eviction lags admission.
	ceilingSlots := int64(sizeBytes) / BlockDataSize
	if ceilingSlots < 1 {
		ceilingSlots = 1
	}
	headroom := ceilingSlots / 64
	if headroom < 64 {
		headroom = 64
	}
	numSlots64 := ceilingSlots + headroom
	if numSlots64 > int64(^uint32(0)) {
		return nil, errors.Errorf("configured cache size too large: %d slots", numSlots64)
	}
	numSlots := uint32(numSlots64)

	arenaLen := int(uintptr(numSlots) * slotSize)
	arena, err := unix.Mmap(-1, 0, arenaLen,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE|unix.MAP_NORESERVE)
	if err != nil {
		return nil, errors.Wrap(err, "failed to mmap off-heap block cache arena")
	}

	// A 2 MB transparent huge page cannot be partially MADV_FREE'd, so disable
	// THP for the arena; partial-page reclaim is the whole point.
	if err := unix.Madvise(arena, unix.MADV_NOHUGEPAGE); err != nil {
		// Non-fatal: THP may be off system-wide.  Log and continue.
		log.Debugf("MADV_NOHUGEPAGE on off-heap arena failed (continuing): %v", err)
	}

	// Confirm MADV_FREE is actually supported on this kernel; if not, unmap
	// and report unsupported so we fall back to ristretto.
	if err := unix.Madvise(arena, unix.MADV_FREE); err != nil {
		_ = unix.Munmap(arena)
		return nil, errors.Wrap(errOffHeapUnsupported, err.Error())
	}

	numCounters := ceilingSlots * 10
	if numCounters < 1000 {
		numCounters = 1000
	}

	c := &offHeapBlockCache{
		arena:        arena,
		arenaPtr:     unsafe.Pointer(&arena[0]),
		arenaLen:     arenaLen,
		slotSize:     slotSize,
		padGenOffset: slotSize - padReserve,
		numSlots:     numSlots,
		slotGen:      make([]atomic.Uint32, numSlots),
		ref:          make([]atomic.Uint32, numSlots),
		occupied:     newAtomicBitmap(numSlots),
		advised:      newAtomicBitmap(numSlots),
		free:         make([]uint32, numSlots),
		maxSlotCap:   ceilingSlots,
		minSlotCap:   maxInt64(ceilingSlots/64, 64),
		growStep:     maxInt64(ceilingSlots/64, 1),
		scavCh:       make(chan bool, 1),
		stopCh:       make(chan struct{}),
	}
	// Bound the un-advised (unreclaimable) resident backlog: at most ~1/8 of the
	// ceiling, and never more than maxUnadvisedBytes in absolute terms (so huge
	// caches keep a small OOM-exposure window).  This is the volume cap of §6.1.
	c.unadvisedHardCap = maxInt64(minInt64(ceilingSlots/8, int64(maxUnadvisedBytes)/int64(slotSize)), 256)
	c.unadvisedSoftCap = maxInt64(c.unadvisedHardCap/2, 1)
	// An inline emergency advise scans enough slots to clear the backlog several
	// times over, capped so it stays cheap even on a multi-million-slot arena.
	c.emergencyScanCap = uint32(minInt64(int64(numSlots), maxInt64(c.unadvisedHardCap*8, 65536)))
	// Initialize the free stack with every slot (reverse order so slot 0 is
	// handed out first, keeping early hot blocks contiguous).
	for i := uint32(0); i < numSlots; i++ {
		c.free[i] = numSlots - 1 - i
	}
	c.slotCap.Store(ceilingSlots)
	c.admitProbPP.Store(admitFull) // admit everything until thrash is observed
	c.ctrlEffEWMA = 1.0            // start healthy so warmup is never throttled

	index, err := ristretto.NewCache(&ristretto.Config[uint64, slotHandle]{
		NumCounters:        numCounters,
		MaxCost:            ceilingSlots, // cost 1 per entry == one slot
		BufferItems:        64,
		IgnoreInternalCost: true,
		OnExit:             c.onIndexExit,
		OnReject:           c.onIndexReject,
		OnEvict:            c.onIndexEvict,
	})
	if err != nil {
		_ = unix.Munmap(arena)
		return nil, errors.Wrap(err, "failed to create off-heap index")
	}
	c.index = index
	log.Debugf("off-heap block cache: %d slots x %d B (%d MiB virtual ceiling), arena copy mode %q",
		numSlots, slotSize, arenaLen>>20, arenaCopyMode)
	return c, nil
}

// startWorkers launches the background scavenger and controller goroutines.
// Split out so tests can construct a cache and drive scavenge/controlStep
// deterministically without the loops racing them.
func (c *offHeapBlockCache) startWorkers() {
	c.wg.Add(3)
	go c.scavengeLoop()
	go c.controlLoop()
	go c.pressureWatchLoop()
}

// pressureWatchLoop is the fast (sub-second) emergency brake.  It reacts to
// external memory pressure — PSI memory-stall and low available memory — far
// quicker than the AI/MD sizing controller, triggering an aggressive advise so
// the kernel always has reclaim candidates before it would otherwise OOM.
// Pairs with the writer-side volume cap (noteAllocForScavenge): the volume cap
// bounds internally-generated backlog, this loop bounds externally-driven
// pressure.
func (c *offHeapBlockCache) pressureWatchLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(pressureInterval)
	defer ticker.Stop()
	psi := openPSISource()
	if psi != nil {
		defer psi.Close()
	}
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			pressured := availableMemoryFraction() < lowMemFraction
			if !pressured && psi != nil {
				if avg10, ok := psi.someAvg10(); ok && avg10 >= psiSomeAvg10Trigger {
					pressured = true
				}
			}
			if pressured {
				c.requestScavenge(true)
			}
		}
	}
}

func (c *offHeapBlockCache) directIO() bool { return true }

// offHeapStats is a snapshot of cache counters and memory accounting, used by
// tests/benchmarks to observe behavior.
type offHeapStats struct {
	hits         uint64
	misses       uint64
	reclaimMiss  uint64
	skipped      uint64
	setCalls     uint64
	admitAttempt uint64
	rejects      uint64
	evictions    uint64
	throttled    uint64
	madviseCalls uint64
	madvisePages uint64
	admitProbPP  int64
	occupied     int64
	slotCap      int64
	numSlots     uint32
	rssKB        uint64 // arena resident set (smaps)
	lazyFreeKB   uint64 // arena MADV_FREE'd-but-not-yet-reclaimed (reclaimable)
}

func (c *offHeapBlockCache) stats() offHeapStats {
	c.freeMu.Lock()
	occ := c.occCount
	c.freeMu.Unlock()
	rss, lazy, _ := readArenaVMA(uintptr(c.arenaPtr))
	return offHeapStats{
		hits:         c.hits.Load(),
		misses:       c.misses.Load(),
		reclaimMiss:  c.reclaimMiss.Load(),
		skipped:      c.skipped.Load(),
		setCalls:     c.setCalls.Load(),
		admitAttempt: c.admitAttempt.Load(),
		rejects:      c.rejects.Load(),
		evictions:    c.evictions.Load(),
		throttled:    c.throttled.Load(),
		madviseCalls: c.madviseCalls.Load(),
		madvisePages: c.madvisePages.Load(),
		admitProbPP:  c.admitProbPP.Load(),
		occupied:     occ,
		slotCap:      c.slotCap.Load(),
		numSlots:     c.numSlots,
		rssKB:        rss,
		lazyFreeKB:   lazy,
	}
}

// openDirectRead opens path for reading with O_DIRECT so reads bypass the
// kernel page cache (avoiding double-caching ciphertext when the off-heap
// plaintext cache is active).  Returns direct=false (and a buffered handle) if
// the filesystem rejects O_DIRECT — e.g. tmpfs/overlayfs — so callers can
// still proceed with ordinary aligned reads.
func openDirectRead(path string) (f *os.File, direct bool, err error) {
	f, err = os.OpenFile(path, os.O_RDONLY|unix.O_DIRECT, 0)
	if err == nil {
		return f, true, nil
	}
	// Fall back to buffered: O_DIRECT is unsupported on this filesystem.
	f, err = os.OpenFile(path, os.O_RDONLY, 0)
	return f, false, err
}

// padPtr returns an aligned *uint32 into slot s's generation pad.
func (c *offHeapBlockCache) padPtr(s uint32) *uint32 {
	return (*uint32)(unsafe.Add(c.arenaPtr, uintptr(s)*c.slotSize+c.padGenOffset))
}

// admit returns whether this Set should be cached, per the admission throttle.
// The common case (no throttle, admitProbPP == admitFull) is a single atomic
// load.  Otherwise a Bresenham accumulator turns the probability into a cheap,
// RNG-free decision that admits ~admitProbPP/admitFull of calls.
func (c *offHeapBlockCache) admit() bool {
	p := c.admitProbPP.Load()
	if p >= admitFull {
		return true
	}
	acc := c.admitAcc.Add(uint64(p))
	return acc%admitFull < uint64(p)
}

// onIndexReject counts ristretto admission rejections, and onIndexEvict counts
// evictions of admitted items.  Together (hits vs evictions+rejects) they form
// the cache-efficiency signal that drives the admission throttle.  Each value's
// slot is returned to the free list via OnExit, so nothing else is needed here.
func (c *offHeapBlockCache) onIndexReject(*ristretto.Item[slotHandle]) {
	c.rejects.Add(1)
}

func (c *offHeapBlockCache) onIndexEvict(*ristretto.Item[slotHandle]) {
	c.evictions.Add(1)
}

// nextGen returns a fresh, never-zero generation.
func (c *offHeapBlockCache) nextGen() uint32 {
	for {
		if g := c.genCounter.Add(1); g != 0 {
			return g
		}
	}
}

// Get copies the cached block for key into dst.  See §3.2: a hit requires the
// index to hold the key AND the slot's page to have survived reclaim, verified
// with a generation seqlock around the copy.  Any mismatch degrades to a miss
// (the caller re-decrypts), which is always correct.
func (c *offHeapBlockCache) Get(key uint64, dst []byte) (int, bool) {
	h, ok := c.index.Get(key)
	if !ok {
		c.misses.Add(1)
		return 0, false
	}
	s, g := h.slot, h.gen
	if c.slotGen[s].Load() != g {
		// Slot recycled to a different occupant (ABA), or freed.
		c.misses.Add(1)
		return 0, false
	}
	pad := c.padPtr(s)
	if atomic.LoadUint32(pad) != g {
		// Page reclaimed (pad zeroed) or mid-rewrite: the kernel took a page
		// we wanted.  This is the harm signal that drives the controller.
		c.reclaimMiss.Add(1)
		return 0, false
	}
	length := int(h.length)
	if length > len(dst) {
		length = len(dst)
	}
	base := unsafe.Add(c.arenaPtr, uintptr(s)*c.slotSize)
	// Copy the payload out.  Correctness against reuse/reclaim rests on the
	// post-copy seqlock recheck below; arenaLoad selects how the bytes are
	// read: atomic words under -race (data-race-free, the default for tests/CI)
	// or a plain memmove otherwise (faster; a benign seqlock race the recheck
	// still covers).  See arenaLoad's build-tagged definitions.
	arenaLoad(dst[:length], base)
	// Re-read the seqlock: if the page was reclaimed or the slot rewritten
	// during the copy, the bytes may be torn -> miss.
	if atomic.LoadUint32(pad) != g || c.slotGen[s].Load() != g {
		c.reclaimMiss.Add(1)
		return 0, false
	}
	n := length
	c.ref[s].Store(1)
	c.hits.Add(1)
	return n, true
}

// Set stores a copy of val under key (§3.3).  It allocates a slot, writes the
// payload and the generation pad (the pad write cancels any pending MADV_FREE),
// then records the handle in the index.
func (c *offHeapBlockCache) Set(key uint64, val []byte) {
	n := len(val)
	if n == 0 || n > BlockDataSize {
		return
	}
	c.setCalls.Add(1)
	// Admission throttle: under thrash (high reject/reclaim-miss rate) caching
	// is not paying off, so admit only a fraction — fewer allocs means fewer
	// evictions and far less wasted MADV_FREE traffic.  Inert (admit all) until
	// the controller observes thrash.
	if !c.admit() {
		c.throttled.Add(1)
		return
	}
	c.admitAttempt.Add(1)
	s, g, ok := c.allocSlot()
	if !ok {
		return // no free slot right now; skip caching (self-heals)
	}
	base := unsafe.Add(c.arenaPtr, uintptr(s)*c.slotSize)
	// Store the payload.  arenaStore mirrors arenaLoad's strategy (atomic words
	// under -race, plain memmove otherwise) so a stale reader's concurrent
	// load is data-race-free under -race; its seqlock recheck fails -> miss.
	arenaStore(base, val)
	// Publish the pad gen last (release): cancels MADV_FREE, marks resident,
	// and makes the slot readable.  slotGen was already set in allocSlot.
	atomic.StoreUint32(c.padPtr(s), g)
	c.advised.clear(s)

	h := slotHandle{slot: s, gen: g, length: uint16(n)}
	if !c.index.Set(key, h, 1) {
		// Dropped set (ristretto buffer full, not an update): ristretto will
		// not call OnExit for this handle, so reclaim the slot ourselves.
		c.freeHandle(h)
	}
}

// allocSlot reserves a free slot for a new block, honoring the controller's
// effective cap.  Returns ok=false if the cache is at capacity or the free
// list is momentarily empty.
func (c *offHeapBlockCache) allocSlot() (slot uint32, gen uint32, ok bool) {
	c.freeMu.Lock()
	// Gate only on physical slot availability.  The logical capacity (the
	// controller's effective ceiling) is enforced by the index's MaxCost:
	// admitting a new block makes ristretto evict an old one, whose OnExit
	// returns its slot here.  The arena's headroom over the logical ceiling
	// absorbs the lag between admission and that eviction, so we must NOT gate
	// on slotCap (doing so would let the arena fill and then starve admission,
	// freezing the working set).
	if len(c.free) == 0 {
		c.freeMu.Unlock()
		c.skipped.Add(1)
		return 0, 0, false
	}
	s := c.free[len(c.free)-1]
	c.free = c.free[:len(c.free)-1]
	c.occCount++
	c.occupied.set(s)
	c.freeMu.Unlock()

	g := c.nextGen()
	// Publish slotGen first (release): invalidates any in-flight reader still
	// holding the prior occupant's handle (their seqlock recheck fails).
	c.slotGen[s].Store(g)
	c.ref[s].Store(1)
	// Enforce the un-advised volume cap (writer backpressure) so the kernel
	// always retains MADV_FREE'd reclaim candidates.
	c.noteAllocForScavenge()
	return s, g, true
}

// freeHandle returns the slot backing h to the free list, but only if the slot
// still belongs to h's generation (so a stale OnExit for a slot already
// recycled is a no-op).  Plaintext is zeroed immediately (§3.7) before the
// page is left for the scavenger to MADV_FREE.
func (c *offHeapBlockCache) freeHandle(h slotHandle) {
	s := h.slot
	if c.slotGen[s].Load() != h.gen {
		return // already recycled by a newer occupant
	}
	// Invalidate readers BEFORE marking the slot free: a concurrent reader
	// holding h will fail its seqlock recheck once slotGen != h.gen.  We do
	// NOT memset the slot here: a plain write would race a delayed stale
	// reader's atomic copy.  Plaintext is overwritten when the slot is reused
	// (Set) and the page is MADV_FREE'd by the scavenger so the kernel zeroes
	// it on reclaim under pressure (same exposure as advised cold slots, §3.7).
	c.slotGen[s].Store(0)

	c.freeMu.Lock()
	if !c.occupied.get(s) {
		c.freeMu.Unlock()
		return
	}
	c.occupied.clear(s)
	c.occCount--
	c.free = append(c.free, s)
	c.freeMu.Unlock()

	// Mark the slot recently-touched (ref=1) so the scavenger gives it a
	// one-sweep grace before advising it: a slot freed and immediately reused
	// (the thrash/churn case) never incurs a wasted MADV_FREE + TLB shootdown.
	// Only a free slot that survives a full sweep (ref cleared, still free —
	// i.e. a genuinely stable free pool) gets advised.
	c.ref[s].Store(1)
	// The page is still dirty/resident; the scavenger will MADV_FREE it in a
	// coalesced batch once it is stably free.  Clearing advised lets that happen.
	c.advised.clear(s)
}

// onIndexExit is ristretto's OnExit: called once for every value removed from
// the index (evict, reject, update-of-old-value, del, close).  It returns the
// evicted block's slot to the free list.
func (c *offHeapBlockCache) onIndexExit(h slotHandle) {
	c.freeHandle(h)
}

func (c *offHeapBlockCache) Close() {
	c.closeOnce.Do(func() {
		close(c.stopCh)
		c.wg.Wait()
		// Closing the index fires OnExit for all remaining entries (freeHandle
		// touches the still-mapped arena), then we unmap.
		c.index.Close()
		if err := unix.Munmap(c.arena); err != nil {
			log.Warningf("failed to unmap off-heap block cache arena: %v", err)
		}
	})
}

// ---- Scavenger (§3.5): CLOCK over reclaimability ----

func (c *offHeapBlockCache) scavengeLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(scavengeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.scavenge(false)
		case aggressive := <-c.scavCh:
			c.scavenge(aggressive)
		}
	}
}

// scavenge runs one full CLOCK revolution over the arena.  It resets the
// allocation-since-scavenge backlog because a full pass has advised everything
// that qualifies.
func (c *offHeapBlockCache) scavenge(aggressive bool) {
	c.scavMu.Lock()
	c.scavengePass(c.numSlots, aggressive)
	c.allocsSinceScav.Store(0)
	c.scavMu.Unlock()
}

// scavengePass advances the CLOCK hand over up to maxScan slots, MADV_FREE'ing
// reclaimable slots in coalesced runs and returning how many slots it advised.
// Free slots and cold live slots are advised; warm live slots get a second
// chance, but only up to a bounded resident-floor budget (unadvisedHardCap) so
// the un-advised set stays bounded regardless of read pattern.  Aggressive
// passes (pressure / emergency) grant no second chances and advise everything
// (§4 resident-floor / §6.1 pressure short-circuit).  Caller must hold scavMu.
func (c *offHeapBlockCache) scavengePass(maxScan uint32, aggressive bool) int {
	advised := 0
	var runStart, runLen uint32
	flush := func() {
		if runLen == 0 {
			return
		}
		c.madviseRun(runStart, runLen)
		advised += int(runLen)
		runLen = 0
	}
	if maxScan > c.numSlots {
		maxScan = c.numSlots
	}
	// secondChanceBudget bounds how many warm (recently-accessed) occupied slots
	// this pass may leave un-advised — i.e. the resident floor.  Without it, a
	// slot that is written once and then read continuously would keep earning a
	// CLOCK second chance forever and stay un-advised (unreclaimable) — reads
	// never advise, only writes do — so the locked set could grow to the whole
	// hot working set.  Capping second chances guarantees the un-advised
	// (unreclaimable) set stays <= unadvisedHardCap after the pass, which is
	// equivalently a guaranteed MINIMUM of MADV_FREE'd / reclaimable pages.
	// Aggressive passes (pressure / emergency) grant none -> advise everything.
	secondChanceBudget := c.unadvisedHardCap
	if aggressive {
		secondChanceBudget = 0
	}
	var secondChances int64

	for scanned := uint32(0); scanned < maxScan; scanned++ {
		s := c.clockHand
		c.clockHand++
		if c.clockHand >= c.numSlots {
			c.clockHand = 0
		}

		advise := false
		switch {
		case !c.occupied.get(s):
			// Free slot.  Give a one-sweep grace (ref set on free) so a slot
			// that is freed and immediately reused under churn is never advised
			// (wasted MADV_FREE); advise only a stably-free slot.
			if c.advised.get(s) {
				// already reclaimable
			} else if c.ref[s].Load() != 0 {
				c.ref[s].Store(0)
			} else {
				advise = true
			}
		case c.advised.get(s):
			// Occupied but already advised: still reclaimable, and a read keeps
			// it resident-and-correct until the kernel actually drops it.  Leave
			// it; nothing to do.
		case c.ref[s].Load() != 0 && secondChances < secondChanceBudget:
			// Warm and within the resident-floor budget: grant a second chance.
			c.ref[s].Store(0)
			secondChances++
		default:
			// Cold, or warm beyond the budget: advise so the locked set stays
			// bounded and reclaim candidates always exist.
			advise = true
		}

		// Coalesce contiguous advise candidates into one madvise call.
		if advise {
			if runLen != 0 && s == runStart+runLen {
				runLen++
			} else {
				flush()
				runStart = s
				runLen = 1
			}
		} else {
			flush()
		}
	}
	flush()
	return advised
}

// emergencyAdvise is the writer-backpressure path: when the un-advised backlog
// crosses the hard cap, the allocating goroutine itself advises a bounded chunk
// (aggressively) so the un-advised resident set cannot grow without bound even
// if the background scavenger stalls.  It is best-effort under scavMu.TryLock —
// if another goroutine is already scavenging, the backlog is being handled.
func (c *offHeapBlockCache) emergencyAdvise() {
	if !c.scavMu.TryLock() {
		return
	}
	c.scavengePass(c.emergencyScanCap, true)
	c.allocsSinceScav.Store(0)
	c.scavMu.Unlock()
}

// noteAllocForScavenge accounts one slot allocation and enforces the un-advised
// volume cap: signal the background scavenger at the soft cap, and apply inline
// backpressure (advise now) at the hard cap.
func (c *offHeapBlockCache) noteAllocForScavenge() {
	n := c.allocsSinceScav.Add(1)
	switch {
	case n >= c.unadvisedHardCap:
		c.emergencyAdvise()
	case n == c.unadvisedSoftCap:
		c.requestScavenge(true)
	}
}

// madviseRun MADV_FREE's a contiguous run of slots and marks them advised.
func (c *offHeapBlockCache) madviseRun(start, length uint32) {
	off := uintptr(start) * c.slotSize
	n := uintptr(length) * c.slotSize
	if err := unix.Madvise(c.arena[off:off+n], unix.MADV_FREE); err != nil {
		log.Debugf("MADV_FREE on off-heap arena run [%d,+%d) failed: %v", start, length, err)
		return
	}
	c.madviseCalls.Add(1)
	c.madvisePages.Add(uint64(length))
	for i := uint32(0); i < length; i++ {
		c.advised.set(start + i)
	}
}

// requestScavenge asks the scavenger to run out of band (non-blocking).
func (c *offHeapBlockCache) requestScavenge(aggressive bool) {
	select {
	case c.scavCh <- aggressive:
	default:
	}
}

// ---- Adaptive sizing controller (§4): asymmetric AI/MD ----

func (c *offHeapBlockCache) controlLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(controlInterval)
	defer ticker.Stop()
	c.ctrlPrevReclaim = c.reclaimMiss.Load()
	for {
		select {
		case <-c.stopCh:
			return
		case now := <-ticker.C:
			c.controlStep(now)
		}
	}
}

// controlStep runs one iteration of the asymmetric-AI/MD sizing controller:
// multiplicative shrink on any harm signal, small additive grow only when all
// signals are healthy, capacity is below the ceiling, and the post-shrink
// cooldown has elapsed.
func (c *offHeapBlockCache) controlStep(now time.Time) {
	rm := c.reclaimMiss.Load()
	delta := rm - c.ctrlPrevReclaim
	c.ctrlPrevReclaim = rm

	rssKB, lazyKB, haveVMA := readArenaVMA(uintptr(c.arenaPtr))
	availFrac := availableMemoryFraction()

	// RSS pegged but few lazyfree candidates: the hot (unreclaimable) set is
	// too large; shrink and advise more aggressively (§4 resident-floor).
	lowCandidates := haveVMA && rssKB > 0 && lazyKB*100 < rssKB*lazyLowPct
	pressured := delta > reclaimMissShrinkThreshold ||
		availFrac < lowMemFraction ||
		lowCandidates

	cap := c.slotCap.Load()
	switch {
	case pressured:
		newCap := cap * shrinkNum / shrinkDen
		if newCap < c.minSlotCap {
			newCap = c.minSlotCap
		}
		if newCap != cap {
			c.slotCap.Store(newCap)
			c.index.UpdateMaxCost(newCap)
		}
		c.ctrlCooldownUntil = now.Add(growCooldown)
		// Make reclaim candidates available right now.
		c.requestScavenge(lowCandidates)
		log.Debugf("off-heap cache shrink: cap %d->%d (reclaimMissΔ=%d availFrac=%.2f rssKB=%d lazyKB=%d)",
			cap, newCap, delta, availFrac, rssKB, lazyKB)
	case cap < c.maxSlotCap && now.After(c.ctrlCooldownUntil):
		newCap := cap + c.growStep
		if newCap > c.maxSlotCap {
			newCap = c.maxSlotCap
		}
		c.slotCap.Store(newCap)
		c.index.UpdateMaxCost(newCap)
	}

	c.updateAdmissionThrottle(delta)
}

// updateAdmissionThrottle recomputes the admit probability from the smoothed
// cache efficiency hits/(hits+evictions+rejects) — high during warmup and when
// the working set fits, low under thrash — escalated when reclaim-miss indicates
// the kernel is actively taking pages (memory-pressure thrash).  reclaimDelta is
// this window's reclaim-miss count (already computed by controlStep).
func (c *offHeapBlockCache) updateAdmissionThrottle(reclaimDelta uint64) {
	hits := c.hits.Load()
	evicts := c.evictions.Load()
	rejects := c.rejects.Load()
	hitsD := hits - c.ctrlPrevHits
	churnD := (evicts - c.ctrlPrevEvicts) + (rejects - c.ctrlPrevRejects)
	c.ctrlPrevHits = hits
	c.ctrlPrevEvicts = evicts
	c.ctrlPrevRejects = rejects

	sample := 1.0 // default to "healthy" when there is too little activity
	if hitsD+churnD >= throttleMinSamples {
		sample = float64(hitsD) / float64(hitsD+churnD)
	}
	// Asymmetric: follow a worsening signal quickly, a recovering one slowly.
	alpha := effEWMAAlphaUp
	if sample < c.ctrlEffEWMA {
		alpha = effEWMAAlphaDown
	}
	c.ctrlEffEWMA = alpha*sample + (1-alpha)*c.ctrlEffEWMA

	eff := c.ctrlEffEWMA
	p := 1.0
	switch {
	case eff >= admitEffHighWater:
		p = 1.0
	case eff <= admitEffLowWater:
		p = minAdmitFrac
	default:
		// Lower efficiency -> lower admit probability.
		t := (eff - admitEffLowWater) / (admitEffHighWater - admitEffLowWater)
		p = minAdmitFrac + t*(1.0-minAdmitFrac)
	}
	// Reclaim-miss escalation: the kernel is taking pages we wanted, so caching
	// at this size is actively harmful — clamp admission harder.
	if reclaimDelta > reclaimMissShrinkThreshold && p > reclaimThrottleCap {
		p = reclaimThrottleCap
	}

	c.admitProbPP.Store(int64(p * admitFull))
	if p < 1.0 {
		log.Debugf("off-heap admission throttle: eff=%.2f reclaimΔ=%d admitProb=%.2f (hitsΔ=%d churnΔ=%d)",
			eff, reclaimDelta, p, hitsD, churnD)
	}
}

// ---- Memory-pressure signals ----

// readArenaVMA reads the arena's own VMA from /proc/self/smaps (never the
// process-wide rollup, §5) and returns its Rss and LazyFree in kB.  haveVMA
// is false if the VMA could not be located.
func readArenaVMA(base uintptr) (rssKB, lazyFreeKB uint64, haveVMA bool) {
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()

	target := strconv.FormatUint(uint64(base), 16)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	inTarget := false
	for sc.Scan() {
		line := sc.Text()
		// Mapping header lines look like "addr_start-addr_end perms ...".
		if len(line) > 0 && isHexAddrHeader(line) {
			start := line[:strings.IndexByte(line, '-')]
			inTarget = start == target
			continue
		}
		if !inTarget {
			continue
		}
		if v, ok := parseSmapsKB(line, "Rss:"); ok {
			rssKB = v
		} else if v, ok := parseSmapsKB(line, "LazyFree:"); ok {
			lazyFreeKB = v
			// LazyFree is near the end of a smaps block; we have what we need.
			return rssKB, lazyFreeKB, true
		}
	}
	return rssKB, lazyFreeKB, rssKB > 0
}

// isHexAddrHeader reports whether a smaps line is a mapping header
// ("hex-hex perms ...") rather than a "Key: value" detail line.
func isHexAddrHeader(line string) bool {
	dash := strings.IndexByte(line, '-')
	if dash <= 0 {
		return false
	}
	for i := 0; i < dash; i++ {
		c := line[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func parseSmapsKB(line, key string) (uint64, bool) {
	if !strings.HasPrefix(line, key) {
		return 0, false
	}
	fields := strings.Fields(line[len(key):])
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// availableMemoryFraction returns the fraction of memory still available,
// taking the tighter of the cgroup v2 budget and the host MemAvailable so the
// controller does the right thing inside a container.
func availableMemoryFraction() float64 {
	frac := hostMemAvailableFraction()
	if cg, ok := cgroupV2AvailableFraction(); ok && cg < frac {
		frac = cg
	}
	return frac
}

func hostMemAvailableFraction() float64 {
	total, avail := readMemInfoPair()
	if total == 0 {
		return 1.0
	}
	return float64(avail) / float64(total)
}

// readMemInfoPair returns (MemTotal, MemAvailable) in kB from /proc/meminfo
// (0, 0 on failure).
func readMemInfoPair() (totalKB, availKB uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := parseSmapsKB(line, "MemTotal:"); ok {
			totalKB = v
		} else if v, ok := parseSmapsKB(line, "MemAvailable:"); ok {
			availKB = v
		}
	}
	return totalKB, availKB
}

// cgroupV2AvailableFraction returns (1 - current/max) for the cgroup v2 memory
// controller, or ok=false if not under a v2 limit.
func cgroupV2AvailableFraction() (float64, bool) {
	maxRaw, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return 0, false
	}
	maxStr := strings.TrimSpace(string(maxRaw))
	if maxStr == "max" || maxStr == "" {
		return 0, false
	}
	max, err := strconv.ParseUint(maxStr, 10, 64)
	if err != nil || max == 0 {
		return 0, false
	}
	curRaw, err := os.ReadFile("/sys/fs/cgroup/memory.current")
	if err != nil {
		return 0, false
	}
	cur, err := strconv.ParseUint(strings.TrimSpace(string(curRaw)), 10, 64)
	if err != nil {
		return 0, false
	}
	if cur >= max {
		return 0, true
	}
	return float64(max-cur) / float64(max), true
}

// ---- PSI (pressure stall information) source ----

// psiSource reads the Linux memory PSI "some" avg10 metric.  It prefers the
// process's own cgroup v2 memory.pressure (the correct, container-scoped
// signal) and falls back to the system-wide /proc/pressure/memory.
type psiSource struct {
	f *os.File
}

// openPSISource opens the best available memory PSI file, or nil if PSI is
// unavailable (older kernel / not compiled in).
func openPSISource() *psiSource {
	if p := cgroupMemoryPressurePath(); p != "" {
		if f, err := os.Open(p); err == nil {
			return &psiSource{f: f}
		}
	}
	if f, err := os.Open("/proc/pressure/memory"); err == nil {
		return &psiSource{f: f}
	}
	return nil
}

func (p *psiSource) Close() {
	if p != nil && p.f != nil {
		_ = p.f.Close()
	}
}

// someAvg10 returns the "some avg10" memory-stall percentage (0–100).
func (p *psiSource) someAvg10() (float64, bool) {
	if p == nil || p.f == nil {
		return 0, false
	}
	if _, err := p.f.Seek(0, 0); err != nil {
		return 0, false
	}
	buf := make([]byte, 256)
	n, err := p.f.Read(buf)
	if err != nil && n == 0 {
		return 0, false
	}
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(f, "avg10="); ok {
				if val, perr := strconv.ParseFloat(v, 64); perr == nil {
					return val, true
				}
			}
		}
	}
	return 0, false
}

// cgroupMemoryPressurePath returns the path to the current process's cgroup v2
// memory.pressure file, or "" if it cannot be determined.
func cgroupMemoryPressurePath() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	// cgroup v2 line: "0::/path/to/cgroup".
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return "/sys/fs/cgroup" + rel + "/memory.pressure"
		}
	}
	return ""
}

// ---- helpers ----

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// atomicBitmap is a lock-free bitmap backed by atomic 64-bit words.
type atomicBitmap struct {
	words []atomic.Uint64
}

func newAtomicBitmap(n uint32) *atomicBitmap {
	return &atomicBitmap{words: make([]atomic.Uint64, (n+63)/64)}
}

// atomicLoadBytes copies len(dst) bytes from the arena at base into dst using
// atomic 64-bit loads, so a concurrent atomic writer of the same words is not a
// data race.  base must be 8-byte aligned (slots are page-aligned) and the
// slot must have room for the trailing partial word (guaranteed: payload <=
// padGenOffset, and the slot extends a further padReserve bytes).
func atomicLoadBytes(dst []byte, base unsafe.Pointer) {
	n := len(dst)
	i := 0
	for ; i+8 <= n; i += 8 {
		w := atomic.LoadUint64((*uint64)(unsafe.Add(base, i)))
		binary.LittleEndian.PutUint64(dst[i:], w)
	}
	if i < n {
		w := atomic.LoadUint64((*uint64)(unsafe.Add(base, i)))
		var tmp [8]byte
		binary.LittleEndian.PutUint64(tmp[:], w)
		copy(dst[i:n], tmp[:n-i])
	}
}

// atomicStoreBytes writes src into the arena at base using atomic 64-bit
// stores.  The trailing partial word is zero-padded so the whole word is
// written atomically (a concurrent atomic loader never sees a torn tail word).
func atomicStoreBytes(base unsafe.Pointer, src []byte) {
	n := len(src)
	i := 0
	for ; i+8 <= n; i += 8 {
		atomic.StoreUint64((*uint64)(unsafe.Add(base, i)), binary.LittleEndian.Uint64(src[i:]))
	}
	if i < n {
		var tmp [8]byte
		copy(tmp[:], src[i:n])
		atomic.StoreUint64((*uint64)(unsafe.Add(base, i)), binary.LittleEndian.Uint64(tmp[:]))
	}
}

// plainLoadBytes copies len(dst) bytes from the arena at base into dst with an
// ordinary memmove.  Concurrent with a writer this is a data race by the Go
// memory model — benign in practice because the caller's seqlock recheck
// discards any torn read, but technically UB and flagged by -race.  Used only
// in non-race builds (see arenaLoad).
func plainLoadBytes(dst []byte, base unsafe.Pointer) {
	copy(dst, unsafe.Slice((*byte)(base), len(dst)))
}

// plainStoreBytes writes src into the arena at base with an ordinary memmove.
func plainStoreBytes(base unsafe.Pointer, src []byte) {
	copy(unsafe.Slice((*byte)(base), len(src)), src)
}

func (b *atomicBitmap) set(i uint32)   { b.words[i>>6].Or(uint64(1) << (i & 63)) }
func (b *atomicBitmap) clear(i uint32) { b.words[i>>6].And(^(uint64(1) << (i & 63))) }
func (b *atomicBitmap) get(i uint32) bool {
	return b.words[i>>6].Load()&(uint64(1)<<(i&63)) != 0
}
