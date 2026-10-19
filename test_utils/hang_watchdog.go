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

package test_utils

// DIAGNOSTIC ONLY (branch windows-hang-diag): a watchdog for a test binary
// that may run away -- goroutines or memory growing without bound, or simply
// never finishing -- badly enough that a CI runner stops answering before
// go test's own -timeout fires, so that no log survives.  It reports the
// binary's state every interval, and on crossing a limit dumps every
// goroutine's stack (aggregated by stack) and exits, so the job ends
// normally and the dump is in its log.

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"
)

func envDuration(name string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// RunWithHangWatchdog runs the package's tests under the watchdog and
// returns m.Run's exit code.
func RunWithHangWatchdog(m *testing.M, pkg string) int {
	interval := envDuration("DIAG_WATCHDOG_INTERVAL", 15*time.Second)
	limit := envDuration("DIAG_WATCHDOG_LIMIT", 12*time.Minute)
	maxGoroutines := envInt("DIAG_WATCHDOG_MAX_GOROUTINES", 20000)
	maxSysMiB := envInt("DIAG_WATCHDOG_MAX_SYS_MIB", 4096)

	start := time.Now()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var ms runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			runtime.ReadMemStats(&ms)
			n := runtime.NumGoroutine()
			elapsed := time.Since(start).Round(time.Second)
			fmt.Fprintf(os.Stderr, "WATCHDOG %s t=%s goroutines=%d heap=%dMiB sys=%dMiB numgc=%d\n",
				pkg, elapsed, n, ms.HeapAlloc>>20, ms.Sys>>20, ms.NumGC)
			reason := ""
			switch {
			case n > maxGoroutines:
				reason = fmt.Sprintf("%d goroutines > %d", n, maxGoroutines)
			case int(ms.Sys>>20) > maxSysMiB:
				reason = fmt.Sprintf("sys %dMiB > %dMiB", ms.Sys>>20, maxSysMiB)
			case elapsed > limit:
				reason = fmt.Sprintf("running %s > %s", elapsed, limit)
			}
			if reason == "" {
				continue
			}
			fmt.Fprintf(os.Stderr, "WATCHDOG %s TRIPPED: %s; goroutine dump follows\n", pkg, reason)
			_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 1)
			fmt.Fprintf(os.Stderr, "WATCHDOG %s exiting\n", pkg)
			os.Exit(3)
		}
	}()
	code := m.Run()
	close(done)
	return code
}
