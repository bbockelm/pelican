//go:build server && !windows

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

package condor_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/transfer_records"
)

// TestPelicanUnderCondorMaster brings pelican-server up as a managed child of a
// real condor_master and exercises the lifecycle the master expects: the daemon
// starts, recognizes its parent, logs to the pool's log directory, and stops on
// condor_off.
//
// The test skips when condor_master is not on PATH, so it is inert on a
// developer machine without HTCondor and runs for real in the pelican-test
// image, which ships HTCondor for exactly this purpose.
func TestPelicanUnderCondorMaster(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping condor_master integration test in -short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH; skipping")
	}

	bin := buildPelicanServer(t)
	stderrFile := filepath.Join(t.TempDir(), "pelican-stderr.log")
	bin = wrapWithStderrCapture(t, bin, stderrFile)

	// A registry is the lightest module set that stands up the web engine with no
	// XRootD process. It needs a federation discovery source, which the director
	// provides, so the daemon runs both.
	//
	// PELICAN_* here are condor_master's per-daemon knobs for a daemon named
	// PELICAN. Note there is no PELICAN_ARGS: under DC_DAEMON_LIST the master
	// supplies DaemonCore's own arguments, and Pelican does not parse the command
	// line at all -- which modules to run and where its configuration lives are
	// themselves configuration.
	pelicanDir := t.TempDir()
	// A fixed port lets the test poll the daemon directly and confirm it is
	// genuinely serving before asking the master to stop it. With a random port
	// the test can only watch the log, and it would race ahead to condor_off
	// while startup was still in flight.
	port := freePort(t)
	// The harness runs its collector on a dynamic port and discovers the address
	// afterwards, but a daemon reads COLLECTOR_HOST from configuration at startup.
	// Pinning the collector to a known free port is what lets the advertisement
	// actually be delivered, and so verified, rather than merely attempted.
	collectorPort := freePort(t)
	cfgFile := writePelicanConfig(t, pelicanDir)
	extra := fmt.Sprintf(`
PELICAN = %s
PELICAN_LOG = $(LOG)/PelicanLog
PELICAN_ADDRESS_FILE = $(LOG)/.pelican_address
PELICAN_SERVER_MODULES = director, registry
PELICAN_CONFIG_FILE = %s
PELICAN_PORT = %d
# Advertise promptly so the test does not wait out the default update interval.
PELICAN_UPDATE_INTERVAL = 5
COLLECTOR_HOST = 127.0.0.1:%d
# A Pelican parameter set from HTCondor configuration rather than the YAML,
# exercising the translation layer end to end.
PELICAN_DIRECTOR_DEFAULTRESPONSE = origin
DAEMON_LIST = $(DAEMON_LIST) PELICAN
# A full DaemonCore daemon: the master gives it a managed command port and
# passes DaemonCore's own arguments, which Pelican ignores entirely.
DC_DAEMON_LIST = +PELICAN
`, bin, cfgFile, port, collectorPort)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()

	pelicanLog := filepath.Join(h.GetLogDir(), "PelicanLog")

	// The daemon came up under the master and wrote to the pool's log directory.
	// Both halves matter: a Pelican that logged only to the console would be
	// silent here, because the master wires a daemon's stdout to /dev/null.
	if !waitForLog(t, pelicanLog, "Starting Pelican under condor_master", 60*time.Second) {
		dumpLog(t, pelicanLog)
		dumpLog(t, stderrFile)
		dumpLog(t, filepath.Join(h.GetLogDir(), "MasterLog"))
		t.Fatal("pelican did not start under condor_master")
	}
	require.True(t, waitForLog(t, pelicanLog, "under_master=true", 10*time.Second),
		"pelican did not detect its condor_master parent")

	// It is genuinely serving, not merely started: the web engine answers on the
	// port the daemon bound. Waiting for this before condor_off is what keeps the
	// shutdown assertion below meaningful -- a daemon interrupted mid-startup
	// takes a different path out.
	if !waitForHealth(t, port, 90*time.Second) {
		dumpLog(t, pelicanLog)
		t.Fatal("pelican daemon never served its health endpoint")
	}
	require.True(t, waitForLog(t, pelicanLog, "Pelican modules are running under condor_master", 10*time.Second),
		"pelican did not report its modules running")

	// A Pelican parameter set only in HTCondor configuration took effect, which is
	// the translation layer working against a real pool configuration rather than
	// a synthesized one.
	require.True(t, waitForLog(t, pelicanLog, "parameter(s) from HTCondor configuration", 30*time.Second),
		"the HTCondor configuration layer never reported applying any parameters")
	// And it changed behavior, not just the log: Director.DefaultResponse defaults
	// to "cache", and only the HTCondor knob above sets it to "origin".
	require.True(t, waitForLog(t, pelicanLog, "will redirect to origins by default", 30*time.Second),
		"Director.DefaultResponse from HTCondor configuration did not take effect")

	// Transfer recording is wired into the real server: the store was opened and
	// its change feed mounted. This exercises the launcher path, which the
	// package's own tests cannot -- they build the store directly.
	require.True(t, waitForLog(t, pelicanLog, "Recording transfers to", 30*time.Second),
		"the transfer-record store was never opened")
	assert.DirExists(t, filepath.Join(pelicanDir, "transfer_records"),
		"the transfer-record store should have been created on disk")

	// The feed is mounted on the real server and refuses an unauthenticated
	// caller. Transfer records carry object paths, client addresses and user
	// identities, so an open feed would be a disclosure -- and a route that is
	// merely absent would 404 rather than 401, so this distinguishes the two.
	feedURL := fmt.Sprintf("https://127.0.0.1:%d%s/changefeed/v1/subscribe?table=transfers", port, transfer_records.FeedRoutePrefix)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // G402: self-signed test certificate
	}
	resp, err := client.Get(feedURL)
	require.NoError(t, err, "the change-feed route should be reachable")
	defer resp.Body.Close()
	// Pelican's token middleware answers a missing token with 403 rather than
	// 401. Either is a refusal; what matters here is the distinction from the two
	// wrong outcomes -- 404 would mean the route was never mounted, and 2xx would
	// mean the feed is open to anyone.
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, "the change-feed route is not mounted")
	assert.GreaterOrEqual(t, resp.StatusCode, 400, "the change feed must not serve records to an unauthenticated caller")
	assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, resp.StatusCode,
		"the change feed must refuse an unauthenticated caller")

	// The command port answers. This is what makes the daemon addressable rather
	// than merely supervised: condor_ping exercises DC_NOP against this daemon
	// specifically, which requires the CEDAR server to be serving the socket the
	// master handed down and the pool's own authorization to admit us.
	require.True(t, waitForLog(t, pelicanLog, "Pelican command port listening on", 30*time.Second),
		"the command port never came up")
	// Located by its address file rather than by -type: PELICAN is not one of
	// HTCondor's own subsystems, so the tools cannot resolve it by name.
	addrFile := filepath.Join(h.GetLogDir(), ".pelican_address")
	require.True(t, eventually(30*time.Second, time.Second, func() bool {
		_, err := os.Stat(addrFile)
		return err == nil
	}), "the daemon never wrote its address file")
	rawAddr, err := os.ReadFile(addrFile)
	require.NoError(t, err)
	addr := strings.TrimSpace(strings.SplitN(string(rawAddr), "\n", 2)[0])
	require.NotEmpty(t, addr)

	// Target the command port directly and assert the daemon reports handling the
	// command. Observing the effect in the daemon's own log is a stronger claim
	// than a tool's exit status: it proves the CEDAR server accepted an
	// authenticated connection, authorized it, and dispatched.
	var reconfigOut string
	if !eventually(60*time.Second, 2*time.Second, func() bool {
		out, _ := condorToolOutput(t, h, "condor_reconfig", "-addr", addr)
		reconfigOut = out
		return waitForLog(t, pelicanLog, "Received condor_reconfig", 3*time.Second)
	}) {
		dumpLog(t, pelicanLog)
		t.Fatalf("a command sent to %s never reached the Pelican command port; tool output:\n%s",
			addr, reconfigOut)
	}

	// The reconfigure went through Pelican's hot-reload path and reached a
	// conclusion, rather than only logging that a signal arrived. Nothing in this
	// pool's configuration changes between reconfigures, so "no change" is the
	// correct outcome to see -- the point is that Reapply ran and said so.
	require.True(t, waitForLog(t, pelicanLog, "no runtime-configurable parameter changed", 20*time.Second),
		"condor_reconfig did not report the outcome of reapplying the configuration")

	// The daemon advertises itself to the pool's collector, so condor_status can
	// see a Pelican server the same way it sees any other daemon.
	if !eventually(90*time.Second, 2*time.Second, func() bool {
		out, err := condorToolOutput(t, h, "condor_status", "-any",
			"-constraint", `MyType == "PelicanServer"`, "-af", "PelicanServerType")
		if err != nil {
			return false
		}
		return strings.Contains(out, "Director") && strings.Contains(out, "Registry")
	}) {
		dumpLog(t, pelicanLog)
		dumpLog(t, filepath.Join(h.GetLogDir(), "CollectorLog"))
		t.Fatal("pelican ad never reached the collector")
	}

	// condor_off makes the master stop the daemon; Pelican should shut down
	// through the framework's SIGTERM handling rather than being killed.
	runCondorTool(t, h, "condor_off", "-subsystem", "PELICAN")
	if !waitForLog(t, pelicanLog, "Shutdown requested", 60*time.Second) {
		dumpLog(t, pelicanLog)
		t.Fatal("pelican did not shut down on condor_off")
	}
	require.True(t, waitForLog(t, pelicanLog, "Pelican daemon has shut down", 30*time.Second),
		"pelican did not complete an orderly shutdown")
}

// freePort returns a TCP port that is free at the moment of the call.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// waitForHealth polls the daemon's health endpoint until it answers or the
// deadline passes. The daemon serves a self-signed certificate, so verification
// is skipped; this checks reachability, not trust.
func waitForHealth(t *testing.T, port int, timeout time.Duration) bool {
	t.Helper()
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // G402: self-signed test certificate
	}
	url := fmt.Sprintf("https://127.0.0.1:%d/api/v1.0/health", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// writePelicanConfig writes the Pelican configuration the daemon runs with and
// returns its path.
//
// The web port is deliberately absent: in this mode it comes from the pool's
// PELICAN_PORT knob, and the daemon adopts the bound address into the rest of
// the configuration. Logging.LogLocation is likewise left unset so the daemon
// derives it from the pool's $(LOG). Both are behaviors under test.
func writePelicanConfig(t *testing.T, dir string) string {
	t.Helper()
	cfg := fmt.Sprintf(`
ConfigBase: %[1]s
RuntimeDir: %[1]s
TLSSkipVerify: true
Logging:
  Level: Debug
Server:
  EnableUI: false
  DbLocation: %[1]s/ns-registry.sqlite
Director:
  DbLocation: %[1]s/director.sqlite
  EnableFederationMetadataHosting: true
Registry:
  RequireOriginApproval: false
  RequireCacheApproval: false
Monitoring:
  EnableTransferRecords: true
  TransferRecordsLocation: %[1]s/transfer_records
`, dir)
	path := filepath.Join(dir, "pelican.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))
	return path
}

// wrapWithStderrCapture returns a wrapper script that runs bin with its standard
// error appended to path. condor_master sends a daemon's stdout and stderr to
// /dev/null, so a failure that happens before the daemon has a log file would
// otherwise leave nothing at all to diagnose.
func wrapWithStderrCapture(t *testing.T, bin, path string) string {
	t.Helper()
	wrapper := filepath.Join(t.TempDir(), "pelican-wrapper.sh")
	script := fmt.Sprintf("#!/bin/sh\nexec \"%s\" \"$@\" 2>>\"%s\"\n", bin, path)
	require.NoError(t, os.WriteFile(wrapper, []byte(script), 0o700))
	return wrapper
}

// buildPelicanServer compiles the pelican-server binary the master will run.
func buildPelicanServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pelican-server")
	// -buildvcs=false: CI checkouts cannot always stamp VCS metadata (git
	// ownership rules, shallow clones), which fails the build outright.
	cmd := exec.CommandContext(context.Background(), "go", "build", "-buildvcs=false",
		"-tags", "server", "-o", bin, "github.com/pelicanplatform/pelican/cmd") //nolint:gosec // G204: fixed build target
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Run(), "building pelican-server")
	return bin
}

// waitForLog polls path until it contains want or the deadline passes.
func waitForLog(t *testing.T, path, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path) //nolint:gosec // G304: test reads its own log file
		if err == nil && strings.Contains(string(b), want) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// runCondorTool runs an admin tool against the harness pool, using its config.
func runCondorTool(t *testing.T, h *htcondor.CondorTestHarness, tool string, args ...string) {
	t.Helper()
	path, err := exec.LookPath(tool)
	if err != nil {
		t.Skipf("%s not found in PATH", tool)
	}
	cmd := exec.CommandContext(context.Background(), path, args...) //nolint:gosec // G204: test invoking a condor admin tool
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("%s %s output: %s", tool, strings.Join(args, " "), out)
		t.Fatalf("%s failed: %v", tool, err)
	}
}

// eventually polls cond until it is true or the timeout elapses.
func eventually(timeout, interval time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(interval)
	}
	return false
}

// condorToolOutput runs an admin tool against the harness pool and returns its
// output, leaving failure handling to the caller (unlike runCondorTool, which
// fails the test) so it can be polled.
func condorToolOutput(t *testing.T, h *htcondor.CondorTestHarness, tool string, args ...string) (string, error) {
	t.Helper()
	path, err := exec.LookPath(tool)
	if err != nil {
		t.Skipf("%s not found in PATH", tool)
	}
	cmd := exec.CommandContext(context.Background(), path, args...) //nolint:gosec // G204: test invoking a condor admin tool
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func dumpLog(t *testing.T, path string) {
	t.Helper()
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: test reads its own log file
		t.Logf("=== %s ===\n%s", path, b)
	} else {
		t.Logf("=== %s === (unreadable: %v)", path, err)
	}
}
