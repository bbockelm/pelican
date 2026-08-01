//go:build linux

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

// Privileged tests for the credential path of §5.
//
// These are the only tests that can verify what §5 actually claims. Everything
// else about credentials can be checked as an ordinary user -- which knob named
// a path, whether the cache avoids a second read -- but the claims that matter
// are about privilege: that a root-owned 0600 file stays readable after the
// daemon has dropped to an unprivileged account, and that the elevation doing so
// is confined to one thread rather than the process.
//
// They are Linux-only because droppriv's per-thread transition is (§5.8), and
// they skip when not running as root so that a developer's `go test ./...` is
// unaffected. In CI they run for real; a silent skip everywhere would be worse
// than no test, so each skip says why.
package condor

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireRoot skips unless the test process can actually drop privilege.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("privileged credential tests need root; run them in CI or under sudo")
	}
}

// unprivilegedIdentity finds an account to drop to. It prefers condor, since
// that is the real target, and falls back to nobody so the test still runs on a
// container without HTCondor installed.
func unprivilegedIdentity(t *testing.T) (uid, gid int, name string) {
	t.Helper()
	for _, candidate := range []string{"condor", "nobody", "daemon"} {
		u, err := lookupUser(candidate)
		if err == nil && u.uid != 0 {
			return u.uid, u.gid, candidate
		}
	}
	t.Skip("no unprivileged account (condor, nobody, daemon) to drop to")
	return 0, 0, ""
}

type userIDs struct{ uid, gid int }

func lookupUser(name string) (userIDs, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return userIDs{}, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return userIDs{}, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return userIDs{}, err
	}
	return userIDs{uid: uid, gid: gid}, nil
}

// TestRootOwnedCredentialReadableAfterDrop is the core claim of §5: a daemon
// that has dropped to the condor account can still read the pool's root-owned
// credentials. If this fails, the whole "read credentials as root" design does
// not hold and the alternative in §5.5 -- a condor-owned token -- becomes
// mandatory rather than optional.
func TestRootOwnedCredentialReadableAfterDrop(t *testing.T) {
	requireRoot(t)
	uid, gid, account := unprivilegedIdentity(t)

	dir := t.TempDir()
	// The directory must be traversable by the dropped-to account, as
	// /etc/condor is; the credential itself is not.
	require.NoError(t, os.Chmod(dir, 0o755))
	certPath := filepath.Join(dir, "host.crt")
	keyPath := filepath.Join(dir, "host.key")
	require.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o644))
	require.NoError(t, os.WriteFile(keyPath, []byte("super-secret-key"), 0o600))
	require.NoError(t, os.Chown(keyPath, 0, 0))
	require.NoError(t, os.Chmod(keyPath, 0o600))

	cfg := configFrom(t, fmt.Sprintf(
		"AUTH_SSL_SERVER_CERTFILE = %s\nAUTH_SSL_SERVER_KEYFILE = %s\n", certPath, keyPath))
	_, key := tlsCredentialPaths(cfg)
	require.Equal(t, keyPath, key)

	// Drop the way the daemon does: reversibly, keeping the real uid.
	mgr, err := droppriv.NewManager(droppriv.Config{
		Enabled: true, CondorIDs: &droppriv.Identity{UID: uint32(uid), GID: uint32(gid)},
	})
	require.NoError(t, err, "building the privilege manager for %s", account)
	require.NoError(t, mgr.Start())
	t.Cleanup(func() { _ = mgr.Stop() })

	require.NotEqual(t, 0, os.Geteuid(), "the test must actually have dropped privilege")

	// Reading as the dropped identity must fail, or the test proves nothing.
	_, directErr := os.ReadFile(keyPath)
	require.Error(t, directErr, "the credential should be unreadable without elevation")

	// ... and through the privileged reader, it must succeed.
	data, err := readCredential(key)
	require.NoError(t, err, "a root-owned credential must stay readable after the drop")
	assert.Equal(t, "super-secret-key", string(data))
}

// TestElevationIsPerThread is the containment claim of §5.2: elevation is
// confined to the calling thread, so concurrent work never runs as root.
//
// Without this, "we read credentials as root" would be indistinguishable from
// "the process briefly becomes root", which is the thing the design rejects --
// and the difference is invisible in ordinary use.
func TestElevationIsPerThread(t *testing.T) {
	requireRoot(t)
	uid, gid, _ := unprivilegedIdentity(t)

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755))
	certPath := filepath.Join(dir, "c.crt")
	keyPath := filepath.Join(dir, "c.key")
	require.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o644))
	require.NoError(t, os.WriteFile(keyPath, []byte("k"), 0o600))

	cfg := configFrom(t, fmt.Sprintf(
		"AUTH_SSL_SERVER_CERTFILE = %s\nAUTH_SSL_SERVER_KEYFILE = %s\n", certPath, keyPath))
	_, key := tlsCredentialPaths(cfg)

	mgr, err := droppriv.NewManager(droppriv.Config{
		Enabled: true, CondorIDs: &droppriv.Identity{UID: uint32(uid), GID: uint32(gid)},
	})
	require.NoError(t, err)
	require.NoError(t, mgr.Start())
	t.Cleanup(func() { _ = mgr.Stop() })

	var sawRoot atomic.Bool
	var sawDropped atomic.Bool
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Observers pinned to their own threads, standing in for request handlers.
	// Each checks its thread's effective uid continuously while credential reads
	// happen on other threads.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			for {
				select {
				case <-stop:
					return
				default:
					switch threadEUID() {
					case 0:
						sawRoot.Store(true)
						return
					case uid:
						// Records that the probe genuinely read a uid. Without
						// this the test would pass even if threadEUID always
						// failed and returned -1, which never equals 0.
						sawDropped.Store(true)
					}
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		flushCredentials() // force a real read, not a cache hit
		_, err := readCredential(key)
		require.NoError(t, err)
	}

	close(stop)
	wg.Wait()

	require.True(t, sawDropped.Load(),
		"the observers never read a valid effective uid, so this test proves nothing")
	assert.False(t, sawRoot.Load(),
		"a concurrent handler observed euid 0; the elevation is not confined to the reading thread")
}

// TestCredentialReadSurvivesReconfigure checks the rotation path under real
// privilege: a rotated root-owned credential is picked up after a flush.
func TestCredentialReadSurvivesReconfigure(t *testing.T) {
	requireRoot(t)
	uid, gid, _ := unprivilegedIdentity(t)

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755))
	certPath := filepath.Join(dir, "r.crt")
	keyPath := filepath.Join(dir, "r.key")
	require.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o644))
	require.NoError(t, os.WriteFile(keyPath, []byte("before"), 0o600))

	cfg := configFrom(t, fmt.Sprintf(
		"AUTH_SSL_SERVER_CERTFILE = %s\nAUTH_SSL_SERVER_KEYFILE = %s\n", certPath, keyPath))
	_, key := tlsCredentialPaths(cfg)

	mgr, err := droppriv.NewManager(droppriv.Config{
		Enabled: true, CondorIDs: &droppriv.Identity{UID: uint32(uid), GID: uint32(gid)},
	})
	require.NoError(t, err)
	require.NoError(t, mgr.Start())
	t.Cleanup(func() { _ = mgr.Stop() })

	flushCredentials()
	first, err := readCredential(key)
	require.NoError(t, err)
	require.Equal(t, "before", string(first))

	// Rotate the credential as root would, then reconfigure.
	require.NoError(t, elevatedWrite(keyPath, "after"))
	flushCredentials()

	after, err := readCredential(key)
	require.NoError(t, err)
	assert.Equal(t, "after", string(after), "condor_reconfig must pick up a rotated credential")
}

// threadEUID reports the calling thread's effective uid. syscall.Geteuid
// reports the process value on Linux, which is not what needs checking here.
func threadEUID() int {
	var ruid, euid, suid int
	if err := getresuid(&ruid, &euid, &suid); err != nil {
		return -1
	}
	return euid
}

// elevatedWrite rewrites a root-owned file, pinned to one thread so the
// elevation does not leak.
func elevatedWrite(path, contents string) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := seteuidThread(0); err != nil {
			done <- err
			return
		}
		err := os.WriteFile(path, []byte(contents), 0o600)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timed out rewriting %s", path)
	}
}

// getresuid reads the calling thread's real, effective and saved uids.
// RawSyscall is used deliberately: Go's syscall wrappers for the setuid family
// propagate across all threads, which is precisely the behavior these tests
// exist to rule out.
func getresuid(ruid, euid, suid *int) error {
	//nolint:gosec // G103: unsafe.Pointer is required by the syscall interface
	if _, _, errno := syscall.RawSyscall(syscall.SYS_GETRESUID,
		uintptr(unsafe.Pointer(ruid)), uintptr(unsafe.Pointer(euid)), uintptr(unsafe.Pointer(suid))); errno != 0 {
		return errno
	}
	return nil
}

// seteuidThread sets only the calling thread's effective uid.
func seteuidThread(uid int) error {
	//nolint:gosec // G115: a uid is a small non-negative integer
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETRESUID,
		^uintptr(0), uintptr(uid), ^uintptr(0)); errno != 0 {
		return errno
	}
	return nil
}
