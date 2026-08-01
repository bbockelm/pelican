//go:build !windows

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

package condor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSCredentialPathsFromPool(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "host.crt")
	keyPath := filepath.Join(dir, "host.key")
	require.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o644))
	require.NoError(t, os.WriteFile(keyPath, []byte("key"), 0o600))

	cfg := configFrom(t, "AUTH_SSL_SERVER_CERTFILE = "+certPath+"\nAUTH_SSL_SERVER_KEYFILE = "+keyPath+"\n")
	cert, key := tlsCredentialPaths(cfg)
	assert.Equal(t, certPath, cert)
	assert.Equal(t, keyPath, key)

	// Reading a credential is attributed to the knob that named it, which is
	// what makes the audit counter and the log line meaningful.
	assert.Equal(t, knobSSLCert, knobForCredential(cert))
	assert.Equal(t, knobSSLKey, knobForCredential(key))
}

// TestTLSCredentialPathsAbsent covers the default configuration. Both knobs
// carry built-in defaults naming files that do not exist on most hosts, so a
// daemon must not adopt them -- doing so would swap Pelican's working
// certificate for one that cannot load.
func TestTLSCredentialPathsAbsent(t *testing.T) {
	cert, key := tlsCredentialPaths(configFrom(t, "# only the built-in defaults\n"))
	assert.Empty(t, cert, "a default naming a nonexistent file must not be adopted")
	assert.Empty(t, key)
}

// TestTLSCredentialPathsPickFirstExisting covers the candidate-list form these
// knobs actually take.
func TestTLSCredentialPathsPickFirstExisting(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.crt")
	key := filepath.Join(dir, "real.key")
	require.NoError(t, os.WriteFile(real, []byte("cert"), 0o644))
	require.NoError(t, os.WriteFile(key, []byte("key"), 0o600))

	cfg := configFrom(t,
		"AUTH_SSL_SERVER_CERTFILE = "+filepath.Join(dir, "missing.crt")+", "+real+"\n"+
			"AUTH_SSL_SERVER_KEYFILE = "+key+"\n")
	gotCert, gotKey := tlsCredentialPaths(cfg)
	assert.Equal(t, real, gotCert, "the first existing candidate should win")
	assert.Equal(t, key, gotKey)
}

// TestTLSCredentialPathsHalfPair checks that a certificate without its key is
// declined rather than half-adopted.
func TestTLSCredentialPathsHalfPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "host.crt")
	require.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o644))

	cfg := configFrom(t, "AUTH_SSL_SERVER_CERTFILE = "+certPath+
		"\nAUTH_SSL_SERVER_KEYFILE = "+filepath.Join(dir, "absent.key")+"\n")
	cert, key := tlsCredentialPaths(cfg)
	assert.Empty(t, cert, "half a pair is no pair")
	assert.Empty(t, key)
}

// TestReadCredentialRefusesUnnamedPath is the containment property of §5.6: the
// privileged operation is "read the file this knob names", not "read a file".
// A path that no configuration knob introduced must be refused, so that
// privileged reads can never become a general-purpose file service reachable
// from anywhere else in the process.
func TestReadCredentialRefusesUnnamedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-credential")
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0o600))

	_, err := readCredential(path)
	require.Error(t, err, "a path no knob named must not be read with privilege")
	assert.Contains(t, err.Error(), "not named by an HTCondor configuration knob")

	_, err = readCredential("")
	require.Error(t, err)
}

func TestReadCredentialReadsNamedPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.key")
	certPath := filepath.Join(dir, "host.crt")
	require.NoError(t, os.WriteFile(path, []byte("key-material"), 0o600))
	require.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o644))

	// Naming it through the pool configuration is what authorizes the read.
	cfg := configFrom(t, "AUTH_SSL_SERVER_CERTFILE = "+certPath+"\nAUTH_SSL_SERVER_KEYFILE = "+path+"\n")
	_, key := tlsCredentialPaths(cfg)
	require.Equal(t, path, key)

	data, err := readCredential(key)
	require.NoError(t, err)
	assert.Equal(t, "key-material", string(data))
}

// TestCredentialCacheAvoidsRepeatedReads matters because each miss is a
// privilege transition. The steady state has to be zero of them, or §5's claim
// that elevation is rare stops being true.
func TestCredentialCacheAvoidsRepeatedReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cached.key")
	certPath := filepath.Join(dir, "cached.crt")
	require.NoError(t, os.WriteFile(path, []byte("first"), 0o600))
	require.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o644))

	cfg := configFrom(t, "AUTH_SSL_SERVER_CERTFILE = "+certPath+"\nAUTH_SSL_SERVER_KEYFILE = "+path+"\n")
	_, key := tlsCredentialPaths(cfg)

	first, err := readCredential(key)
	require.NoError(t, err)
	assert.Equal(t, "first", string(first))

	// Change the file underneath. A cached read must not see it.
	require.NoError(t, os.WriteFile(path, []byte("second"), 0o600))
	cached, err := readCredential(key)
	require.NoError(t, err)
	assert.Equal(t, "first", string(cached), "a cached credential should not re-read the file")

	// ... until a reconfigure flushes the cache, which is how a rotated
	// credential is picked up.
	flushCredentials()
	after, err := readCredential(key)
	require.NoError(t, err)
	assert.Equal(t, "second", string(after), "condor_reconfig must pick up a rotated credential")
}
