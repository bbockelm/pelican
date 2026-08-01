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
	"crypto/tls"
	"os"
	"strings"
	"sync"

	htcondor "github.com/bbockelm/golang-htcondor"
	htcondorconfig "github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
)

// credentialReads counts privileged credential reads, by the knob that named
// the file.
//
// Steady state is near zero: the cache means a credential is read once per
// process and once per reconfigure. That makes the counter a useful signal
// rather than noise -- a rate above roughly one per credential per reconfigure
// means something is defeating the cache, and elevation on a hot path is
// exactly what §5 is trying to avoid.
var credentialReads = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "pelican_condor_credential_reads_total",
	Help: "Privileged reads of HTCondor credentials, by the configuration knob naming the file.",
}, []string{"knob"})

func init() {
	prometheus.MustRegister(credentialReads)
}

var (
	credentialsOnce  sync.Once
	credentialCache  *htcondor.CredentialCache
	credentialKnobMu sync.Mutex
	// credentialKnobs maps a credential path back to the knob that named it, so
	// a read can be attributed in the log and the counter. Paths are learned as
	// they are configured rather than guessed.
	credentialKnobs = map[string]string{}
)

// credentials returns the process-wide privileged credential reader.
//
// The cache reads root-owned files through droppriv, which elevates a single
// thread for the duration of one open() and restores it immediately -- the
// set_priv model every C++ HTCondor daemon uses for the same purpose. It is not
// a process-wide switch to root: concurrent request handlers keep running as the
// condor account throughout. See §5.2 and §5.3 of the design.
func credentials() *htcondor.CredentialCache {
	credentialsOnce.Do(func() {
		credentialCache = htcondor.NewCredentialCache()
	})
	return credentialCache
}

// flushCredentials discards cached credential bytes so the next read picks up a
// rotated key or a renewed certificate. Wired to condor_reconfig, following
// HTCondor's convention that credential reload follows a reconfigure.
func flushCredentials() {
	if credentialCache != nil {
		credentialCache.Reload()
		log.Debug("Flushed cached HTCondor credentials")
	}
}

// noteCredentialKnob records which knob named a credential path.
func noteCredentialKnob(path, knob string) {
	if path == "" {
		return
	}
	credentialKnobMu.Lock()
	defer credentialKnobMu.Unlock()
	credentialKnobs[path] = knob
}

// knobForCredential returns the knob that named a path, for attribution.
func knobForCredential(path string) string {
	credentialKnobMu.Lock()
	defer credentialKnobMu.Unlock()
	if knob, ok := credentialKnobs[path]; ok {
		return knob
	}
	return "unknown"
}

// readCredential reads a credential file with privilege, for callers outside
// CEDAR's own hooks.
//
// Every path reaching this function must come from an HTCondor configuration
// knob, never from request data. That is the containment §5.6 depends on: the
// privileged operation is "read the file this knob names", not "read a file".
// The knob must have been registered with noteCredentialKnob, which is what
// enforces the rule in practice -- an unregistered path is refused rather than
// read.
func readCredential(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("no credential path was given")
	}
	knob := knobForCredential(path)
	if knob == "unknown" {
		// Refusing is the point. A path that no knob named did not come from the
		// pool configuration, and privileged reads are not a general-purpose file
		// service.
		return nil, errors.Errorf(
			"refusing a privileged read of %s: it was not named by an HTCondor configuration knob", path)
	}

	data, err := credentials().ReadCredential(path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read the credential named by %s", knob)
	}
	credentialReads.WithLabelValues(knob).Inc()
	log.Debugf("Read credential %s (named by %s, %d bytes)", path, knob, len(data))
	return data, nil
}

// TLS credential knobs. These are HTCondor's own SSL host credential, which the
// pool already provisions and rotates.
const (
	knobSSLCert = "AUTH_SSL_SERVER_CERTFILE"
	knobSSLKey  = "AUTH_SSL_SERVER_KEYFILE"
)

// tlsCredentialPaths returns the pool's SSL host certificate and key, or empty
// strings when the host has no usable pair.
//
// Two properties of these knobs make this less direct than it looks, and both
// were found by trying it rather than by reading the design:
//
//   - Each is a *comma-separated list of candidates*, not a single path, and
//     HTCondor uses the first that exists.
//   - Both carry built-in defaults (/etc/pki/tls/certs/localhost.crt and
//     friends), so they are never unset. "Did the operator configure one?"
//     cannot be answered by asking whether the knob has a value.
//
// So existence is the test. A host with a real SSL credential gets it; a host
// where the knobs are only their defaults, naming files nobody created, keeps
// Pelican's own certificate. Adopting a default that points at a nonexistent
// localhost.crt would replace a working certificate with one that cannot load.
func tlsCredentialPaths(cfg *htcondorconfig.Config) (certFile, keyFile string) {
	certFile = firstExisting(knobString(cfg, knobSSLCert))
	keyFile = firstExisting(knobString(cfg, knobSSLKey))
	if certFile == "" || keyFile == "" {
		// Only half a pair is no pair; presenting a certificate without its key
		// is not something to attempt.
		return "", ""
	}
	noteCredentialKnob(certFile, knobSSLCert)
	noteCredentialKnob(keyFile, knobSSLKey)
	return certFile, keyFile
}

// firstExisting returns the first path in a comma-separated candidate list that
// exists, or "" if none do.
//
// Existence is checked as the daemon's current identity, which is the condor
// account. A root-owned 0600 credential is still visible to os.Stat -- that
// needs only the directory to be traversable -- so this decides *whether* to
// adopt the pair, while reading it remains privileged.
func firstExisting(list string) string {
	for _, candidate := range strings.Split(list, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// useCondorTLSCredential makes the HTTPS port present the pool's SSL host
// credential, read with privilege.
//
// One certificate per host, provisioned and rotated by the mechanism the site
// already runs for HTCondor, rather than a second one just for Pelican (§5.7).
// The private key is root-owned and mode 0600, so both the initial load and
// every reload have to go through the privileged reader -- a loader wired only
// into startup would work until the first renewal and then fail in production.
//
// When the pool configures no SSL credential, Pelican keeps its own certificate
// and this does nothing.
func useCondorTLSCredential(d *daemon.Daemon) error {
	certFile, keyFile := tlsCredentialPaths(d.Config())
	if certFile == "" || keyFile == "" {
		log.Debugf("The pool configures no SSL host credential (%s / %s); keeping Pelican's own certificate",
			knobSSLCert, knobSSLKey)
		return nil
	}

	if err := param.Server_TLSCertificateChain.Set(certFile); err != nil {
		return errors.Wrapf(err, "failed to point %s at %s", param.Server_TLSCertificateChain.GetName(), certFile)
	}
	if err := param.Server_TLSKey.Set(keyFile); err != nil {
		return errors.Wrapf(err, "failed to point %s at %s", param.Server_TLSKey.GetName(), keyFile)
	}

	web_ui.SetCertificateLoader(func(cert, key string) (tls.Certificate, error) {
		certPEM, err := readCredential(cert)
		if err != nil {
			return tls.Certificate{}, err
		}
		keyPEM, err := readCredential(key)
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(certPEM, keyPEM)
	})

	log.Infof("Serving HTTPS with the pool's SSL host credential from %s", certFile)
	return nil
}
