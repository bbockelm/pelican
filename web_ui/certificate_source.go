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

package web_ui

import (
	"crypto/tls"
	"sync/atomic"
)

// CertificateLoader builds the web engine's TLS keypair from the configured
// certificate and key paths.
//
// It exists because the files are not always readable as the user Pelican runs
// as. Under condor_master the server presents the pool's SSL host credential,
// whose private key is root-owned and mode 0600; reading it needs a privileged
// path that the config package has no business knowing about.
//
// A loader is handed the paths rather than being expected to find them, so
// configuration stays in one place and a loader only decides *how* to read.
type CertificateLoader func(certFile, keyFile string) (tls.Certificate, error)

// certificateLoader overrides how the keypair is read; nil means read the files
// directly.
var certificateLoader atomic.Pointer[CertificateLoader]

// SetCertificateLoader installs a loader for the web engine's TLS keypair,
// replacing any previous one. Passing nil restores reading the files directly.
//
// It must be called before the web engine starts. Both the initial load and the
// periodic reload go through it -- the reload especially, since a loader wired
// only into startup would work until the certificate was first renewed and then
// fail in production, which is the worst possible time to discover it.
func SetCertificateLoader(loader CertificateLoader) {
	if loader == nil {
		certificateLoader.Store(nil)
		return
	}
	certificateLoader.Store(&loader)
}

// loadCertificate reads the keypair through the installed loader, or directly
// from the filesystem when none is installed.
func loadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	if loader := certificateLoader.Load(); loader != nil {
		return (*loader)(certFile, keyFile)
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}
