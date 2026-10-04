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

package backendcred

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

// fakeIssuer is an OAuth authorization server with exactly the surface the
// credential manager uses: metadata, dynamic client registration, client ID
// metadata document fetching (with private_key_jwt verification against the
// document's jwks_uri), device authorization, and the device-code and
// refresh-token grants with refresh token rotation.
type fakeIssuer struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client

	supportsDCR  bool
	supportsCIMD bool
	// Lifetimes handed out.
	accessTokenLifetime int64
	deviceCodeLifetime  int64
	// Whether the device-code grant returns a refresh token.
	issueRefreshTokens bool
	// Advertise a cleartext token endpoint.
	insecureTokenEndpoint bool
	// Polls arriving sooner than this after the previous one (or the
	// authorization) get slow_down, as RFC 8628 section 3.5 allows.
	minPollInterval time.Duration

	mu sync.Mutex
	// Registered confidential clients: client_id -> secret.
	dcrClients map[string]string
	// client_id -> fetched metadata document, for CIMD clients.
	cimdDocs map[string]*ClientIDMetadataDocument
	// Pending device codes.
	devices map[string]*fakeDevice
	// Live refresh tokens -> client_id.
	refreshTokens map[string]string
	usedJTIs      map[string]bool
	seq           int

	registrations int
	cimdFetches   int
	refreshes     int
	// Every refresh request, including failed ones.
	refreshAttempts int
	slowDowns       int
	// The next failRefreshes refresh requests and failPolls device-code polls
	// get a 503 with no OAuth error body.
	failRefreshes int
	failPolls     int
	// Access tokens handed out, newest last.
	accessTokens []string
	// Scopes and audience requested in the last device authorization.
	lastScope    string
	lastAudience string
}

type fakeDevice struct {
	lastPoll time.Time
	clientID string
	userCode string
	approved bool
	denied   bool
	expires  time.Time
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	fi := &fakeIssuer{
		t:                   t,
		supportsDCR:         true,
		accessTokenLifetime: 3600,
		deviceCodeLifetime:  600,
		issueRefreshTokens:  true,
		dcrClients:          map[string]string{},
		cimdDocs:            map[string]*ClientIDMetadataDocument{},
		devices:             map[string]*fakeDevice{},
		refreshTokens:       map[string]string{},
		usedJTIs:            map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fi.metadata)
	mux.HandleFunc("/register", fi.register)
	mux.HandleFunc("/device", fi.deviceAuthorization)
	mux.HandleFunc("/token", fi.token)
	fi.server = httptest.NewTLSServer(mux)
	// Every httptest TLS server presents the same certificate, so this
	// client also reaches the fake director and registry.
	fi.client = fi.server.Client()
	t.Cleanup(fi.server.Close)
	return fi
}

func (fi *fakeIssuer) URL() string { return fi.server.URL }

func (fi *fakeIssuer) metadata(w http.ResponseWriter, _ *http.Request) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	tokenEndpoint := fi.URL() + "/token"
	if fi.insecureTokenEndpoint {
		tokenEndpoint = strings.Replace(tokenEndpoint, "https://", "http://", 1)
	}
	md := map[string]any{
		"issuer":                                fi.URL(),
		"token_endpoint":                        tokenEndpoint,
		"device_authorization_endpoint":         fi.URL() + "/device",
		"grant_types_supported":                 []string{grantTypeDeviceCode, grantTypeRefreshToken},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "private_key_jwt", "none"},
	}
	if fi.supportsDCR {
		md["registration_endpoint"] = fi.URL() + "/register"
	}
	if fi.supportsCIMD {
		md["client_id_metadata_document_supported"] = true
	}
	writeJSON(w, http.StatusOK, md)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": "fake issuer says " + code})
}

func (fi *fakeIssuer) register(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.seq++
	fi.registrations++
	id := fmt.Sprintf("dcr-client-%d", fi.seq)
	secret := fmt.Sprintf("dcr-secret-%d", fi.seq)
	fi.dcrClients[id] = secret
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_secret":              secret,
		"client_id_issued_at":        time.Now().Unix(),
		"client_secret_expires_at":   time.Now().Add(90 * 24 * time.Hour).Unix(),
		"registration_access_token":  "rat-" + id,
		"registration_client_uri":    fi.URL() + "/register/" + id,
		"grant_types":                req["grant_types"],
		"token_endpoint_auth_method": req["token_endpoint_auth_method"],
	})
}

// authenticateClient returns the authenticated client_id, or "" after writing
// an invalid_client response.
func (fi *fakeIssuer) authenticateClient(w http.ResponseWriter, r *http.Request) string {
	if id, secret, ok := r.BasicAuth(); ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		fi.mu.Lock()
		want, known := fi.dcrClients[id]
		fi.mu.Unlock()
		if !known || want != secret {
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return ""
		}
		return id
	}
	clientID := r.PostForm.Get("client_id")
	if r.PostForm.Get("client_assertion_type") != clientAssertionType || !fi.supportsCIMD || !strings.HasPrefix(clientID, "https://") {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return ""
	}
	doc, err := fi.fetchCIMD(clientID)
	if err != nil {
		fi.t.Logf("fake issuer: CIMD fetch failed: %v", err)
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return ""
	}
	if err := fi.verifyAssertion(r.PostForm.Get("client_assertion"), clientID, doc.JWKSURI); err != nil {
		fi.t.Logf("fake issuer: client assertion rejected: %v", err)
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return ""
	}
	return clientID
}

func (fi *fakeIssuer) fetchCIMD(clientID string) (*ClientIDMetadataDocument, error) {
	resp, err := fi.client.Get(clientID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	doc := &ClientIDMetadataDocument{}
	if err := json.NewDecoder(resp.Body).Decode(doc); err != nil {
		return nil, err
	}
	if doc.ClientID != clientID {
		return nil, fmt.Errorf("document names %q", doc.ClientID)
	}
	fi.mu.Lock()
	fi.cimdFetches++
	fi.cimdDocs[clientID] = doc
	fi.mu.Unlock()
	return doc, nil
}

func (fi *fakeIssuer) verifyAssertion(assertion, clientID, jwksURI string) error {
	resp, err := fi.client.Get(jwksURI)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks_uri returned HTTP %d", resp.StatusCode)
	}
	set, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return err
	}
	tok, err := jwt.Parse([]byte(assertion), jwt.WithKeySet(set), jwt.WithValidate(true),
		jwt.WithIssuer(clientID), jwt.WithSubject(clientID), jwt.WithAudience(fi.URL()))
	if err != nil {
		return err
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if tok.JwtID() == "" || fi.usedJTIs[tok.JwtID()] {
		return fmt.Errorf("replayed or missing jti %q", tok.JwtID())
	}
	fi.usedJTIs[tok.JwtID()] = true
	return nil
}

func (fi *fakeIssuer) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID := fi.authenticateClient(w, r)
	if clientID == "" {
		return
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.seq++
	code := fmt.Sprintf("device-%d", fi.seq)
	userCode := fmt.Sprintf("USER-%04d", fi.seq)
	fi.devices[code] = &fakeDevice{
		clientID: clientID,
		userCode: userCode,
		expires:  time.Now().Add(time.Duration(fi.deviceCodeLifetime) * time.Second),
		lastPoll: time.Now(),
	}
	fi.lastScope = r.PostForm.Get("scope")
	fi.lastAudience = r.PostForm.Get("audience")
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               code,
		"user_code":                 userCode,
		"verification_uri":          fi.URL() + "/activate",
		"verification_uri_complete": fi.URL() + "/activate?code=" + userCode,
		"expires_in":                fi.deviceCodeLifetime,
		"interval":                  1,
	})
}

// approve marks the device authorization carrying userCode as approved.
func (fi *fakeIssuer) approve(userCode string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	for _, d := range fi.devices {
		if d.userCode == userCode {
			d.approved = true
			return
		}
	}
	fi.t.Fatalf("fake issuer: no device authorization with user code %s", userCode)
}

func (fi *fakeIssuer) deny(userCode string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	for _, d := range fi.devices {
		if d.userCode == userCode {
			d.denied = true
		}
	}
}

// revokeAll invalidates every outstanding refresh token.
func (fi *fakeIssuer) revokeAll() {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.refreshTokens = map[string]string{}
}

func (fi *fakeIssuer) issueLocked(w http.ResponseWriter, clientID string, withRefresh bool) {
	fi.seq++
	access := fmt.Sprintf("access-%d", fi.seq)
	fi.accessTokens = append(fi.accessTokens, access)
	body := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   fi.accessTokenLifetime,
		"scope":        "offline_access storage.read:/",
	}
	if withRefresh {
		rt := fmt.Sprintf("refresh-%d", fi.seq)
		fi.refreshTokens[rt] = clientID
		body["refresh_token"] = rt
	}
	writeJSON(w, http.StatusOK, body)
}

func (fi *fakeIssuer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID := fi.authenticateClient(w, r)
	if clientID == "" {
		return
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	switch r.PostForm.Get("grant_type") {
	case grantTypeDeviceCode:
		if fi.failPolls > 0 {
			fi.failPolls--
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
			return
		}
		d, ok := fi.devices[r.PostForm.Get("device_code")]
		tooSoon := ok && fi.minPollInterval > 0 && time.Since(d.lastPoll) < fi.minPollInterval
		if ok {
			d.lastPoll = time.Now()
		}
		switch {
		case tooSoon:
			fi.slowDowns++
			oauthError(w, http.StatusBadRequest, errCodeSlowDown)
		case !ok || d.clientID != clientID:
			oauthError(w, http.StatusBadRequest, "invalid_grant")
		case time.Now().After(d.expires):
			oauthError(w, http.StatusBadRequest, "expired_token")
		case d.denied:
			oauthError(w, http.StatusBadRequest, "access_denied")
		case !d.approved:
			oauthError(w, http.StatusBadRequest, errCodeAuthorizationPending)
		default:
			delete(fi.devices, r.PostForm.Get("device_code"))
			fi.issueLocked(w, clientID, fi.issueRefreshTokens)
		}
	case grantTypeRefreshToken:
		fi.refreshAttempts++
		if fi.failRefreshes > 0 {
			fi.failRefreshes--
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
			return
		}
		rt := r.PostForm.Get("refresh_token")
		if owner, ok := fi.refreshTokens[rt]; !ok || owner != clientID {
			oauthError(w, http.StatusBadRequest, errCodeInvalidGrant)
			return
		}
		// Rotate: the presented refresh token dies.
		delete(fi.refreshTokens, rt)
		fi.refreshes++
		fi.issueLocked(w, clientID, true)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (fi *fakeIssuer) counts() (registrations, cimdFetches, refreshes int) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return fi.registrations, fi.cimdFetches, fi.refreshes
}

func (fi *fakeIssuer) attempts() (refreshAttempts, slowDowns int) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return fi.refreshAttempts, fi.slowDowns
}

// set runs f with the fake's lock held, for changing knobs while requests
// may be in flight.
func (fi *fakeIssuer) set(f func()) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	f()
}

func (fi *fakeIssuer) latestAccessToken() string {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if len(fi.accessTokens) == 0 {
		return ""
	}
	return fi.accessTokens[len(fi.accessTokens)-1]
}

// fakeFederation stands in for a director serving client ID metadata
// documents and a registry serving server JWKS.
type fakeFederation struct {
	server *httptest.Server
	key    jwk.Key

	mu        sync.Mutex
	serveCIMD bool
	serveJWKS bool
	// When set, the registry serves this key instead of key (a rotation the
	// registry has not caught up with).
	registryKey jwk.Key
}

func (ff *fakeFederation) set(f func()) {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	f()
}

func newFakeFederation(t *testing.T) *fakeFederation {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "server-key-1"))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.ES256))

	ff := &fakeFederation{key: key, serveCIMD: true, serveJWKS: true}
	mux := http.NewServeMux()
	mux.HandleFunc(ClientIDMetadataDocumentPath+"/", func(w http.ResponseWriter, r *http.Request) {
		ff.mu.Lock()
		serve := ff.serveCIMD
		ff.mu.Unlock()
		if !serve {
			http.NotFound(w, r)
			return
		}
		prefix := strings.TrimPrefix(r.URL.Path, ClientIDMetadataDocumentPath)
		doc, err := NewClientIDMetadataDocument(ff.server.URL, ff.server.URL, prefix, "test federation")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, doc)
	})
	mux.HandleFunc("/api/v1.0/registry/caches/test-cache/.well-known/issuer.jwks", func(w http.ResponseWriter, _ *http.Request) {
		ff.mu.Lock()
		serve, served := ff.serveJWKS, ff.key
		if ff.registryKey != nil {
			served = ff.registryKey
		}
		ff.mu.Unlock()
		if !serve {
			writeJSON(w, http.StatusForbidden, map[string]string{"msg": "The cache has not been approved by federation administrator"})
			return
		}
		pub, err := served.PublicKey()
		require.NoError(t, err)
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(pub))
		writeJSON(w, http.StatusOK, set)
	})
	ff.server = httptest.NewTLSServer(mux)
	t.Cleanup(ff.server.Close)
	return ff
}

func (ff *fakeFederation) cimdURL(t *testing.T) string {
	u, err := ClientIDMetadataDocumentURL(ff.server.URL, "/caches/test-cache")
	require.NoError(t, err)
	return u
}

func (ff *fakeFederation) signingKey() (jwk.Key, error) { return ff.key, nil }
