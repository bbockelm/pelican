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

// Package backendcred acquires and maintains long-lived OAuth credentials that
// a Pelican server uses to reach its own storage backends -- a WebDAV/HTTPS
// origin backend, a cache tiering target -- in place of a token file that an
// administrator has to keep fresh by hand.
//
// An administrator activates a credential from the server's web UI.  The
// server performs the OAuth 2.0 device authorization grant (RFC 8628) against
// the backend's issuer and shows the user code and verification URI; the
// administrator approves on any device, and the server keeps the resulting
// refresh token (encrypted at rest, as the Globus backend keeps its own) and
// refreshes access tokens ahead of their expiry.  Only outbound connections
// from the server to the issuer are needed, so this works for a site-local
// cache behind a firewall.
//
// The device flow needs an OAuth client.  In order of preference:
//
//  1. A client the administrator configured (client ID and optional secret).
//  2. A client ID metadata document (draft-ietf-oauth-client-id-metadata-
//     document) published by the federation's director, when the director
//     serves one for this server and the issuer advertises
//     client_id_metadata_document_supported.  The server authenticates with
//     private_key_jwt using its federation-registered key.
//  3. Dynamic client registration (RFC 7591) at the issuer's
//     registration_endpoint, with the resulting client kept alongside the
//     refresh token.
package backendcred

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	pelican_oauth2 "github.com/pelicanplatform/pelican/oauth2"
)

// ClientRegistrationMode selects how a credential's OAuth client is obtained
// when the administrator has not configured one.
type ClientRegistrationMode string

const (
	// Use the director's client ID metadata document when both the director
	// and the issuer support it, and dynamic client registration otherwise.
	ClientRegistrationAuto ClientRegistrationMode = "auto"
	// Require the client ID metadata document.
	ClientRegistrationCIMD ClientRegistrationMode = "cimd"
	// Require dynamic client registration.
	ClientRegistrationDCR ClientRegistrationMode = "dcr"
)

// ParseClientRegistrationMode accepts "", "auto", "cimd" and "dcr".
func ParseClientRegistrationMode(s string) (ClientRegistrationMode, error) {
	switch ClientRegistrationMode(s) {
	case "", ClientRegistrationAuto:
		return ClientRegistrationAuto, nil
	case ClientRegistrationCIMD, ClientRegistrationDCR:
		return ClientRegistrationMode(s), nil
	}
	return "", errors.Errorf("unknown client registration mode %q (expected auto, cimd or dcr)", s)
}

// Config describes one backend credential.
type Config struct {
	// ID names the credential in the database and the admin API.  It must be
	// stable across restarts and match [A-Za-z0-9][A-Za-z0-9._-]*.
	ID string
	// Owner is the server module the credential belongs to ("origin",
	// "cache"); each module's admin API lists only its own credentials.
	Owner string
	// DisplayName is shown to administrators.
	DisplayName string

	// Issuer is the OAuth issuer of the backend's tokens.
	Issuer string
	// Scopes are requested in the device authorization.  Include
	// offline_access (or the issuer's equivalent) or there will be no refresh
	// token to keep.
	Scopes []string
	// Audience, when set, is sent as the "audience" parameter (honored by
	// WLCG-profile issuers such as INDIGO IAM) on authorization and refresh.
	Audience string

	// ClientID and ClientSecret configure a pre-registered client.  When
	// ClientID is set, no client is registered; an empty ClientSecret makes it
	// a public client.
	ClientID     string
	ClientSecret string

	// RegistrationMode selects between CIMD and DCR when no client is
	// configured.  The zero value means ClientRegistrationAuto.
	RegistrationMode ClientRegistrationMode
	// ClientIDMetadataDocumentURL is this server's client_id under the
	// director's metadata documents (see ClientIDMetadataDocumentURL), or ""
	// when the server is not part of a federation.
	ClientIDMetadataDocumentURL string
	// SigningKey returns the key whose public half the registry serves for this
	// server; it signs private_key_jwt client assertions.
	SigningKey func() (jwk.Key, error)
	// ClientName is the client_name sent with a dynamic client registration.
	ClientName string

	// TokenSink, if set, receives every new access token, and "" when the
	// credential stops being usable.  It mirrors the token to wherever another
	// process (XRootD) reads it.
	TokenSink func(accessToken string) error

	// HTTPClient talks to the issuer and the director.  Defaults to a client
	// on config.GetTransport().
	HTTPClient *http.Client
}

var credentialIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// State is where a credential is in its lifecycle.
type State string

const (
	// No refresh token; an administrator must activate the credential.
	StateInactive State = "inactive"
	// A device flow is waiting for the administrator's approval.
	StatePending State = "pending"
	// A refresh token is held and the last refresh succeeded.
	StateActive State = "active"
	// A refresh token is held but the last refresh failed for a reason that
	// may pass (the issuer was unreachable); the manager keeps retrying.
	StateError State = "error"
)

// Status is a snapshot of a credential for administrators.  It never carries
// a token.
type Status struct {
	ID                      string             `json:"id"`
	DisplayName             string             `json:"displayName"`
	Issuer                  string             `json:"issuer"`
	State                   State              `json:"state"`
	Message                 string             `json:"message,omitempty"`
	RegistrationMethod      RegistrationMethod `json:"registrationMethod,omitempty"`
	ClientID                string             `json:"clientId,omitempty"`
	Scopes                  []string           `json:"scopes,omitempty"`
	GrantedScopes           []string           `json:"grantedScopes,omitempty"`
	ClientSecretExpiresAt   *time.Time         `json:"clientSecretExpiresAt,omitempty"`
	UserCode                string             `json:"userCode,omitempty"`
	VerificationURI         string             `json:"verificationUri,omitempty"`
	VerificationURIComplete string             `json:"verificationUriComplete,omitempty"`
	DeviceCodeExpiresAt     *time.Time         `json:"deviceCodeExpiresAt,omitempty"`
	AccessTokenExpiresAt    *time.Time         `json:"accessTokenExpiresAt,omitempty"`
	LastRefresh             *time.Time         `json:"lastRefresh,omitempty"`
	ActivatedBy             string             `json:"activatedBy,omitempty"`
	ActivatedAt             *time.Time         `json:"activatedAt,omitempty"`
}

// NotActivatedError reports that a credential has no refresh token.  Storage
// backends surface it as 503 Service Unavailable: the backend is fine, the
// server just has not been given access to it yet.
type NotActivatedError struct {
	ID     string
	Reason string
}

func (e *NotActivatedError) Error() string {
	msg := fmt.Sprintf("backend credential %s is not activated; an administrator must activate it from the web UI", e.ID)
	if e.Reason != "" {
		msg += " (" + e.Reason + ")"
	}
	return msg
}

func (e *NotActivatedError) HTTPStatusCode() int { return http.StatusServiceUnavailable }

// ErrNotActivated matches every *NotActivatedError under errors.Is.
var ErrNotActivated = errors.New("backend credential is not activated")

func (e *NotActivatedError) Is(target error) bool { return target == ErrNotActivated }

const (
	// An access token closer than this to expiry is not handed out.
	minTokenValidity = 30 * time.Second
	// Authorization server metadata is re-discovered after this long.
	metadataTTL = time.Hour
	// Lifetime assumed for an access token whose response omits expires_in.
	defaultTokenLifetime = time.Hour
	// Bounds on the retry delay after a failed background refresh.
	minRetryDelay = 15 * time.Second
	// After a failed refresh, on-demand refreshes wait this long before
	// contacting the issuer again.
	failureHoldoff = 5 * time.Second
	maxRetryDelay  = 5 * time.Minute
	// RFC 8628 section 3.5: the default polling interval, and the increase
	// on slow_down.
	defaultPollInterval = 5 * time.Second
	slowDownIncrement   = 5 * time.Second
	// The longest wait between device-code polls after transient failures.
	maxPollBackoff = time.Minute
	// A device authorization with no expires_in is abandoned after this.
	defaultDeviceCodeLifetime = 15 * time.Minute
)

type pendingFlow struct {
	cancel                  context.CancelFunc
	userCode                string
	verificationURI         string
	verificationURIComplete string
	expiresAt               time.Time
}

// Manager owns one backend credential.  It is safe for concurrent use.
type Manager struct {
	cfg        Config
	store      Store
	httpClient *http.Client

	// refreshSem (capacity 1) serializes token-endpoint refreshes, so that
	// concurrent callers of Token and the background loop redeem a (possibly
	// rotating) refresh token once, and serializes them against activation
	// and deactivation.  It is a channel rather than a mutex so that a caller
	// waiting for someone else's slow refresh can give up when its own
	// context ends.
	refreshSem chan struct{}

	mu           sync.Mutex
	runCtx       context.Context
	egrp         *errgroup.Group
	record       *Record
	accessToken  string
	accessExpiry time.Time
	lastRefresh  time.Time
	state        State
	message      string
	failures     int
	lastFailure  time.Time
	// grantedScope is the scope the issuer reported with the last token.
	grantedScope string
	// unsaved is set when the issuer rotated the refresh token but the new
	// one could not be stored; until a retry succeeds, a restart would lose
	// the credential.
	unsaved error
	// loadErr is set when the stored credential could not be read at
	// startup (for example, a locked database); the loop retries.
	loadErr      error
	loadFailures int
	pending      *pendingFlow
	metadata     *config.OauthIssuer
	metadataAt   time.Time
	// A dynamically registered client not yet attached to a refresh token,
	// reused by the next activation attempt rather than registering anew.
	spareDCRClient *Record

	wake chan struct{}

	// Test hooks.
	now               func() time.Time
	pollInterval      time.Duration
	slowDownIncrement time.Duration
}

// NewManager validates cfg and returns a manager for it.  Call Start before
// using it.
func NewManager(cfg Config, store Store) (*Manager, error) {
	if !credentialIDPattern.MatchString(cfg.ID) {
		return nil, errors.Errorf("invalid backend credential ID %q", cfg.ID)
	}
	if cfg.Issuer == "" {
		return nil, errors.Errorf("backend credential %s has no issuer configured", cfg.ID)
	}
	if err := requireHTTPS("issuer", cfg.Issuer); err != nil {
		return nil, errors.Wrapf(err, "backend credential %s", cfg.ID)
	}
	if store == nil {
		return nil, errors.New("a credential store is required")
	}
	mode, err := ParseClientRegistrationMode(string(cfg.RegistrationMode))
	if err != nil {
		return nil, err
	}
	cfg.RegistrationMode = mode
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.ID
	}
	if cfg.ClientName == "" {
		cfg.ClientName = "Pelican server (" + cfg.DisplayName + ")"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Transport: config.GetTransport()}
	}
	return &Manager{
		cfg:        cfg,
		store:      store,
		httpClient: hc,
		state:      StateInactive,
		refreshSem: make(chan struct{}, 1),
		wake:       make(chan struct{}, 1),
		now:        time.Now,

		slowDownIncrement: slowDownIncrement,
	}, nil
}

// requireHTTPS refuses a URL that would carry client secrets, assertions or
// tokens in cleartext (RFC 6749 sections 2.3.1 and 3.2, RFC 8628 section 3.1).
func requireHTTPS(what, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.Wrapf(err, "invalid %s URL %q", what, raw)
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.Errorf("the %s URL %q must be an https URL", what, raw)
	}
	return nil
}

// lockRefresh acquires refreshSem, or gives up when ctx ends.
func (m *Manager) lockRefresh(ctx context.Context) error {
	select {
	case m.refreshSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) unlockRefresh() { <-m.refreshSem }

// ID returns the credential's ID.
func (m *Manager) ID() string { return m.cfg.ID }

// Owner returns the module the credential belongs to.
func (m *Manager) Owner() string { return m.cfg.Owner }

// Start loads the stored credential and launches the background loop on
// egrp, which obtains the first access token.  It returns once the stored
// state is loaded, so a backend constructed afterwards sees the credential's
// real state, but it does not wait for the issuer: an unreachable issuer
// must not delay server startup.
func (m *Manager) Start(ctx context.Context, egrp *errgroup.Group) error {
	rec, err := m.loadRecord(ctx)

	m.mu.Lock()
	m.runCtx = ctx
	m.egrp = egrp
	m.applyLoadedLocked(rec, err)
	m.mu.Unlock()

	if err == nil && (rec == nil || rec.RefreshToken == "") {
		m.sink("")
	}

	egrp.Go(func() error {
		m.run(ctx)
		return nil
	})
	return nil
}

// loadRecord reads the stored credential, discarding it only when it can no
// longer be the configured credential: a different issuer, or a configured
// client that has changed.  Any other failure is returned with the row left
// alone -- a locked database or a briefly unreadable key directory must not
// cost the administrator a re-activation.
func (m *Manager) loadRecord(ctx context.Context) (*Record, error) {
	rec, err := m.store.Load(ctx, m.cfg.ID)
	if err != nil {
		return nil, err
	}
	if rec != nil && rec.Issuer != m.cfg.Issuer {
		log.Warningf("Backend credential %s was issued by %s but the configured issuer is now %s; it must be re-activated",
			m.cfg.ID, rec.Issuer, m.cfg.Issuer)
		if err := m.store.Delete(ctx, m.cfg.ID); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if rec != nil && rec.Method == RegistrationPreconfigured {
		if rec.ClientID != m.cfg.ClientID {
			log.Warningf("Backend credential %s was issued to client %s, which is no longer configured; it must be re-activated",
				m.cfg.ID, rec.ClientID)
			if err := m.store.Delete(ctx, m.cfg.ID); err != nil {
				return nil, err
			}
			return nil, nil
		}
		rec.ClientSecret = m.cfg.ClientSecret
	}
	return rec, nil
}

// applyLoadedLocked installs the result of loadRecord.
func (m *Manager) applyLoadedLocked(rec *Record, err error) {
	if err != nil {
		m.loadErr = err
		m.loadFailures++
		m.state = StateError
		m.message = fmt.Sprintf("The stored credential could not be loaded (%v); retrying.  Activating the credential again replaces it.", err)
		log.Errorf("Failed to load backend credential %s: %v", m.cfg.ID, err)
		return
	}
	m.loadErr = nil
	m.loadFailures = 0
	m.record = rec
	if rec == nil || rec.RefreshToken == "" {
		m.state = StateInactive
		m.message = "Not activated"
	} else {
		m.state = StateActive
		m.message = ""
	}
}

// Token returns a valid access token, refreshing it first if it is about to
// expire.  It returns an error matching ErrNotActivated when the credential
// has never been activated or its refresh token was revoked.
func (m *Manager) Token(ctx context.Context) (string, error) {
	if tok, ok := m.currentToken(); ok {
		return tok, nil
	}
	return m.refresh(ctx, false)
}

// Available reports whether the credential can currently produce tokens.
// A storage backend calls it to answer 503 before attempting a request it
// knows will be unauthenticated.
func (m *Manager) Available() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil || m.record.RefreshToken == "" {
		return &NotActivatedError{ID: m.cfg.ID, Reason: m.message}
	}
	return nil
}

func (m *Manager) currentToken() (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accessToken != "" && m.now().Add(m.validityMarginLocked()).Before(m.accessExpiry) {
		return m.accessToken, true
	}
	return "", false
}

// validityMarginLocked is how close to expiry the current access token may
// get before it is no longer handed out: minTokenValidity, but never more than
// a quarter of the token's lifetime, so that short-lived tokens are usable.
func (m *Manager) validityMarginLocked() time.Duration {
	return min(minTokenValidity, m.accessExpiry.Sub(m.lastRefresh)/4)
}

// Status returns a snapshot for administrators.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{
		ID:          m.cfg.ID,
		DisplayName: m.cfg.DisplayName,
		Issuer:      m.cfg.Issuer,
		State:       m.state,
		Message:     m.message,
		Scopes:      m.cfg.Scopes,
	}
	if m.record != nil {
		st.RegistrationMethod = m.record.Method
		st.ClientID = m.record.ClientID
		st.Scopes = m.record.Scopes
		if m.record.RefreshToken != "" {
			st.ActivatedBy = m.record.ActivatedBy
			if !m.record.ActivatedAt.IsZero() {
				at := m.record.ActivatedAt
				st.ActivatedAt = &at
			}
		}
	}
	if m.record != nil && !m.record.ClientSecretExpiresAt.IsZero() {
		exp := m.record.ClientSecretExpiresAt
		st.ClientSecretExpiresAt = &exp
	}
	if m.accessToken != "" {
		exp := m.accessExpiry
		st.AccessTokenExpiresAt = &exp
		if m.grantedScope != "" {
			st.GrantedScopes = strings.Fields(m.grantedScope)
		}
	}
	if !m.lastRefresh.IsZero() {
		lr := m.lastRefresh
		st.LastRefresh = &lr
	}
	if p := m.pending; p != nil {
		st.State = StatePending
		st.UserCode = p.userCode
		st.VerificationURI = p.verificationURI
		st.VerificationURIComplete = p.verificationURIComplete
		exp := p.expiresAt
		st.DeviceCodeExpiresAt = &exp
	}
	return st
}

// discover returns the issuer's metadata, re-fetching it when forced or stale.
func (m *Manager) discover(ctx context.Context, force bool) (*config.OauthIssuer, error) {
	m.mu.Lock()
	md, at := m.metadata, m.metadataAt
	m.mu.Unlock()
	if md != nil && !force && m.now().Sub(at) < metadataTTL {
		return md, nil
	}
	md, err := config.GetAuthServerMetadata(ctx, m.cfg.Issuer, m.httpClient)
	if err != nil {
		return nil, err
	}
	if md.TokenURL == "" {
		return nil, errors.Errorf("issuer %s does not advertise a token_endpoint", m.cfg.Issuer)
	}
	for _, ep := range []struct{ name, url string }{
		{"token_endpoint", md.TokenURL},
		{"device_authorization_endpoint", md.DeviceAuthURL},
		{"registration_endpoint", md.RegistrationURL},
	} {
		if ep.url == "" {
			continue
		}
		if err := requireHTTPS(ep.name, ep.url); err != nil {
			return nil, errors.Wrapf(err, "issuer %s", m.cfg.Issuer)
		}
	}
	m.mu.Lock()
	m.metadata, m.metadataAt = md, m.now()
	m.mu.Unlock()
	return md, nil
}

// authenticatorFor returns how the client in rec authenticates to md.
func (m *Manager) authenticatorFor(rec *Record, md *config.OauthIssuer) clientAuthenticator {
	switch {
	case rec.Method == RegistrationCIMD:
		return privateKeyJWTClient{clientID: rec.ClientID, audience: md.Issuer, key: m.cfg.SigningKey, now: m.now}
	case rec.ClientSecret != "":
		return secretBasicClient{clientID: rec.ClientID, clientSecret: rec.ClientSecret}
	default:
		return publicClient{clientID: rec.ClientID}
	}
}

func (m *Manager) tokenClientFor(rec *Record, md *config.OauthIssuer) *tokenClient {
	return &tokenClient{
		httpClient:    m.httpClient,
		tokenURL:      md.TokenURL,
		deviceAuthURL: md.DeviceAuthURL,
		auth:          m.authenticatorFor(rec, md),
	}
}

// refresh redeems the stored refresh token.
//
// Unless forced, it returns the current access token without contacting the
// issuer if the token is still comfortably valid -- which is the case when
// another caller refreshed while this one waited -- and, after a failure, it
// does not retry sooner than failureHoldoff, so that requests arriving while
// the issuer is down do not each hammer it.
//
// Only invalid_grant -- the issuer saying the refresh token itself is dead --
// gives up the credential.  Every other failure, including invalid_client,
// keeps the refresh token and retries with backoff: under a client ID
// metadata document, invalid_client is what an issuer reports when it could
// not fetch the director's document or the registry's keys, which is an
// outage on the federation's side, not a reason to make an administrator
// re-activate.
func (m *Manager) refresh(ctx context.Context, force bool) (string, error) {
	if err := m.lockRefresh(ctx); err != nil {
		return "", err
	}
	defer m.unlockRefresh()

	if !force {
		if tok, ok := m.currentToken(); ok {
			return tok, nil
		}
	}
	m.retryUnsavedLocked(ctx)
	m.mu.Lock()
	if m.record == nil || m.record.RefreshToken == "" {
		reason := m.message
		m.mu.Unlock()
		return "", &NotActivatedError{ID: m.cfg.ID, Reason: reason}
	}
	rec := *m.record
	staleToken, staleExpiry := m.accessToken, m.accessExpiry
	if !force && m.failures > 0 && m.now().Sub(m.lastFailure) < failureHoldoff {
		msg := m.message
		m.mu.Unlock()
		if staleToken != "" && m.now().Before(staleExpiry) {
			return staleToken, nil
		}
		return "", errors.Errorf("backend credential %s is unavailable: %s", m.cfg.ID, msg)
	}
	m.mu.Unlock()

	md, err := m.discover(ctx, false)
	var tr *tokenResponse
	if err == nil {
		tr, err = m.tokenClientFor(&rec, md).refresh(ctx, rec.RefreshToken, nil, m.cfg.Audience)
	}
	if err != nil {
		code := tokenErrorCode(err)
		if code == errCodeInvalidGrant {
			m.invalidate(ctx, fmt.Sprintf("The issuer no longer accepts the refresh token: %v", err))
			return "", &NotActivatedError{ID: m.cfg.ID, Reason: err.Error()}
		}
		msg := fmt.Sprintf("Refreshing the access token failed: %v; retrying", err)
		if code == errCodeInvalidClient || code == errCodeUnauthorizedClient {
			msg = fmt.Sprintf("The issuer rejected this server's client authentication (%v); retrying. %s", err, clientRejectionHint(&rec, m.now()))
		}
		m.mu.Lock()
		m.state = StateError
		m.message = msg
		m.failures++
		m.lastFailure = m.now()
		m.mu.Unlock()
		log.Warningf("Backend credential %s: %s", m.cfg.ID, msg)
		// An unexpired access token is still better than none.
		if staleToken != "" && m.now().Before(staleExpiry) {
			return staleToken, nil
		}
		return "", errors.Wrapf(err, "failed to refresh backend credential %s", m.cfg.ID)
	}

	var saveErr error
	if tr.RefreshToken != "" && tr.RefreshToken != rec.RefreshToken {
		// The issuer rotated the refresh token; the old one is now dead, so
		// the new one must be durable.  If the write fails, keep retrying it
		// (retryUnsavedLocked) rather than lose the credential at the next
		// restart.
		rec.RefreshToken = tr.RefreshToken
		saveErr = m.persist(ctx, &rec)
	}
	m.adoptToken(&rec, tr)
	if saveErr != nil {
		m.markUnsaved(saveErr)
	}
	return tr.AccessToken, nil
}

// clientRejectionHint suggests why an issuer refused the client's
// authentication.
func clientRejectionHint(rec *Record, now time.Time) string {
	switch rec.Method {
	case RegistrationCIMD:
		return "The issuer may be unable to fetch the client metadata document from the director, or this server's keys from the registry."
	case RegistrationDCR:
		if !rec.ClientSecretExpiresAt.IsZero() && now.After(rec.ClientSecretExpiresAt) {
			return "The registered client's secret expired; activate the credential again to register a new client."
		}
		return "The registered client may have been removed at the issuer; activate the credential again if this persists."
	}
	return "Check the configured client ID and secret."
}

// markUnsaved records that the in-memory refresh token is not yet durable.
func (m *Manager) markUnsaved(err error) {
	log.Errorf("Failed to store the rotated refresh token of backend credential %s (will retry): %v", m.cfg.ID, err)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unsaved = err
	m.state = StateError
	m.message = fmt.Sprintf("The issuer rotated the refresh token but storing it failed (%v); retrying.  Restarting the server before this succeeds would lose the credential.", err)
	m.nudgeLocked()
}

// retryUnsavedLocked retries storing a rotated refresh token.  The caller
// holds refreshSem.
func (m *Manager) retryUnsavedLocked(ctx context.Context) {
	m.mu.Lock()
	if m.unsaved == nil || m.record == nil {
		m.mu.Unlock()
		return
	}
	rec := *m.record
	m.mu.Unlock()
	if err := m.persist(ctx, &rec); err != nil {
		m.markUnsaved(err)
		return
	}
	m.mu.Lock()
	m.unsaved = nil
	if m.failures == 0 {
		m.state = StateActive
		m.message = ""
	}
	m.mu.Unlock()
	log.Infof("Stored the rotated refresh token of backend credential %s", m.cfg.ID)
}

// adoptToken installs a fresh token response as the current state.
func (m *Manager) adoptToken(rec *Record, tr *tokenResponse) {
	now := m.now()
	lifetime := defaultTokenLifetime
	if tr.ExpiresIn > 0 {
		lifetime = time.Duration(tr.ExpiresIn) * time.Second
	}
	m.mu.Lock()
	m.record = rec
	m.loadErr = nil
	m.accessToken = tr.AccessToken
	m.accessExpiry = now.Add(lifetime)
	m.lastRefresh = now
	m.grantedScope = tr.Scope
	m.state = StateActive
	m.message = ""
	m.failures = 0
	m.mu.Unlock()
	m.sink(tr.AccessToken)
	m.nudge()
}

// invalidate forgets the refresh token after the issuer declared it dead,
// keeping a dynamically registered client for the next activation.
func (m *Manager) invalidate(ctx context.Context, reason string) {
	m.mu.Lock()
	var rec *Record
	if m.record != nil && m.record.Method == RegistrationDCR {
		cp := *m.record
		cp.RefreshToken = ""
		cp.ActivatedBy = ""
		cp.ActivatedAt = time.Time{}
		rec = &cp
	}
	m.record = rec
	m.unsaved = nil
	m.accessToken = ""
	m.accessExpiry = time.Time{}
	m.state = StateInactive
	m.message = reason
	m.mu.Unlock()
	log.Errorf("Backend credential %s must be re-activated: %s", m.cfg.ID, reason)

	var err error
	if rec == nil {
		err = m.store.Delete(ctx, m.cfg.ID)
	} else {
		err = m.persist(ctx, rec)
	}
	if err != nil {
		log.Errorf("Failed to update stored backend credential %s: %v", m.cfg.ID, err)
	}
	m.sink("")
}

// persist saves rec.  A configured client's secret belongs to the
// configuration, so it is not copied into the database.
func (m *Manager) persist(ctx context.Context, rec *Record) error {
	stored := *rec
	if stored.Method == RegistrationPreconfigured {
		stored.ClientSecret = ""
	}
	return m.store.Save(ctx, &stored)
}

func (m *Manager) sink(token string) {
	if m.cfg.TokenSink == nil {
		return
	}
	if err := m.cfg.TokenSink(token); err != nil {
		log.Errorf("Failed to publish the access token of backend credential %s: %v", m.cfg.ID, err)
	}
}

func (m *Manager) nudge() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// nudgeLocked is nudge for callers holding mu (the channel send never
// blocks, so it is safe either way; the name documents intent).
func (m *Manager) nudgeLocked() { m.nudge() }

// retryDelay is the backoff after n consecutive failures.
func retryDelay(n int) time.Duration {
	return min(minRetryDelay<<min(max(n-1, 0), 5), maxRetryDelay)
}

// nextRefreshDelay is how long the background loop sleeps before its next
// refresh attempt; ok is false when there is nothing to refresh until woken.
func (m *Manager) nextRefreshDelay() (delay time.Duration, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil || m.record.RefreshToken == "" {
		return 0, false
	}
	now := m.now()
	if m.failures > 0 {
		return retryDelay(m.failures), true
	}
	if m.accessToken == "" {
		return 0, true
	}
	// Refresh three quarters of the way through the token's life, leaving
	// the last quarter for retries if the issuer is briefly unavailable --
	// and before the token stops being handed out.
	lifetime := m.accessExpiry.Sub(m.lastRefresh)
	refreshAt := m.lastRefresh.Add(lifetime * 3 / 4)
	if limit := m.accessExpiry.Add(-m.validityMarginLocked()); refreshAt.After(limit) {
		refreshAt = limit
	}
	return max(refreshAt.Sub(now), 0), true
}

// housekeepingDelay is when the loop should next retry a failed load or a
// failed write of a rotated refresh token; ok is false when neither is
// outstanding.
func (m *Manager) housekeepingDelay() (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil && m.record == nil {
		return retryDelay(m.loadFailures), true
	}
	if m.unsaved != nil {
		return minRetryDelay, true
	}
	return 0, false
}

// housekeep retries a failed load or a failed write.
func (m *Manager) housekeep(ctx context.Context) {
	m.mu.Lock()
	reload := m.loadErr != nil && m.record == nil
	m.mu.Unlock()
	if reload {
		if err := m.lockRefresh(ctx); err != nil {
			return
		}
		rec, err := m.loadRecord(ctx)
		m.mu.Lock()
		// An activation may have installed a credential meanwhile.
		if m.record == nil && m.loadErr != nil {
			m.applyLoadedLocked(rec, err)
		}
		m.mu.Unlock()
		m.unlockRefresh()
		return
	}
	if err := m.lockRefresh(ctx); err != nil {
		return
	}
	m.retryUnsavedLocked(ctx)
	m.unlockRefresh()
}

func (m *Manager) run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		delay, refreshOK := m.nextRefreshDelay()
		hkDelay, hkOK := m.housekeepingDelay()
		wait, ok := delay, refreshOK
		if hkOK && (!ok || hkDelay < wait) {
			wait, ok = hkDelay, true
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		var fire <-chan time.Time
		if ok {
			timer.Reset(wait)
			fire = timer.C
		}
		select {
		case <-ctx.Done():
			m.cancelPending()
			return
		case <-m.wake:
			continue
		case <-fire:
		}
		if _, hk := m.housekeepingDelay(); hk {
			m.housekeep(ctx)
		}
		if d, due := m.nextRefreshDelay(); due && d <= 0 {
			if _, err := m.refresh(ctx, true); err != nil && !errors.Is(err, ErrNotActivated) && ctx.Err() == nil {
				log.Warningf("Background refresh of backend credential %s failed: %v", m.cfg.ID, err)
			}
		}
	}
}

func (m *Manager) cancelPending() {
	m.mu.Lock()
	p := m.pending
	m.pending = nil
	m.mu.Unlock()
	if p != nil {
		p.cancel()
	}
}

// RefreshNow forces a refresh immediately, regardless of the current token's
// remaining lifetime.
func (m *Manager) RefreshNow(ctx context.Context) error {
	_, err := m.refresh(ctx, true)
	return err
}

// Deactivate forgets the credential: the refresh token, any registered client
// and any device flow in progress.  The backend stops receiving tokens.
func (m *Manager) Deactivate(ctx context.Context) error {
	m.cancelPending()
	if err := m.lockRefresh(ctx); err != nil {
		return err
	}
	defer m.unlockRefresh()
	if err := m.store.Delete(ctx, m.cfg.ID); err != nil {
		return err
	}
	m.mu.Lock()
	m.record = nil
	m.unsaved = nil
	m.loadErr = nil
	m.spareDCRClient = nil
	m.accessToken = ""
	m.accessExpiry = time.Time{}
	m.state = StateInactive
	m.message = "Deactivated by an administrator"
	m.failures = 0
	m.mu.Unlock()
	m.sink("")
	m.nudge()
	return nil
}

// BeginDeviceFlow starts the device authorization grant and returns the
// status carrying the user code and verification URI to show the
// administrator.  Polling continues in the background until the
// administrator approves, the code expires, or the server stops; the
// credential becomes active on approval.  actor is recorded as who activated
// it.
//
// Calling it while a flow is pending returns that flow rather than starting a
// second one.  An active credential keeps working until the new flow
// succeeds, so a re-activation that is never approved changes nothing.
func (m *Manager) BeginDeviceFlow(ctx context.Context, actor string) (Status, error) {
	m.mu.Lock()
	runCtx, egrp := m.runCtx, m.egrp
	pending := m.pending != nil && m.now().Before(m.pending.expiresAt)
	m.mu.Unlock()
	if runCtx == nil {
		return Status{}, errors.Errorf("backend credential %s has not been started", m.cfg.ID)
	}
	if runCtx.Err() != nil {
		return Status{}, errors.Errorf("backend credential %s is shutting down", m.cfg.ID)
	}
	if pending {
		return m.Status(), nil
	}

	md, err := m.discover(ctx, true)
	if err != nil {
		return Status{}, err
	}
	if md.DeviceAuthURL == "" {
		return Status{}, errors.Errorf("issuer %s does not support the device authorization grant (no device_authorization_endpoint)", m.cfg.Issuer)
	}
	client, err := m.chooseClient(ctx, md)
	if err != nil {
		return Status{}, err
	}
	tc := m.tokenClientFor(client, md)
	da, err := tc.authorizeDevice(ctx, m.cfg.Scopes, m.cfg.Audience)
	if err != nil {
		if client.Method == RegistrationDCR && tokenErrorCode(err) == errCodeInvalidClient {
			// A stored registration the issuer has since forgotten; the next
			// attempt registers afresh.
			m.mu.Lock()
			m.spareDCRClient = nil
			m.mu.Unlock()
		}
		return Status{}, err
	}

	lifetime := defaultDeviceCodeLifetime
	if da.ExpiresIn > 0 {
		lifetime = time.Duration(da.ExpiresIn) * time.Second
	}
	interval := defaultPollInterval
	if da.Interval > 0 {
		interval = time.Duration(da.Interval) * time.Second
	}
	if m.pollInterval > 0 {
		interval = m.pollInterval
	}
	flowCtx, cancel := context.WithDeadline(runCtx, m.now().Add(lifetime))
	flow := &pendingFlow{
		cancel:                  cancel,
		userCode:                da.UserCode,
		verificationURI:         da.VerificationURI,
		verificationURIComplete: da.VerificationURIComplete,
		expiresAt:               m.now().Add(lifetime),
	}

	m.mu.Lock()
	if m.pending != nil {
		// Lost a race with a concurrent BeginDeviceFlow; keep theirs.
		m.mu.Unlock()
		cancel()
		return m.Status(), nil
	}
	m.pending = flow
	m.mu.Unlock()

	log.Infof("Device authorization for backend credential %s started by %s; waiting for approval at %s",
		m.cfg.ID, actor, da.VerificationURI)
	egrp.Go(func() error {
		m.pollDevice(flowCtx, flow, tc, client, da.DeviceCode, interval, actor)
		return nil
	})
	return m.Status(), nil
}

// chooseClient returns the OAuth client for a new activation: configured,
// then CIMD, then DCR, as the package documentation describes.
func (m *Manager) chooseClient(ctx context.Context, md *config.OauthIssuer) (*Record, error) {
	base := Record{ID: m.cfg.ID, Issuer: m.cfg.Issuer, Scopes: m.cfg.Scopes}
	if m.cfg.ClientID != "" {
		base.Method = RegistrationPreconfigured
		base.ClientID = m.cfg.ClientID
		base.ClientSecret = m.cfg.ClientSecret
		return &base, nil
	}

	mode := m.cfg.RegistrationMode
	var cimdReason string
	if mode == ClientRegistrationAuto || mode == ClientRegistrationCIMD {
		switch {
		case m.cfg.ClientIDMetadataDocumentURL == "":
			cimdReason = "this server has no federation director to publish a client metadata document"
		case !md.ClientIDMetadataDocumentSupported:
			cimdReason = fmt.Sprintf("issuer %s does not advertise client_id_metadata_document_supported", m.cfg.Issuer)
		case len(md.TokenEndpointAuthMethods) > 0 && !slices.Contains(md.TokenEndpointAuthMethods, authMethodPrivateKeyJWT):
			cimdReason = fmt.Sprintf("issuer %s does not accept private_key_jwt client authentication", m.cfg.Issuer)
		case m.cfg.SigningKey == nil:
			cimdReason = "no signing key is configured for client assertions"
		default:
			if reason := m.cimdUnusableReason(ctx, md); reason != "" {
				cimdReason = reason
			} else {
				base.Method = RegistrationCIMD
				base.ClientID = m.cfg.ClientIDMetadataDocumentURL
				return &base, nil
			}
		}
		if mode == ClientRegistrationCIMD {
			return nil, errors.Errorf("a client ID metadata document cannot be used: %s", cimdReason)
		}
		log.Infof("Backend credential %s will use dynamic client registration: %s", m.cfg.ID, cimdReason)
	}

	// Reuse a client registered earlier for this issuer.
	m.mu.Lock()
	for _, cand := range []*Record{m.record, m.spareDCRClient} {
		if cand != nil && cand.Method == RegistrationDCR && cand.Issuer == m.cfg.Issuer && cand.ClientID != "" {
			reuse := *cand
			reuse.RefreshToken = ""
			reuse.Scopes = m.cfg.Scopes
			m.mu.Unlock()
			return &reuse, nil
		}
	}
	m.mu.Unlock()

	if md.RegistrationURL == "" {
		if cimdReason != "" {
			return nil, errors.Errorf("issuer %s supports neither dynamic client registration nor a client ID metadata document usable by this server (%s); configure a client ID instead", m.cfg.Issuer, cimdReason)
		}
		return nil, errors.Errorf("issuer %s does not support dynamic client registration; configure a client ID instead", m.cfg.Issuer)
	}
	dcr := pelican_oauth2.DCRPConfig{
		ClientRegistrationEndpointURL: md.RegistrationURL,
		Transport:                     m.httpClient.Transport,
		Metadata: pelican_oauth2.Metadata{
			TokenEndpointAuthMethod: authMethodSecretBasic,
			GrantTypes:              []string{grantTypeDeviceCode, grantTypeRefreshToken},
			ClientName:              m.cfg.ClientName,
			Scopes:                  m.cfg.Scopes,
			SoftwareID:              pelicanSoftwareID,
		},
	}
	resp, err := dcr.Register()
	if err != nil {
		return nil, errors.Wrapf(err, "dynamic client registration with %s failed", md.RegistrationURL)
	}
	base.Method = RegistrationDCR
	base.ClientID = resp.ClientID
	base.ClientSecret = resp.ClientSecret
	base.RegistrationAccessToken = resp.RegistrationAccessToken
	base.RegistrationClientURI = resp.RegistrationClientURI
	if resp.ClientSecret != "" && resp.ClientSecretExpiresAt.Unix() > 0 {
		base.ClientSecretExpiresAt = resp.ClientSecretExpiresAt
	}
	m.mu.Lock()
	spare := base
	m.spareDCRClient = &spare
	m.mu.Unlock()
	log.Infof("Registered OAuth client %s with %s for backend credential %s", resp.ClientID, m.cfg.Issuer, m.cfg.ID)
	return &base, nil
}

// cimdUnusableReason checks everything an issuer will check before it
// accepts this server's client ID metadata document, returning why it would
// not ("" if it would): the director must serve a valid document, the
// registry must serve this server's current public key at the document's
// jwks_uri (it does not for a server awaiting approval, or just after a key
// rotation it has not yet seen), and the issuer must accept the key's
// signing algorithm.  Checking up front lets an activation fall back to
// dynamic client registration instead of failing at the issuer.
func (m *Manager) cimdUnusableReason(ctx context.Context, md *config.OauthIssuer) string {
	doc, err := fetchClientIDMetadataDocument(ctx, m.httpClient, m.cfg.ClientIDMetadataDocumentURL)
	if err != nil {
		return err.Error()
	}
	key, err := m.cfg.SigningKey()
	if err != nil {
		return fmt.Sprintf("the client assertion signing key is unavailable: %v", err)
	}
	if len(md.TokenEndpointAuthSigningAlgs) > 0 {
		alg, err := config.SigningAlgorithmForJWK(key)
		if err != nil {
			return fmt.Sprintf("cannot determine the signing algorithm of this server's key: %v", err)
		}
		if !slices.Contains(md.TokenEndpointAuthSigningAlgs, alg.String()) {
			return fmt.Sprintf("issuer %s does not accept %s client assertions", m.cfg.Issuer, alg)
		}
	}
	if err := jwksServesKey(ctx, m.httpClient, doc.JWKSURI, key); err != nil {
		return err.Error()
	}
	return ""
}

// installDeviceToken makes the token from an approved device flow the
// credential.  It holds refreshSem so that it cannot interleave with a refresh
// or a Deactivate: a flow cancelled by Deactivate must not resurrect the
// credential it was meant to discard.
func (m *Manager) installDeviceToken(ctx context.Context, flow *pendingFlow, client *Record, tr *tokenResponse, actor string, finish func(State, string)) {
	if err := m.lockRefresh(ctx); err != nil {
		finish(StateInactive, "The device authorization was cancelled")
		return
	}
	defer m.unlockRefresh()

	m.mu.Lock()
	current := m.pending == flow
	m.mu.Unlock()
	if !current {
		log.Warningf("Discarding a device authorization for backend credential %s that was cancelled as it completed", m.cfg.ID)
		return
	}

	rec := *client
	rec.RefreshToken = tr.RefreshToken
	rec.ActivatedBy = actor
	rec.ActivatedAt = m.now()
	if err := m.persist(ctx, &rec); err != nil {
		finish(StateInactive, fmt.Sprintf("Failed to store the new credential: %v", err))
		return
	}
	m.mu.Lock()
	m.unsaved = nil
	m.mu.Unlock()
	m.mu.Lock()
	if m.pending == flow {
		m.pending = nil
	}
	if rec.Method == RegistrationDCR {
		m.spareDCRClient = nil
	}
	m.mu.Unlock()
	m.adoptToken(&rec, tr)
	log.Infof("Backend credential %s activated by %s", m.cfg.ID, actor)
}

// pollDevice waits for the administrator's approval and installs the result.
func (m *Manager) pollDevice(ctx context.Context, flow *pendingFlow, tc *tokenClient, client *Record, deviceCode string, interval time.Duration, actor string) {
	defer flow.cancel()
	finish := func(state State, msg string) {
		m.mu.Lock()
		if m.pending == flow {
			m.pending = nil
		}
		// A failed re-activation leaves a working credential working.
		if state != StateActive && (m.record == nil || m.record.RefreshToken == "") {
			m.state = state
			m.message = msg
		} else if state != StateActive {
			log.Warningf("Re-activation of backend credential %s did not complete (%s); keeping the existing credential", m.cfg.ID, msg)
		}
		m.mu.Unlock()
	}

	// Consecutive failures that say nothing about the authorization itself
	// (network errors, 5xx, 429): polling backs off and continues until the
	// device code expires, so an issuer blip does not waste an approval the
	// administrator may already have given (RFC 8628 section 3.5).
	transient := 0
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				finish(StateInactive, "The device code expired before it was approved")
			} else {
				finish(StateInactive, "The device authorization was cancelled")
			}
			return
		case <-timer.C:
		}

		tr, err := tc.pollDeviceToken(ctx, deviceCode)
		if err == nil {
			if tr.RefreshToken == "" {
				finish(StateInactive, "The issuer approved the request but issued no refresh token; make sure the requested scopes include offline_access and that the issuer allows refresh tokens for this client")
				return
			}
			m.installDeviceToken(ctx, flow, client, tr, actor, finish)
			return
		}

		if ctx.Err() != nil {
			continue // reported by the ctx.Done branch
		}
		wait := interval
		var te *TokenError
		switch {
		case tokenErrorCode(err) == errCodeAuthorizationPending:
			transient = 0
		case tokenErrorCode(err) == errCodeSlowDown:
			transient = 0
			interval += m.slowDownIncrement
			wait = interval
		case errors.As(err, &te) && te.StatusCode >= 400 && te.StatusCode < 500 && te.StatusCode != http.StatusTooManyRequests:
			// access_denied, expired_token, invalid_grant, invalid_client...:
			// the issuer has decided.
			finish(StateInactive, fmt.Sprintf("Device authorization failed: %v", err))
			return
		default:
			transient++
			wait = min(interval<<min(transient, 4), maxPollBackoff)
			log.Warningf("Polling the issuer for backend credential %s failed (attempt %d); retrying in %s: %v",
				m.cfg.ID, transient, wait, err)
		}
		timer.Reset(wait)
	}
}
