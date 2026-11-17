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
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// setupStore returns a store on a freshly migrated database, with an issuer
// key available to encrypt the stored secrets.
func setupStore(t *testing.T) (Store, *gorm.DB) {
	t.Helper()
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.IssuerKeysDirectory.Set(filepath.Join(t.TempDir(), "issuer-keys")))

	db, err := utils.InitSQLiteDB(filepath.Join(t.TempDir(), "server.sqlite"))
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, utils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	return NewDBStore(db), db
}

// tokenRecorder collects what a manager publishes through TokenSink.
type tokenRecorder struct {
	mu     sync.Mutex
	tokens []string
}

func (r *tokenRecorder) sink(tok string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens = append(r.tokens, tok)
	return nil
}

func (r *tokenRecorder) last() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.tokens) == 0 {
		return "", false
	}
	return r.tokens[len(r.tokens)-1], true
}

type testEnv struct {
	issuer *fakeIssuer
	fed    *fakeFederation
	store  Store
	db     *gorm.DB
	sink   *tokenRecorder
}

func newTestEnv(t *testing.T) *testEnv {
	store, db := setupStore(t)
	return &testEnv{
		issuer: newFakeIssuer(t),
		fed:    newFakeFederation(t),
		store:  store,
		db:     db,
		sink:   &tokenRecorder{},
	}
}

func (e *testEnv) config(t *testing.T) Config {
	return Config{
		ID:                          "test-backend",
		Owner:                       "cache",
		DisplayName:                 "Test backend",
		Issuer:                      e.issuer.URL(),
		Scopes:                      []string{"offline_access", "storage.read:/"},
		ClientIDMetadataDocumentURL: e.fed.cimdURL(t),
		SigningKey:                  e.fed.signingKey,
		TokenSink:                   e.sink.sink,
		HTTPClient:                  e.issuer.client,
	}
}

// startManager starts a manager whose lifetime ends with the test.
func startManager(t *testing.T, cfg Config, store Store, tweaks ...func(*Manager)) *Manager {
	t.Helper()
	m, err := NewManager(cfg, store)
	require.NoError(t, err)
	m.pollInterval = 10 * time.Millisecond
	for _, tweak := range tweaks {
		tweak(m)
	}
	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)
	require.NoError(t, m.Start(ctx, egrp))
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
	})
	return m
}

// activate runs a device flow to completion and returns the user code used.
func activate(t *testing.T, m *Manager, fi *fakeIssuer) Status {
	t.Helper()
	st, err := m.BeginDeviceFlow(context.Background(), "admin-user")
	require.NoError(t, err)
	require.Equal(t, StatePending, st.State)
	require.NotEmpty(t, st.UserCode)
	require.NotEmpty(t, st.VerificationURI)
	require.NotNil(t, st.DeviceCodeExpiresAt)
	fi.approve(st.UserCode)
	require.Eventually(t, func() bool { return m.Status().State == StateActive }, 10*time.Second, 10*time.Millisecond)
	return m.Status()
}

func TestDeviceFlowWithDynamicRegistration(t *testing.T) {
	env := newTestEnv(t)
	// The director publishes a document, but the issuer does not do CIMD:
	// the manager must fall back to DCR.
	env.issuer.supportsCIMD = false
	m := startManager(t, env.config(t), env.store)

	_, err := m.Token(context.Background())
	require.ErrorIs(t, err, ErrNotActivated)
	var nae *NotActivatedError
	require.ErrorAs(t, m.Available(), &nae)
	assert.Equal(t, 503, nae.HTTPStatusCode())
	assert.Equal(t, StateInactive, m.Status().State)

	st := activate(t, m, env.issuer)
	assert.Equal(t, RegistrationDCR, st.RegistrationMethod)
	assert.Equal(t, "admin-user", st.ActivatedBy)
	assert.Equal(t, "offline_access storage.read:/", env.issuer.lastScope)
	assert.Equal(t, []string{"offline_access", "storage.read:/"}, st.GrantedScopes)
	require.NotNil(t, st.ClientSecretExpiresAt, "the DCR secret's expiry is recorded")
	assert.True(t, st.ClientSecretExpiresAt.After(time.Now().Add(80*24*time.Hour)))
	require.NoError(t, m.Available())

	tok, err := m.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, env.issuer.latestAccessToken(), tok)
	published, _ := env.sink.last()
	assert.Equal(t, tok, published)

	registrations, cimdFetches, _ := env.issuer.counts()
	assert.Equal(t, 1, registrations)
	assert.Zero(t, cimdFetches)

	// Secrets are encrypted at rest.
	var row credentialRow
	require.NoError(t, env.db.Where("id = ?", "test-backend").Take(&row).Error)
	assert.NotEmpty(t, row.RefreshToken)
	assert.NotContains(t, row.RefreshToken, "refresh-")
	assert.NotContains(t, row.ClientSecret, "dcr-secret-")
	assert.Equal(t, string(RegistrationDCR), row.RegistrationMethod)
}

func TestDeviceFlowWithClientIDMetadataDocument(t *testing.T) {
	env := newTestEnv(t)
	env.issuer.supportsCIMD = true
	m := startManager(t, env.config(t), env.store)

	st := activate(t, m, env.issuer)
	assert.Equal(t, RegistrationCIMD, st.RegistrationMethod)
	assert.Equal(t, env.fed.cimdURL(t), st.ClientID)

	registrations, cimdFetches, _ := env.issuer.counts()
	assert.Zero(t, registrations, "CIMD must not register a client")
	assert.Positive(t, cimdFetches)

	// Refreshing authenticates with a fresh assertion each time; the fake
	// issuer rejects a reused jti.
	require.NoError(t, m.RefreshNow(context.Background()))
	require.NoError(t, m.RefreshNow(context.Background()))
	tok, err := m.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, env.issuer.latestAccessToken(), tok)

	var row credentialRow
	require.NoError(t, env.db.Where("id = ?", "test-backend").Take(&row).Error)
	assert.Empty(t, row.ClientSecret, "a CIMD client has no secret to store")
}

func TestFallsBackToDCRWhenDirectorHasNoDocument(t *testing.T) {
	env := newTestEnv(t)
	env.issuer.supportsCIMD = true
	env.fed.set(func() { env.fed.serveCIMD = false })
	m := startManager(t, env.config(t), env.store)

	st := activate(t, m, env.issuer)
	assert.Equal(t, RegistrationDCR, st.RegistrationMethod)
}

func TestFallsBackToDCRWithoutFederation(t *testing.T) {
	env := newTestEnv(t)
	env.issuer.supportsCIMD = true
	cfg := env.config(t)
	cfg.ClientIDMetadataDocumentURL = ""
	m := startManager(t, cfg, env.store)

	st := activate(t, m, env.issuer)
	assert.Equal(t, RegistrationDCR, st.RegistrationMethod)
}

func TestRequiredCIMDFailsWhenUnsupported(t *testing.T) {
	env := newTestEnv(t)
	env.issuer.supportsCIMD = false
	cfg := env.config(t)
	cfg.RegistrationMode = ClientRegistrationCIMD
	m := startManager(t, cfg, env.store)

	_, err := m.BeginDeviceFlow(context.Background(), "admin")
	require.ErrorContains(t, err, "client_id_metadata_document_supported")
	registrations, _, _ := env.issuer.counts()
	assert.Zero(t, registrations)
}

func TestNoUsableRegistrationMethod(t *testing.T) {
	env := newTestEnv(t)
	env.issuer.supportsCIMD = false
	env.issuer.supportsDCR = false
	m := startManager(t, env.config(t), env.store)

	_, err := m.BeginDeviceFlow(context.Background(), "admin")
	require.ErrorContains(t, err, "neither dynamic client registration nor a client ID metadata document")
	assert.Equal(t, StateInactive, m.Status().State)
}

func TestPreconfiguredClient(t *testing.T) {
	env := newTestEnv(t)
	env.issuer.supportsCIMD = true
	env.issuer.dcrClients["admin-made"] = "s3cret"
	cfg := env.config(t)
	cfg.ClientID = "admin-made"
	cfg.ClientSecret = "s3cret"
	m := startManager(t, cfg, env.store)

	st := activate(t, m, env.issuer)
	assert.Equal(t, RegistrationPreconfigured, st.RegistrationMethod)
	assert.Equal(t, "admin-made", st.ClientID)
	registrations, cimdFetches, _ := env.issuer.counts()
	assert.Zero(t, registrations)
	assert.Zero(t, cimdFetches)

	var row credentialRow
	require.NoError(t, env.db.Where("id = ?", "test-backend").Take(&row).Error)
	assert.Empty(t, row.ClientSecret, "a configured secret stays in the configuration, not the database")
}

func TestRotatedRefreshTokenSurvivesRestart(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.config(t)

	m, err := NewManager(cfg, env.store)
	require.NoError(t, err)
	m.pollInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	egrp, gctx := errgroup.WithContext(ctx)
	require.NoError(t, m.Start(gctx, egrp))
	activate(t, m, env.issuer)
	// Each refresh rotates the refresh token and kills the old one.
	require.NoError(t, m.RefreshNow(context.Background()))
	require.NoError(t, m.RefreshNow(context.Background()))
	cancel()
	require.NoError(t, egrp.Wait())

	_, _, before := env.issuer.counts()
	restarted := startManager(t, cfg, env.store)
	assert.Equal(t, StateActive, restarted.Status().State)
	// The first access token is fetched by the background loop, not by
	// Start, so that an unreachable issuer cannot delay server startup.
	require.Eventually(t, func() bool {
		_, _, after := env.issuer.counts()
		return after == before+1 && restarted.Status().AccessTokenExpiresAt != nil
	}, 10*time.Second, 10*time.Millisecond)
	tok, err := restarted.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, env.issuer.latestAccessToken(), tok)
	assert.Equal(t, "admin-user", restarted.Status().ActivatedBy)
}

func TestRevokedRefreshTokenRequiresReactivation(t *testing.T) {
	env := newTestEnv(t)
	m := startManager(t, env.config(t), env.store)
	activate(t, m, env.issuer)

	env.issuer.revokeAll()
	err := m.RefreshNow(context.Background())
	require.ErrorIs(t, err, ErrNotActivated)
	st := m.Status()
	assert.Equal(t, StateInactive, st.State)
	assert.Contains(t, st.Message, "invalid_grant")
	_, err = m.Token(context.Background())
	require.ErrorIs(t, err, ErrNotActivated)
	published, _ := env.sink.last()
	assert.Empty(t, published, "the published token is withdrawn")

	// The registered client is kept, so re-activation does not register again.
	activate(t, m, env.issuer)
	registrations, _, _ := env.issuer.counts()
	assert.Equal(t, 1, registrations)
}

func TestBackgroundRefreshBeforeExpiry(t *testing.T) {
	env := newTestEnv(t)
	env.issuer.accessTokenLifetime = 2
	m := startManager(t, env.config(t), env.store)
	activate(t, m, env.issuer)
	first, err := m.Token(context.Background())
	require.NoError(t, err)

	// With a 2s lifetime the loop refreshes at 1.5s, without any caller.
	require.Eventually(t, func() bool {
		_, _, refreshes := env.issuer.counts()
		return refreshes >= 2
	}, 10*time.Second, 50*time.Millisecond)
	published, _ := env.sink.last()
	assert.NotEqual(t, first, published)
}

func TestDeviceFlowOutcomes(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		env := newTestEnv(t)
		m := startManager(t, env.config(t), env.store)
		st, err := m.BeginDeviceFlow(context.Background(), "admin")
		require.NoError(t, err)
		// A second call while pending returns the same flow.
		again, err := m.BeginDeviceFlow(context.Background(), "admin")
		require.NoError(t, err)
		assert.Equal(t, st.UserCode, again.UserCode)

		env.issuer.deny(st.UserCode)
		require.Eventually(t, func() bool { return m.Status().State == StateInactive }, 10*time.Second, 10*time.Millisecond)
		assert.Contains(t, m.Status().Message, "access_denied")
	})

	t.Run("expired", func(t *testing.T) {
		env := newTestEnv(t)
		env.issuer.deviceCodeLifetime = 1
		m := startManager(t, env.config(t), env.store)
		_, err := m.BeginDeviceFlow(context.Background(), "admin")
		require.NoError(t, err)
		require.Eventually(t, func() bool { return m.Status().State == StateInactive }, 10*time.Second, 10*time.Millisecond)
		assert.Contains(t, m.Status().Message, "expired")
	})

	t.Run("no refresh token", func(t *testing.T) {
		env := newTestEnv(t)
		env.issuer.issueRefreshTokens = false
		m := startManager(t, env.config(t), env.store)
		st, err := m.BeginDeviceFlow(context.Background(), "admin")
		require.NoError(t, err)
		env.issuer.approve(st.UserCode)
		require.Eventually(t, func() bool {
			s := m.Status()
			return s.State == StateInactive && s.Message != "Not activated"
		}, 10*time.Second, 10*time.Millisecond)
		assert.Contains(t, m.Status().Message, "offline_access")
		_, err = m.Token(context.Background())
		require.ErrorIs(t, err, ErrNotActivated)
	})

	t.Run("failed reactivation keeps working credential", func(t *testing.T) {
		env := newTestEnv(t)
		m := startManager(t, env.config(t), env.store)
		activate(t, m, env.issuer)
		st, err := m.BeginDeviceFlow(context.Background(), "admin")
		require.NoError(t, err)
		env.issuer.deny(st.UserCode)
		require.Eventually(t, func() bool { return m.Status().State == StateActive }, 10*time.Second, 10*time.Millisecond)
		_, err = m.Token(context.Background())
		require.NoError(t, err)
	})
}

func TestDeactivate(t *testing.T) {
	env := newTestEnv(t)
	m := startManager(t, env.config(t), env.store)
	activate(t, m, env.issuer)

	require.NoError(t, m.Deactivate(context.Background()))
	assert.Equal(t, StateInactive, m.Status().State)
	_, err := m.Token(context.Background())
	require.ErrorIs(t, err, ErrNotActivated)
	rec, err := env.store.Load(context.Background(), "test-backend")
	require.NoError(t, err)
	assert.Nil(t, rec)
}

func TestIssuerChangeDiscardsCredential(t *testing.T) {
	env := newTestEnv(t)
	require.NoError(t, env.store.Save(context.Background(), &Record{
		ID: "test-backend", Issuer: "https://old-issuer.example", Method: RegistrationDCR,
		ClientID: "old", ClientSecret: "old-secret", RefreshToken: "old-refresh",
	}))
	m := startManager(t, env.config(t), env.store)
	assert.Equal(t, StateInactive, m.Status().State)
	rec, err := env.store.Load(context.Background(), "test-backend")
	require.NoError(t, err)
	assert.Nil(t, rec)
}

func TestAudienceIsRequested(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.config(t)
	cfg.Audience = "https://storage.example.org"
	m := startManager(t, cfg, env.store)
	activate(t, m, env.issuer)
	env.issuer.mu.Lock()
	defer env.issuer.mu.Unlock()
	assert.Equal(t, "https://storage.example.org", env.issuer.lastAudience)
}

func TestNewManagerValidation(t *testing.T) {
	store, _ := setupStore(t)
	_, err := NewManager(Config{ID: "../etc", Issuer: "https://x"}, store)
	require.Error(t, err)
	_, err = NewManager(Config{ID: "ok"}, store)
	require.Error(t, err)
	_, err = NewManager(Config{ID: "ok", Issuer: "https://x", RegistrationMode: "bogus"}, store)
	require.Error(t, err)
	_, err = NewManager(Config{ID: "ok", Issuer: "https://x"}, nil)
	require.Error(t, err)
}
