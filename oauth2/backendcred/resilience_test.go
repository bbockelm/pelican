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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file cover how a credential survives failures: of the
// federation services a CIMD client depends on, of the issuer, and of the
// server's own database.

// storedRefreshToken returns the refresh token in the store.
func storedRefreshToken(t *testing.T, store Store) string {
	t.Helper()
	rec, err := store.Load(context.Background(), "test-backend")
	require.NoError(t, err)
	if rec == nil {
		return ""
	}
	return rec.RefreshToken
}

func TestClientAuthenticationFailureKeepsCredential(t *testing.T) {
	t.Run("cimd document unavailable", func(t *testing.T) {
		env := newTestEnv(t)
		env.issuer.supportsCIMD = true
		m := startManager(t, env.config(t), env.store)
		st := activate(t, m, env.issuer)
		require.Equal(t, RegistrationCIMD, st.RegistrationMethod)

		// The director stops serving the document for one refresh: the
		// issuer answers invalid_client.  That is an outage on the
		// federation's side and must not cost the refresh token.
		env.fed.set(func() { env.fed.serveCIMD = false })
		require.NoError(t, m.RefreshNow(context.Background()), "the still-valid access token is served")
		st = m.Status()
		assert.Equal(t, StateError, st.State)
		assert.Contains(t, st.Message, "client authentication")
		assert.Contains(t, st.Message, "client metadata document")
		assert.NotEmpty(t, storedRefreshToken(t, env.store))
		require.NoError(t, m.Available())

		env.fed.set(func() { env.fed.serveCIMD = true })
		require.NoError(t, m.RefreshNow(context.Background()))
		assert.Equal(t, StateActive, m.Status().State)
		assert.Empty(t, m.Status().Message)
	})

	t.Run("dcr client forgotten", func(t *testing.T) {
		env := newTestEnv(t)
		m := startManager(t, env.config(t), env.store)
		st := activate(t, m, env.issuer)
		require.Equal(t, RegistrationDCR, st.RegistrationMethod)

		env.issuer.set(func() { delete(env.issuer.dcrClients, st.ClientID) })
		require.NoError(t, m.RefreshNow(context.Background()))
		assert.Equal(t, StateError, m.Status().State)
		assert.Contains(t, m.Status().Message, "client authentication")
		assert.NotEmpty(t, storedRefreshToken(t, env.store))
	})
}

func TestCIMDNeedsTheRegistryToServeTheKey(t *testing.T) {
	t.Run("not approved", func(t *testing.T) {
		env := newTestEnv(t)
		env.issuer.supportsCIMD = true
		env.fed.set(func() { env.fed.serveJWKS = false })
		m := startManager(t, env.config(t), env.store)
		st := activate(t, m, env.issuer)
		assert.Equal(t, RegistrationDCR, st.RegistrationMethod)
	})

	t.Run("rotation not yet registered", func(t *testing.T) {
		env := newTestEnv(t)
		env.issuer.supportsCIMD = true
		raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		other, err := jwk.FromRaw(raw)
		require.NoError(t, err)
		env.fed.set(func() { env.fed.registryKey = other })
		m := startManager(t, env.config(t), env.store)
		st := activate(t, m, env.issuer)
		assert.Equal(t, RegistrationDCR, st.RegistrationMethod)
	})

	t.Run("required cimd explains", func(t *testing.T) {
		env := newTestEnv(t)
		env.issuer.supportsCIMD = true
		env.fed.set(func() { env.fed.serveJWKS = false })
		cfg := env.config(t)
		cfg.RegistrationMode = ClientRegistrationCIMD
		m := startManager(t, cfg, env.store)
		_, err := m.BeginDeviceFlow(context.Background(), "admin")
		require.ErrorContains(t, err, "not be registered or approved")
	})
}

func TestTransientRefreshFailure(t *testing.T) {
	env := newTestEnv(t)
	m := startManager(t, env.config(t), env.store)
	activate(t, m, env.issuer)
	good, err := m.Token(context.Background())
	require.NoError(t, err)

	env.issuer.set(func() { env.issuer.failRefreshes = 1 })
	require.NoError(t, m.RefreshNow(context.Background()))
	st := m.Status()
	assert.Equal(t, StateError, st.State)
	assert.Contains(t, st.Message, "503")

	// While the issuer is failing and the token is past its refresh point,
	// callers get the still-valid token without each contacting the issuer.
	attempts, _ := env.issuer.attempts()
	m.mu.Lock()
	m.lastRefresh = m.now().Add(-time.Hour)
	m.accessExpiry = m.now().Add(time.Second)
	m.mu.Unlock()
	for i := 0; i < 5; i++ {
		tok, err := m.Token(context.Background())
		require.NoError(t, err)
		assert.Equal(t, good, tok)
	}
	after, _ := env.issuer.attempts()
	assert.Equal(t, attempts, after, "the failure hold-off keeps requests off the issuer")
	d, ok := m.nextRefreshDelay()
	assert.True(t, ok)
	assert.Equal(t, minRetryDelay, d, "the background loop backs off")

	require.NoError(t, m.RefreshNow(context.Background()))
	assert.Equal(t, StateActive, m.Status().State)
}

// flakyStore fails the next failLoads loads and failSaves saves.
type flakyStore struct {
	Store
	mu        sync.Mutex
	failLoads int
	failSaves int
}

func (f *flakyStore) Load(ctx context.Context, id string) (*Record, error) {
	f.mu.Lock()
	fail := f.failLoads > 0
	if fail {
		f.failLoads--
	}
	f.mu.Unlock()
	if fail {
		return nil, errors.New("database is locked")
	}
	return f.Store.Load(ctx, id)
}

func (f *flakyStore) Save(ctx context.Context, rec *Record) error {
	f.mu.Lock()
	fail := f.failSaves > 0
	if fail {
		f.failSaves--
	}
	f.mu.Unlock()
	if fail {
		return errors.New("disk full")
	}
	return f.Store.Save(ctx, rec)
}

func TestRotatedTokenIsNeverLost(t *testing.T) {
	env := newTestEnv(t)
	store := &flakyStore{Store: env.store}
	cfg := env.config(t)
	m := startManager(t, cfg, store)
	activate(t, m, env.issuer)

	store.mu.Lock()
	store.failSaves = 1
	store.mu.Unlock()
	require.NoError(t, m.RefreshNow(context.Background()))
	st := m.Status()
	assert.Equal(t, StateError, st.State)
	assert.Contains(t, st.Message, "disk full")
	// The stored token is now dead at the issuer.
	m.mu.Lock()
	live := m.record.RefreshToken
	m.mu.Unlock()
	assert.NotEqual(t, live, storedRefreshToken(t, env.store))

	m.housekeep(context.Background())
	assert.Equal(t, live, storedRefreshToken(t, env.store), "the retry stores the rotated token")
	assert.Equal(t, StateActive, m.Status().State)
}

func TestLoadFailureKeepsStoredCredential(t *testing.T) {
	env := newTestEnv(t)
	m := startManager(t, env.config(t), env.store)
	activate(t, m, env.issuer)
	stored := storedRefreshToken(t, env.store)
	require.NotEmpty(t, stored)

	store := &flakyStore{Store: env.store, failLoads: 1}
	restarted := startManager(t, env.config(t), store)
	st := restarted.Status()
	assert.Equal(t, StateError, st.State)
	assert.Contains(t, st.Message, "database is locked")
	assert.Equal(t, stored, storedRefreshToken(t, env.store), "a failed load must not delete the row")

	restarted.housekeep(context.Background())
	assert.Equal(t, StateActive, restarted.Status().State)
	_, err := restarted.Token(context.Background())
	require.NoError(t, err)
}

func TestDeviceFlowHonorsSlowDown(t *testing.T) {
	env := newTestEnv(t)
	env.issuer.minPollInterval = 150 * time.Millisecond
	m := startManager(t, env.config(t), env.store, func(m *Manager) {
		m.slowDownIncrement = 200 * time.Millisecond
	})
	activate(t, m, env.issuer)
	_, slowDowns := env.issuer.attempts()
	assert.Equal(t, 1, slowDowns, "after one slow_down the poller must wait longer")
}

func TestDeviceFlowSurvivesTransientPollErrors(t *testing.T) {
	env := newTestEnv(t)
	env.issuer.failPolls = 3
	m := startManager(t, env.config(t), env.store)
	st := activate(t, m, env.issuer)
	assert.Equal(t, StateActive, st.State)
}

func TestConcurrentTokenCallersRefreshOnce(t *testing.T) {
	env := newTestEnv(t)
	m := startManager(t, env.config(t), env.store)
	activate(t, m, env.issuer)
	m.mu.Lock()
	m.lastRefresh = m.now().Add(-time.Hour)
	m.accessExpiry = m.now()
	m.mu.Unlock()
	_, _, before := env.issuer.counts()

	var wg sync.WaitGroup
	var failures atomic.Int32
	tokens := make([]string, 32)
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := m.Token(context.Background())
			if err != nil {
				failures.Add(1)
			}
			tokens[i] = tok
		}(i)
	}
	wg.Wait()
	require.Zero(t, failures.Load())
	_, _, after := env.issuer.counts()
	assert.Equal(t, before+1, after, "concurrent callers share one refresh")
	for _, tok := range tokens {
		assert.Equal(t, tokens[0], tok)
	}
}

func TestTokenWaitHonorsCallerContext(t *testing.T) {
	env := newTestEnv(t)
	m := startManager(t, env.config(t), env.store)
	activate(t, m, env.issuer)
	m.mu.Lock()
	m.accessExpiry = m.now()
	m.mu.Unlock()

	// Someone else's refresh is stuck.
	require.NoError(t, m.lockRefresh(context.Background()))
	defer m.unlockRefresh()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := m.Token(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestHTTPSIsRequired(t *testing.T) {
	store, _ := setupStore(t)
	_, err := NewManager(Config{ID: "x", Issuer: "http://issuer.example.org"}, store)
	require.ErrorContains(t, err, "https")

	env := newTestEnv(t)
	env.issuer.insecureTokenEndpoint = true
	m := startManager(t, env.config(t), env.store)
	_, err = m.BeginDeviceFlow(context.Background(), "admin")
	require.ErrorContains(t, err, "token_endpoint")
}
