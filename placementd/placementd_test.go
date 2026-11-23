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

package placementd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const testTrustDomain = "pool.example.com"

// makeToken builds a JWT with the given header and claims. The signature is
// nonsense on purpose: nothing in this package verifies it, which is the whole
// reason the placement daemon has to be asked.
func makeToken(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	seg := func(v map[string]any) string {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return seg(header) + "." + seg(claims) + ".c2lnbmF0dXJl"
}

// poolToken is a plausible IDToken from the configured pool.
func poolToken(t *testing.T) string {
	t.Helper()
	return makeToken(t,
		map[string]any{"alg": "HS256", "kid": "POOL"},
		map[string]any{
			"iss":   testTrustDomain,
			"sub":   "alice@pool.example.com",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"scope": "condor:/READ condor:/WRITE",
		})
}

// newTestVerifier builds a verifier whose daemon round trip is ping.
func newTestVerifier(t *testing.T, cfg Config, ping func(ctx context.Context, address, trustDomain, tokenStr string) (string, error)) *Verifier {
	t.Helper()
	if cfg.Address == "" {
		cfg.Address = "placement.example.com:9618"
	}
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = testTrustDomain
	}
	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})
	v, err := NewVerifier(ctx, egrp, cfg)
	require.NoError(t, err)
	require.NotNil(t, v)
	if ping != nil {
		v.ping = ping
	}
	return v
}

func TestNewVerifier(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp, ctx := errgroup.WithContext(ctx)

	t.Run("no address disables the verifier", func(t *testing.T) {
		v, err := NewVerifier(ctx, egrp, Config{TrustDomain: testTrustDomain})
		require.NoError(t, err)
		assert.Nil(t, v, "an origin with no placement daemon configured must get no verifier")
	})

	t.Run("address without a trust domain is refused", func(t *testing.T) {
		// Without it every token that reached the origin would become a
		// connection to somebody else's daemon.
		_, err := NewVerifier(ctx, egrp, Config{Address: "placement:9618"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trust domain")
	})

	t.Run("a nil verifier recognizes nothing", func(t *testing.T) {
		var v *Verifier
		assert.False(t, v.Recognize(poolToken(t)))
		_, err := v.Verify(ctx, poolToken(t))
		assert.ErrorIs(t, err, ErrNotConfigured)
	})
}

func TestRecognize(t *testing.T) {
	v := newTestVerifier(t, Config{}, nil)

	longToken := makeToken(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"iss": testTrustDomain, "pad": string(make([]byte, maxTokenLength))})

	for _, tc := range []struct {
		name  string
		token string
		want  bool
		why   string
	}{
		{
			name:  "pool IDToken",
			token: poolToken(t),
			want:  true,
			why:   "an unexpired HMAC token carrying the pool's issuer is exactly what the daemon should be asked about",
		},
		{
			name: "no expiry",
			token: makeToken(t, map[string]any{"alg": "HS256"},
				map[string]any{"iss": testTrustDomain, "sub": "alice"}),
			want: true,
			why:  "only the daemon can say whether an eternal token is still honored",
		},
		{
			name: "asymmetric signature",
			token: makeToken(t, map[string]any{"alg": "RS256"},
				map[string]any{"iss": testTrustDomain, "exp": time.Now().Add(time.Hour).Unix()}),
			want: false,
			why:  "a token signed with a key Pelican could fetch is Pelican's own to verify",
		},
		{
			name: "another issuer",
			token: makeToken(t, map[string]any{"alg": "HS256"},
				map[string]any{"iss": "https://other.example.com", "exp": time.Now().Add(time.Hour).Unix()}),
			want: false,
			why:  "a token from outside the configured pool must not cost a round trip",
		},
		{
			name: "expired",
			token: makeToken(t, map[string]any{"alg": "HS256"},
				map[string]any{"iss": testTrustDomain, "exp": time.Now().Add(-time.Minute).Unix()}),
			want: false,
			why:  "the answer is already known, so asking would waste a connection",
		},
		{name: "empty", token: "", want: false, why: "not a token"},
		{name: "not a JWT", token: "hello-world", want: false, why: "not a token"},
		{name: "two segments", token: "aaa.bbb", want: false, why: "not a JWT"},
		{name: "unparsable header", token: "!!!.!!!.!!!", want: false, why: "not base64"},
		{name: "oversized", token: longToken, want: false, why: "an IDToken is a few hundred bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, v.Recognize(tc.token), tc.why)
		})
	}
}

func TestVerifyRemembersOutcomes(t *testing.T) {
	t.Run("success is reused", func(t *testing.T) {
		var calls atomic.Int32
		v := newTestVerifier(t, Config{}, func(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
			calls.Add(1)
			return "alice@pool.example.com", nil
		})
		tok := poolToken(t)
		for i := 0; i < 3; i++ {
			identity, err := v.Verify(context.Background(), tok)
			require.NoError(t, err)
			assert.Equal(t, "alice@pool.example.com", identity.Subject)
			assert.False(t, identity.Expiration.IsZero(), "the token's exp must bound how long the identity is held")
		}
		assert.Equal(t, int32(1), calls.Load(), "a token already verified must not be sent to the daemon again")
	})

	t.Run("refusal is reused", func(t *testing.T) {
		var calls atomic.Int32
		v := newTestVerifier(t, Config{}, func(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
			calls.Add(1)
			return "", errors.Wrap(ErrRefused, "all authentication methods failed")
		})
		tok := poolToken(t)
		for i := 0; i < 3; i++ {
			_, err := v.Verify(context.Background(), tok)
			assert.ErrorIs(t, err, ErrRefused)
		}
		assert.Equal(t, int32(1), calls.Load(), "a client retrying a bad token must not reach the daemon again")
	})

	t.Run("an unreachable daemon is not remembered", func(t *testing.T) {
		var calls atomic.Int32
		v := newTestVerifier(t, Config{RatePerSecond: 1000, Burst: 1000}, func(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
			calls.Add(1)
			return "", errors.Wrap(ErrUnavailable, "dial: connection refused")
		})
		tok := poolToken(t)
		for i := 0; i < 3; i++ {
			_, err := v.Verify(context.Background(), tok)
			assert.ErrorIs(t, err, ErrUnavailable)
		}
		assert.Equal(t, int32(3), calls.Load(),
			"a transport failure says nothing about the token, so caching it would refuse a good token for as long as the daemon was down")
	})

	t.Run("an unclassified failure is treated as not knowing", func(t *testing.T) {
		// A ping that returns a bare error must not be read as a
		// statement about the token: ErrUnavailable is the safe reading,
		// and the only one that is not cached.
		var calls atomic.Int32
		v := newTestVerifier(t, Config{RatePerSecond: 1000, Burst: 1000}, func(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
			calls.Add(1)
			return "", errors.New("something nobody classified")
		})
		for i := 0; i < 2; i++ {
			_, err := v.Verify(context.Background(), poolToken(t))
			assert.ErrorIs(t, err, ErrUnavailable)
		}
		assert.Equal(t, int32(2), calls.Load())
	})

	t.Run("an authenticated session naming nobody is a refusal", func(t *testing.T) {
		v := newTestVerifier(t, Config{}, func(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
			return "", nil
		})
		_, err := v.Verify(context.Background(), poolToken(t))
		assert.ErrorIs(t, err, ErrRefused)
	})

	t.Run("an unrecognized token never reaches the daemon", func(t *testing.T) {
		var calls atomic.Int32
		v := newTestVerifier(t, Config{}, func(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
			calls.Add(1)
			return "alice", nil
		})
		_, err := v.Verify(context.Background(), makeToken(t,
			map[string]any{"alg": "RS256"}, map[string]any{"iss": testTrustDomain}))
		assert.ErrorIs(t, err, ErrNotRecognized)
		assert.Zero(t, calls.Load())
	})
}

func TestVerifyCollapsesConcurrentVerifications(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	v := newTestVerifier(t, Config{RatePerSecond: 1, Burst: 1, Timeout: time.Minute},
		func(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
			calls.Add(1)
			close(entered)
			<-release
			return "alice@pool.example.com", nil
		})

	tok := poolToken(t)
	type result struct {
		identity Identity
		err      error
	}
	first := make(chan result, 1)
	go func() {
		id, err := v.Verify(context.Background(), tok)
		first <- result{id, err}
	}()

	// Once the stub has been entered, the first verification is registered
	// as in-flight, so a second one is guaranteed to join it rather than
	// start its own.
	<-entered
	second := make(chan result, 1)
	go func() {
		id, err := v.Verify(context.Background(), tok)
		second <- result{id, err}
	}()

	close(release)
	for _, ch := range []chan result{first, second} {
		got := <-ch
		require.NoError(t, got.err)
		assert.Equal(t, "alice@pool.example.com", got.identity.Subject)
	}
	assert.Equal(t, int32(1), calls.Load(),
		"concurrent requests bearing the same new token must share one round trip, or the rate limit would fail a good token")
}

func TestVerifyRateLimits(t *testing.T) {
	var calls atomic.Int32
	// One verification per second with no burst left over, and a deadline
	// far shorter than the next refill: the second distinct token cannot be
	// served inside its timeout.
	v := newTestVerifier(t, Config{RatePerSecond: 1, Burst: 1, Timeout: 50 * time.Millisecond},
		func(ctx context.Context, address, trustDomain, tokenStr string) (string, error) {
			calls.Add(1)
			return "alice@pool.example.com", nil
		})

	_, err := v.Verify(context.Background(), poolToken(t))
	require.NoError(t, err)

	// A different token, so the cache cannot answer it.
	other := makeToken(t, map[string]any{"alg": "HS256"},
		map[string]any{"iss": testTrustDomain, "sub": "bob", "exp": time.Now().Add(time.Hour).Unix()})
	_, err = v.Verify(context.Background(), other)
	assert.ErrorIs(t, err, ErrRateLimited,
		"a flood of unseen tokens must be refused rather than turned into connections to the daemon")
	assert.Equal(t, int32(1), calls.Load())
}

func TestRememberFor(t *testing.T) {
	v := newTestVerifier(t, Config{SuccessTTL: time.Hour, FailureTTL: time.Minute}, nil)

	t.Run("a long-lived token is held for the configured timeout", func(t *testing.T) {
		ttl, remember := v.rememberFor(outcome{identity: Identity{
			Subject:    "alice",
			Expiration: time.Now().Add(24 * time.Hour),
		}})
		require.True(t, remember)
		assert.Equal(t, time.Hour, ttl)
	})

	t.Run("a token expiring sooner clamps the timeout", func(t *testing.T) {
		ttl, remember := v.rememberFor(outcome{identity: Identity{
			Subject:    "alice",
			Expiration: time.Now().Add(90 * time.Second),
		}})
		require.True(t, remember)
		assert.Less(t, ttl, time.Hour, "an identity must not outlive the credential that established it")
		assert.Greater(t, ttl, time.Minute)
	})

	t.Run("an already-expired token is not remembered", func(t *testing.T) {
		_, remember := v.rememberFor(outcome{identity: Identity{
			Subject:    "alice",
			Expiration: time.Now().Add(-time.Second),
		}})
		assert.False(t, remember)
	})

	t.Run("a refusal is remembered for the refusal timeout", func(t *testing.T) {
		ttl, remember := v.rememberFor(outcome{err: errors.Wrap(ErrRefused, "nope")})
		require.True(t, remember)
		assert.Equal(t, time.Minute, ttl)
	})

	t.Run("not knowing is not remembered", func(t *testing.T) {
		for _, err := range []error{ErrUnavailable, ErrRateLimited, context.Canceled} {
			_, remember := v.rememberFor(outcome{err: err})
			assert.False(t, remember, "%v says nothing about the token", err)
		}
	})
}
