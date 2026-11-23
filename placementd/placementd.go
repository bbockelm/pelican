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

// Package placementd turns a token issued by an HTCondor placement daemon
// (condor_placementd) into the identity that daemon authenticates it as.
//
// Pelican cannot check such a token by itself. An HTCondor IDToken is signed
// with a symmetric pool key that only the pool's daemons hold, so there is no
// JWKS to fetch and no signature Pelican can verify. What Pelican can do is
// ask: open a CEDAR connection to the placement daemon presenting the token as
// the only credential and let the daemon's own security layer accept or refuse
// it. That is exactly what `condor_ping` does, and the identity the daemon
// reports back in the post-authentication handshake is the identity the token
// speaks for.
//
// Because every such check is a round trip to somebody else's daemon, this
// package is built to do as few of them as possible:
//
//   - Recognize reports whether a token could possibly be one of the pool's,
//     from the token alone. A token that is not a candidate never reaches the
//     network.
//   - Verify memoizes both outcomes, so a client retrying with the same token
//     — valid or not — is answered from memory.
//   - Concurrent verifications of the same token collapse into one round trip.
//   - What survives all of that is rate limited, so a flood of unseen tokens
//     cannot be turned into a flood of connections to the placement daemon.
package placementd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// Sentinel errors. Callers distinguish them because they call for different
// handling: a refusal is the token's fault and is remembered, while an
// unavailable daemon is the deployment's and is not.
var (
	// ErrNotConfigured is returned when no placement daemon is configured.
	ErrNotConfigured = errors.New("no HTCondor placement daemon is configured")

	// ErrNotRecognized is returned by Verify for a token Recognize would
	// have refused. It means the token cannot be one this placement daemon
	// issued, so no verification was attempted.
	ErrNotRecognized = errors.New("token is not a candidate placement-daemon token")

	// ErrRefused is returned when the placement daemon declined to
	// authenticate the token. The token is bad (forged, expired, revoked,
	// signed with a key the pool no longer holds); retrying will not help.
	ErrRefused = errors.New("the placement daemon refused the token")

	// ErrUnavailable is returned when the placement daemon could not be
	// reached, or did not answer in time, so nothing is known about the
	// token. Unlike ErrRefused this says nothing about the token itself.
	ErrUnavailable = errors.New("the placement daemon could not be reached")

	// ErrRateLimited is returned when the verification rate limit could not
	// be satisfied within the configured timeout. Like ErrUnavailable it is
	// a statement about this origin, not about the token.
	ErrRateLimited = errors.New("placement-daemon verification rate limit exceeded")
)

// maxTokenLength caps what Recognize will decode. HTCondor IDTokens are a few
// hundred bytes; anything approaching this is not one, and refusing it by
// length keeps a large body from being base64-decoded and JSON-parsed on the
// request path.
const maxTokenLength = 16 * 1024

// identityCacheCapacity bounds how many verification outcomes are remembered.
// The cache is keyed by a digest of the token, so its size is driven by how
// many distinct tokens arrive, which an unauthenticated client controls.
const identityCacheCapacity = 4096

type (
	// Config is how a Verifier is set up. See the Origin.Placementd.*
	// parameters for what each of these means to an administrator.
	Config struct {
		// Address is the placement daemon's CEDAR address: a sinful string
		// or a plain host:port. Empty disables the verifier.
		Address string

		// TrustDomain is the pool's HTCondor trust domain, which is the
		// `iss` claim on the tokens it issues. Recognize matches on it, and
		// CEDAR will not present a token whose issuer does not match it,
		// so it is required.
		TrustDomain string

		// Timeout bounds one verification end to end, rate-limit wait
		// included.
		Timeout time.Duration

		// RatePerSecond and Burst are the token bucket applied to
		// verifications that are not answered from cache.
		RatePerSecond int
		Burst         int

		// SuccessTTL is how long a reported identity is reused; FailureTTL
		// how long a refusal is remembered.
		SuccessTTL time.Duration
		FailureTTL time.Duration
	}

	// Identity is what the placement daemon reported about a token.
	Identity struct {
		// Subject is the fully-qualified identity ("user@domain") the
		// daemon authenticated the token as — the same string its own
		// ALLOW/DENY lists match, and what `condor_ping` prints. This is
		// the daemon's answer, not the token's `sub` claim: the daemon may
		// map the credential onto a different identity, and it is the
		// mapped one that means anything.
		Subject string

		// Expiration is the token's `exp` claim, or the zero time when it
		// carries none. The caller may hold the identity no longer than
		// this.
		Expiration time.Time
	}

	// Verifier answers "whose token is this?" for one placement daemon.
	//
	// It is safe for concurrent use and is meant to be long-lived: its
	// caches and rate limiter are what keep the placement daemon from being
	// asked the same question twice.
	Verifier struct {
		cfg     Config
		limiter *rate.Limiter
		cache   *ttlcache.Cache[string, outcome]

		// inflight collapses concurrent verifications of the same token.
		// Written under mu.
		mu       sync.Mutex
		inflight map[string]*pending

		// ping is how the daemon is actually asked: it returns the
		// identity the daemon reported, or an error already sorted into
		// ErrRefused / ErrUnavailable. Platform-dependent, since CEDAR
		// does not build everywhere, and a field so tests can stand in
		// for a daemon.
		ping func(ctx context.Context, address string, trustDomain string, tokenStr string) (string, error)
	}

	// outcome is a remembered verification result. A nil err means the
	// identity is good for as long as the entry lives.
	outcome struct {
		identity Identity
		err      error
	}

	pending struct {
		done chan struct{}
		out  outcome
	}
)

// NewVerifier builds a Verifier from cfg, or returns nil when cfg names no
// placement daemon — the ordinary state of an origin that does not accept
// these tokens. A nil *Verifier is usable: every method reports "not mine".
//
// ctx and egrp own the cache's eviction loop, which stops when ctx is done.
func NewVerifier(ctx context.Context, egrp *errgroup.Group, cfg Config) (*Verifier, error) {
	if strings.TrimSpace(cfg.Address) == "" {
		return nil, nil
	}
	if !cedarAvailable {
		// Better a refused startup than an origin that accepts the
		// configuration and then refuses every token it was configured
		// for.
		return nil, errors.New("verifying HTCondor placement-daemon tokens is not supported on this platform")
	}
	if strings.TrimSpace(cfg.TrustDomain) == "" {
		// Without the trust domain there is nothing to recognize a token
		// by, so every token that reached the origin would become a
		// connection to the placement daemon. Refuse at startup rather
		// than turn the origin into a load generator.
		return nil, errors.New("a placement daemon address was configured without a trust domain")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.RatePerSecond <= 0 {
		cfg.RatePerSecond = 1
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 1
	}
	if cfg.SuccessTTL <= 0 {
		cfg.SuccessTTL = 15 * time.Minute
	}
	if cfg.FailureTTL <= 0 {
		cfg.FailureTTL = time.Minute
	}

	v := &Verifier{
		cfg:      cfg,
		limiter:  rate.NewLimiter(rate.Limit(cfg.RatePerSecond), cfg.Burst),
		inflight: make(map[string]*pending),
		ping:     defaultPing,
		cache: ttlcache.New[string, outcome](
			ttlcache.WithTTL[string, outcome](cfg.SuccessTTL),
			ttlcache.WithCapacity[string, outcome](identityCacheCapacity),
			ttlcache.WithDisableTouchOnHit[string, outcome](),
		),
	}

	if egrp != nil {
		egrp.Go(func() error {
			v.cache.Start()
			return nil
		})
		egrp.Go(func() error {
			<-ctx.Done()
			v.cache.Stop()
			v.cache.DeleteAll()
			return nil
		})
	}
	return v, nil
}

// Address reports the placement daemon this verifier talks to, for logging.
func (v *Verifier) Address() string {
	if v == nil {
		return ""
	}
	return v.cfg.Address
}

// TrustDomain reports the pool trust domain this verifier recognizes.
func (v *Verifier) TrustDomain() string {
	if v == nil {
		return ""
	}
	return v.cfg.TrustDomain
}

// Recognize reports whether tokenStr could be a token this placement daemon
// issued, judging from the token alone — no network, no cache, no state.
//
// This is the gate that keeps the placement daemon out of the common path. A
// Pelican-issued token, a WLCG token, a share token, a malformed string: all
// are refused here, for free. A true answer is not a claim that the token is
// valid, only that asking the daemon about it is worth a round trip.
func (v *Verifier) Recognize(tokenStr string) bool {
	if v == nil {
		return false
	}
	if tokenStr == "" || len(tokenStr) > maxTokenLength {
		return false
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return false
	}

	// An HTCondor IDToken is HMAC-signed with a pool key. Every token
	// Pelican itself issues, and every SciToken/WLCG token, is signed with
	// an asymmetric key. Splitting on the algorithm family therefore
	// separates "a credential only the pool can check" from "a credential
	// this origin can check itself", which is the whole reason the two
	// paths differ.
	var header struct {
		Alg string `json:"alg"`
	}
	if !decodeJWTSegment(parts[0], &header) {
		return false
	}
	if !strings.HasPrefix(header.Alg, "HS") {
		return false
	}

	var claims struct {
		Issuer string `json:"iss"`
		Expiry int64  `json:"exp"`
	}
	if !decodeJWTSegment(parts[1], &claims) {
		return false
	}
	if claims.Issuer != v.cfg.TrustDomain {
		return false
	}
	// An expired token is refused here rather than by the daemon: the
	// answer is already known, and asking costs a connection. Tokens with
	// no `exp` are left to the daemon, which is the only party that can say
	// whether an eternal token is still honored.
	if claims.Expiry != 0 && time.Now().After(time.Unix(claims.Expiry, 0)) {
		return false
	}
	return true
}

// Verify returns the identity the placement daemon authenticates tokenStr as.
//
// A remembered outcome — success or refusal — is returned without touching the
// network. Otherwise one CEDAR handshake is made, subject to the rate limit,
// and its outcome remembered: ErrRefused for the configured refusal timeout,
// successes until the sooner of the identity timeout and the token's own
// expiry. ErrUnavailable and ErrRateLimited are never remembered, because they
// say nothing about the token.
func (v *Verifier) Verify(ctx context.Context, tokenStr string) (Identity, error) {
	if v == nil {
		return Identity{}, ErrNotConfigured
	}
	if !v.Recognize(tokenStr) {
		return Identity{}, ErrNotRecognized
	}

	key := cacheKey(tokenStr)
	if item := v.cache.Get(key); item != nil {
		out := item.Value()
		return out.identity, out.err
	}

	// One verification per token at a time. Without this, N concurrent
	// requests bearing a token nobody has seen yet are N connections to the
	// placement daemon, and the rate limiter turns all but a few of them
	// into spurious failures for a token that is perfectly good.
	v.mu.Lock()
	if p, ok := v.inflight[key]; ok {
		v.mu.Unlock()
		select {
		case <-p.done:
			return p.out.identity, p.out.err
		case <-ctx.Done():
			return Identity{}, errors.Wrap(ctx.Err(), "gave up waiting for an in-flight placement-daemon verification")
		}
	}
	p := &pending{done: make(chan struct{})}
	v.inflight[key] = p
	v.mu.Unlock()

	p.out = v.verifyNow(ctx, tokenStr)
	close(p.done)

	v.mu.Lock()
	delete(v.inflight, key)
	v.mu.Unlock()

	if ttl, remember := v.rememberFor(p.out); remember {
		v.cache.Set(key, p.out, ttl)
	}
	return p.out.identity, p.out.err
}

// rememberFor says how long an outcome may be cached, and whether it may be
// cached at all.
func (v *Verifier) rememberFor(out outcome) (time.Duration, bool) {
	switch {
	case errors.Is(out.err, ErrRefused):
		return v.cfg.FailureTTL, true
	case out.err != nil:
		// ErrUnavailable / ErrRateLimited / a cancelled request: we never
		// learned anything about the token.
		return 0, false
	}
	ttl := v.cfg.SuccessTTL
	if !out.identity.Expiration.IsZero() {
		// Never hold an identity past the credential that established it.
		if until := time.Until(out.identity.Expiration); until < ttl {
			ttl = until
		}
	}
	if ttl <= 0 {
		return 0, false
	}
	return ttl, true
}

// verifyNow does the rate-limited round trip.
func (v *Verifier) verifyNow(ctx context.Context, tokenStr string) outcome {
	ctx, cancel := context.WithTimeout(ctx, v.cfg.Timeout)
	defer cancel()

	// Wait rather than refuse outright: the budget exists to bound the load
	// this origin puts on somebody else's daemon, not to fail requests that
	// arrived in a clump. The timeout above is the backstop — rate.Limiter
	// refuses immediately when the wait would outlast the deadline, so a
	// genuine flood fails fast instead of queueing.
	if err := v.limiter.Wait(ctx); err != nil {
		if ctx.Err() != nil {
			return outcome{err: errors.Wrap(ErrUnavailable, "timed out before a placement-daemon verification could be attempted")}
		}
		return outcome{err: ErrRateLimited}
	}

	subject, err := v.ping(ctx, v.cfg.Address, v.cfg.TrustDomain, tokenStr)
	if err != nil {
		return outcome{err: classified(err)}
	}
	if subject == "" {
		// A handshake that authenticated but named nobody is not an
		// identity we can authorize against.
		return outcome{err: errors.Wrap(ErrRefused, "the placement daemon authenticated the token but reported no identity")}
	}

	log.WithFields(log.Fields{
		"placementd": v.cfg.Address,
		"identity":   subject,
	}).Debug("Placement daemon authenticated a token")

	return outcome{identity: Identity{Subject: subject, Expiration: tokenExpiry(tokenStr)}}
}

// classified makes sure every failure carries one of this package's sentinels,
// whatever the ping returned. Callers switch on them, and rememberFor decides
// what to cache from them, so an unclassified error would be silently treated
// as the most cacheable thing it resembled. Anything unrecognized becomes
// ErrUnavailable: never knowing is the safe reading of a failure we cannot
// attribute to the token.
func classified(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrRefused), errors.Is(err, ErrUnavailable), errors.Is(err, ErrRateLimited), errors.Is(err, ErrNotRecognized):
		return err
	default:
		return errors.Wrap(ErrUnavailable, err.Error())
	}
}

// cacheKey hashes a token so that the cache does not keep bearer credentials
// as map keys for the life of the entry.
func cacheKey(tokenStr string) string {
	sum := sha256.Sum256([]byte(tokenStr))
	return hex.EncodeToString(sum[:])
}

// decodeJWTSegment base64url-decodes one JWT segment into out, reporting
// whether it held the JSON object expected.
func decodeJWTSegment(segment string, out any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}

// tokenExpiry reads a token's `exp` claim, returning the zero time when it has
// none. The token has already been through Recognize, so it parses.
func tokenExpiry(tokenStr string) time.Time {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	var claims struct {
		Expiry int64 `json:"exp"`
	}
	if !decodeJWTSegment(parts[1], &claims) || claims.Expiry == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Expiry, 0)
}
