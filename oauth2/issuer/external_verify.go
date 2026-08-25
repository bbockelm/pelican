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

package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/token"
)

const (
	// externalJWKSTTL is how long a successfully resolved key set stays in the
	// cache before the issuer is re-discovered.
	externalJWKSTTL = 15 * time.Minute
	// externalJWKSFailureTTL bounds how often a broken issuer is retried. It is
	// short enough to recover quickly and long enough that an IdP outage cannot
	// turn every exchange request into an outbound fetch.
	externalJWKSFailureTTL = 5 * time.Minute
)

// externalKeySet is a cache entry: either a live, self-refreshing key set or
// the error that prevented resolving one.
type externalKeySet struct {
	set jwk.Set
	err error
}

// externalKeyCache resolves an external issuer URL to its JWKS.
//
// Two layers of caching are at work, mirroring origin_serve/authz.go: the
// ttlcache maps issuer URL to a jwk.Set, and each entry is a jwk.CachedSet
// backed by a jwk.Cache that refreshes the key material on its own schedule.
// The result is that key rotation at the IdP is picked up without a restart
// and without a fetch on the request path.
type externalKeyCache struct {
	mu    sync.Mutex
	cache *ttlcache.Cache[string, externalKeySet]
	// jwkCache is the long-lived registry of JWKS URLs; it outlives individual
	// ttlcache entries so that re-resolving an issuer does not discard key
	// material that is still perfectly good.
	jwkCache *jwk.Cache
	ctx      context.Context
}

var (
	extKeyCacheOnce sync.Once
	extKeyCache     *externalKeyCache
)

// InitExternalKeyCache prepares the process-wide JWKS cache used to verify
// subject tokens from trusted external issuers, and arranges for it to be torn
// down when ctx is cancelled. Safe to call more than once.
func InitExternalKeyCache(ctx context.Context) {
	extKeyCacheOnce.Do(func() {
		c := &externalKeyCache{
			jwkCache: jwk.NewCache(ctx),
			ctx:      ctx,
		}
		c.cache = ttlcache.New[string, externalKeySet](
			ttlcache.WithTTL[string, externalKeySet](externalJWKSTTL),
			// Do NOT renew an entry's TTL on read. A negative entry (a failed
			// discovery/fetch, cached for externalJWKSFailureTTL) must actually
			// expire so a recovered IdP is retried; with touch-on-hit a busy
			// issuer's failure would be renewed on every request and never age
			// out. Positive entries self-refresh via the jwk.Cache regardless.
			ttlcache.WithDisableTouchOnHit[string, externalKeySet](),
		)
		go c.cache.Start()
		go func() {
			<-ctx.Done()
			c.cache.Stop()
			c.cache.DeleteAll()
		}()
		extKeyCache = c
	})
}

// resolveKeySet returns the key set for an external issuer, discovering the
// JWKS URI if the issuer record does not pin one.
func (c *externalKeyCache) resolveKeySet(ctx context.Context, issuerURL, jwksURL string) (jwk.Set, error) {
	if item := c.cache.Get(issuerURL); item != nil {
		v := item.Value()
		return v.set, v.err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check under the lock: a concurrent request may have populated it.
	if item := c.cache.Get(issuerURL); item != nil {
		v := item.Value()
		return v.set, v.err
	}

	resolved := jwksURL
	if resolved == "" {
		u, err := token.LookupIssuerJwksUrl(ctx, issuerURL)
		if err != nil {
			err = errors.Wrapf(err, "failed to discover the JWKS URL for issuer %s", issuerURL)
			c.cache.Set(issuerURL, externalKeySet{err: err}, externalJWKSFailureTTL)
			return nil, err
		}
		resolved = u.String()
	}

	if !c.jwkCache.IsRegistered(resolved) {
		client := &http.Client{Transport: config.GetBasicTransport()}
		if err := c.jwkCache.Register(resolved,
			jwk.WithMinRefreshInterval(externalJWKSTTL),
			jwk.WithHTTPClient(client)); err != nil {
			err = errors.Wrapf(err, "failed to register the JWKS URL %s", resolved)
			c.cache.Set(issuerURL, externalKeySet{err: err}, externalJWKSFailureTTL)
			return nil, err
		}
	}

	// Force one fetch now so a misconfigured URL fails here — with a useful
	// error — rather than at signature-verification time as "no matching key".
	if _, err := c.jwkCache.Refresh(ctx, resolved); err != nil {
		err = errors.Wrapf(err, "failed to fetch the JWKS for issuer %s from %s", issuerURL, resolved)
		c.cache.Set(issuerURL, externalKeySet{err: err}, externalJWKSFailureTTL)
		return nil, err
	}

	set := jwk.NewCachedSet(c.jwkCache, resolved)
	c.cache.Set(issuerURL, externalKeySet{set: set}, externalJWKSTTL)
	log.Debugf("Embedded issuer: cached JWKS for external issuer %s (%s)", issuerURL, resolved)
	return set, nil
}

// ExternalIssuerKeySet resolves and caches the key set for a trusted external
// issuer. Exported for the admin "probe" endpoint.
func ExternalIssuerKeySet(ctx context.Context, detail *ExternalIssuerDetail) (jwk.Set, error) {
	InitExternalKeyCache(context.Background())
	return extKeyCache.resolveKeySet(ctx, detail.IssuerURL, detail.JWKSURL)
}

// InvalidateExternalIssuerKeys drops any cached key set for an issuer URL, so
// that an operator editing a record (or probing after fixing the IdP) sees the
// new state immediately instead of waiting out the TTL.
func InvalidateExternalIssuerKeys(issuerURL string) {
	if extKeyCache == nil {
		return
	}
	extKeyCache.cache.Delete(NormalizeIssuerURL(issuerURL))
}

// PeekTokenIssuer reads the `iss` claim from a JWT *without verifying it*.
//
// This is used only to decide which trust anchor to evaluate the token
// against; the value is never itself trusted. Any decision made from it is
// re-derived from the verified claims afterwards (see VerifyExternalToken,
// which re-checks `iss` post-verification).
func PeekTokenIssuer(tokenStr string) (string, bool) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	if claims.Iss == "" {
		return "", false
	}
	return claims.Iss, true
}

// checkSignatureAlgorithm enforces the issuer's algorithm allow-list against
// the token's protected header, before any key material is consulted.
//
// Doing this first is what closes the key-confusion hole: if an HMAC algorithm
// were permitted here, a verifier holding the issuer's public JWKS could be
// asked to validate an attacker-signed token using a public key as the shared
// secret. Rejecting the family up front means no verification path can ever be
// reached with one.
func checkSignatureAlgorithm(tokenStr string, allowed []string) error {
	msg, err := jws.Parse([]byte(tokenStr))
	if err != nil {
		return errors.Wrap(err, "subject token is not a well-formed JWS")
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return errors.Errorf("subject token must carry exactly one signature (found %d)", len(sigs))
	}
	alg := sigs[0].ProtectedHeaders().Algorithm()
	if alg == jwa.NoSignature || alg.String() == "" {
		return errors.New("subject token is unsigned")
	}
	for _, a := range allowed {
		if a == alg.String() {
			return nil
		}
	}
	return errors.Errorf("subject token is signed with %s, which this issuer's allowed_algorithms does not permit", alg.String())
}

// VerifyExternalToken checks a subject token against a trusted external
// issuer's configuration and returns its verified claims.
//
// The order matters. Cheap, local checks that cannot be influenced by the
// token's contents run first; the network is touched only once the token is
// structurally plausible and its algorithm is permitted.
func VerifyExternalToken(ctx context.Context, detail *ExternalIssuerDetail, tokenStr string) (jwt.Token, error) {
	if err := checkSignatureAlgorithm(tokenStr, detail.AllowedAlgorithms); err != nil {
		return nil, err
	}

	keySet, err := ExternalIssuerKeySet(ctx, detail)
	if err != nil {
		return nil, err
	}

	// Signature plus the temporal claims (exp/nbf/iat), with the codebase's
	// standard clock-skew allowance — these tokens come from another host, so
	// some skew is expected.
	parsed, err := token.VerifyWithKeyset(tokenStr, keySet)
	if err != nil {
		return nil, errors.Wrap(err, "subject token failed verification")
	}

	// Re-check the issuer against the *verified* claims. PeekTokenIssuer chose
	// the trust anchor from unverified bytes; this is what makes that safe.
	if NormalizeIssuerURL(parsed.Issuer()) != NormalizeIssuerURL(detail.IssuerURL) {
		return nil, errors.Errorf("subject token issuer %q does not match the trusted issuer %q",
			parsed.Issuer(), detail.IssuerURL)
	}
	if parsed.Subject() == "" && detail.SubjectClaim == "sub" {
		return nil, errors.New("subject token has no subject claim")
	}

	// Require an expiry. jwt.Validate does not mandate exp, but a token without
	// one cannot be lifetime-capped against "never outlive the assertion" — the
	// cap in resolveExternalExchange is skipped when exp is absent — so a
	// missing exp would silently yield a full-lifespan Pelican token from an
	// assertion that never expires. Reject it instead.
	if parsed.Expiration().IsZero() {
		return nil, errors.New("subject token has no expiration; refusing to exchange a token that never expires")
	}

	if err := checkAudience(parsed, detail); err != nil {
		return nil, err
	}
	if err := checkRequiredScopes(parsed, detail); err != nil {
		return nil, err
	}
	if err := checkRequiredClaims(parsed, detail); err != nil {
		return nil, err
	}
	return parsed, nil
}

// checkAudience enforces that the token was minted for us.
//
// Without this the feature degrades into "any token this IdP issues to anyone
// is accepted here", which is why an empty list requires allow_any_audience at
// configuration time rather than being a silent default.
func checkAudience(parsed jwt.Token, detail *ExternalIssuerDetail) error {
	if detail.AllowAnyAudience {
		return nil
	}
	if len(detail.RequiredAudiences) == 0 {
		// Defense in depth: validateDetail refuses this combination, so
		// reaching it means a row was written by something other than the
		// admin API. Fail closed rather than trusting the row.
		return errors.New("this external issuer has no required_audiences configured; refusing the exchange")
	}
	tokenAud := parsed.Audience()
	for _, want := range detail.RequiredAudiences {
		for _, got := range tokenAud {
			if got == want {
				return nil
			}
		}
	}
	return errors.Errorf("subject token audience %v does not include any of the required audiences %v",
		tokenAud, detail.RequiredAudiences)
}

// tokenScopeSet extracts the space-delimited `scope` claim (RFC 8693 / RFC 9068).
func tokenScopeSet(parsed jwt.Token) map[string]bool {
	out := map[string]bool{}
	raw, ok := parsed.Get("scope")
	if !ok {
		return out
	}
	switch v := raw.(type) {
	case string:
		for _, s := range strings.Fields(v) {
			out[s] = true
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out[s] = true
			}
		}
	case []string:
		for _, s := range v {
			out[s] = true
		}
	}
	return out
}

// checkRequiredScopes enforces the operator's precondition that the presented
// token carry particular scopes.
//
// These scopes say nothing about what Pelican will authorize — that is
// computed from the mapped local user's own rules. They are purely a gate on
// which of the IdP's tokens are eligible to be exchanged at all.
func checkRequiredScopes(parsed jwt.Token, detail *ExternalIssuerDetail) error {
	if len(detail.RequiredScopes) == 0 {
		return nil
	}
	have := tokenScopeSet(parsed)
	for _, want := range detail.RequiredScopes {
		if !have[want] {
			return errors.Errorf("subject token is missing the required scope %q", want)
		}
	}
	return nil
}

// checkRequiredClaims enforces exact-match claim requirements, e.g. pinning
// `azp` to the one client an operator expects tokens to originate from.
func checkRequiredClaims(parsed jwt.Token, detail *ExternalIssuerDetail) error {
	for claim, want := range detail.RequiredClaims {
		raw, ok := parsed.Get(claim)
		if !ok {
			return errors.Errorf("subject token is missing the required claim %q", claim)
		}
		got, ok := raw.(string)
		if !ok {
			return errors.Errorf("subject token claim %q is not a string", claim)
		}
		if got != want {
			return errors.Errorf("subject token claim %q does not have the required value", claim)
		}
	}
	return nil
}
