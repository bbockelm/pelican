//go:build server

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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtpkg "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	dbutils "github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/param"
)

// ---- Stub external identity provider ----

// stubIdP is a minimal OIDC issuer: a discovery document, a JWKS, and the
// ability to mint signed tokens. It stands in for Keycloak.
type stubIdP struct {
	server    *httptest.Server
	key       *rsa.PrivateKey
	kid       string
	jwksHits  atomic.Int32
	discHits  atomic.Int32
	failJWKS  atomic.Bool
	issuerURL string
}

func newStubIdP(t *testing.T) *stubIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idp := &stubIdP{key: key, kid: "stub-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		idp.discHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   idp.issuerURL,
			"jwks_uri": idp.issuerURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.jwksHits.Add(1)
		if idp.failJWKS.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		pub, err := jwk.FromRaw(key.Public())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = pub.Set(jwk.KeyIDKey, idp.kid)
		_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
		_ = pub.Set(jwk.KeyUsageKey, "sig")
		set := jwk.NewSet()
		_ = set.AddKey(pub)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})

	idp.server = httptest.NewServer(mux)
	idp.issuerURL = idp.server.URL
	t.Cleanup(idp.server.Close)
	return idp
}

// tokenOpts describes a token the stub IdP should mint.
type tokenOpts struct {
	sub      string
	aud      []string
	scope    string
	groups   interface{}
	username string
	email    string
	azp      string
	expIn    time.Duration
	issuer   string // override, for issuer-spoofing tests
	alg      jwa.SignatureAlgorithm
	hmacKey  []byte // when set, sign symmetrically
	noExp    bool   // when set, omit the exp claim entirely
	extra    map[string]interface{}
}

func (idp *stubIdP) mint(t *testing.T, o tokenOpts) string {
	t.Helper()
	if o.expIn == 0 {
		o.expIn = time.Hour
	}
	iss := idp.issuerURL
	if o.issuer != "" {
		iss = o.issuer
	}

	b := jwtpkg.NewBuilder().
		Issuer(iss).
		Subject(o.sub).
		IssuedAt(time.Now())
	if !o.noExp {
		b = b.Expiration(time.Now().Add(o.expIn))
	}
	if len(o.aud) > 0 {
		b = b.Audience(o.aud)
	}
	if o.scope != "" {
		b = b.Claim("scope", o.scope)
	}
	if o.groups != nil {
		b = b.Claim("groups", o.groups)
	}
	if o.username != "" {
		b = b.Claim("preferred_username", o.username)
	}
	if o.email != "" {
		b = b.Claim("email", o.email)
	}
	if o.azp != "" {
		b = b.Claim("azp", o.azp)
	}
	for k, v := range o.extra {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	require.NoError(t, err)

	if o.hmacKey != nil {
		signed, err := jwtpkg.Sign(tok, jwtpkg.WithKey(jwa.HS256, o.hmacKey))
		require.NoError(t, err)
		return string(signed)
	}

	alg := o.alg
	if alg == "" {
		alg = jwa.RS256
	}
	privJWK, err := jwk.FromRaw(idp.key)
	require.NoError(t, err)
	_ = privJWK.Set(jwk.KeyIDKey, idp.kid)
	signed, err := jwtpkg.Sign(tok, jwtpkg.WithKey(alg, privJWK))
	require.NoError(t, err)
	return string(signed)
}

// ---- Test harness ----

const (
	extClientID = "ext-exchange-client"
	extSecret   = "ext-exchange-secret"
	extNS       = "/test/ns"
)

// setupExternalExchange builds an origin issuer with a token-exchange client
// and a stub external IdP, and returns both.
func setupExternalExchange(t *testing.T) (*OIDCProvider, *httptest.Server, *stubIdP) {
	t.Helper()
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)

	tmpDir := t.TempDir()
	require.NoError(t, param.IssuerKey.Set(filepath.Join(tmpDir, "issuer.jwk")))
	require.NoError(t, param.Origin_FederationPrefix.Set(extNS))
	require.NoError(t, param.Server_ExternalWebUrl.Set("https://test-origin.example.com"))
	require.NoError(t, param.Issuer_DisableExternalTokenExchange.Set(false))

	// Templates keyed on the *prefixed* group name, which is what a foreign
	// issuer's groups become by default.
	require.NoError(t, param.Issuer_AuthorizationTemplates.Set([]map[string]interface{}{
		{"actions": []string{"read"}, "prefix": "/data/$GROUP"},
		{"actions": []string{"read", "modify"}, "prefix": "/home/$USER"},
	}))
	require.NoError(t, oa4mp.InitAuthzRules())

	dbPath := filepath.Join(tmpDir, "ext-exchange.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	// The identity layer reads through database.ServerDatabase.
	prevDB := database.ServerDatabase
	database.ServerDatabase = db
	t.Cleanup(func() { database.ServerDatabase = prevDB })

	issuerURL := IssuerURLForNamespace(extNS)
	provider, err := NewOIDCProvider(db, issuerURL, 5*time.Minute, extNS)
	require.NoError(t, err)
	require.NoError(t, provider.EnsureClient(context.Background(), extClientID, extSecret, []string{"https://example.com/cb"}))

	// Bless the client for token exchange.
	grants := []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"}
	_, err = provider.Storage().UpdateClient(context.Background(), extClientID, ClientUpdate{GrantTypes: &grants})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	registry := NewProviderRegistry()
	registry.Register(extNS, provider)
	RegisterRoutesWithMiddleware(engine, registry)
	// Admin routes (external-issuer CRUD, dry-run, probe, group-maps) are what
	// the dry-run test drives. No auth middleware is injected — these tests
	// exercise handler behavior, not the admin gate (covered elsewhere).
	RegisterAdminRoutes(engine, registry)
	ts := httptest.NewTLSServer(engine)
	t.Cleanup(ts.Close)

	InitExternalKeyCache(context.Background())

	return provider, ts, newStubIdP(t)
}

// detailFromInput applies and validates a config-style input into a full
// ExternalIssuerDetail, the same path ParseExternalIssuers uses.
func detailFromInput(t *testing.T, in ExternalIssuerInput) ExternalIssuerDetail {
	t.Helper()
	d := ExternalIssuerDetail{Enabled: true, AutoEnroll: true, IncludeLocalGroups: true}
	if in.Enabled != nil {
		d.Enabled = *in.Enabled
	}
	require.NoError(t, applyInput(&d, in, true))
	return d
}

// blessExchangeClient sets the test client's allow-external-exchange flag.
func blessExchangeClient(t *testing.T, provider *OIDCProvider) {
	t.Helper()
	allow := true
	_, err := provider.Storage().UpdateClient(context.Background(), extClientID, ClientUpdate{AllowExternalExchange: &allow})
	require.NoError(t, err)
}

// registerIssuer adds a trusted external issuer to the provider's configured
// list and optionally blesses the test client, returning the stored issuer.
// External issuers now come from configuration, so this appends to the
// provider's in-memory list rather than writing a database row.
func registerIssuer(t *testing.T, provider *OIDCProvider, in ExternalIssuerInput, blessClient bool) *ExternalIssuerDetail {
	t.Helper()
	d := detailFromInput(t, in)
	provider.SetExternalIssuers(append(provider.ExternalIssuers(), d))
	if blessClient {
		blessExchangeClient(t, provider)
	}
	InvalidateExternalIssuerKeys(d.IssuerURL)
	issuers := provider.ExternalIssuers()
	return &issuers[len(issuers)-1]
}

func strPtr(s string) *string       { return &s }
func boolPtr(b bool) *bool          { return &b }
func slicePtr(s []string) *[]string { return &s }

// exchange performs the RFC 8693 request and returns the decoded response.
func exchange(t *testing.T, ts *httptest.Server, subjectToken string, scope string) (int, map[string]interface{}) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token": {subjectToken},
		"client_id":     {extClientID},
		"client_secret": {extSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	resp, err := ts.Client().PostForm(ts.URL+"/api/v1.0/issuer/ns"+extNS+"/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// baseIssuerInput is a valid, minimal configuration pointing at the stub IdP.
func baseIssuerInput(idp *stubIdP, name string) ExternalIssuerInput {
	return ExternalIssuerInput{
		Name:              strPtr(name),
		IssuerURL:         strPtr(idp.issuerURL),
		RequiredAudiences: slicePtr([]string{"pelican-origin"}),
	}
}

// ---- Happy path ----

func TestExternalExchangeHappyPath(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	subjectToken := idp.mint(t, tokenOpts{
		sub:      "kc-subject-1",
		aud:      []string{"pelican-origin"},
		username: "alice",
		groups:   []string{"cms", "atlas"},
	})

	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusOK, status, "unexpected response: %v", body)
	require.NotEmpty(t, body["access_token"])
	assert.Equal(t, "Bearer", body["token_type"])
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", body["issued_token_type"])

	tok := validateWLCGToken(t, body["access_token"].(string), provider)

	// The username came from the IdP's preferred_username claim, and the
	// account was enrolled on the fly.
	assert.Equal(t, "alice", tok.Subject())

	// Groups are namespaced behind the issuer's name by default, so a foreign
	// "cms" cannot collide with a local group of the same name.
	rawGroups, ok := tok.Get("wlcg.groups")
	require.True(t, ok, "token should carry wlcg.groups")
	groups := toStringSlice(rawGroups)
	assert.Contains(t, groups, "keycloak:cms")
	assert.Contains(t, groups, "keycloak:atlas")
	assert.NotContains(t, groups, "cms")

	// Scopes were computed from Pelican's own templates against those groups,
	// not copied from the Keycloak token.
	// The colon in the group prefix survives into the scope's path component;
	// every scope parser in the codebase splits on the first colon only
	// (SplitN(s, ":", 2)), so this is unambiguous.
	scopes := tokenScopeStrings(t, tok)
	assert.Contains(t, scopes, "storage.read:/data/keycloak:cms")
	assert.Contains(t, scopes, "storage.read:/home/alice")

	// RFC 8693 §4.1 provenance.
	act, ok := tok.Get("act")
	require.True(t, ok, "token should carry an act claim")
	actMap, ok := act.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "kc-subject-1", actMap["sub"])
	assert.Equal(t, idp.issuerURL, actMap["iss"])
}

func toStringSlice(raw interface{}) []string {
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, i := range v {
			if s, ok := i.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func tokenScopeStrings(t *testing.T, tok jwtpkg.Token) []string {
	t.Helper()
	raw, ok := tok.Get("scope")
	require.True(t, ok)
	if s, ok := raw.(string); ok {
		return strings.Fields(s)
	}
	return toStringSlice(raw)
}

// ---- Trust boundary ----

func TestExternalExchangeUnknownIssuerMakesNoNetworkCall(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	// Deliberately do NOT register the stub IdP.
	_ = provider

	subjectToken := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"pelican-origin"}})
	status, body := exchange(t, ts, subjectToken, "")

	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "not trusted")
	// An unknown issuer must be rejected before anything is fetched, so an
	// attacker cannot use this endpoint to make the server call out.
	assert.Zero(t, idp.discHits.Load(), "discovery should not be contacted for an untrusted issuer")
	assert.Zero(t, idp.jwksHits.Load(), "JWKS should not be fetched for an untrusted issuer")
}

func TestExternalExchangeDisabledIssuerRejected(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	in := baseIssuerInput(idp, "keycloak")
	in.Enabled = boolPtr(false)
	registerIssuer(t, provider, in, true)

	subjectToken := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"pelican-origin"}})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "not trusted")
}

func TestExternalExchangeClientNotBlessedRejected(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	// Register the issuer but do NOT add it to the client's exchange_issuers.
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), false)

	subjectToken := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"pelican-origin"}})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "not authorized to exchange")
}

func TestExternalExchangeWrongAudienceRejected(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	// A token minted for a different client of the same IdP.
	subjectToken := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"some-other-service"}})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "audience")
}

func TestExternalExchangeMissingRequiredScopeRejected(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	in := baseIssuerInput(idp, "keycloak")
	in.RequiredScopes = slicePtr([]string{"pelican-access"})
	registerIssuer(t, provider, in, true)

	// Right audience, but without the scope the operator requires.
	subjectToken := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"pelican-origin"}, scope: "openid profile"})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "pelican-access")

	// With it, the exchange succeeds.
	ok := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"pelican-origin"},
		scope: "openid pelican-access", username: "alice"})
	status, _ = exchange(t, ts, ok, "")
	require.Equal(t, http.StatusOK, status)
}

func TestExternalExchangeRequiredClaimRejected(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	in := baseIssuerInput(idp, "keycloak")
	claims := map[string]string{"azp": "jupyterhub"}
	in.RequiredClaims = &claims
	registerIssuer(t, provider, in, true)

	bad := idp.mint(t, tokenOpts{sub: "s", aud: []string{"pelican-origin"}, azp: "some-other-client"})
	status, body := exchange(t, ts, bad, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "azp")

	good := idp.mint(t, tokenOpts{sub: "s", aud: []string{"pelican-origin"}, azp: "jupyterhub", username: "alice"})
	status, _ = exchange(t, ts, good, "")
	require.Equal(t, http.StatusOK, status)
}

// TestExternalExchangeSymmetricAlgorithmRejected covers the key-confusion case:
// a token signed with HMAC must never be verified against the issuer's public
// JWKS, no matter what the header claims.
func TestExternalExchangeSymmetricAlgorithmRejected(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	subjectToken := idp.mint(t, tokenOpts{
		sub: "kc-subject-1", aud: []string{"pelican-origin"},
		hmacKey: []byte("a-shared-secret-that-should-never-be-honored"),
	})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "allowed_algorithms")
}

func TestExternalExchangeExpiredTokenRejected(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	subjectToken := idp.mint(t, tokenOpts{
		sub: "kc-subject-1", aud: []string{"pelican-origin"}, expIn: -10 * time.Minute,
	})
	status, _ := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
}

// TestExternalExchangeIssuerSpoofRejected mints a token whose `iss` names the
// trusted issuer but which is signed by a different key.
func TestExternalExchangeIssuerSpoofRejected(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	attacker := newStubIdP(t)
	subjectToken := attacker.mint(t, tokenOpts{
		sub: "kc-subject-1", aud: []string{"pelican-origin"},
		issuer: idp.issuerURL, // claim to be the trusted issuer
	})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "verification")
}

// ---- Enrollment ----

func TestExternalExchangeNoAutoEnrollRequiresLinkedAccount(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	in := baseIssuerInput(idp, "keycloak")
	in.AutoEnroll = boolPtr(false)
	registerIssuer(t, provider, in, true)

	subjectToken := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "alice"})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
	// RFC 8693/6749 token-endpoint error set: a refused grant is invalid_grant,
	// not the authorization-endpoint-only access_denied.
	assert.Equal(t, "invalid_grant", body["error"])

	// Link the identity to an existing account and the same token now works.
	existing, err := database.CreateUser(database.ServerDatabase, "realalice", "local-sub", "https://local", database.Creator{UserID: "admin"})
	require.NoError(t, err)
	_, err = database.CreateUserIdentity(database.ServerDatabase, existing.ID, "kc-subject-1", idp.issuerURL)
	require.NoError(t, err)

	status, body = exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusOK, status, "unexpected response: %v", body)
	tok := validateWLCGToken(t, body["access_token"].(string), provider)
	assert.Equal(t, "realalice", tok.Subject(), "should map to the linked account, not the IdP's username claim")
}

func TestExternalExchangeAutoEnrollStampsCreator(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	detail := registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	subjectToken := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "newuser"})
	status, _ := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusOK, status)

	user, err := database.GetUserByIdentity(database.ServerDatabase, "kc-subject-1", idp.issuerURL)
	require.NoError(t, err)
	assert.Equal(t, "newuser", user.Username)
	// Auto-enrolled accounts must stay identifiable, so an operator who later
	// mistrusts this IdP can find everything it brought in.
	assert.Equal(t, database.CreatorExternalExchange, user.CreatedBy)
	assert.Equal(t, detail.Name, user.CreatorAuthMethodID)
}

// ---- Token policy ----

func TestExternalExchangeLifetimeCappedBySubjectToken(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	// A subject token with only two minutes left must not yield a token good
	// for the issuer's full access-token lifespan.
	subjectToken := idp.mint(t, tokenOpts{
		sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "alice", expIn: 2 * time.Minute,
	})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusOK, status)

	expiresIn, ok := body["expires_in"].(float64)
	require.True(t, ok)
	assert.LessOrEqual(t, int(expiresIn), 120)
	assert.Greater(t, int(expiresIn), 0)
}

func TestExternalExchangeNoRefreshTokenByDefault(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	scopes := []string{"openid", "offline_access", "wlcg", "storage.read:/", "storage.modify:/", "storage.create:/"}
	_, err := provider.Storage().UpdateClient(context.Background(), extClientID, ClientUpdate{Scopes: &scopes})
	require.NoError(t, err)

	subjectToken := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "alice"})
	status, body := exchange(t, ts, subjectToken, "openid offline_access")
	require.Equal(t, http.StatusOK, status)
	// A refresh token would outlive the foreign session that justified it.
	assert.Nil(t, body["refresh_token"], "refresh tokens must be opt-in per issuer")
}

func TestExternalExchangeKillSwitch(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)
	require.NoError(t, param.Issuer_DisableExternalTokenExchange.Set(true))

	subjectToken := idp.mint(t, tokenOpts{sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "alice"})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "disabled")
}

// TestExternalExchangeLocalTokenPathUnaffected guards the dispatch: a client
// blessed for an external issuer must still be able to exchange locally-issued
// tokens exactly as before.
func TestExternalExchangeLocalPathStillWorks(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	// An opaque (non-JWT) subject token has no `iss` to peek at and must take
	// the local path, which rejects it as an invalid grant rather than
	// treating it as an untrusted external token.
	status, body := exchange(t, ts, "not-a-jwt-opaque-token", "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "subject_token is invalid")
}

// ---- Group policy ----

func TestExternalExchangeGroupFiltering(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	in := baseIssuerInput(idp, "keycloak")
	in.GroupAllowPatterns = slicePtr([]string{"^cms"})
	registerIssuer(t, provider, in, true)

	subjectToken := idp.mint(t, tokenOpts{
		sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "alice",
		groups: []string{"cms", "cms-admin", "unrelated"},
	})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusOK, status)

	tok := validateWLCGToken(t, body["access_token"].(string), provider)
	raw, _ := tok.Get("wlcg.groups")
	groups := toStringSlice(raw)
	assert.Contains(t, groups, "keycloak:cms")
	assert.Contains(t, groups, "keycloak:cms-admin")
	assert.NotContains(t, groups, "keycloak:unrelated")
}

func TestExternalExchangeFlatGroupsWhenAcknowledged(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	in := baseIssuerInput(idp, "keycloak")
	in.GroupPrefix = strPtr("")
	in.AllowFlatGroups = boolPtr(true)
	registerIssuer(t, provider, in, true)

	subjectToken := idp.mint(t, tokenOpts{
		sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "alice", groups: []string{"cms"},
	})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusOK, status)

	tok := validateWLCGToken(t, body["access_token"].(string), provider)
	raw, _ := tok.Get("wlcg.groups")
	assert.Contains(t, toStringSlice(raw), "cms")
}

// ---- Configuration validation ----

// mapEntry builds one config-shaped external-issuer entry for ParseExternalIssuers.
func mapEntry(m map[string]interface{}) []interface{} { return []interface{}{m} }

// parseIssuerErr runs a single config entry through the real parse+validate path.
func parseIssuerErr(entry map[string]interface{}) error {
	_, err := ParseExternalIssuers(mapEntry(entry))
	return err
}

func TestExternalIssuerConfigValidation(t *testing.T) {
	_, _, idp := setupExternalExchange(t)

	t.Run("empty audience list is refused", func(t *testing.T) {
		err := parseIssuerErr(map[string]interface{}{"Name": "kc1", "IssuerURL": idp.issuerURL})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required_audiences")
	})
	t.Run("empty audience list is allowed when acknowledged", func(t *testing.T) {
		require.NoError(t, parseIssuerErr(map[string]interface{}{
			"Name": "kc2", "IssuerURL": idp.issuerURL, "AllowAnyAudience": true}))
	})
	t.Run("flat group names are refused without acknowledgment", func(t *testing.T) {
		err := parseIssuerErr(map[string]interface{}{
			"Name": "kc3", "IssuerURL": idp.issuerURL, "RequiredAudiences": []string{"aud"}, "GroupPrefix": ""})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "group_prefix")
	})
	t.Run("symmetric algorithms cannot be configured", func(t *testing.T) {
		err := parseIssuerErr(map[string]interface{}{
			"Name": "kc4", "IssuerURL": idp.issuerURL, "RequiredAudiences": []string{"aud"},
			"AllowedAlgorithms": []string{"HS256"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "asymmetric")
	})
	t.Run("plaintext issuer URLs are refused", func(t *testing.T) {
		err := parseIssuerErr(map[string]interface{}{
			"Name": "kc5", "IssuerURL": "http://keycloak.example.org/realms/p", "RequiredAudiences": []string{"aud"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})
	t.Run("mapped mode rejects a reserved local group target", func(t *testing.T) {
		err := parseIssuerErr(map[string]interface{}{
			"Name": "kc6", "IssuerURL": idp.issuerURL, "RequiredAudiences": []string{"aud"},
			"GroupMode": "mapped", "GroupMappings": map[string]string{"cms": "user-victim"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reserved ACL name")
	})
	t.Run("mapped mode rejects an invalid local group name", func(t *testing.T) {
		err := parseIssuerErr(map[string]interface{}{
			"Name": "kc7", "IssuerURL": idp.issuerURL, "RequiredAudiences": []string{"aud"},
			"GroupMode": "mapped", "GroupMappings": map[string]string{"cms": "not/a/group"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "group_mappings target")
	})
	t.Run("duplicate names are rejected across the list", func(t *testing.T) {
		_, err := ParseExternalIssuers([]interface{}{
			map[string]interface{}{"Name": "dup", "IssuerURL": idp.issuerURL, "RequiredAudiences": []string{"a"}},
			map[string]interface{}{"Name": "dup", "IssuerURL": idp.issuerURL + "/two", "RequiredAudiences": []string{"a"}},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate external issuer name")
	})
	t.Run("a valid entry parses with defaults", func(t *testing.T) {
		issuers, err := ParseExternalIssuers(mapEntry(map[string]interface{}{
			"Name": "keycloak", "IssuerURL": idp.issuerURL, "RequiredAudiences": []string{"pelican-origin"}}))
		require.NoError(t, err)
		require.Len(t, issuers, 1)
		assert.True(t, issuers[0].Enabled)
		assert.True(t, issuers[0].AutoEnroll)
		assert.Equal(t, "keycloak:", issuers[0].GroupPrefix, "prefix defaults to <name>:")
		assert.Equal(t, GroupModeClaim, issuers[0].GroupMode)
	})
}

func TestExternalExchangeMappedGroups(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	in := baseIssuerInput(idp, "keycloak")
	in.GroupMode = strPtr(GroupModeMapped)
	mapping := map[string]string{"cms": "cms-users"}
	in.GroupMappings = &mapping
	detail := registerIssuer(t, provider, in, true)

	// Mapped mode produces plain local group names — no prefix — because the
	// operator chose them explicitly.
	assert.Empty(t, detail.GroupPrefix, "mapped mode must not default a prefix")

	subjectToken := idp.mint(t, tokenOpts{
		sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "alice",
		groups: []string{"cms", "atlas"},
	})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusOK, status, "unexpected response: %v", body)

	tok := validateWLCGToken(t, body["access_token"].(string), provider)
	raw, _ := tok.Get("wlcg.groups")
	groups := toStringSlice(raw)
	assert.Contains(t, groups, "cms-users", "the mapped local name is what lands in the token")
	assert.NotContains(t, groups, "cms", "the external name itself must not survive")
	// The mapping is the allow-list: an unmapped assertion contributes nothing.
	assert.NotContains(t, groups, "atlas")
	assert.NotContains(t, groups, "keycloak:atlas")
}

func TestExternalExchangeIgnoreGroupMode(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	in := baseIssuerInput(idp, "keycloak")
	in.GroupMode = strPtr(GroupModeIgnore)
	registerIssuer(t, provider, in, true)

	subjectToken := idp.mint(t, tokenOpts{
		sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "alice",
		groups: []string{"cms"},
	})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusOK, status)

	tok := validateWLCGToken(t, body["access_token"].(string), provider)
	raw, ok := tok.Get("wlcg.groups")
	if ok {
		assert.NotContains(t, toStringSlice(raw), "cms")
		assert.NotContains(t, toStringSlice(raw), "keycloak:cms")
	}
}

// TestDryRunDoesNotEnroll proves the admin dry-run endpoint is side-effect free:
// evaluating an unlinked identity must report wouldEnroll without creating the
// account, so an operator can test a token without silently provisioning users.
func TestDryRunDoesNotEnroll(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	detail := registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	subjectToken := idp.mint(t, tokenOpts{
		sub: "kc-preview-1", aud: []string{"pelican-origin"}, username: "previewuser",
	})

	// Drive the dry-run endpoint directly.
	body, _ := json.Marshal(map[string]interface{}{"subject_token": subjectToken})
	url := ts.URL + "/api/v1.0/issuer/admin/ns" + extNS + "/external-issuers/" + detail.Name + "/dry-run"
	resp, err := ts.Client().Post(url, "application/json", bytesReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))

	assert.Equal(t, true, out["ok"], "dry run should accept the token")
	assert.Equal(t, true, out["would_enroll"], "an unlinked identity should report would_enroll")
	assert.Equal(t, "previewuser", out["username"])

	// The crucial assertion: NOTHING was created.
	_, lookupErr := database.GetUserByIdentity(database.ServerDatabase, "kc-preview-1", idp.issuerURL)
	assert.ErrorIs(t, lookupErr, gorm.ErrRecordNotFound, "dry-run must not create the account")
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// TestExternalExchangeRejectsReservedGroupNames is the security regression for
// reserved-group impersonation: a foreign token must never be able to assert a
// "user-<name>" personal group or the @authenticated sentinel and thereby
// inherit another principal's ACL authority. The filter applies AFTER
// prefixing, so it holds in flat-groups mode and even under a hostile prefix.
func TestExternalExchangeRejectsReservedGroupNames(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)

	// Flat-groups mode (the acknowledged, riskier config) is the sharp case:
	// the foreign name reaches the token verbatim unless filtered.
	in := baseIssuerInput(idp, "keycloak")
	in.GroupPrefix = strPtr("")
	in.AllowFlatGroups = boolPtr(true)
	registerIssuer(t, provider, in, true)

	subjectToken := idp.mint(t, tokenOpts{
		sub: "attacker-1", aud: []string{"pelican-origin"}, username: "attacker",
		groups: []string{"user-victim", "@authenticated", "legit-team"},
	})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusOK, status, "unexpected: %v", body)

	tok := validateWLCGToken(t, body["access_token"].(string), provider)
	raw, _ := tok.Get("wlcg.groups")
	groups := toStringSlice(raw)

	assert.NotContains(t, groups, "user-victim", "must not impersonate a personal group")
	assert.NotContains(t, groups, "@authenticated", "must not assert the all-authenticated sentinel")
	assert.Contains(t, groups, "legit-team", "a non-reserved group still passes")
}

// TestExternalIssuerRejectsReservedPrefix covers the config-time guard: a
// prefix that lands foreign names in the personal-group namespace is refused.
func TestExternalIssuerRejectsReservedPrefix(t *testing.T) {
	_, _, idp := setupExternalExchange(t)
	err := parseIssuerErr(map[string]interface{}{
		"Name": "keycloak", "IssuerURL": idp.issuerURL,
		"RequiredAudiences": []string{"pelican-origin"}, "GroupPrefix": "user-"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved ACL namespace")
}

// TestExternalIssuerAdminHTTP exercises the read-only admin surface over HTTP:
// listing the configured issuers (external issuers are config, not created via
// the API) and that a dry-run against a missing issuer 404s.
func TestExternalIssuerAdminHTTP(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)
	base := ts.URL + "/api/v1.0/issuer/admin/ns" + extNS + "/external-issuers"

	// List returns the configured issuer with its defaults filled in.
	resp, err := ts.Client().Get(base)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list []map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	resp.Body.Close()
	require.Len(t, list, 1)
	assert.Equal(t, "keycloak", list[0]["name"])
	assert.Equal(t, idp.issuerURL, list[0]["issuer_url"])
	assert.Equal(t, "keycloak:", list[0]["group_prefix"])
	assert.Equal(t, true, list[0]["auto_enroll"])

	// Probe/dry-run against an unknown issuer name 404s.
	resp, err = ts.Client().Post(base+"/no-such/probe", "application/json", bytesReader([]byte("{}")))
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

// TestExternalExchangeRejectsTokenWithoutExpiry proves a subject token with no
// exp is refused: it could not be lifetime-capped, so it would mint a
// full-lifespan Pelican token from an assertion that never expires.
func TestExternalExchangeRejectsTokenWithoutExpiry(t *testing.T) {
	provider, ts, idp := setupExternalExchange(t)
	registerIssuer(t, provider, baseIssuerInput(idp, "keycloak"), true)

	subjectToken := idp.mint(t, tokenOpts{
		sub: "kc-subject-1", aud: []string{"pelican-origin"}, username: "alice", noExp: true,
	})
	status, body := exchange(t, ts, subjectToken, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, fmt.Sprint(body["error_description"]), "never expires")
}
