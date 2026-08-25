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

package fed_tests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtpkg "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/oauth2/issuer"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// e2eStubIdP is a minimal external OIDC issuer standing in for a collaborating
// project's Keycloak: an OIDC discovery document, a JWKS, and RS256 token
// minting.
type e2eStubIdP struct {
	server    *httptest.Server
	key       *rsa.PrivateKey
	kid       string
	issuerURL string
}

func newE2EStubIdP(t *testing.T) *e2eStubIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idp := &e2eStubIdP{key: key, kid: "e2e-stub-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   idp.issuerURL,
			"jwks_uri": idp.issuerURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
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

func (idp *e2eStubIdP) mint(t *testing.T, sub, username, audience string) string {
	t.Helper()
	tok, err := jwtpkg.NewBuilder().
		Issuer(idp.issuerURL).
		Subject(sub).
		Audience([]string{audience}).
		Claim("preferred_username", username).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)
	privJWK, err := jwk.FromRaw(idp.key)
	require.NoError(t, err)
	_ = privJWK.Set(jwk.KeyIDKey, idp.kid)
	signed, err := jwtpkg.Sign(tok, jwtpkg.WithKey(jwa.RS256, privJWK))
	require.NoError(t, err)
	return string(signed)
}

// externalExchangeOriginConfig takes the storage prefix and the stub IdP's
// issuer URL. External issuers are configuration, so the trusted Keycloak stand-in
// is declared here on the export rather than seeded into the database.
const externalExchangeOriginConfig = `
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  Exports:
    - FederationPrefix: /users
      StoragePrefix: %s
      Capabilities: ["Reads", "Writes", "Listings"]
      ExternalIssuers:
        - Name: keycloak
          IssuerURL: %s
          RequiredAudiences: [pelican-origin]
          UsernameClaims: [preferred_username]
          GroupMode: ignore
          IncludeLocalGroups: false
Issuer:
  AuthorizationTemplates:
    - prefix: /users/$USER
      actions: ["read", "write", "create"]
`

// TestExternalTokenExchangeE2E proves the whole feature end to end against a
// live federation: a token minted by an external issuer is exchanged for a
// Pelican token, and that Pelican token is accepted by the data plane for a
// real object download.
//
//	stub IdP token  --(RFC 8693 exchange at the origin's issuer)-->  Pelican token
//	                                                                      |
//	                                                     client.DoGet through XRootD
func TestExternalTokenExchangeE2E(t *testing.T) {
	// Data-plane download needs a real XRootD-backed federation, like the other
	// e2e transfer tests; skip where XRootD is unavailable.
	skipIfNoXRootD(t)
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	idp := newE2EStubIdP(t)

	// An admin is required in the htpasswd file for the auth subsystem to start.
	htpasswdDir := t.TempDir()
	htpasswdFile := filepath.Join(htpasswdDir, "htpasswd")
	adminHash, err := bcrypt.GenerateFromPassword([]byte(randomString(16)), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(htpasswdFile, []byte(fmt.Sprintf("admin:%s\n", string(adminHash))), 0600))
	require.NoError(t, param.Server_UIPasswordFile.Set(htpasswdFile))

	// Storage for the /users export, with alice's object pre-staged.
	tmpDir := t.TempDir()
	usersDir := filepath.Join(tmpDir, "users-store")
	aliceDir := filepath.Join(usersDir, "alice")
	require.NoError(t, os.MkdirAll(aliceDir, 0755))
	objectContent := "data behind an exchanged Keycloak token"
	require.NoError(t, os.WriteFile(filepath.Join(aliceDir, "hello.txt"), []byte(objectContent), 0644))

	ft := fed_test_utils.NewFedTest(t, fmt.Sprintf(externalExchangeOriginConfig, usersDir, idp.issuerURL))
	require.NotNil(t, ft)

	serverURL := param.Server_ExternalWebUrl.GetString()
	const namespace = "/users"
	const clientID = "e2e-exchange-client"
	const clientSecret = "e2e-exchange-secret"

	// The trusted external issuer is declared in the origin configuration above.
	// The per-client blessing (allow_external_exchange) still lives in the DB,
	// since clients are created at runtime; seed a blessed exchange client.
	seedExchangeClient(t, database.ServerDatabase, namespace, clientID, clientSecret)

	// ----- Mint a token at the external issuer for "alice" -----
	subjectToken := idp.mint(t, "alice-kc-subject", "alice", "pelican-origin")

	// ----- Exchange it at the origin's embedded issuer (RFC 8693) -----
	tokenURL := serverURL + "/api/v1.0/issuer/ns" + namespace + "/token"
	httpClient := &http.Client{Transport: config.GetTransport()}
	form := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token": {subjectToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	resp, err := httpClient.PostForm(tokenURL, form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var exchange struct {
		AccessToken     string `json:"access_token"`
		TokenType       string `json:"token_type"`
		IssuedTokenType string `json:"issued_token_type"`
		Scope           string `json:"scope"`
		Error           string `json:"error"`
		ErrorDesc       string `json:"error_description"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&exchange))
	require.Equal(t, http.StatusOK, resp.StatusCode, "exchange failed: %s / %s", exchange.Error, exchange.ErrorDesc)
	require.NotEmpty(t, exchange.AccessToken)
	assert.Equal(t, "Bearer", exchange.TokenType)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", exchange.IssuedTokenType)

	// The Pelican token is issued by THIS origin's issuer, and its scopes came
	// from alice's $USER authorization template — not from the Keycloak token.
	issuerURL := issuer.IssuerURLForNamespace(namespace)
	claims := validateWLCGToken(t, exchange.AccessToken, issuerURL)
	assert.Equal(t, "alice", claims["sub"])
	assert.Contains(t, exchange.Scope, "storage.read:/users/alice")

	// ----- The auto-enrolled account exists and is stamped as external -----
	user, err := database.GetUserByIdentity(database.ServerDatabase, "alice-kc-subject", idp.issuerURL)
	require.NoError(t, err)
	assert.Equal(t, "alice", user.Username)
	assert.Equal(t, database.CreatorExternalExchange, user.CreatedBy)

	// ----- Use the exchanged token to download the object via the data plane -----
	hostname := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	objectURL := fmt.Sprintf("pelican://%s:%d/users/alice/hello.txt", hostname, port)

	downloadFile := filepath.Join(t.TempDir(), "downloaded.txt")
	results, err := client.DoGet(ft.Ctx, objectURL, downloadFile, false,
		client.WithToken(exchange.AccessToken))
	require.NoError(t, err, "the exchanged token must be accepted by the origin data plane")
	require.NotEmpty(t, results)
	assert.Greater(t, results[0].TransferredBytes, int64(0))

	got, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, objectContent, string(got), "downloaded content must match what was stored")

	// ----- Negative control: a path outside alice's namespace is refused -----
	require.NoError(t, os.MkdirAll(filepath.Join(usersDir, "bob"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(usersDir, "bob", "secret.txt"), []byte("nope"), 0644))
	_, err = client.DoGet(ft.Ctx,
		fmt.Sprintf("pelican://%s:%d/users/bob/secret.txt", hostname, port),
		filepath.Join(t.TempDir(), "bob.txt"), false,
		client.WithToken(exchange.AccessToken))
	require.Error(t, err, "alice's exchanged token must not read another user's namespace")
}

// seedExchangeClient inserts a confidential OAuth2 client blessed for token
// exchange from the given external issuer.
func seedExchangeClient(t *testing.T, db *gorm.DB, namespace, clientID, clientSecret string) {
	t.Helper()
	j := func(v interface{}) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return string(b)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	require.NoError(t, err)
	rec := &issuer.OIDCClientRecord{
		ID:                    clientID,
		Namespace:             namespace,
		ClientSecret:          string(hash),
		RedirectURIs:          j([]string{}),
		GrantTypes:            j([]string{"urn:ietf:params:oauth:grant-type:token-exchange"}),
		ResponseTypes:         j([]string{}),
		Scopes:                j([]string{"openid", "wlcg", "storage.read:/", "storage.modify:/", "storage.create:/"}),
		AllowExternalExchange: true,
	}
	require.NoError(t, db.Create(rec).Error)
}
