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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientIDMetadataDocumentURL(t *testing.T) {
	for _, tc := range []struct {
		director, prefix, want string
	}{
		{"https://director.example.org", "/caches/site-a", "https://director.example.org/api/v1.0/director/oauthClients/caches/site-a"},
		// The default port, a trailing slash and an http scheme all
		// normalize away, so a server and its director agree on the
		// client_id even when configured with different spellings.
		{"https://director.example.org:443/", "/caches/site-a", "https://director.example.org/api/v1.0/director/oauthClients/caches/site-a"},
		{"http://director.example.org", "/origins/origin.example.org:8443", "https://director.example.org/api/v1.0/director/oauthClients/origins/origin.example.org:8443"},
		{"https://director.example.org:8444", "/caches/site-a", "https://director.example.org:8444/api/v1.0/director/oauthClients/caches/site-a"},
	} {
		got, err := ClientIDMetadataDocumentURL(tc.director, tc.prefix)
		require.NoError(t, err, tc.prefix)
		assert.Equal(t, tc.want, got)
	}

	for _, bad := range []string{
		"", "/caches/", "/origins/", "/namespace/foo", "/caches/a/b", "/caches/..", "/caches/a..b",
		"/caches/%2e%2e", "/caches/a?b", "/caches/a#b", "/caches/.hidden",
	} {
		_, err := ClientIDMetadataDocumentURL("https://director.example.org", bad)
		assert.Error(t, err, "prefix %q must be rejected", bad)
	}
	_, err := ClientIDMetadataDocumentURL("https://user:pw@director.example.org", "/caches/a")
	assert.Error(t, err)
}

func TestNewClientIDMetadataDocument(t *testing.T) {
	doc, err := NewClientIDMetadataDocument("https://director.example.org", "https://registry.example.org:443",
		"/caches/site-a", "OSDF")
	require.NoError(t, err)
	assert.Equal(t, "https://director.example.org/api/v1.0/director/oauthClients/caches/site-a", doc.ClientID)
	assert.Equal(t, "https://registry.example.org/api/v1.0/registry/caches/site-a/.well-known/issuer.jwks", doc.JWKSURI)
	assert.Equal(t, "private_key_jwt", doc.TokenEndpointAuthMethod)
	assert.ElementsMatch(t, []string{grantTypeDeviceCode, grantTypeRefreshToken}, doc.GrantTypes)
	assert.Equal(t, "Pelican cache site-a (OSDF)", doc.ClientName)

	// The draft forbids shared secrets in a metadata document; make sure
	// nothing resembling one is ever serialized.
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "client_secret")
	assert.NotContains(t, string(raw), "redirect_uris")
}

func TestFetchClientIDMetadataDocumentValidation(t *testing.T) {
	var body any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, body)
	}))
	defer srv.Close()
	clientID := srv.URL + ClientIDMetadataDocumentPath + "/caches/a"

	good := ClientIDMetadataDocument{
		ClientID:                clientID,
		GrantTypes:              []string{grantTypeDeviceCode, grantTypeRefreshToken},
		TokenEndpointAuthMethod: authMethodPrivateKeyJWT,
		JWKSURI:                 "https://registry.example.org/jwks",
	}
	body = good
	_, err := fetchClientIDMetadataDocument(context.Background(), srv.Client(), clientID)
	require.NoError(t, err)

	wrongID := good
	wrongID.ClientID = clientID + "x"
	body = wrongID
	_, err = fetchClientIDMetadataDocument(context.Background(), srv.Client(), clientID)
	assert.ErrorContains(t, err, "names client_id")

	public := good
	public.TokenEndpointAuthMethod = authMethodNone
	body = public
	_, err = fetchClientIDMetadataDocument(context.Background(), srv.Client(), clientID)
	assert.ErrorContains(t, err, "token_endpoint_auth_method")

	noDevice := good
	noDevice.GrantTypes = []string{"authorization_code"}
	body = noDevice
	_, err = fetchClientIDMetadataDocument(context.Background(), srv.Client(), clientID)
	assert.ErrorContains(t, err, "device code")
}

func TestFileTokenSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("  abc\n"), 0600))
	tok, err := FileTokenSource{Path: path}.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "abc", tok)

	// A replaced file is read on the next call.
	require.NoError(t, os.WriteFile(path, []byte("def"), 0600))
	tok, err = FileTokenSource{Path: path}.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "def", tok)

	_, err = FileTokenSource{Path: path + ".missing"}.Token(context.Background())
	assert.Error(t, err)
}

func TestAdminAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	env := newTestEnv(t)
	m := startManager(t, env.config(t), env.store)
	reg := NewRegistry()
	require.NoError(t, reg.Add(m))
	require.Error(t, reg.Add(m), "duplicate IDs are refused")

	engine := gin.New()
	authCalls := 0
	auth := func(ctx *gin.Context) {
		authCalls++
		ctx.Set("User", "alice")
	}
	RegisterAPI(engine.Group("/api/v1.0/cache_ui/backend_credentials"), reg, "cache", auth)
	// Another module's API must not see this credential.
	RegisterAPI(engine.Group("/api/v1.0/origin_ui/backend_credentials"), reg, "origin", auth)

	do := func(method, path string) (*httptest.ResponseRecorder, []byte) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		engine.ServeHTTP(w, req)
		return w, w.Body.Bytes()
	}

	w, body := do(http.MethodGet, "/api/v1.0/cache_ui/backend_credentials")
	require.Equal(t, http.StatusOK, w.Code)
	var list []Status
	require.NoError(t, json.Unmarshal(body, &list))
	require.Len(t, list, 1)
	assert.Equal(t, StateInactive, list[0].State)

	w, body = do(http.MethodGet, "/api/v1.0/origin_ui/backend_credentials")
	require.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, "[]", string(body))
	w, _ = do(http.MethodPost, "/api/v1.0/origin_ui/backend_credentials/test-backend/activate")
	assert.Equal(t, http.StatusNotFound, w.Code)

	w, body = do(http.MethodPost, "/api/v1.0/cache_ui/backend_credentials/test-backend/activate")
	require.Equal(t, http.StatusOK, w.Code, string(body))
	var st Status
	require.NoError(t, json.Unmarshal(body, &st))
	assert.Equal(t, StatePending, st.State)
	assert.NotEmpty(t, st.UserCode)
	assert.NotEmpty(t, st.VerificationURIComplete)
	assert.NotContains(t, string(body), "device-", "the device code is the poller's secret, never shown")

	env.issuer.approve(st.UserCode)
	require.Eventually(t, func() bool { return m.Status().State == StateActive }, 10*time.Second, 10*time.Millisecond)
	assert.Equal(t, "alice", m.Status().ActivatedBy)

	w, body = do(http.MethodGet, "/api/v1.0/cache_ui/backend_credentials")
	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, string(body), "access-", "statuses never carry tokens")
	assert.NotContains(t, string(body), "refresh-")

	w, _ = do(http.MethodDelete, "/api/v1.0/cache_ui/backend_credentials/test-backend")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, StateInactive, m.Status().State)
	assert.Positive(t, authCalls)

	w, _ = do(http.MethodDelete, "/api/v1.0/cache_ui/backend_credentials/nope")
	assert.Equal(t, http.StatusNotFound, w.Code)
}
