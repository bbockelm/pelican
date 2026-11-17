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

package director

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/oauth2/backendcred"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestServeClientIDMetadataDocument(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	// Configured with a redundant default port: the document's client_id
	// must still be the URL a server derives from the same endpoint.
	fedInfo := pelican_url.FederationDiscovery{DirectorEndpoint: mockRawDirUrl443, RegistryEndpoint: mockRegUrlWoPort}
	test_utils.MockFederationRoot(t, &fedInfo, nil)
	test_utils.InitClient(t, map[param.Param]any{
		param.Federation_DiscoveryUrl: param.Federation_DiscoveryUrl.GetString(),
		param.Federation_DirectorUrl:  mockRawDirUrl443,
		param.Federation_RegistryUrl:  mockRegUrlWoPort,
		param.TLSSkipVerify:           true,
	})

	// Route through the real director API registration, so the route and
	// backendcred.ClientIDMetadataDocumentPath cannot drift apart.
	egrp := &errgroup.Group{}
	ctx := context.WithValue(context.Background(), config.EgrpKey, egrp)
	router := gin.New()
	RegisterDirectorAPI(ctx, router.Group("/"))

	get := func(rawURL string) *httptest.ResponseRecorder {
		u, err := url.Parse(rawURL)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u.Path, nil))
		return w
	}

	for _, prefix := range []string{"/caches/site-a", "/origins/origin.example.org:8443"} {
		clientID, err := backendcred.ClientIDMetadataDocumentURL(mockRawDirUrl443, prefix)
		require.NoError(t, err)
		w := get(clientID)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"))

		var doc backendcred.ClientIDMetadataDocument
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
		assert.Equal(t, clientID, doc.ClientID)
		assert.Equal(t, mockRegUrlWoPort+"/api/v1.0/registry"+prefix+"/.well-known/issuer.jwks", doc.JWKSURI)
		assert.Equal(t, "private_key_jwt", doc.TokenEndpointAuthMethod)
	}

	// Anything but a single cache or origin name is not a server.
	for _, bad := range []string{"/caches/a/b", "/namespaces/foo", "/caches/..", "/"} {
		w := get(mockDirUrlWoPort + backendcred.ClientIDMetadataDocumentPath + bad)
		assert.Equal(t, http.StatusNotFound, w.Code, bad)
	}

	require.NoError(t, param.Director_DisableClientIDMetadataDocuments.Set(true))
	clientID, err := backendcred.ClientIDMetadataDocumentURL(mockDirUrlWoPort, "/caches/site-a")
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, get(clientID).Code)
}
