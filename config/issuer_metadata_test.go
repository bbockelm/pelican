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

package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestGetAuthServerMetadata(t *testing.T) {
	var srv *httptest.Server
	served := map[string]map[string]any{}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md, ok := served[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(md)
	}))
	defer srv.Close()

	t.Run("openid-configuration", func(t *testing.T) {
		served = map[string]map[string]any{
			"/tenant/.well-known/openid-configuration": {
				"issuer":                                srv.URL + "/tenant",
				"token_endpoint":                        srv.URL + "/token",
				"client_id_metadata_document_supported": true,
				"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
			},
		}
		md, err := GetAuthServerMetadata(context.Background(), srv.URL+"/tenant", srv.Client())
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/token", md.TokenURL)
		assert.True(t, md.ClientIDMetadataDocumentSupported)
		assert.Equal(t, []string{"private_key_jwt"}, md.TokenEndpointAuthMethods)
	})

	t.Run("rfc8414 path insertion", func(t *testing.T) {
		served = map[string]map[string]any{
			"/.well-known/oauth-authorization-server/tenant": {
				"issuer":         srv.URL + "/tenant",
				"token_endpoint": srv.URL + "/token",
			},
		}
		md, err := GetAuthServerMetadata(context.Background(), srv.URL+"/tenant/", srv.Client())
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/token", md.TokenURL)
	})

	t.Run("issuer mismatch", func(t *testing.T) {
		served = map[string]map[string]any{
			"/.well-known/openid-configuration": {
				"issuer":         "https://elsewhere.example.org",
				"token_endpoint": srv.URL + "/token",
			},
		}
		_, err := GetAuthServerMetadata(context.Background(), srv.URL, srv.Client())
		require.ErrorContains(t, err, "elsewhere.example.org")
	})

	t.Run("nothing served", func(t *testing.T) {
		served = map[string]map[string]any{}
		_, err := GetAuthServerMetadata(context.Background(), srv.URL, srv.Client())
		require.Error(t, err)
	})
}

func TestDecryptStringAndRotate(t *testing.T) {
	ResetConfig()
	t.Cleanup(ResetConfig)
	keyDir := filepath.Join(t.TempDir(), "issuer-keys")
	require.NoError(t, param.IssuerKeysDirectory.Set(keyDir))

	sealed, err := EncryptString("refresh-token")
	require.NoError(t, err)

	plain, rotated, err := DecryptStringAndRotate(sealed)
	require.NoError(t, err)
	assert.Equal(t, "refresh-token", plain)
	assert.Empty(t, rotated, "no rotation while the sealing key is current")

	// Make a new key current (lowest lexical order wins), as in
	// TestDecryptString.
	keyFiles, err := os.ReadDir(keyDir)
	require.NoError(t, err)
	require.Len(t, keyFiles, 1)
	require.NoError(t, os.Rename(filepath.Join(keyDir, keyFiles[0].Name()), filepath.Join(keyDir, "pelican_generated_2.pem")))
	_, err = GeneratePEM(keyDir)
	require.NoError(t, err)
	changed, err := RefreshKeys()
	require.NoError(t, err)
	require.True(t, changed)

	plain, rotated, err = DecryptStringAndRotate(sealed)
	require.NoError(t, err)
	assert.Equal(t, "refresh-token", plain)
	require.NotEmpty(t, rotated)
	current, err := GetIssuerPrivateJWK()
	require.NoError(t, err)
	again, keyID, err := DecryptString(rotated)
	require.NoError(t, err)
	assert.Equal(t, "refresh-token", again)
	assert.Equal(t, current.KeyID(), keyID)
}
