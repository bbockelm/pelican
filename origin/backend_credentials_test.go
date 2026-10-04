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

package origin

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/oauth2/backendcred"
	"github.com/pelicanplatform/pelican/origin_serve"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestInitBackendCredentials(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	backendcred.ResetDefaultForTest()
	t.Cleanup(backendcred.ResetDefaultForTest)

	tmp := t.TempDir()
	require.NoError(t, param.IssuerKeysDirectory.Set(filepath.Join(tmp, "issuer-keys")))
	db, err := utils.InitSQLiteDB(filepath.Join(tmp, "origin.sqlite"))
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, utils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	oldDB := database.ServerDatabase
	database.ServerDatabase = db
	t.Cleanup(func() { database.ServerDatabase = oldDB })

	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
	})

	// Without the knob nothing is created.
	require.NoError(t, param.Origin_StorageType.Set(string(server_structs.OriginStorageHTTPSv2)))
	require.NoError(t, InitBackendCredentials(ctx, egrp))
	assert.Nil(t, backendcred.Default().Get(origin_serve.HTTPSBackendCredentialID))
	assert.Empty(t, ManagedHTTPSTokenFile())

	require.NoError(t, param.Origin_HttpAuthOAuth2DeviceFlow.Set(true))
	require.NoError(t, param.Origin_HttpAuthOAuth2Issuer.Set("https://issuer.example.org"))
	require.NoError(t, param.Origin_HttpAuthOAuth2Scopes.Set([]string{"offline_access", "storage.read:/"}))
	require.NoError(t, param.Origin_EnableStandaloneMode.Set(true))
	require.NoError(t, InitBackendCredentials(ctx, egrp))

	mgr := backendcred.Default().Get(origin_serve.HTTPSBackendCredentialID)
	require.NotNil(t, mgr)
	assert.Equal(t, backendCredentialOwner, mgr.Owner())
	st := mgr.Status()
	assert.Equal(t, backendcred.StateInactive, st.State)
	assert.Equal(t, "https://issuer.example.org", st.Issuer)
	assert.Equal(t, []string{"offline_access", "storage.read:/"}, st.Scopes)
	require.ErrorIs(t, mgr.Available(), backendcred.ErrNotActivated)
	// The native backend needs no token file; only the XRootD one does.
	assert.Empty(t, ManagedHTTPSTokenFile())

	// Settings that backendcred rejects fail origin startup.
	for _, bad := range []struct {
		param param.StringParam
		value string
	}{
		{param.Origin_HttpAuthOAuth2ClientRegistration, "bogus"},
		{param.Origin_HttpAuthOAuth2Issuer, "http://issuer.example.org"},
	} {
		backendcred.ResetDefaultForTest()
		old := bad.param.GetString()
		require.NoError(t, bad.param.Set(bad.value))
		assert.Error(t, InitBackendCredentials(ctx, egrp), "%s=%s", bad.param.GetName(), bad.value)
		require.NoError(t, bad.param.Set(old))
	}

	require.NoError(t, param.Origin_StorageType.Set(string(server_structs.OriginStorageHTTPS)))
	assert.Equal(t, filepath.Join(param.Origin_RunLocation.GetString(), "backend-credentials", "origin-https.tok"), ManagedHTTPSTokenFile())
}
