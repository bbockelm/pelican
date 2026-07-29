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

package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// setupFollowerTest configures issuer keys and a migrated registry database,
// mirroring the on-disk state of a real registry server.
func setupFollowerTest(t *testing.T) (dbPath string) {
	t.Helper()
	config.ResetConfig()
	t.Cleanup(func() {
		if database.ServerDatabase != nil {
			_ = database.ShutdownDB()
			database.ServerDatabase = nil
		}
		config.ResetFederationForTest()
		config.ResetConfig()
	})

	tmpDir := t.TempDir()
	dbPath = filepath.Join(tmpDir, "test.sqlite")
	keysDir := filepath.Join(tmpDir, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0750))

	require.NoError(t, param.IssuerKeysDirectory.Set(keysDir))
	config.ResetIssuerPrivateKeys()
	_, err := config.GeneratePEM(keysDir)
	require.NoError(t, err)
	_, err = config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	require.NoError(t, param.MultiSet(map[string]interface{}{
		"Server.DbLocation":              dbPath,
		"Server.DatabaseBackup.Location": filepath.Join(tmpDir, "backups"),
		"Server.ExternalWebUrl":          "https://this-registry.test:8444",
	}))

	db, err := utils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	database.ServerDatabase = db
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, utils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, utils.MigrateServerSpecificDB(sqlDB, database.EmbedRegistryMigrations, "registry_migrations", "registry"))
	require.NoError(t, db.Exec("CREATE TABLE test_data (id INTEGER PRIMARY KEY, value TEXT)").Error)
	require.NoError(t, db.Exec("INSERT INTO test_data (value) VALUES ('hello'), ('world')").Error)

	resetFollowerState()
	resetSnapshotCache()
	return dbPath
}

func resetFollowerState() {
	followerStatus.mu.Lock()
	defer followerStatus.mu.Unlock()
	followerStatus.sourceEndpoint = ""
	followerStatus.baseline = time.Time{}
	followerStatus.lastAttempt = time.Time{}
	followerStatus.lastError = ""
	followerStatus.lastSync = time.Time{}
	followerStatus.snapshotTime = time.Time{}
}

func resetSnapshotCache() {
	snapshotCache.mu.Lock()
	defer snapshotCache.mu.Unlock()
	snapshotCache.path = ""
	snapshotCache.created = time.Time{}
	snapshotCache.target = database.MigrationVersions{}
	snapshotCache.meta = database.BackupMetadata{}
}

func snapshotTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1.0/registry/*wildcard", wildcardHandler)
	return router
}

func mintSnapshotToken(t *testing.T, scope token_scopes.TokenScope) string {
	t.Helper()
	tokCfg := token.NewWLCGToken()
	tokCfg.Lifetime = time.Minute
	tokCfg.Issuer = "https://follower.test:8444"
	tokCfg.Subject = "https://follower.test:8444"
	tokCfg.AddAudiences("this-registry.test:8444")
	tokCfg.AddScopes(scope)
	tok, err := tokCfg.CreateToken()
	require.NoError(t, err)
	return tok
}

func TestBlockInFollowerMode(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() { config.ResetConfig() })
	gin.SetMode(gin.TestMode)

	run := func(followerEnabled bool) *httptest.ResponseRecorder {
		require.NoError(t, param.MultiSet(map[string]interface{}{
			"Registry.Follower.Enabled": followerEnabled,
		}))
		router := gin.New()
		router.POST("/mutate", blockInFollowerMode, func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{"ok": true})
		})
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mutate", nil)
		router.ServeHTTP(recorder, req)
		return recorder
	}

	assert.Equal(t, http.StatusServiceUnavailable, run(true).Code)
	assert.Equal(t, http.StatusOK, run(false).Code)
}

func TestFollowerReadOnlyMiddleware(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() { config.ResetConfig() })
	gin.SetMode(gin.TestMode)

	require.NoError(t, param.MultiSet(map[string]interface{}{
		"Registry.Follower.Enabled": true,
	}))
	router := gin.New()
	router.Use(followerReadOnlyMiddleware)
	handler := func(ctx *gin.Context) { ctx.JSON(http.StatusOK, gin.H{"ok": true}) }
	router.GET("/thing", handler)
	router.POST("/thing", handler)
	router.DELETE("/thing", handler)

	for method, expected := range map[string]int{
		http.MethodGet:    http.StatusOK,
		http.MethodPost:   http.StatusServiceUnavailable,
		http.MethodDelete: http.StatusServiceUnavailable,
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(method, "/thing", nil))
		assert.Equal(t, expected, recorder.Code, "method %s", method)
	}
}

func TestServeDatabaseSnapshot(t *testing.T) {
	setupFollowerTest(t)
	router := snapshotTestRouter()

	get := func(query string, token string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1.0/registry/database/snapshot"+query, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		router.ServeHTTP(recorder, req)
		return recorder
	}

	t.Run("no-token-rejected", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, get("", "").Code)
	})

	t.Run("wrong-scope-rejected", func(t *testing.T) {
		tok := mintSnapshotToken(t, token_scopes.Registry_EditRegistration)
		assert.Equal(t, http.StatusForbidden, get("", tok).Code)
	})

	t.Run("self-instance-rejected", func(t *testing.T) {
		tok := mintSnapshotToken(t, token_scopes.Registry_DatabaseDownload)
		recorder := get("?instance="+registryInstanceID, tok)
		assert.Equal(t, http.StatusConflict, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "self-download")
	})

	t.Run("follower-refuses-to-serve", func(t *testing.T) {
		require.NoError(t, param.MultiSet(map[string]interface{}{
			"Registry.Follower.Enabled": true,
		}))
		t.Cleanup(func() {
			require.NoError(t, param.MultiSet(map[string]interface{}{
				"Registry.Follower.Enabled": false,
			}))
		})
		tok := mintSnapshotToken(t, token_scopes.Registry_DatabaseDownload)
		recorder := get("", tok)
		assert.Equal(t, http.StatusConflict, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "follower mode")
	})

	t.Run("valid-token-gets-snapshot", func(t *testing.T) {
		tok := mintSnapshotToken(t, token_scopes.Registry_DatabaseDownload)
		recorder := get("?instance=some-other-instance", tok)
		require.Equal(t, http.StatusOK, recorder.Code)
		assert.NotEmpty(t, recorder.Header().Get(snapshotTimestampHeader))

		// The payload must be a decryptable snapshot with a metadata block.
		snapPath := filepath.Join(t.TempDir(), "downloaded.bak")
		require.NoError(t, os.WriteFile(snapPath, recorder.Body.Bytes(), 0600))
		_, snapTime, err := database.DecryptedSnapshotMetadata(snapPath)
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().UTC(), snapTime, time.Minute)
		preparedPath, err := database.PrepareSnapshotForCutover(snapPath)
		require.NoError(t, err)
		os.Remove(preparedPath)
	})

	t.Run("bad-version-param-rejected", func(t *testing.T) {
		tok := mintSnapshotToken(t, token_scopes.Registry_DatabaseDownload)
		assert.Equal(t, http.StatusBadRequest, get("?universalVersion=abc", tok).Code)
	})
}

func TestFollowerSyncOnce(t *testing.T) {
	setupFollowerTest(t)
	ctx := context.Background()

	// Build the "leader's" snapshot from the current database contents, then
	// dirty the local database so a successful sync is observable.
	snapshotPath := filepath.Join(t.TempDir(), "leader-snap.bak")
	_, err := database.CreateEncryptedSnapshot(ctx, snapshotPath, database.MigrationVersions{})
	require.NoError(t, err)
	require.NoError(t, database.ServerDatabase.Exec("DELETE FROM test_data").Error)

	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1.0/registry/database/snapshot", r.URL.Path)
		assert.NotEmpty(t, r.URL.Query().Get("instance"))
		assert.NotEmpty(t, r.URL.Query().Get("universalVersion"))
		assert.NotEmpty(t, r.URL.Query().Get("registryVersion"))
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
		http.ServeFile(w, r, snapshotPath)
	}))
	t.Cleanup(leader.Close)

	config.SetFederation(pelican_url.FederationDiscovery{
		DiscoveryEndpoint: leader.URL,
		DirectorEndpoint:  leader.URL,
		RegistryEndpoint:  leader.URL,
		JwksUri:           leader.URL + "/.well-known/issuer.jwks",
	})

	require.NoError(t, followerSyncOnce(ctx))

	// The deleted rows are back: the local database was cut over to the snapshot.
	var count int64
	require.NoError(t, database.ServerDatabase.Raw("SELECT COUNT(*) FROM test_data").Scan(&count).Error)
	assert.Equal(t, int64(2), count)

	followerStatus.mu.Lock()
	snapTime := followerStatus.snapshotTime
	lastSync := followerStatus.lastSync
	followerStatus.mu.Unlock()
	assert.False(t, snapTime.IsZero())
	assert.False(t, lastSync.IsZero())

	// A second sync with the identical snapshot skips the cutover but succeeds.
	require.NoError(t, followerSyncOnce(ctx))
	followerStatus.mu.Lock()
	assert.Equal(t, lastSync, followerStatus.lastSync)
	followerStatus.mu.Unlock()
}

// TestFollowerManagerHotReload verifies the registry switches between leader
// and follower roles when Registry.Follower.Enabled changes at runtime via
// the config-callback bus — no restart involved.
func TestFollowerManagerHotReload(t *testing.T) {
	setupFollowerTest(t)
	t.Cleanup(param.ClearCallbacks)

	ctx, cancel := context.WithCancel(context.Background())
	egrp := &errgroup.Group{}
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})

	// Starts as leader: no follower-sync health component.
	require.NoError(t, LaunchFollowerManager(ctx, egrp))
	_, err := metrics.GetComponentStatus(metrics.Registry_FollowerSync)
	require.Error(t, err)

	// Demote to follower via a hot config reload.
	require.NoError(t, param.MultiSet(map[string]interface{}{
		"Registry.Follower.Enabled": true,
	}))
	require.Eventually(t, func() bool {
		_, err := metrics.GetComponentStatus(metrics.Registry_FollowerSync)
		return err == nil
	}, 10*time.Second, 20*time.Millisecond, "follower-sync health component should appear after demotion")

	// Promote back to leader; the sync loop stops and its health component is retired.
	require.NoError(t, param.MultiSet(map[string]interface{}{
		"Registry.Follower.Enabled": false,
	}))
	require.Eventually(t, func() bool {
		_, err := metrics.GetComponentStatus(metrics.Registry_FollowerSync)
		return err != nil
	}, 10*time.Second, 20*time.Millisecond, "follower-sync health component should be retired after promotion")
}

func TestFollowerSyncRefusesSelfEndpoint(t *testing.T) {
	setupFollowerTest(t)

	config.SetFederation(pelican_url.FederationDiscovery{
		DiscoveryEndpoint: "https://this-registry.test:8444",
		DirectorEndpoint:  "https://this-registry.test:8444",
		RegistryEndpoint:  "https://this-registry.test:8444",
		JwksUri:           "https://this-registry.test:8444/.well-known/issuer.jwks",
	})

	err := followerSyncOnce(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to sync from self")
}
