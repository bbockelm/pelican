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

// Leader-side support for warm-standby (follower) registries: serve encrypted
// snapshots of the registry database to authenticated followers.

package registry

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

const (
	// snapshotTimestampHeader carries the snapshot creation time (RFC3339) so
	// followers can track staleness without decrypting the payload.
	snapshotTimestampHeader = "X-Pelican-Snapshot-Timestamp"

	snapshotFilePrefix = "pelican-registry-snapshot-"
	snapshotFileExt    = ".bak"
)

// cachedSnapshot throttles snapshot generation: followers polling within
// Registry.SnapshotCacheLifetime of each other (and requesting the same schema
// versions) are served the same file.
type cachedSnapshot struct {
	mu      sync.Mutex
	path    string
	created time.Time
	target  database.MigrationVersions
	meta    database.BackupMetadata
}

var snapshotCache cachedSnapshot

// snapshotDir returns the directory used to stage snapshots for followers.
func snapshotDir() string {
	return filepath.Join(param.Server_DatabaseBackup_Location.GetString(), "snapshots")
}

// verifySnapshotToken checks the bearer token authorizing a database snapshot
// download. The token must carry the registry.database_download scope, be
// addressed to this registry, and be signed either by this registry's own
// issuer keys (leader and follower share key material — the snapshot is
// encrypted to those keys anyway) or by the federation issuer.
func verifySnapshotToken(ctx *gin.Context) error {
	tokenStr := token.GetAuthzEscaped(ctx)
	if tokenStr == "" {
		return errors.New("no authorization token provided")
	}

	validateOpts := []jwt.ValidateOption{
		jwt.WithValidator(token_scopes.CreateScopeValidator([]token_scopes.TokenScope{token_scopes.Registry_DatabaseDownload}, true)),
	}
	if extUrlStr := param.Server_ExternalWebUrl.GetString(); extUrlStr != "" {
		if extUrl, err := url.Parse(extUrlStr); err == nil && extUrl.Host != "" {
			validateOpts = append(validateOpts, jwt.WithAudience(extUrl.Host))
		}
	}

	ownJwks, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return errors.Wrap(err, "failed to load this registry's public keys")
	}
	_, ownErr := token.VerifyWithKeyset(tokenStr, ownJwks, validateOpts...)
	if ownErr == nil {
		return nil
	}

	// Fall back to the federation issuer's keys (typically the director's).
	fedInfo, err := config.GetFederation(ctx.Request.Context())
	if err != nil || fedInfo.JwksUri == "" {
		return errors.Wrapf(ownErr, "token not signed by this registry's keys and federation JWKS is unavailable")
	}
	fedJwks, err := utils.GetJwks(ctx.Request.Context(), config.GetTransport(), fedInfo.JwksUri)
	if err != nil {
		return errors.Wrapf(ownErr, "token not signed by this registry's keys and federation JWKS could not be fetched")
	}
	if _, fedErr := token.VerifyWithKeyset(tokenStr, fedJwks, validateOpts...); fedErr != nil {
		return errors.Errorf("token rejected by both this registry's keys (%v) and the federation's keys (%v)", ownErr, fedErr)
	}
	return nil
}

// getOrCreateSnapshot returns the path and metadata of a snapshot downgraded to
// at most target, reusing the cached one when it is fresh enough.
func getOrCreateSnapshot(ctx *gin.Context, target database.MigrationVersions) (string, database.BackupMetadata, error) {
	snapshotCache.mu.Lock()
	defer snapshotCache.mu.Unlock()

	lifetime := param.Registry_SnapshotCacheLifetime.GetDuration()
	if snapshotCache.path != "" && snapshotCache.target == target && time.Since(snapshotCache.created) < lifetime {
		if _, err := os.Stat(snapshotCache.path); err == nil {
			return snapshotCache.path, snapshotCache.meta, nil
		}
	}

	destDir := snapshotDir()
	destPath := filepath.Join(destDir, fmt.Sprintf("%s%s%s", snapshotFilePrefix, time.Now().UTC().Format("2006-01-02T150405.000"), snapshotFileExt))
	meta, err := database.CreateEncryptedSnapshot(ctx.Request.Context(), destPath, target)
	if err != nil {
		return "", database.BackupMetadata{}, err
	}

	// Remove superseded snapshot files (best effort).
	if entries, err := os.ReadDir(destDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasPrefix(name, snapshotFilePrefix) || !strings.HasSuffix(name, snapshotFileExt) {
				continue
			}
			if stale := filepath.Join(destDir, name); stale != destPath {
				if err := os.Remove(stale); err != nil {
					log.Debugf("Failed to remove superseded snapshot %s: %v", stale, err)
				}
			}
		}
	}

	snapshotCache.path = destPath
	snapshotCache.created = time.Now()
	snapshotCache.target = target
	snapshotCache.meta = meta
	return destPath, meta, nil
}

// parseVersionParam parses an optional integer query parameter; absent or
// empty means 0 ("unconstrained").
func parseVersionParam(ctx *gin.Context, name string) (int64, error) {
	raw := ctx.Query(name)
	if raw == "" {
		return 0, nil
	}
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || version < 0 {
		return 0, errors.Errorf("invalid %s parameter %q", name, raw)
	}
	return version, nil
}

// serveDatabaseSnapshot handles GET /api/v1.0/registry/database/snapshot.
// Followers include their per-process instance ID (so a registry never
// downloads from itself) and the newest migration versions their binary
// understands (so a newer leader downgrades the copy before serving it).
func serveDatabaseSnapshot(ctx *gin.Context) {
	// A follower does not serve snapshots itself unless chained topologies are
	// explicitly enabled — otherwise standbys must sync from the active registry.
	if param.Registry_Follower_Enabled.GetBool() && !param.Registry_Follower_AllowChainedSnapshots.GetBool() {
		ctx.JSON(http.StatusConflict, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "This registry is running in follower mode and does not serve database snapshots (see Registry.Follower.AllowChainedSnapshots)"})
		return
	}

	if instance := ctx.Query("instance"); instance != "" && instance == registryInstanceID {
		ctx.JSON(http.StatusConflict, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Snapshot request originated from this registry instance itself; refusing self-download"})
		return
	}

	if err := verifySnapshotToken(ctx); err != nil {
		log.Debugf("Rejected database snapshot request: %v", err)
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Authorization failed for database snapshot download: " + err.Error()})
		return
	}

	var target database.MigrationVersions
	var err error
	if target.Universal, err = parseVersionParam(ctx, "universalVersion"); err == nil {
		target.Registry, err = parseVersionParam(ctx, "registryVersion")
	}
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error()})
		return
	}

	snapshotPath, meta, err := getOrCreateSnapshot(ctx, target)
	if err != nil {
		log.Errorf("Failed to create database snapshot for follower: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to create database snapshot"})
		return
	}

	ctx.Header(snapshotTimestampHeader, meta.Timestamp)
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.File(snapshotPath)
}
