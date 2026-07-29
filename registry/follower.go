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

// Follower-side support for the warm-standby registry: periodically download
// an encrypted snapshot of the active registry's database and cut the local
// database over to it, keeping this registry ready to be promoted to leader.

package registry

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// registryInstanceID uniquely identifies this registry process. It is sent
// with snapshot download requests so a registry can detect (and refuse) a
// request that has looped back to itself, e.g. via misconfigured federation
// metadata or DNS round-robin.
var registryInstanceID = uuid.NewString()

// followerState tracks the progress of follower synchronization for health
// reporting and the web UI.
type followerState struct {
	mu             sync.Mutex
	sourceEndpoint string
	baseline       time.Time // launch time; grace baseline for health before the first sync
	lastAttempt    time.Time
	lastError      string
	lastSync       time.Time // last successful cutover to a downloaded snapshot
	snapshotTime   time.Time // creation time (on the leader) of the snapshot in use
}

var followerStatus followerState

// FollowerStatus is the JSON representation of the registry's follower/leader
// state, served to the web UI.
type FollowerStatus struct {
	FollowerEnabled    bool       `json:"follower_enabled"`
	InstanceID         string     `json:"instance_id"`
	SourceEndpoint     string     `json:"source_endpoint,omitempty"`
	LastAttempt        *time.Time `json:"last_attempt,omitempty"`
	LastSuccessfulSync *time.Time `json:"last_successful_sync,omitempty"`
	SnapshotTimestamp  *time.Time `json:"snapshot_timestamp,omitempty"`
	LastError          string     `json:"last_error,omitempty"`
	SyncInterval       string     `json:"sync_interval,omitempty"`
	HealthStatus       string     `json:"health_status,omitempty"`
}

// GetFollowerStatus snapshots the current follower state.
func GetFollowerStatus() FollowerStatus {
	status := FollowerStatus{
		FollowerEnabled: param.Registry_Follower_Enabled.GetBool(),
		InstanceID:      registryInstanceID,
	}
	if !status.FollowerEnabled {
		return status
	}

	followerStatus.mu.Lock()
	defer followerStatus.mu.Unlock()
	status.SourceEndpoint = followerStatus.sourceEndpoint
	status.LastError = followerStatus.lastError
	status.SyncInterval = param.Registry_Follower_SyncInterval.GetDuration().String()
	if !followerStatus.lastAttempt.IsZero() {
		t := followerStatus.lastAttempt
		status.LastAttempt = &t
	}
	if !followerStatus.lastSync.IsZero() {
		t := followerStatus.lastSync
		status.LastSuccessfulSync = &t
	}
	if !followerStatus.snapshotTime.IsZero() {
		t := followerStatus.snapshotTime
		status.SnapshotTimestamp = &t
	}
	if health, err := metrics.GetComponentStatus(metrics.Registry_FollowerSync); err == nil {
		status.HealthStatus = health
	}
	return status
}

// getFollowerStatusHandler serves GET /api/v1.0/registry_ui/follower.
func getFollowerStatusHandler(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, GetFollowerStatus())
}

// blockInFollowerMode is a per-route middleware for mutating registry APIs
// that are not distinguishable by HTTP method (the machine-facing API uses
// POST for several read-only queries).
func blockInFollowerMode(ctx *gin.Context) {
	if param.Registry_Follower_Enabled.GetBool() {
		ctx.AbortWithStatusJSON(http.StatusServiceUnavailable, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "This registry is running in follower (read-only) mode; mutating APIs are disabled"})
		return
	}
	ctx.Next()
}

// followerReadOnlyMiddleware rejects all mutating HTTP methods while the
// registry runs in follower mode. It is safe to apply to RESTful route groups
// (the web UI API); the machine-facing API needs per-route guards instead.
func followerReadOnlyMiddleware(ctx *gin.Context) {
	if !param.Registry_Follower_Enabled.GetBool() {
		ctx.Next()
		return
	}
	switch ctx.Request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		ctx.Next()
	default:
		ctx.AbortWithStatusJSON(http.StatusServiceUnavailable, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "This registry is running in follower (read-only) mode; mutating APIs are disabled"})
	}
}

// followerSyncOnce performs one snapshot download + cutover cycle.
func followerSyncOnce(ctx context.Context) error {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to discover federation metadata")
	}
	endpoint := fedInfo.RegistryEndpoint
	if endpoint == "" {
		return errors.New("federation metadata does not advertise a registry endpoint")
	}
	regURL, err := url.Parse(endpoint)
	if err != nil {
		return errors.Wrapf(err, "failed to parse registry endpoint %q", endpoint)
	}

	followerStatus.mu.Lock()
	followerStatus.sourceEndpoint = endpoint
	followerStatus.mu.Unlock()

	// First line of self-download defense: if the federation metadata points at
	// this very instance, there is no leader to sync from. (The instance ID
	// sent below catches the cases a URL comparison cannot, e.g. round-robin
	// DNS in front of several registries.)
	if extUrlStr := param.Server_ExternalWebUrl.GetString(); extUrlStr != "" {
		if extUrl, err := url.Parse(extUrlStr); err == nil && extUrl.Host == regURL.Host {
			return errors.Errorf("federation metadata registry endpoint (%s) is this instance; refusing to sync from self", endpoint)
		}
	}

	localVersions, err := database.EmbeddedMigrationVersions()
	if err != nil {
		return errors.Wrap(err, "failed to determine local migration versions")
	}

	reqURL := *regURL
	reqURL.Path = path.Join(reqURL.Path, "api", "v1.0", "registry", "database", "snapshot")
	query := url.Values{}
	query.Set("instance", registryInstanceID)
	query.Set("universalVersion", fmt.Sprintf("%d", localVersions.Universal))
	query.Set("registryVersion", fmt.Sprintf("%d", localVersions.Registry))
	reqURL.RawQuery = query.Encode()

	tokCfg := token.NewWLCGToken()
	tokCfg.Lifetime = 5 * time.Minute
	tokCfg.Subject = param.Server_ExternalWebUrl.GetString()
	tokCfg.AddAudiences(regURL.Host)
	tokCfg.AddScopes(token_scopes.Registry_DatabaseDownload)
	tok, err := tokCfg.CreateToken()
	if err != nil {
		return errors.Wrap(err, "failed to mint snapshot download token")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "failed to construct snapshot request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", "pelican-registry/"+config.GetVersion())

	resp, err := config.GetClient().Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to download database snapshot from %s", endpoint)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return errors.Errorf("snapshot download from %s failed with status %d: %s", endpoint, resp.StatusCode, string(body))
	}

	// Stream the snapshot to a temporary file next to the database.
	dbDir := filepath.Dir(param.Server_DbLocation.GetString())
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return errors.Wrap(err, "failed to create database directory")
	}
	tmpFile, err := os.CreateTemp(dbDir, "pelican-snapshot-download-*.bak")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary snapshot file")
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return errors.Wrap(err, "failed to download snapshot payload")
	}
	if err := tmpFile.Close(); err != nil {
		return errors.Wrap(err, "failed to finalize downloaded snapshot")
	}

	_, snapshotTime, err := database.DecryptedSnapshotMetadata(tmpPath)
	if err != nil {
		return errors.Wrap(err, "failed to read snapshot metadata")
	}

	// The leader throttles snapshot generation, so polls may return the exact
	// snapshot already in use; skip the cutover but count the attempt as
	// proof the leader is reachable and the snapshot is current.
	followerStatus.mu.Lock()
	current := followerStatus.snapshotTime
	followerStatus.mu.Unlock()
	if !current.IsZero() && snapshotTime.Equal(current) {
		log.Debugf("Registry snapshot from %s is unchanged (created %s); skipping cutover", endpoint, snapshotTime)
		return nil
	}

	preparedPath, err := database.PrepareSnapshotForCutover(tmpPath)
	if err != nil {
		return errors.Wrap(err, "failed to prepare downloaded snapshot")
	}
	if err := database.CutoverServerDatabase(preparedPath); err != nil {
		os.Remove(preparedPath)
		return errors.Wrap(err, "failed to cut over to downloaded snapshot")
	}

	followerStatus.mu.Lock()
	followerStatus.lastSync = time.Now()
	followerStatus.snapshotTime = snapshotTime
	followerStatus.mu.Unlock()

	log.Infof("Registry database synchronized from %s (snapshot created %s)", endpoint, snapshotTime.Format(time.RFC3339))
	return nil
}

// updateFollowerSyncHealth recomputes the follower-sync health component from
// the age of the snapshot currently in use, degrading to warning and then
// critical when no fresh snapshot has been cut over for too long.
func updateFollowerSyncHealth(warnAge, critAge time.Duration) {
	followerStatus.mu.Lock()
	snapTime := followerStatus.snapshotTime
	lastErr := followerStatus.lastError
	baseline := followerStatus.baseline
	followerStatus.mu.Unlock()

	// Before the first successful sync, measure the grace period from launch.
	ref := snapTime
	if ref.IsZero() {
		ref = baseline
	}
	age := time.Since(ref)

	var msg string
	if snapTime.IsZero() {
		msg = "No database snapshot synchronized from the active registry yet"
	} else {
		msg = fmt.Sprintf("Database snapshot in use was created %s ago", age.Truncate(time.Second))
	}
	if lastErr != "" {
		msg += "; last sync attempt failed: " + lastErr
	}

	switch {
	case critAge > 0 && age > critAge:
		metrics.SetComponentHealthStatus(metrics.Registry_FollowerSync, metrics.StatusCritical, msg)
	case warnAge > 0 && age > warnAge:
		metrics.SetComponentHealthStatus(metrics.Registry_FollowerSync, metrics.StatusWarning, msg)
	case lastErr != "":
		metrics.SetComponentHealthStatus(metrics.Registry_FollowerSync, metrics.StatusWarning, msg)
	default:
		metrics.SetComponentHealthStatus(metrics.Registry_FollowerSync, metrics.StatusOK, msg)
	}
}

// LaunchFollowerSync starts the periodic snapshot synchronization loop for a
// registry running in follower mode. The returned channel is closed once the
// loop has fully exited (after ctx is canceled), letting the role manager
// sequence a clean promotion.
func LaunchFollowerSync(ctx context.Context, egrp *errgroup.Group) <-chan struct{} {
	interval := param.Registry_Follower_SyncInterval.GetDuration()
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	// Capture thresholds at launch to avoid Viper races in tests.
	warnAge := param.Registry_Follower_SnapshotWarningAge.GetDuration()
	critAge := param.Registry_Follower_SnapshotCriticalAge.GetDuration()

	followerStatus.mu.Lock()
	followerStatus.baseline = time.Now()
	followerStatus.mu.Unlock()
	metrics.SetComponentHealthStatus(metrics.Registry_FollowerSync, metrics.StatusWarning,
		"Follower registry has not synchronized a database snapshot yet")

	log.Infof("Registry running in follower (read-only) mode; synchronizing the database from the active registry every %s", interval)

	done := make(chan struct{})
	egrp.Go(func() error {
		defer close(done)
		doSync := func() {
			err := followerSyncOnce(ctx)
			// A canceled context means the registry is being promoted (or shut
			// down): leave the health component alone so the promotion path
			// can retire it without racing a final update.
			if ctx.Err() != nil {
				return
			}
			followerStatus.mu.Lock()
			followerStatus.lastAttempt = time.Now()
			if err != nil {
				followerStatus.lastError = err.Error()
			} else {
				followerStatus.lastError = ""
			}
			followerStatus.mu.Unlock()
			if err != nil {
				log.Errorf("Follower registry synchronization failed: %v", err)
			}
			updateFollowerSyncHealth(warnAge, critAge)
		}

		doSync()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info("Stopping follower registry synchronization")
				return nil
			case <-ticker.C:
				doSync()
			}
		}
	})
	return done
}

// followerManager owns the registry's role-specific background tasks and
// switches them when Registry.Follower.Enabled changes at runtime via a hot
// config reload — no restart needed. The per-request guards (mutable-API
// blocking, snapshot serving, last_seen updates) read the parameter live and
// follow automatically; this manager handles the long-running tasks.
type followerManager struct {
	mu        sync.Mutex
	serverCtx context.Context
	egrp      *errgroup.Group
	stopRole  context.CancelFunc // cancels the current role's background tasks
	syncDone  <-chan struct{}    // closed when a running follower sync loop has exited
}

var followerMgr followerManager

// LaunchFollowerManager starts the background tasks for the configured role
// and registers a config callback so later changes to
// Registry.Follower.Enabled switch roles in place.
func LaunchFollowerManager(ctx context.Context, egrp *errgroup.Group) error {
	followerMgr.mu.Lock()
	followerMgr.serverCtx = ctx
	followerMgr.egrp = egrp
	followerMgr.mu.Unlock()

	if err := followerMgr.applyRole(param.Registry_Follower_Enabled.GetBool(), true); err != nil {
		return err
	}

	param.RegisterCallback("registry-follower-mode", func(oldConfig, newConfig *param.Config) {
		if oldConfig.Registry.Follower.Enabled == newConfig.Registry.Follower.Enabled {
			return
		}
		if err := followerMgr.applyRole(newConfig.Registry.Follower.Enabled, false); err != nil {
			log.Errorf("Failed to switch registry between follower and leader roles: %v", err)
		}
	})
	return nil
}

// applyRole stops the current role's background tasks and starts the other
// role's. At startup a topology-population failure is fatal (matching the
// registry's historical launch behavior); on a runtime switch it is logged
// and retried by the periodic reload.
func (m *followerManager) applyRole(follower bool, startup bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.serverCtx == nil {
		return errors.New("follower manager has not been launched")
	}

	if m.stopRole != nil {
		m.stopRole()
		m.stopRole = nil
	}
	if m.syncDone != nil {
		// Wait for the sync loop to fully exit so a final health update can't
		// race the promotion cleanup below.
		<-m.syncDone
		m.syncDone = nil
	}

	roleCtx, cancel := context.WithCancel(m.serverCtx)
	m.stopRole = cancel

	if follower {
		if !startup {
			log.Info("Registry demoted to follower (read-only) mode by configuration change")
			// The topology status belongs to the leader's reload task, which
			// was just stopped.
			metrics.DeleteComponentHealthStatus(metrics.DirectorRegistry_Topology)
		}
		m.syncDone = LaunchFollowerSync(roleCtx, m.egrp)
		return nil
	}

	if !startup {
		log.Info("Registry promoted from follower to active (leader) mode by configuration change")
		metrics.DeleteComponentHealthStatus(metrics.Registry_FollowerSync)
	}

	// Leader-only maintenance — everything below writes to the database.
	LaunchInactiveRegistrationCleanup(roleCtx, m.egrp)

	if config.GetPreferredPrefix() == config.OsdfPrefix && !param.Topology_DisableOrigins.GetBool() {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusWarning, "Start requesting from topology, status unknown")
		log.Info("Populating registry with namespaces from OSG topology service...")
		if err := PopulateTopology(roleCtx); err != nil {
			if startup {
				return errors.Wrap(err, "unable to populate topology table")
			}
			log.Errorf("Unable to populate topology table after promotion to leader: %v", err)
		}
		// Checks topology for updates every 10 minutes
		go PeriodicTopologyReload(roleCtx)
	}
	return nil
}
