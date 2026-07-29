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

package database

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database/utils"
)

// setupMigratedTestDB builds on setupTestDBAndKeys by applying the real
// universal and registry migration sets, mirroring a registry server database.
func setupMigratedTestDB(t *testing.T) (dbPath string) {
	t.Helper()
	dbPath, _, _ = setupTestDBAndKeys(t)

	sqlDB, err := ServerDatabase.DB()
	require.NoError(t, err)
	require.NoError(t, utils.MigrateDB(sqlDB, EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, utils.MigrateServerSpecificDB(sqlDB, EmbedRegistryMigrations, "registry_migrations", "registry"))
	return dbPath
}

// registryMigrationRange returns the oldest and newest registry migration
// versions embedded in this binary.
func registryMigrationRange(t *testing.T) (oldest, newest int64) {
	t.Helper()
	entries, err := fs.ReadDir(EmbedRegistryMigrations, "registry_migrations")
	require.NoError(t, err)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		version, err := strconv.ParseInt(name[:strings.Index(name, "_")], 10, 64)
		require.NoError(t, err)
		if oldest == 0 || version < oldest {
			oldest = version
		}
		if version > newest {
			newest = version
		}
	}
	require.NotZero(t, oldest)
	return
}

func TestEmbeddedMigrationVersions(t *testing.T) {
	versions, err := EmbeddedMigrationVersions()
	require.NoError(t, err)
	assert.Greater(t, versions.Universal, int64(0))
	assert.Greater(t, versions.Registry, int64(0))
}

func TestFileMigrationVersions(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() { config.ResetConfig() })

	dbPath := setupMigratedTestDB(t)

	fileVersions, err := FileMigrationVersions(dbPath)
	require.NoError(t, err)
	embedded, err := EmbeddedMigrationVersions()
	require.NoError(t, err)
	assert.Equal(t, embedded, fileVersions)

	// A database without goose tables reports zero versions.
	emptyPath := filepath.Join(t.TempDir(), "empty.sqlite")
	emptyDB, err := utils.InitSQLiteDB(emptyPath)
	require.NoError(t, err)
	sqlDB, err := emptyDB.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	fileVersions, err = FileMigrationVersions(emptyPath)
	require.NoError(t, err)
	assert.Equal(t, MigrationVersions{}, fileVersions)
}

func TestSnapshotRoundTripAndCutover(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() { config.ResetConfig() })

	dbPath := setupMigratedTestDB(t)
	ctx := context.Background()

	snapshotPath := filepath.Join(t.TempDir(), "snapshots", "snap.bak")
	meta, err := CreateEncryptedSnapshot(ctx, snapshotPath, MigrationVersions{})
	require.NoError(t, err)
	require.FileExists(t, snapshotPath)

	// The snapshot metadata block is plaintext and carries a parseable timestamp.
	readMeta, snapTime, err := DecryptedSnapshotMetadata(snapshotPath)
	require.NoError(t, err)
	assert.Equal(t, meta.Timestamp, readMeta.Timestamp)
	assert.WithinDuration(t, time.Now().UTC(), snapTime, time.Minute)

	// Prepare the snapshot for cutover; schema already matches, so it should
	// come back at the embedded versions.
	preparedPath, err := PrepareSnapshotForCutover(snapshotPath)
	require.NoError(t, err)
	require.FileExists(t, preparedPath)
	preparedVersions, err := FileMigrationVersions(preparedPath)
	require.NoError(t, err)
	embedded, err := EmbeddedMigrationVersions()
	require.NoError(t, err)
	assert.Equal(t, embedded, preparedVersions)

	// Dirty the live database after the snapshot was taken; the cutover must
	// discard this row.
	require.NoError(t, ServerDatabase.Exec("INSERT INTO test_data (value) VALUES ('stale')").Error)

	require.NoError(t, CutoverServerDatabase(preparedPath))

	var count int64
	require.NoError(t, ServerDatabase.Raw("SELECT COUNT(*) FROM test_data WHERE value = 'stale'").Scan(&count).Error)
	assert.Zero(t, count, "post-snapshot write should be gone after cutover")
	require.NoError(t, ServerDatabase.Raw("SELECT COUNT(*) FROM test_data").Scan(&count).Error)
	assert.Equal(t, int64(2), count, "snapshot rows should survive cutover")

	// The previous database is kept alongside for operators.
	require.FileExists(t, dbPath+preSyncSuffix)
}

func TestSnapshotDowngradeForOlderFollower(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() { config.ResetConfig() })

	setupMigratedTestDB(t)
	ctx := context.Background()

	oldest, newest := registryMigrationRange(t)
	if oldest == newest {
		t.Skip("only one registry migration embedded; nothing to downgrade")
	}
	embedded, err := EmbeddedMigrationVersions()
	require.NoError(t, err)

	// Ask for a snapshot as an older follower would: registry schema capped at
	// the oldest migration.
	snapshotPath := filepath.Join(t.TempDir(), "snap-downgraded.bak")
	_, err = CreateEncryptedSnapshot(ctx, snapshotPath, MigrationVersions{Universal: embedded.Universal, Registry: oldest})
	require.NoError(t, err)

	// Decrypt without upgrading to inspect the schema the leader produced.
	rawPath := filepath.Join(t.TempDir(), "raw.sqlite")
	restored, err := restoreFromSingleBackup(rawPath, snapshotPath, config.GetIssuerPrivateKeys())
	require.NoError(t, err)
	require.True(t, restored)
	rawVersions, err := FileMigrationVersions(rawPath)
	require.NoError(t, err)
	assert.Equal(t, oldest, rawVersions.Registry, "leader should downgrade the registry schema for an older follower")
	assert.Equal(t, embedded.Universal, rawVersions.Universal)

	// A follower at the current release upgrades the same snapshot back to its
	// own schema before cutover.
	preparedPath, err := PrepareSnapshotForCutover(snapshotPath)
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(preparedPath) })
	preparedVersions, err := FileMigrationVersions(preparedPath)
	require.NoError(t, err)
	assert.Equal(t, embedded, preparedVersions)
}

// TestCutoverServerDatabaseZeroInterruption verifies that queries running
// concurrently with a cutover never observe an error: the handle is never
// closed, the file is replaced atomically, and only the pool's connections
// are recycled.
func TestCutoverServerDatabaseZeroInterruption(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() { config.ResetConfig() })

	dbPath := setupMigratedTestDB(t)
	ctx := context.Background()

	snapshotPath := filepath.Join(t.TempDir(), "snap.bak")
	_, err := CreateEncryptedSnapshot(ctx, snapshotPath, MigrationVersions{})
	require.NoError(t, err)
	preparedPath, err := PrepareSnapshotForCutover(snapshotPath)
	require.NoError(t, err)

	// Post-snapshot write that the cutover must discard.
	require.NoError(t, ServerDatabase.Exec("INSERT INTO test_data (value) VALUES ('stale')").Error)

	// Hammer the database from several goroutines across the entire cutover.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var readErrs atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				var n int64
				if err := ServerDatabase.Raw("SELECT COUNT(*) FROM test_data").Scan(&n).Error; err != nil {
					readErrs.Add(1)
				}
				// Brief pause between queries so the WAL checkpoint can find an
				// instant with no active readers.
				time.Sleep(time.Millisecond)
			}
		}()
	}

	require.NoError(t, CutoverServerDatabase(preparedPath))

	close(stop)
	wg.Wait()
	assert.Zero(t, readErrs.Load(), "no query should fail during a cutover")

	// Queries started after the cutover see the snapshot contents.
	var count int64
	require.NoError(t, ServerDatabase.Raw("SELECT COUNT(*) FROM test_data WHERE value = 'stale'").Scan(&count).Error)
	assert.Zero(t, count)
	require.NoError(t, ServerDatabase.Raw("SELECT COUNT(*) FROM test_data").Scan(&count).Error)
	assert.Equal(t, int64(2), count)
	require.FileExists(t, dbPath+preSyncSuffix)
}

func TestPrepareSnapshotRejectsNewerSchema(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() { config.ResetConfig() })

	dbPath := setupMigratedTestDB(t)
	ctx := context.Background()

	// Fabricate a "future" schema by recording a migration version this binary
	// does not know about, then snapshot it.
	require.NoError(t, ServerDatabase.Exec("INSERT INTO registry_goose_db_version (version_id, is_applied) VALUES (99999999999999, 1)").Error)
	snapshotPath := filepath.Join(t.TempDir(), "snap-future.bak")
	_, err := CreateEncryptedSnapshot(ctx, snapshotPath, MigrationVersions{})
	require.NoError(t, err)

	_, err = PrepareSnapshotForCutover(snapshotPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "newer than this binary")
	assert.NoFileExists(t, dbPath+".incoming")
}
