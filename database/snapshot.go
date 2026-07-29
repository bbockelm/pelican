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

// Snapshot support for the warm-standby ("follower") registry. The active
// registry serves encrypted snapshots of its database, downgraded on the fly
// when the follower runs an older release; the follower decrypts a snapshot,
// upgrades it when the leader runs an older release, and atomically cuts its
// live database over to the result.

package database

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/param"
)

// MigrationVersions identifies a registry database schema by the newest
// applied goose migration in each of the two migration sets the registry uses.
// A zero value means "unknown/unconstrained".
type MigrationVersions struct {
	Universal int64 `json:"universal"`
	Registry  int64 `json:"registry"`
}

// preSyncSuffix is appended to the previous live database file when a follower
// cuts over to a fresh snapshot; only the most recent pre-sync copy is kept.
const preSyncSuffix = ".pre-sync"

// cutoverMu serializes database cutovers so concurrent sync attempts cannot
// interleave the close/rename/reopen sequence.
var cutoverMu sync.Mutex

// maxEmbeddedVersion returns the largest goose version number among the
// migration files in dir of the embedded filesystem. Goose migration files are
// named "<version>_<description>.sql".
func maxEmbeddedVersion(fsys fs.FS, dir string) (int64, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to list embedded migrations in %s", dir)
	}
	var maxVersion int64
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		idx := strings.Index(name, "_")
		if idx <= 0 {
			continue
		}
		version, err := strconv.ParseInt(name[:idx], 10, 64)
		if err != nil {
			continue
		}
		if version > maxVersion {
			maxVersion = version
		}
	}
	if maxVersion == 0 {
		return 0, errors.Errorf("no goose migrations found in embedded directory %s", dir)
	}
	return maxVersion, nil
}

// EmbeddedMigrationVersions returns the newest universal and registry
// migration versions known to this binary.
func EmbeddedMigrationVersions() (MigrationVersions, error) {
	universal, err := maxEmbeddedVersion(EmbedUniversalMigrations, "universal_migrations")
	if err != nil {
		return MigrationVersions{}, err
	}
	registry, err := maxEmbeddedVersion(EmbedRegistryMigrations, "registry_migrations")
	if err != nil {
		return MigrationVersions{}, err
	}
	return MigrationVersions{Universal: universal, Registry: registry}, nil
}

// maxAppliedVersion returns the newest applied migration recorded in the given
// goose version table, or 0 if the table does not exist (schema predates the
// migration set entirely).
func maxAppliedVersion(db *sql.DB, table string) (int64, error) {
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&name)
	if err == sql.ErrNoRows {
		return 0, nil
	} else if err != nil {
		return 0, errors.Wrapf(err, "failed to check for goose version table %s", table)
	}

	var version int64
	// Goose inserts a row per applied migration (plus a version-0 bootstrap row)
	// and deletes the row again on rollback, so MAX(version_id) over applied
	// rows is the current schema version.
	if err := db.QueryRow("SELECT COALESCE(MAX(version_id), 0) FROM " + table + " WHERE is_applied = 1").Scan(&version); err != nil {
		return 0, errors.Wrapf(err, "failed to query goose version table %s", table)
	}
	return version, nil
}

// FileMigrationVersions reads the goose version tables of the SQLite database
// at dbPath.
func FileMigrationVersions(dbPath string) (MigrationVersions, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return MigrationVersions{}, errors.Wrapf(err, "failed to open database %s", dbPath)
	}
	defer db.Close()

	universal, err := maxAppliedVersion(db, "goose_db_version")
	if err != nil {
		return MigrationVersions{}, err
	}
	registry, err := maxAppliedVersion(db, "registry_goose_db_version")
	if err != nil {
		return MigrationVersions{}, err
	}
	return MigrationVersions{Universal: universal, Registry: registry}, nil
}

// prepareSnapshotDB vacuums the live server database into destPath and, when
// the copy's schema is newer than target, downgrades it with goose so a
// follower running an older release can use it. A zero target component means
// "leave that migration set as is". destPath must not exist.
func prepareSnapshotDB(ctx context.Context, destPath string, target MigrationVersions) error {
	if ServerDatabase == nil {
		return errors.New("server database is not initialized")
	}
	sqlDB, err := ServerDatabase.DB()
	if err != nil {
		return errors.Wrap(err, "failed to get underlying SQL database")
	}

	escapedPath := strings.ReplaceAll(destPath, "'", "''")
	if _, err := sqlDB.ExecContext(ctx, "VACUUM INTO '"+escapedPath+"'"); err != nil {
		return errors.Wrap(err, "failed to snapshot database via VACUUM INTO")
	}

	versions, err := FileMigrationVersions(destPath)
	if err != nil {
		return err
	}

	needRegistryDown := target.Registry > 0 && versions.Registry > target.Registry
	needUniversalDown := target.Universal > 0 && versions.Universal > target.Universal
	if !needRegistryDown && !needUniversalDown {
		return nil
	}

	log.Infof("Downgrading database snapshot from schema %+v to at most %+v for an older follower", versions, target)
	db, err := sql.Open("sqlite", destPath)
	if err != nil {
		return errors.Wrap(err, "failed to open snapshot copy for downgrade")
	}
	defer db.Close()

	// Downgrade in the reverse of the upgrade order: registry-specific
	// migrations first, then universal ones.
	if needRegistryDown {
		if err := utils.DowngradeServerSpecificDB(db, EmbedRegistryMigrations, "registry_migrations", "registry", target.Registry); err != nil {
			return errors.Wrapf(err, "failed to downgrade registry migrations to version %d", target.Registry)
		}
	}
	if needUniversalDown {
		if err := utils.DowngradeServerSpecificDB(db, EmbedUniversalMigrations, "universal_migrations", "", target.Universal); err != nil {
			return errors.Wrapf(err, "failed to downgrade universal migrations to version %d", target.Universal)
		}
	}
	return nil
}

// CreateEncryptedSnapshot writes an encrypted snapshot of the live database to
// destPath (atomically, via rename), downgraded to at most the target
// migration versions. It returns the snapshot's metadata.
func CreateEncryptedSnapshot(ctx context.Context, destPath string, target MigrationVersions) (BackupMetadata, error) {
	dbPath := param.Server_DbLocation.GetString()

	allKeys := config.GetIssuerPrivateKeys()
	if len(allKeys) == 0 {
		return BackupMetadata{}, errors.New("no issuer keys available for snapshot encryption")
	}

	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0750); err != nil {
		return BackupMetadata{}, errors.Wrapf(err, "failed to create snapshot directory %s", destDir)
	}

	// Reserve a temp filename for VACUUM INTO (which requires the file to not exist).
	vacuumFile, err := os.CreateTemp(destDir, vacuumTempPrefix+"*.sqlite")
	if err != nil {
		return BackupMetadata{}, errors.Wrap(err, "failed to create temporary vacuum file")
	}
	vacuumPath := vacuumFile.Name()
	vacuumFile.Close()
	os.Remove(vacuumPath)
	defer os.Remove(vacuumPath)

	if err := prepareSnapshotDB(ctx, vacuumPath, target); err != nil {
		return BackupMetadata{}, err
	}

	tmpFile, err := os.CreateTemp(destDir, backupTempPrefix+"*.tmp")
	if err != nil {
		return BackupMetadata{}, errors.Wrap(err, "failed to create temporary snapshot file")
	}
	tmpPath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath) // clean up on failure; no-op after rename
	}()

	meta := collectBackupMetadata(dbPath, time.Now().UTC())
	if err := encryptSQLiteToStream(vacuumPath, tmpFile, meta, allKeys); err != nil {
		return BackupMetadata{}, err
	}

	if err := tmpFile.Sync(); err != nil {
		return BackupMetadata{}, errors.Wrap(err, "failed to sync temporary snapshot file")
	}
	if err := tmpFile.Close(); err != nil {
		return BackupMetadata{}, errors.Wrap(err, "failed to close temporary snapshot file")
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return BackupMetadata{}, errors.Wrapf(err, "failed to rename snapshot into place at %s", destPath)
	}
	return meta, nil
}

// PrepareSnapshotForCutover decrypts the downloaded snapshot and, when the
// leader runs an older release than this binary, upgrades the copy to the
// local migration versions. The prepared plain SQLite database is written next
// to the live database (so the final cutover rename stays on one filesystem)
// and its path is returned.
func PrepareSnapshotForCutover(snapshotPath string) (string, error) {
	dbPath := param.Server_DbLocation.GetString()
	if dbPath == "" {
		return "", errors.New("database path is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return "", errors.Wrap(err, "failed to create database directory")
	}

	allKeys := config.GetIssuerPrivateKeys()
	if len(allKeys) == 0 {
		return "", errors.New("no issuer keys available for snapshot decryption")
	}

	preparedPath := dbPath + ".incoming"
	os.Remove(preparedPath)

	restored, err := restoreFromSingleBackup(preparedPath, snapshotPath, allKeys)
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt database snapshot")
	}
	if !restored {
		return "", errors.New("snapshot decryption did not complete")
	}

	success := false
	defer func() {
		if !success {
			os.Remove(preparedPath)
		}
	}()

	versions, err := FileMigrationVersions(preparedPath)
	if err != nil {
		return "", err
	}
	local, err := EmbeddedMigrationVersions()
	if err != nil {
		return "", err
	}

	if versions.Universal > local.Universal || versions.Registry > local.Registry {
		// The leader was asked to downgrade to our versions; if the snapshot is
		// still newer, this binary cannot know how to use (or downgrade) it.
		return "", errors.Errorf("snapshot schema %+v is newer than this binary supports (%+v)", versions, local)
	}

	if versions.Universal < local.Universal || versions.Registry < local.Registry {
		log.Infof("Upgrading database snapshot from schema %+v to local schema %+v", versions, local)
		db, err := sql.Open("sqlite", preparedPath)
		if err != nil {
			return "", errors.Wrap(err, "failed to open snapshot for migration")
		}
		defer db.Close()
		if err := utils.MigrateDB(db, EmbedUniversalMigrations, "universal_migrations"); err != nil {
			return "", errors.Wrap(err, "failed to apply universal migrations to snapshot")
		}
		if err := utils.MigrateServerSpecificDB(db, EmbedRegistryMigrations, "registry_migrations", "registry"); err != nil {
			return "", errors.Wrap(err, "failed to apply registry migrations to snapshot")
		}
	}

	success = true
	return preparedPath, nil
}

// connRecycleGrace is how long connection reuse stays disabled after a
// cutover: any pool connection opened against the previous database file is
// destroyed as soon as its in-flight query completes, and no registry query
// runs anywhere near this long.
const connRecycleGrace = 30 * time.Second

// defaultMaxIdleConns restores database/sql's default idle-connection count
// once the post-cutover grace period expires.
const defaultMaxIdleConns = 2

// recycleRestoreTimer restores normal connection pooling after a cutover;
// guarded by cutoverMu so back-to-back cutovers reset the grace period.
var recycleRestoreTimer *time.Timer

// moveDBFiles renames a SQLite database file along with any WAL/SHM sidecars.
func moveDBFiles(fromPath, toPath string) error {
	if err := os.Rename(fromPath, toPath); err != nil {
		return err
	}
	for _, ext := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(fromPath + ext); err == nil {
			_ = os.Rename(fromPath+ext, toPath+ext)
		}
	}
	return nil
}

// CutoverServerDatabase replaces the live server database with the prepared
// database file without interrupting concurrent queries. The gorm/sql.DB
// handle (and thus the ServerDatabase global) is never swapped or closed;
// instead the file is atomically replaced underneath the pool and the pool's
// connections are recycled: connections opened before the swap keep the old
// inode and finish their in-flight queries undisturbed, while every query
// started afterwards runs on a fresh connection that sees the new database.
//
// This relies on the follower being read-only: the WAL must stay empty across
// the swap (both old and new connections share the -wal path) and the
// archived pre-sync copy must be frozen. The previous database file is
// retained alongside with a ".pre-sync" suffix (only the most recent copy is
// kept).
func CutoverServerDatabase(preparedPath string) error {
	cutoverMu.Lock()
	defer cutoverMu.Unlock()

	dbPath := param.Server_DbLocation.GetString()
	if dbPath == "" {
		return errors.New("database path is not configured")
	}
	if ServerDatabase == nil {
		return errors.New("server database is not initialized")
	}
	sqlDB, err := ServerDatabase.DB()
	if err != nil {
		return errors.Wrap(err, "failed to get underlying SQL database")
	}

	// Checkpoint the WAL so the current main file is self-contained: the
	// pre-sync archive then needs no sidecars, and the -wal file — whose path
	// the new database inherits — is empty during the swap. A non-empty WAL
	// paired with a different main file would corrupt reads, so a cutover is
	// refused (and retried next sync) if the WAL cannot be fully truncated.
	walEmpty := false
	for attempt := 0; attempt < 3 && !walEmpty; attempt++ {
		if attempt > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		var busy, logFrames, checkpointed int
		if err := sqlDB.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil {
			return errors.Wrap(err, "failed to checkpoint WAL before cutover")
		}
		if busy != 0 {
			continue
		}
		if info, err := os.Stat(dbPath + "-wal"); err == nil && info.Size() > 0 {
			continue
		}
		walEmpty = true
	}
	if !walEmpty {
		// A truncating checkpoint needs an instant with no active readers;
		// under constant load, take the (briefly interrupting) reopen path
		// rather than pairing the new file with a non-empty old WAL.
		log.Warn("Could not fully checkpoint the WAL before cutover; falling back to close-and-reopen cutover")
		return cutoverByReopen(preparedPath, dbPath, dbPath+preSyncSuffix)
	}

	// Archive the current database via hardlink; its contents are frozen since
	// follower mode blocks writes and the WAL was just checkpointed.
	preSyncPath := dbPath + preSyncSuffix
	for _, ext := range []string{"", "-wal", "-shm"} {
		os.Remove(preSyncPath + ext)
	}
	if err := os.Link(dbPath, preSyncPath); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to archive current database to %s: %v", preSyncPath, err)
	}

	// Atomically replace the live file. The database path never has a moment
	// of nonexistence, so a connection opened at any instant sees either the
	// old or the new database — never an empty auto-created one.
	if err := os.Rename(preparedPath, dbPath); err != nil {
		// Windows cannot replace a file that has open handles; fall back to
		// the close-swap-reopen sequence, which has a brief window where
		// queries fail gracefully with "database is closed".
		log.Warnf("In-place database replacement failed (%v); falling back to close-and-reopen cutover", err)
		return cutoverByReopen(preparedPath, dbPath, preSyncPath)
	}

	// Recycle the pool. Dropping the idle limit to zero immediately closes
	// idle old-file connections and destroys in-use ones the moment their
	// query completes (the nanosecond lifetime catches any that slip back to
	// the pool), so every query from here on sees the new database. Normal
	// pooling resumes after the grace period.
	sqlDB.SetMaxIdleConns(0)
	sqlDB.SetConnMaxLifetime(time.Nanosecond)
	if recycleRestoreTimer != nil {
		recycleRestoreTimer.Stop()
	}
	recycleRestoreTimer = time.AfterFunc(connRecycleGrace, func() {
		sqlDB.SetConnMaxLifetime(0)
		sqlDB.SetMaxIdleConns(defaultMaxIdleConns)
	})

	log.Infof("Registry database cut over to new snapshot at %s", dbPath)
	return nil
}

// cutoverByReopen is the fallback cutover for platforms where a file with
// open handles cannot be replaced in place (Windows): close the current
// handle, swap the files, and open a fresh handle. Concurrent queries during
// the swap fail gracefully with "database is closed" (see ShutdownDB).
func cutoverByReopen(preparedPath, dbPath, preSyncPath string) error {
	if sqldb, err := ServerDatabase.DB(); err == nil {
		if err := sqldb.Close(); err != nil {
			log.Warnf("Failed to close database handle during cutover: %v", err)
		}
	}

	for _, ext := range []string{"", "-wal", "-shm"} {
		os.Remove(preSyncPath + ext)
	}

	oldExists := false
	if _, err := os.Stat(dbPath); err == nil {
		oldExists = true
		// Move the WAL/SHM sidecars along with the old main file so the fresh
		// database is not opened against a stale WAL.
		if err := moveDBFiles(dbPath, preSyncPath); err != nil {
			return errors.Wrapf(err, "failed to move current database aside to %s", preSyncPath)
		}
	}

	if err := os.Rename(preparedPath, dbPath); err != nil {
		// Try to put the old database back so the registry can keep serving.
		if oldExists {
			if rbErr := moveDBFiles(preSyncPath, dbPath); rbErr != nil {
				log.Errorf("Failed to roll back database cutover: %v", rbErr)
			}
		}
		if reopenErr := reopenServerDatabase(dbPath); reopenErr != nil {
			log.Errorf("Failed to reopen database after aborted cutover: %v", reopenErr)
		}
		return errors.Wrap(err, "failed to move prepared database into place")
	}

	if err := reopenServerDatabase(dbPath); err != nil {
		return errors.Wrap(err, "failed to open database after cutover")
	}

	log.Infof("Registry database cut over to new snapshot at %s (via close-and-reopen)", dbPath)
	return nil
}

// reopenServerDatabase opens a fresh gorm handle on dbPath and installs it as
// the global ServerDatabase.
func reopenServerDatabase(dbPath string) error {
	newDB, err := utils.InitSQLiteDB(dbPath)
	if err != nil {
		return err
	}
	if err := newDB.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		return errors.Wrap(err, "failed to enable foreign key constraints")
	}
	openedServerDatabasesMu.Lock()
	openedServerDatabases = append(openedServerDatabases, newDB)
	openedServerDatabasesMu.Unlock()
	ServerDatabase = newDB
	return nil
}

// DecryptedSnapshotMetadata reads the plaintext metadata block from a
// downloaded snapshot and parses its creation timestamp.
func DecryptedSnapshotMetadata(snapshotPath string) (*BackupMetadata, time.Time, error) {
	meta, err := ReadBackupMetadata(snapshotPath)
	if err != nil {
		return nil, time.Time{}, err
	}
	if meta == nil {
		return nil, time.Time{}, errors.New("snapshot is missing its metadata block")
	}
	ts, err := time.Parse(time.RFC3339, meta.Timestamp)
	if err != nil {
		return meta, time.Time{}, errors.Wrapf(err, "failed to parse snapshot timestamp %q", meta.Timestamp)
	}
	return meta, ts, nil
}
