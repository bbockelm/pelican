package utils

import (
	"database/sql"
	"embed"
	"os"
	"path/filepath"
	"sync"

	"github.com/glebarez/sqlite"
	"github.com/pkg/errors"
	"github.com/pressly/goose/v3"
	log "github.com/sirupsen/logrus"
	gormlog "github.com/thomas-tacquet/gormv2-logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/pelicanplatform/pelican/config"
)

// SQLiteDSN builds a SQLite connection string with the project's standard
// connection parameters. This centralizes DSN construction so callers don't
// duplicate query parameters as ad-hoc string literals.
func SQLiteDSN(dbPath string) string {
	// Use repeated _pragma entries, as glebarez/sqlite (modernc.org/sqlite) requires.
	// The mattn-style `_name=value` shorthand is silently ignored.
	//
	// `_txlock=immediate` makes every non-readonly Begin() / gorm Transaction()
	// issue `BEGIN IMMEDIATE`, acquiring the write lock at BEGIN. Without this,
	// SQLite defaults to BEGIN DEFERRED and a read-then-write tx can hit
	// SQLITE_BUSY_SNAPSHOT when a concurrent writer commits between its first
	// SELECT and its UPDATE — busy_timeout does not retry that error.
	return dbPath + "?" +
		"_pragma=busy_timeout(5000)&" +
		"_pragma=journal_mode(WAL)&" +
		"_pragma=foreign_keys(1)&" +
		"_txlock=immediate"
}

func InitSQLiteDB(dbPath string) (*gorm.DB, error) {
	if dbPath == "" {
		return nil, errors.New("SQLite database path is empty")
	}

	// Before attempting to create the database, the path
	// must exist or sql.Open will panic.
	err := os.MkdirAll(filepath.Dir(dbPath), 0755)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create directory for SQLite database at %s", dbPath)
	}

	if len(filepath.Ext(dbPath)) == 0 { // No fp extension, let's add .sqlite so it's obvious what the file is
		dbPath += ".sqlite"
	}

	dbName := SQLiteDSN(dbPath)

	globalLogLevel := config.GetEffectiveLogLevel()
	var ormLevel logger.LogLevel
	if globalLogLevel == log.DebugLevel || globalLogLevel == log.TraceLevel || globalLogLevel == log.InfoLevel {
		ormLevel = logger.Info
	} else if globalLogLevel == log.WarnLevel {
		ormLevel = logger.Warn
	} else if globalLogLevel == log.ErrorLevel {
		ormLevel = logger.Error
	} else {
		ormLevel = logger.Info
	}

	gormLogger := gormlog.NewGormlog(
		gormlog.WithLogrusEntry(log.WithField("component", "gorm")),
		gormlog.WithGormOptions(gormlog.GormOptions{
			LogLatency: true,
			LogLevel:   ormLevel,
		}),
	)

	log.Debugln("Opening connection to sqlite DB", dbName)

	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{Logger: gormLogger})

	if err != nil {
		return nil, errors.Wrapf(err, "failed to open the database with path: %s", dbPath)
	}

	return db, nil
}

// gooseMu serializes access to goose's package-level state (base FS, dialect,
// table name). Migrations normally only run at startup, but a follower registry
// also up/downgrades snapshot databases at runtime.
var gooseMu sync.Mutex

// configureGoose points goose's package-level state at the given migration set.
// Callers must hold gooseMu.
func configureGoose(migrationFS embed.FS, tablePrefix string) error {
	goose.SetBaseFS(migrationFS)

	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}

	// Set table prefix if provided (for server-type-specific migrations)
	if tablePrefix != "" {
		goose.SetTableName(tablePrefix + "_goose_db_version")
	} else {
		goose.SetTableName("goose_db_version") // Default table name
	}
	return nil
}

func MigrateDB(sqldb *sql.DB, migrationFS embed.FS, migrationPath string) error {
	return MigrateServerSpecificDB(sqldb, migrationFS, migrationPath, "")
}

func MigrateServerSpecificDB(sqldb *sql.DB, migrationFS embed.FS, migrationPath string, tablePrefix string) error {
	gooseMu.Lock()
	defer gooseMu.Unlock()

	if err := configureGoose(migrationFS, tablePrefix); err != nil {
		return err
	}

	if err := goose.Up(sqldb, migrationPath); err != nil {
		return err
	}
	return nil
}

// DowngradeServerSpecificDB rolls the database back until its migration version
// is at most targetVersion. It is the inverse of MigrateServerSpecificDB and is
// used when serving a database snapshot to a follower registry running an older
// release than this one.
func DowngradeServerSpecificDB(sqldb *sql.DB, migrationFS embed.FS, migrationPath string, tablePrefix string, targetVersion int64) error {
	gooseMu.Lock()
	defer gooseMu.Unlock()

	if err := configureGoose(migrationFS, tablePrefix); err != nil {
		return err
	}

	if err := goose.DownTo(sqldb, migrationPath, targetVersion); err != nil {
		return err
	}
	return nil
}
