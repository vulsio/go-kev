package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/glebarez/sqlite"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/vulsio/go-kev/config"
	"github.com/vulsio/go-kev/models"
)

const (
	dialectSqlite3    = "sqlite3"
	dialectMysql      = "mysql"
	dialectPostgreSQL = "postgres"
)

// RDBDriver :
type RDBDriver struct {
	name string
	conn *gorm.DB
}

// https://github.com/mattn/go-sqlite3/blob/edc3bb69551dcfff02651f083b21f3366ea2f5ab/error.go#L18-L66
type errNo int

type sqliteError struct {
	Code errNo /* The error code returned by SQLite */
}

// result codes from http://www.sqlite.org/c3ref/c_abort.html
var (
	errBusy   = errNo(5) /* The database file is locked */
	errLocked = errNo(6) /* A table in the database is locked */
)

// ErrDBLocked :
var ErrDBLocked = xerrors.New("database is locked")

// Name return db name
func (r *RDBDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool, _ Option) (err error) {
	gormConfig := gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger: logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				LogLevel: logger.Silent,
			},
		),
	}

	if debugSQL {
		gormConfig.Logger = logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold: time.Second,
				LogLevel:      logger.Info,
				Colorful:      true,
			},
		)
	}

	switch r.name {
	case dialectSqlite3:
		r.conn, err = gorm.Open(sqlite.Open(dbPath), &gormConfig)
		if err != nil {
			parsedErr, marshalErr := json.Marshal(err)
			if marshalErr != nil {
				return xerrors.Errorf("Failed to marshal err. err: %w", marshalErr)
			}

			var errMsg sqliteError
			if unmarshalErr := json.Unmarshal(parsedErr, &errMsg); unmarshalErr != nil {
				return xerrors.Errorf("Failed to unmarshal. err: %w", unmarshalErr)
			}

			switch errMsg.Code {
			case errBusy, errLocked:
				return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, ErrDBLocked)
			default:
				return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
			}
		}

		r.conn.Exec("PRAGMA foreign_keys = ON")
	case dialectMysql:
		r.conn, err = gorm.Open(mysql.Open(dbPath), &gormConfig)
		if err != nil {
			return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
		}
	case dialectPostgreSQL:
		r.conn, err = gorm.Open(postgres.Open(dbPath), &gormConfig)
		if err != nil {
			return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
		}
	default:
		return xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
	}
	return nil
}

// CloseDB close Database
func (r *RDBDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}

	var sqlDB *sql.DB
	if sqlDB, err = r.conn.DB(); err != nil {
		return xerrors.Errorf("Failed to get DB Object. err : %w", err)
	}
	if err = sqlDB.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	if err := r.conn.AutoMigrate(
		&models.FetchMeta{},

		&models.KEVuln{},

		&models.VulnCheck{},
		&models.VulnCheckCVE{},
		&models.VulnCheckXDB{},
		&models.VulnCheckReportedExploitation{},
	); err != nil {
		switch r.name {
		case dialectSqlite3:
			if r.name == dialectSqlite3 {
				parsedErr, marshalErr := json.Marshal(err)
				if marshalErr != nil {
					return xerrors.Errorf("Failed to marshal err. err: %w", marshalErr)
				}

				var errMsg sqliteError
				if unmarshalErr := json.Unmarshal(parsedErr, &errMsg); unmarshalErr != nil {
					return xerrors.Errorf("Failed to unmarshal. err: %w", unmarshalErr)
				}

				switch errMsg.Code {
				case errBusy, errLocked:
					return xerrors.Errorf("Failed to migrate. err: %w", ErrDBLocked)
				default:
					return xerrors.Errorf("Failed to migrate. err: %w", err)
				}
			}
		case dialectMysql, dialectPostgreSQL:
			return xerrors.Errorf("Failed to migrate. err: %w", err)
		default:
			return xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
		}
	}

	return nil
}

// IsGoKEVModelV1 determines if the DB was created at the time of go-kev Model v1
func (r *RDBDriver) IsGoKEVModelV1() (bool, error) {
	if r.conn.Migrator().HasTable(&models.FetchMeta{}) {
		return false, nil
	}

	var (
		count int64
		err   error
	)
	switch r.name {
	case dialectSqlite3:
		err = r.conn.Table("sqlite_master").Where("type = ?", "table").Count(&count).Error
	case dialectMysql:
		err = r.conn.Table("information_schema.tables").Where("table_schema = ?", r.conn.Migrator().CurrentDatabase()).Count(&count).Error
	case dialectPostgreSQL:
		err = r.conn.Table("pg_tables").Where("schemaname = ?", "public").Count(&count).Error
	}

	if count > 0 {
		return true, nil
	}
	return false, err
}

// GetFetchMeta get FetchMeta from Database
func (r *RDBDriver) GetFetchMeta() (fetchMeta *models.FetchMeta, err error) {
	if err = r.conn.Take(&fetchMeta).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return &models.FetchMeta{GoKEVRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion, LastFetchedAt: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)}, nil
	}

	return fetchMeta, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RDBDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	fetchMeta.GoKEVRevision = config.Revision
	fetchMeta.SchemaVersion = models.LatestSchemaVersion
	return r.conn.Save(fetchMeta).Error
}

// InsertKEVulns :
func (r *RDBDriver) InsertKEVulns(records []models.KEVuln) (err error) {
	log15.Info("Inserting Known Exploited Vulnerabilities...")
	return r.deleteAndInsertKEVulns(records)
}

func (r *RDBDriver) deleteAndInsertKEVulns(records []models.KEVuln) (err error) {
	bar := pb.StartNew(len(records)).SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	tx := r.conn.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(models.KEVuln{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete old records. err: %w", err)
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	for chunk := range slices.Chunk(records, batchSize) {
		if err = tx.Create(chunk).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(len(chunk))
	}
	bar.Finish()
	log15.Info("CveID Count", "count", len(records))
	return nil
}

// InsertVulnCheck :
func (r *RDBDriver) InsertVulnCheck(records []models.VulnCheck) (err error) {
	log15.Info("Inserting VulnCheck Known Exploited Vulnerabilities...")
	return r.deleteAndInsertVulnCheck(records)
}

func (r *RDBDriver) deleteAndInsertVulnCheck(records []models.VulnCheck) (err error) {
	bar := pb.StartNew(len(records)).SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	tx := r.conn.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	for _, table := range []interface{}{models.VulnCheck{}, models.VulnCheckCVE{}, models.VulnCheckXDB{}, models.VulnCheckReportedExploitation{}} {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(table).Error; err != nil {
			return xerrors.Errorf("Failed to delete old records. err: %w", err)
		}
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	for chunk := range slices.Chunk(records, batchSize) {
		if err = tx.Create(chunk).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(len(chunk))
	}
	bar.Finish()
	log15.Info("CveID Count", "count", len(records))
	return nil
}

// GetKEVByCveID :
func (r *RDBDriver) GetKEVByCveID(cveID string) (Response, error) {
	var res Response
	if err := r.conn.Where(&models.KEVuln{CveID: cveID}).Find(&res.CISA).Error; err != nil {
		return Response{}, xerrors.Errorf("Failed to get CISA info by CVE-ID. err: %w", err)
	}
	if err := r.conn.
		Joins("JOIN vuln_check_cves ON vuln_check_cves.vuln_check_id = vuln_checks.id AND vuln_check_cves.cve_id = ?", cveID).
		Preload("CVE").
		Preload("VulnCheckXDB").
		Preload("VulnCheckReportedExploitation").
		Find(&res.VulnCheck).Error; err != nil {
		return Response{}, xerrors.Errorf("Failed to get VulnCheck info by CVE-ID. err: %w", err)
	}
	return res, nil
}

// GetKEVByMultiCveID :
func (r *RDBDriver) GetKEVByMultiCveID(cveIDs []string) (map[string]Response, error) {
	m := make(map[string]Response)
	for _, cveID := range cveIDs {
		res, err := r.GetKEVByCveID(cveID)
		if err != nil {
			return nil, xerrors.Errorf("Failed to get KEV by %s. err: %w", cveID, err)
		}
		m[cveID] = res
	}
	return m, nil
}
