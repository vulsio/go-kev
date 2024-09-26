package db

import (
	"time"

	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/models"
)

// DB :
type DB interface {
	Name() string
	OpenDB(dbType, dbPath string, debugSQL bool, option Option) error
	MigrateDB() error
	CloseDB() error

	IsGoKEVModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error

	InsertKEVulns([]models.KEVuln) error
	InsertVulnCheck([]models.VulnCheck) error
	GetKEVByCveID(string) (Response, error)
	GetKEVByMultiCveID([]string) (map[string]Response, error)
}

// Option :
type Option struct {
	RedisTimeout time.Duration
}

// Response :
type Response struct {
	CISA      []models.KEVuln    `json:"cisa,omitempty"`
	VulnCheck []models.VulnCheck `json:"vulncheck,omitempty"`
}

// NewDB :
func NewDB(dbType string, dbPath string, debugSQL bool, option Option) (driver DB, err error) {
	if driver, err = newDB(dbType); err != nil {
		return driver, xerrors.Errorf("Failed to new db. err: %w", err)
	}

	if err := driver.OpenDB(dbType, dbPath, debugSQL, option); err != nil {
		return nil, xerrors.Errorf("Failed to open db. err: %w", err)
	}

	isV1, err := driver.IsGoKEVModelV1()
	if err != nil {
		return nil, xerrors.Errorf("Failed to IsGoKEVModelV1. err: %w", err)
	}
	if isV1 {
		return nil, xerrors.New("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again.")
	}

	if err := driver.MigrateDB(); err != nil {
		return driver, xerrors.Errorf("Failed to migrate db. err: %w", err)
	}
	return driver, nil
}

func newDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, xerrors.Errorf("Invalid database dialect, %s", dbType)
}
