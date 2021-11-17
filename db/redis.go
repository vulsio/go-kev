package db

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/cheggaaa/pb/v3"
	"github.com/go-redis/redis/v8"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/config"
	"github.com/vulsio/go-kev/models"
)

/**
# Redis Data Structure
- Strings
  ┌───┬─────────┬────────┬──────────────────────────────────────────────────┐
  │NO │  KEY    │ MEMBER │                    PURPOSE                       │
  └───┴─────────┴────────┴──────────────────────────────────────────────────┘
  ┌───┬─────────┬────────┬──────────────────────────────────────────────────┐
  │ 1 │ KEV#DEP │  JSON  │ TO DELETE OUTDATED AND UNNEEDED FIELD AND MEMBER │
  └───┴─────────┴────────┴──────────────────────────────────────────────────┘
- Hash
  ┌───┬────────────────┬───────────────┬──────────────┬──────────────────────────────┐
  │NO │     KEY        │   FIELD       │     VALUE    │           PURPOSE            │
  └───┴────────────────┴───────────────┴──────────────┴──────────────────────────────┘
  ┌───┬────────────────┬───────────────┬──────────────┬──────────────────────────────┐
  │ 1 │ KEV#CVE#$CVEID │    MD5SUM     │     JSON     │ TO GET VULN FROM CVEID       │
  ├───┼────────────────┼───────────────┼──────────────┼──────────────────────────────┤
  │ 2 │ KEV#FETCHMETA  │   Revision    │    string    │ GET Go-KEV Binary Revision   │
  ├───┼────────────────┼───────────────┼──────────────┼──────────────────────────────┤
  │ 3 │ KEV#FETCHMETA  │ SchemaVersion │     uint     │ GET Go-KEV Schema Version    │
  └───┴────────────────┴───────────────┴──────────────┴──────────────────────────────┘
**/

const (
	dialectRedis   = "redis"
	cveIDKeyFormat = "KEV#CVE#%s"
	depKey         = "KEV#DEP"
	fetchMetaKey   = "KEV#FETCHMETA"
)

// RedisDriver is Driver for Redis
type RedisDriver struct {
	name string
	conn *redis.Client
}

// Name return db name
func (r *RedisDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RedisDriver) OpenDB(_, dbPath string, _ bool, option Option) (bool, error) {
	return false, r.connectRedis(dbPath, option)
}

func (r *RedisDriver) connectRedis(dbPath string, option Option) error {
	ctx := context.Background()
	var err error
	var opt *redis.Options
	if opt, err = redis.ParseURL(dbPath); err != nil {
		return xerrors.Errorf("Failed to parse url. err: %w", err)
	}
	if 0 < option.RedisTimeout.Seconds() {
		opt.ReadTimeout = option.RedisTimeout
	}
	r.conn = redis.NewClient(opt)
	return r.conn.Ping(ctx).Err()
}

// CloseDB close Database
func (r *RedisDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}
	if err = r.conn.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// MigrateDB migrates Database
func (r *RedisDriver) MigrateDB() error {
	return nil
}

// IsGoKEVModelV1 determines if the DB was created at the time of go-kev Model v1
func (r *RedisDriver) IsGoKEVModelV1() (bool, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return false, xerrors.Errorf("Failed to Exists. err: %w", err)
	}
	if exists == 0 {
		keys, _, err := r.conn.Scan(ctx, 0, "KEV#*", 1).Result()
		if err != nil {
			return false, xerrors.Errorf("Failed to Scan. err: %w", err)
		}
		if len(keys) == 0 {
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

// GetFetchMeta get FetchMeta from Database
func (r *RedisDriver) GetFetchMeta() (*models.FetchMeta, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to Exists. err: %w", err)
	}
	if exists == 0 {
		return &models.FetchMeta{GoKEVRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	revision, err := r.conn.HGet(ctx, fetchMetaKey, "Revision").Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HGet Revision. err: %w", err)
	}

	verstr, err := r.conn.HGet(ctx, fetchMetaKey, "SchemaVersion").Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HGet SchemaVersion. err: %w", err)
	}
	version, err := strconv.ParseUint(verstr, 10, 8)
	if err != nil {
		return nil, xerrors.Errorf("Failed to ParseUint. err: %w", err)
	}

	return &models.FetchMeta{GoKEVRevision: revision, SchemaVersion: uint(version)}, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RedisDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	return r.conn.HSet(context.Background(), fetchMetaKey, map[string]interface{}{"Revision": fetchMeta.GoKEVRevision, "SchemaVersion": fetchMeta.SchemaVersion}).Err()
}

// InsertKEVulns :
func (r *RedisDriver) InsertKEVulns(records []models.KEVuln) (err error) {
	ctx := context.Background()
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	// newDeps, oldDeps: {"CVEID": {"HashSum(CVEJSON)": {}}}
	newDeps := map[string]map[string]struct{}{}
	oldDepsStr, err := r.conn.Get(ctx, depKey).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return xerrors.Errorf("Failed to Get key: %s. err: %w", depKey, err)
		}
		oldDepsStr = "{}"
	}
	var oldDeps map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return xerrors.Errorf("Failed to unmarshal JSON. err: %w", err)
	}

	log15.Info("Inserting Known Exploited Vulnerabilities...")
	bar := pb.StartNew(len(records))
	for idx := range chunkSlice(len(records), batchSize) {
		pipe := r.conn.Pipeline()
		for _, record := range records[idx.From:idx.To] {
			j, err := json.Marshal(record)
			if err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}

			hash := fmt.Sprintf("%x", md5.Sum(j))
			if err := pipe.HSet(ctx, fmt.Sprintf(cveIDKeyFormat, record.CveID), hash, string(j)).Err(); err != nil {
				return xerrors.Errorf("Failed to HSet CVE. err: %w", err)
			}

			if _, ok := newDeps[record.CveID]; !ok {
				newDeps[record.CveID] = map[string]struct{}{}
			}
			if _, ok := newDeps[record.CveID][hash]; !ok {
				newDeps[record.CveID][hash] = struct{}{}
			}
			if _, ok := oldDeps[record.CveID]; ok {
				if _, ok := oldDeps[record.CveID][hash]; ok {
					delete(oldDeps[record.CveID], hash)
				}
				if len(oldDeps[record.CveID]) == 0 {
					delete(oldDeps, record.CveID)
				}
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	pipe := r.conn.Pipeline()
	for cveID, hashes := range oldDeps {
		for hash := range hashes {
			if err := pipe.HDel(ctx, fmt.Sprintf(cveIDKeyFormat, cveID), hash).Err(); err != nil {
				return xerrors.Errorf("Failed to HDel. err: %w", err)
			}
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return xerrors.Errorf("Failed to Marshal JSON. err: %w", err)
	}
	if err := pipe.Set(ctx, depKey, string(newDepsJSON), 0).Err(); err != nil {
		return xerrors.Errorf("Failed to Set depkey. err: %w", err)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
	}

	log15.Info("CveID Count", "count", len(records))
	return nil
}

// GetKEVulnByCveID :
func (r *RedisDriver) GetKEVulnByCveID(cveID string) ([]models.KEVuln, error) {
	results, err := r.conn.HGetAll(context.Background(), fmt.Sprintf(cveIDKeyFormat, cveID)).Result()
	if err != nil {
		return nil, err
	}

	vulns := []models.KEVuln{}
	for _, s := range results {
		var vuln models.KEVuln
		if err := json.Unmarshal([]byte(s), &vuln); err != nil {
			return nil, err
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

// GetKEVulnByMultiCveID :
func (r *RedisDriver) GetKEVulnByMultiCveID(cveIDs []string) (map[string][]models.KEVuln, error) {
	ctx := context.Background()

	if len(cveIDs) == 0 {
		return map[string][]models.KEVuln{}, nil
	}

	m := map[string]*redis.StringStringMapCmd{}
	pipe := r.conn.Pipeline()
	for _, cveID := range cveIDs {
		m[cveID] = pipe.HGetAll(ctx, fmt.Sprintf(cveIDKeyFormat, cveID))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}

	vulns := map[string][]models.KEVuln{}
	for cveID, cmd := range m {
		results, err := cmd.Result()
		if err != nil {
			return nil, err
		}

		var vs []models.KEVuln
		for _, s := range results {
			var v models.KEVuln
			if err := json.Unmarshal([]byte(s), &v); err != nil {
				return nil, err
			}
			vs = append(vs, v)
		}
		vulns[cveID] = vs
	}
	return vulns, nil
}
