package commands

import (
	"errors"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/db"
	fetcher "github.com/vulsio/go-kev/fetcher/vulncheck"
	"github.com/vulsio/go-kev/models"
	"github.com/vulsio/go-kev/utils"
)

var fetchVulnCheckCmd = &cobra.Command{
	Use:   "vulncheck <vuls-data-raw-vulncheck-kev directory>",
	Short: "Fetch the data of known exploited vulnerabilities catalog by VulnCheck (https://vulncheck.com/kev)",
	Long:  `Fetch the data of known exploited vulnerabilities catalog by VulnCheck (https://vulncheck.com/kev)`,
	Args:  cobra.NoArgs,
	RunE:  fetchVulnCheck,
}

func init() {
	fetchCmd.AddCommand(fetchVulnCheckCmd)
}

func fetchVulnCheck(_ *cobra.Command, _ []string) (err error) {
	if err := utils.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"), db.Option{})
	if err != nil {
		if errors.Is(err, db.ErrDBLocked) {
			return xerrors.Errorf("Failed to open DB. Close DB connection before fetching. err: %w", err)
		}
		return xerrors.Errorf("Failed to open DB. err: %w", err)
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to Insert CVEs into DB. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}
	// If the fetch fails the first time (without SchemaVersion), the DB needs to be cleaned every time, so insert SchemaVersion.
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	log15.Info("Fetching VulnCheck Known Exploited Vulnerabilities")
	var vulns []models.VulnCheck
	if vulns, err = fetcher.Fetch(); err != nil {
		return xerrors.Errorf("Failed to fetch VulnCheck Known Exploited Vulnerabilities. err: %w", err)
	}

	log15.Info("Insert VulnCheck Known Exploited Vulnerabilities into go-kev.", "db", driver.Name())
	if err := driver.InsertVulnCheck(vulns); err != nil {
		return xerrors.Errorf("Failed to insert. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	fetchMeta.LastFetchedAt = time.Now()
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	return nil
}
