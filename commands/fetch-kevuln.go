package commands

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/db"
	"github.com/vulsio/go-kev/fetcher"
	"github.com/vulsio/go-kev/models"
	"github.com/vulsio/go-kev/utils"
)

var fetchCatalogCmd = &cobra.Command{
	Use:   "kevuln",
	Short: "Fetch the data of known exploited vulnerabilities catalog by CISA",
	Long:  `Fetch the data of known exploited vulnerabilities catalog by CISA`,
	RunE:  fetchKEVuln,
}

func init() {
	fetchCmd.AddCommand(fetchCatalogCmd)
}

func fetchKEVuln(_ *cobra.Command, _ []string) (err error) {
	if err := utils.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"), db.Option{})
	if err != nil {
		if locked {
			return xerrors.Errorf("Failed to initialize DB. Close DB connection before fetching. err: %w", err)
		}
		return err
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to Insert CVEs into DB. SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	log15.Info("Fetching Known Exploited Vulnerabilities")
	var vulns []models.KEVuln
	if vulns, err = fetcher.FetchKEVuln(); err != nil {
		return xerrors.Errorf("Failed to fetch Known Exploited Vulnerabilities. err: %w", err)
	}

	log15.Info("Insert Known Exploited Vulnerabilities into go-kev.", "db", driver.Name())
	if err := driver.InsertKEVulns(vulns); err != nil {
		return xerrors.Errorf("Failed to insert. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	return nil
}
