package convert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/fetcher"
	"github.com/vulsio/go-kev/models"
	"github.com/vulsio/go-kev/utils"
)

var convertCatalogCmd = &cobra.Command{
	Use:   "kevuln",
	Short: "Convert the data of known exploited vulnerabilities catalog by CISA to CVE units",
	Long:  `Convert the data of known exploited vulnerabilities catalog by CISA to CVE units`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlag("vuln-dir", cmd.Parent().PersistentFlags().Lookup("vuln-dir")); err != nil {
			return err
		}
		return nil
	},
	RunE: convertKEV,
}

func convertKEV(_ *cobra.Command, _ []string) (err error) {
	if err := utils.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	vulnDir := viper.GetString("vuln-dir")
	if f, err := os.Stat(vulnDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(vulnDir, 0700); err != nil {
				return xerrors.Errorf("Failed to create vuln directory. err: %w", err)
			}
		} else {
			return xerrors.Errorf("Failed to check vuln directory. err: %w", err)
		}
	} else if !f.IsDir() {
		return xerrors.Errorf("Failed to check vuln directory. err: %s is not directory", vulnDir)
	}

	log15.Info("Fetching Known Exploited Vulnerabilities")
	var vulns []models.KEVuln
	if vulns, err = fetcher.FetchKEVuln(); err != nil {
		return xerrors.Errorf("Failed to fetch Known Exploited Vulnerabilities. err: %w", err)
	}

	log15.Info("Converting Known Exploited Vulnerabilities")
	vulnsMap := map[string][]models.KEVuln{}
	for _, v := range vulns {
		vulnsMap[v.CveID] = append(vulnsMap[v.CveID], v)
	}

	log15.Info("Deleting Old Known Exploited Vulnerabilities")
	files, err := filepath.Glob(filepath.Join(vulnDir, "*"))
	if err != nil {
		return xerrors.Errorf("Failed to get all files in vuln directory. err: %w", err)
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			return xerrors.Errorf("Failed to remove vuln data file. err: %w", err)
		}
	}

	log15.Info("Creating Known Exploited Vulnerabilities")
	for cveID, vs := range vulnsMap {
		f, err := os.Create(filepath.Join(vulnDir, fmt.Sprintf("%s.json", cveID)))
		if err != nil {
			return xerrors.Errorf("Failed to create vuln data file. err: %w", err)
		}

		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(vs); err != nil {
			_ = f.Close() // ignore error; Write error takes precedence
			return xerrors.Errorf("Failed to encode vuln data. err: %w", err)
		}

		if err := f.Close(); err != nil {
			return xerrors.Errorf("Failed to close vuln data file. err: %w", err)
		}
	}

	log15.Info("Setting Last Updated Date")
	if err := setLastUpdatedDate("go-kev/kevuln"); err != nil {
		return xerrors.Errorf("Failed to set last updated date. err: %w", err)
	}

	return nil
}
