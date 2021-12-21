package fetcher

import (
	"encoding/json"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/models"
	"github.com/vulsio/go-kev/utils"
)

// FetchKEVuln :
func FetchKEVuln() ([]models.KEVulnJSON, error) {
	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	log15.Info("Fetching", "URL", url)
	vulnJSON, err := utils.FetchURL(url)
	if err != nil {
		return nil, err
	}

	kevCatalog := models.KEVCatalog{}
	if err := json.Unmarshal(vulnJSON, &kevCatalog); err != nil {
		return nil, xerrors.Errorf("failed to decode CISA Known Exploited Vulnerabilities JSON: %w", err)
	}

	return kevCatalog.Vulnerabilities, nil
}
