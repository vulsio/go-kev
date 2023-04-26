package fetcher

import (
	"encoding/json"
	"time"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/models"
	"github.com/vulsio/go-kev/utils"
)

// FetchKEVuln :
func FetchKEVuln() ([]models.KEVuln, error) {
	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	log15.Info("Fetching", "URL", url)
	vulnJSON, err := utils.FetchURL(url)
	if err != nil {
		return nil, err
	}

	catalog := catalog{}
	if err := json.Unmarshal(vulnJSON, &catalog); err != nil {
		return nil, xerrors.Errorf("failed to decode CISA Known Exploited Vulnerabilities JSON: %w", err)
	}

	vs := make([]models.KEVuln, 0, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		vs = append(vs, models.KEVuln{
			CveID:             v.CveID,
			VendorProject:     v.VendorProject,
			Product:           v.Product,
			VulnerabilityName: v.VulnerabilityName,
			DateAdded:         parsedOrDefaultTime("2006-01-02", v.DateAdded),
			ShortDescription:  v.ShortDescription,
			RequiredAction:    v.RequiredAction,
			DueDate:           parsedOrDefaultTime("2006-01-02", v.DueDate),
			Notes:             v.Notes,
		})
	}

	return vs, nil
}

func parsedOrDefaultTime(layout string, value string) time.Time {
	defaultTime := time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
	if value == "" {
		return defaultTime
	}

	if t, err := time.Parse(layout, value); err == nil {
		return t
	}
	log15.Warn("Failed to parse string", "timeformat", layout, "target string", value)
	return defaultTime
}
