package fetcher

import (
	"bytes"

	"github.com/gocarina/gocsv"
	"github.com/inconshreveable/log15"

	"github.com/MaineK00n/go-kev/models"
	"github.com/MaineK00n/go-kev/utils"
)

var UTF8_BOM = []byte{239, 187, 191}

func hasBOM(in []byte) bool {
	return bytes.HasPrefix(in, UTF8_BOM)
}

func stripBOM(in []byte) []byte {
	return bytes.TrimPrefix(in, UTF8_BOM)
}

func FetchKEVuln() ([]models.KEVuln, error) {
	url := "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
	log15.Info("Fetching", "URL", url)
	vulnCsv, err := utils.FetchURL(url)
	if err != nil {
		return nil, err
	}

	if hasBOM(vulnCsv) {
		vulnCsv = stripBOM(vulnCsv)
	}

	var vulns []models.KEVuln
	if err := gocsv.UnmarshalBytes(vulnCsv, &vulns); err != nil {
		return nil, err
	}
	return vulns, nil
}
