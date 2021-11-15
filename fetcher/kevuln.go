package fetcher

import (
	"bytes"

	"github.com/gocarina/gocsv"
	"github.com/inconshreveable/log15"

	"github.com/MaineK00n/go-kev/models"
	"github.com/MaineK00n/go-kev/utils"
)

var utf8Bom = []byte{239, 187, 191}

func hasBOM(in []byte) bool {
	return bytes.HasPrefix(in, utf8Bom)
}

func stripBOM(in []byte) []byte {
	return bytes.TrimPrefix(in, utf8Bom)
}

var zeroWidthSpace = []byte{226, 128, 139}

func hasZeroWidthSpace(in []byte) bool {
	return bytes.HasPrefix(in, zeroWidthSpace) || bytes.HasSuffix(in, zeroWidthSpace)
}

func stripZeroWidthSpace(in []byte) []byte {
	return bytes.ReplaceAll(in, zeroWidthSpace, []byte{})
}

// FetchKEVuln :
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

	for i := range vulns {
		if hasZeroWidthSpace([]byte(vulns[i].CveID)) {
			vulns[i].CveID = string(stripZeroWidthSpace([]byte(vulns[i].CveID)))
		}
	}

	return vulns, nil
}
