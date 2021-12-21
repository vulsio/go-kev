package models

import (
	"time"

	"golang.org/x/xerrors"
	"gorm.io/gorm"
)

// LatestSchemaVersion manages the Schema version used in the latest go-kev.
const LatestSchemaVersion = 2

// FetchMeta has meta information
type FetchMeta struct {
	gorm.Model    `json:"-"`
	GoKEVRevision string
	SchemaVersion uint
}

// OutDated checks whether last fetched feed is out dated
func (f FetchMeta) OutDated() bool {
	return f.SchemaVersion != LatestSchemaVersion
}

// KEVCatalog : CISA Catalog of Known Exploited Vulnerabilities
type KEVCatalog struct {
	Title           string       `json:"title"`
	CatalogVersion  string       `json:"catalogVersion"`
	DateReleased    time.Time    `json:"dateReleased"`
	Count           int          `json:"count"`
	Vulnerabilities []KEVulnJSON `json:"vulnerabilities"`
}

// KEVulnJSON : Known Exploited Vulnerabilities JSON
type KEVulnJSON struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
}

// KEVuln : Known Exploited Vulnerabilities
type KEVuln struct {
	ID                int64     `json:"-"`
	CveID             string    `gorm:"type:varchar(255);index:idx_kev_cve_id" json:"cveID"`
	VendorProject     string    `gorm:"type:varchar(255)" json:"vendorProject"`
	Product           string    `gorm:"type:varchar(255)" json:"product"`
	VulnerabilityName string    `gorm:"type:varchar(255)" json:"vulnerabilityName"`
	DateAdded         time.Time `gorm:"type:time" json:"dateAdded"`
	ShortDescription  string    `gorm:"type:text" json:"shortDescription"`
	RequiredAction    string    `gorm:"type:varchar(255)" json:"requiredAction"`
	DueDate           time.Time `gorm:"type:time" json:"dueDate"`
}

// ConvertKEVuln :
func ConvertKEVuln(kevJSONs []KEVulnJSON) ([]KEVuln, error) {
	kevs := []KEVuln{}
	for _, kevJSON := range kevJSONs {
		if kevJSON.CveID == "" {
			return nil, xerrors.New("Failed to convert vulnerability info. err: CVE-ID is empty.")
		}

		const timeformat = "2006-01-02"
		dateAdded, err := time.Parse(timeformat, kevJSON.DateAdded)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse kevJSON.DateAdded. err: %w", err)
		}

		dueDate, err := time.Parse(timeformat, kevJSON.DueDate)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse kevJSON.DueDate. err: %w", err)
		}

		kevs = append(kevs, KEVuln{
			CveID:             kevJSON.CveID,
			VendorProject:     kevJSON.VendorProject,
			Product:           kevJSON.Product,
			VulnerabilityName: kevJSON.VulnerabilityName,
			DateAdded:         dateAdded,
			ShortDescription:  kevJSON.ShortDescription,
			RequiredAction:    kevJSON.RequiredAction,
			DueDate:           dueDate,
		})
	}
	return kevs, nil
}
