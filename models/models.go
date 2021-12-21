package models

import (
	"database/sql/driver"
	"time"

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
	Title           string    `json:"title"`
	CatalogVersion  string    `json:"catalogVersion"`
	DateReleased    time.Time `json:"dateReleased"`
	Count           int       `json:"count"`
	Vulnerabilities []KEVuln  `json:"vulnerabilities"`
}

// KEVuln : Known Exploited Vulnerabilities
type KEVuln struct {
	ID                int64      `json:"-"`
	CveID             string     `gorm:"type:varchar(255);index:idx_kev_cve_id" json:"cveID"`
	VendorProject     string     `gorm:"type:varchar(255)" json:"vendorProject"`
	Product           string     `gorm:"type:varchar(255)" json:"product"`
	VulnerabilityName string     `gorm:"type:varchar(255)" json:"vulnerabilityName"`
	DateAdded         KEVulnTime `gorm:"type:time" json:"dateAdded"`
	ShortDescription  string     `gorm:"type:text" json:"shortDescription"`
	RequiredAction    string     `gorm:"type:varchar(255)" json:"requiredAction"`
	DueDate           KEVulnTime `gorm:"type:time" json:"dueDate"`
}

// KEVulnTime :
type KEVulnTime struct {
	time.Time
}

const kevDateFormat = "2006-01-02"

// UnmarshalJSON :
func (date *KEVulnTime) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		date.Time = time.Time{}
		return nil
	}

	var err error
	date.Time, err = time.Parse(`"`+kevDateFormat+`"`, string(b))
	return err
}

// Scan :
func (date *KEVulnTime) Scan(value interface{}) error {
	date.Time = value.(time.Time)
	return nil
}

// Value :
func (date KEVulnTime) Value() (driver.Value, error) {
	return date.Time, nil
}
