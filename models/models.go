package models

import (
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
	LastFetchedAt time.Time
}

// OutDated checks whether last fetched feed is out dated
func (f FetchMeta) OutDated() bool {
	return f.SchemaVersion != LatestSchemaVersion
}

// KEVuln : Known Exploited Vulnerabilities
type KEVuln struct {
	ID                         int64     `json:"-"`
	CveID                      string    `gorm:"type:varchar(255);index:idx_kev_cve_id" json:"cveID"`
	VendorProject              string    `gorm:"type:varchar(255)" json:"vendorProject"`
	Product                    string    `gorm:"type:varchar(255)" json:"product"`
	VulnerabilityName          string    `gorm:"type:varchar(255)" json:"vulnerabilityName"`
	DateAdded                  time.Time `json:"dateAdded"`
	ShortDescription           string    `gorm:"type:text" json:"shortDescription"`
	RequiredAction             string    `gorm:"type:text" json:"requiredAction"`
	DueDate                    time.Time `json:"dueDate"`
	KnownRansomwareCampaignUse string    `gorm:"type:varchar(255)" json:"knownRansomwareCampaignUse"`
	Notes                      string    `gorm:"type:text" json:"notes"`
}
