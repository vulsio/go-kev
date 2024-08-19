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

// VulnCheck : https://docs.vulncheck.com/community/vulncheck-kev/schema
type VulnCheck struct {
	ID                         int64  `json:"-"`
	VendorProject              string `gorm:"type:varchar(255)" json:"vendorProject"`
	Product                    string `gorm:"type:varchar(255)" json:"product"`
	Description                string `gorm:"type:text" json:"shortDescription"`
	Name                       string `gorm:"type:varchar(255)" json:"vulnerabilityName"`
	RequiredAction             string `gorm:"type:text" json:"required_action"`
	KnownRansomwareCampaignUse string `gorm:"type:varchar(255)" json:"knownRansomwareCampaignUse"`

	CVE []VulnCheckCVE `json:"cve"`

	VulnCheckXDB                  []VulnCheckXDB                  `json:"vulncheck_xdb"`
	VulnCheckReportedExploitation []VulnCheckReportedExploitation `json:"vulncheck_reported_exploitation"`

	DueDate       *time.Time `json:"dueDate,omitempty"`
	CisaDateAdded *time.Time `json:"cisa_date_added,omitempty"`
	DateAdded     time.Time  `json:"date_added"`
}

// VulnCheckCVE :
type VulnCheckCVE struct {
	ID          int64  `json:"-"`
	VulnCheckID uint   `json:"-" gorm:"index:idx_vulncheck_cve"`
	CveID       string `gorm:"type:varchar(255);index:idx_vulncheck_cve_cve_id" json:"cveID"`
}

// VulnCheckXDB :
type VulnCheckXDB struct {
	ID          int64     `json:"-"`
	VulnCheckID uint      `json:"-" gorm:"index:idx_vulncheck_xdb"`
	XDBID       string    `gorm:"type:varchar(255)" json:"xdb_id"`
	XDBURL      string    `gorm:"type:varchar(255)" json:"xdb_url"`
	DateAdded   time.Time `json:"date_added"`
	ExploitType string    `gorm:"type:varchar(255)" json:"exploit_type"`
	CloneSSHURL string    `gorm:"type:text" json:"clone_ssh_url"`
}

// VulnCheckReportedExploitation :
type VulnCheckReportedExploitation struct {
	ID          int64     `json:"-"`
	VulnCheckID uint      `json:"-" gorm:"index:idx_vulncheck_reported_exploitation"`
	URL         string    `gorm:"type:text" json:"url"`
	DateAdded   time.Time `json:"date_added"`
}
