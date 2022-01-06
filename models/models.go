package models

import (
	"database/sql/driver"
	"time"

	"gorm.io/gorm"
)

// LatestSchemaVersion manages the Schema version used in the latest go-kev.
const LatestSchemaVersion = 1

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
	ID          int64      `json:"-"`
	CveID       string     `gorm:"type:varchar(255);index:idx_kev_cve_id" csv:"cveID"`
	Source      string     `gorm:"type:varchar(255)" csv:"vendorProject"`
	Product     string     `gorm:"type:varchar(255)" csv:"product"`
	Title       string     `gorm:"type:varchar(255)" csv:"vulnerabilityName"`
	AddedDate   KEVulnTime `gorm:"type:time" csv:"dateAdded"`
	Description string     `gorm:"type:text" csv:"shortDescription"`
	Action      string     `gorm:"type:varchar(255)" csv:"requiredAction"`
	DueDate     KEVulnTime `gorm:"type:time" csv:"dueDate"`
	Notes       string     `gorm:"type:text" csv:"notes"`
}

// KEVulnTime :
type KEVulnTime struct {
	time.Time
}

const kevDateFormat = "2006-01-02"

// UnmarshalCSV :
func (date *KEVulnTime) UnmarshalCSV(csv string) (err error) {
	date.Time, err = time.Parse(kevDateFormat, csv)
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
