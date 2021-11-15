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
}

// OutDated checks whether last fetched feed is out dated
func (f FetchMeta) OutDated() bool {
	return f.SchemaVersion != LatestSchemaVersion
}

// KEVuln : Known Exploited Vulnerabilities
type KEVuln struct {
	ID          int64      `json:"-"`
	CveID       string     `gorm:"type:varchar(255);index:idx_kev_cve_id" csv:"CVE"`
	Source      string     `gorm:"type:varchar(255)" csv:"Vendor/Project"`
	Product     string     `gorm:"type:varchar(255)" csv:"Product"`
	Title       string     `gorm:"type:varchar(255)" csv:"Vulnerability Name"`
	AddedDate   KEVulnTime `gorm:"type:time" csv:"Date Added to Catalog"`
	Description string     `gorm:"type:text" csv:"Short Description"`
	Action      string     `gorm:"type:varchar(255)" csv:"Action"`
	DueDate     KEVulnTime `gorm:"type:time" csv:"Due Date"`
	Notes       string     `gorm:"type:text" csv:"Notes"`
}

// KEVulnTime :
type KEVulnTime struct {
	time.Time
}

const kevDateFormat = "2-Jan-06"

// UnmarshalCSV :
func (date *KEVulnTime) UnmarshalCSV(csv string) (err error) {
	date.Time, err = time.Parse(kevDateFormat, csv)
	if err != nil {
		return err
	}
	return nil
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
