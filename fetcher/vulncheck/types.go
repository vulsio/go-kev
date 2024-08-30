package vulncheck

import "time"

// https://docs.vulncheck.com/community/vulncheck-kev/schema
type vulncheck struct {
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	Description                string `json:"shortDescription"`
	Name                       string `json:"vulnerabilityName"`
	RequiredAction             string `json:"required_action"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`

	CVE []string `json:"cve"`

	VulnCheckXDB                  []xdb             `json:"vulncheck_xdb"`
	VulnCheckReportedExploitation []reportedExploit `json:"vulncheck_reported_exploitation"`

	DueDate       *time.Time `json:"dueDate,omitempty"`
	CisaDateAdded *time.Time `json:"cisa_date_added,omitempty"`
	DateAdded     time.Time  `json:"date_added"`
}

type reportedExploit struct {
	URL       string    `json:"url"`
	DateAdded time.Time `json:"date_added"`
}

type xdb struct {
	XDBID       string    `json:"xdb_id"`
	XDBURL      string    `json:"xdb_url"`
	DateAdded   time.Time `json:"date_added"`
	ExploitType string    `json:"exploit_type"`
	CloneSSHURL string    `json:"clone_ssh_url"`
}
