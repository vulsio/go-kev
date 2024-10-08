package db_test

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/db"
	"github.com/vulsio/go-kev/models"
	"github.com/vulsio/go-kev/utils"
)

func setupRedis() (*miniredis.Miniredis, db.DB, error) {
	s, err := miniredis.Run()
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to run miniredis: %w", err)
	}
	driver, err := db.NewDB("redis", fmt.Sprintf("redis://%s", s.Addr()), false, db.Option{})
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to new db: %w", err)
	}
	return s, driver, nil
}

func teardownRedis(s *miniredis.Miniredis, driver db.DB) {
	s.Close()
	_ = driver.CloseDB()
}

func TestRedisDriver_GetKEVByMultiCveID(t *testing.T) {
	t.Parallel()
	s, driver, err := setupRedis()
	if err != nil {
		t.Fatalf("Failed to prepare redis: %s", err)
	}
	defer teardownRedis(s, driver)
	if err := prepareTestData(driver); err != nil {
		t.Fatalf("Failed to prepare testdata of KEV: %s", err)
	}

	testdata := []struct {
		name     string
		cveIDs   []string
		expected map[string]db.Response
	}{
		{
			name:   "single cveID",
			cveIDs: []string{"CVE-2021-27104"},
			expected: map[string]db.Response{
				"CVE-2021-27104": {
					[]models.KEVuln{
						{
							CveID:                      "CVE-2021-27104",
							VendorProject:              "Accellion",
							Product:                    "FTA",
							VulnerabilityName:          "Accellion FTA OS Command Injection Vulnerability",
							DateAdded:                  time.Date(2021, 11, 3, 0, 0, 0, 0, time.UTC),
							ShortDescription:           "Accellion FTA contains an OS command injection vulnerability exploited via a crafted POST request to various admin endpoints.",
							RequiredAction:             "Apply updates per vendor instructions.",
							DueDate:                    time.Date(2021, 11, 17, 0, 0, 0, 0, time.UTC),
							KnownRansomwareCampaignUse: "Known",
							Notes:                      "",
						},
					},
					[]models.VulnCheck{
						{
							VendorProject:              "Accellion",
							Product:                    "FTA",
							Description:                "Accellion FTA contains an OS command injection vulnerability exploited via a crafted POST request to various admin endpoints.",
							Name:                       "Accellion FTA OS Command Injection Vulnerability",
							RequiredAction:             "Apply updates per vendor instructions.",
							KnownRansomwareCampaignUse: "Known",
							CVE: []models.VulnCheckCVE{
								{
									CveID: "CVE-2021-27104",
								},
							},
							VulnCheckXDB: []models.VulnCheckXDB{},
							VulnCheckReportedExploitation: []models.VulnCheckReportedExploitation{
								{
									URL:       "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
									DateAdded: time.Date(2021, 11, 3, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://unit42.paloaltonetworks.com/clop-ransomware/",
									DateAdded: time.Date(2021, 4, 13, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/ransomware-double-extortion-and-beyond-revil-clop-and-conti",
									DateAdded: time.Date(2021, 6, 3, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://cybersecurityworks.com/howdymanage/uploads/file/ransomware-_-2022-spotlight-report_compressed.pdf",
									DateAdded: time.Date(2022, 1, 26, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/2022-unit42-ransomware-threat-report-final.pdf",
									DateAdded: time.Date(2022, 3, 24, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://static.tenable.com/marketing/whitepapers/Whitepaper-Ransomware_Ecosystem.pdf",
									DateAdded: time.Date(2022, 6, 22, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://www.group-ib.com/resources/research-hub/hi-tech-crime-trends-2022/",
									DateAdded: time.Date(2023, 1, 17, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://fourcore.io/blogs/clop-ransomware-history-adversary-simulation",
									DateAdded: time.Date(2023, 6, 3, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://blog.talosintelligence.com/talos-ir-q2-2023-quarterly-recap/",
									DateAdded: time.Date(2023, 7, 26, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://www.sentinelone.com/resources/watchtower-end-of-year-report-2023/",
									DateAdded: time.Date(2021, 11, 3, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://www.trustwave.com/en-us/resources/blogs/trustwave-blog/defending-the-energy-sector-against-cyber-threats-insights-from-trustwave-spiderlabs/",
									DateAdded: time.Date(2024, 5, 15, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://cisa.gov/news-events/cybersecurity-advisories/aa21-055a",
									DateAdded: time.Date(2021, 6, 17, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-209a",
									DateAdded: time.Date(2021, 8, 20, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://cisa.gov/news-events/alerts/2022/04/27/2021-top-routinely-exploited-vulnerabilities",
									DateAdded: time.Date(2022, 4, 28, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://cisa.gov/news-events/cybersecurity-advisories/aa22-117a",
									DateAdded: time.Date(2022, 4, 28, 0, 0, 0, 0, time.UTC),
								},
								{
									URL:       "https://www.hhs.gov/sites/default/files/threat-profile-june-2023.pdf",
									DateAdded: time.Date(2023, 06, 13, 0, 0, 0, 0, time.UTC),
								},
							},
							DueDate:       utils.ToPtr(time.Date(2021, 11, 17, 0, 0, 0, 0, time.UTC)),
							CisaDateAdded: utils.ToPtr(time.Date(2021, 11, 3, 0, 0, 0, 0, time.UTC)),
							DateAdded:     time.Date(2021, 4, 13, 0, 0, 0, 0, time.UTC),
						},
					},
				},
			},
		},
	}

	for _, tt := range testdata {
		got, err := driver.GetKEVByMultiCveID(tt.cveIDs)
		if err != nil {
			t.Errorf("RedisDriver.GetKEVByMultiCveID() error = %v", err)
			return
		}
		if !reflect.DeepEqual(got, tt.expected) {
			t.Errorf("got: %v, expected: %v", got, tt.expected)
		}
	}
}
