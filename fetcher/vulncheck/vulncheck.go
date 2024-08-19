package vulncheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/vulsio/go-kev/models"
	"github.com/vulsio/go-kev/utils"
)

// Fetch :
func Fetch() ([]models.VulnCheck, error) {
	bs, err := utils.FetchURL("https://github.com/vulsio/vuls-data-raw-vulncheck-kev/archive/refs/heads/main.tar.gz")
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch vulsio/vuls-data-raw-vulncheck-kev. err: %w", err)
	}

	var vs []models.VulnCheck

	gr, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, xerrors.Errorf("Failed to new gzip reader. err: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf("Failed to next tar reader. err: %w", err)
		}

		if hdr.FileInfo().IsDir() || filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		var v vulncheck
		if err := json.NewDecoder(tr).Decode(&v); err != nil {
			return nil, xerrors.Errorf("Failed to decode %s", hdr.Name)
		}

		vs = append(vs, models.VulnCheck{
			VendorProject:              v.VendorProject,
			Product:                    v.Product,
			Description:                v.Description,
			Name:                       v.Name,
			RequiredAction:             v.RequiredAction,
			KnownRansomwareCampaignUse: v.KnownRansomwareCampaignUse,

			CVE: func() []models.VulnCheckCVE {
				cs := make([]models.VulnCheckCVE, 0, len(v.CVE))
				for _, c := range v.CVE {
					cs = append(cs, models.VulnCheckCVE{
						CveID: c,
					})
				}
				return cs
			}(),

			VulnCheckXDB: func() []models.VulnCheckXDB {
				xs := make([]models.VulnCheckXDB, 0, len(v.VulnCheckXDB))
				for _, x := range v.VulnCheckXDB {
					xs = append(xs, models.VulnCheckXDB{
						XDBID:       x.XDBID,
						XDBURL:      x.XDBURL,
						DateAdded:   x.DateAdded,
						ExploitType: x.ExploitType,
						CloneSSHURL: x.CloneSSHURL,
					})
				}
				return xs
			}(),
			VulnCheckReportedExploitation: func() []models.VulnCheckReportedExploitation {
				es := make([]models.VulnCheckReportedExploitation, 0, len(v.VulnCheckReportedExploitation))
				for _, e := range v.VulnCheckReportedExploitation {
					es = append(es, models.VulnCheckReportedExploitation{
						URL:       e.URL,
						DateAdded: e.DateAdded,
					})
				}
				return es
			}(),

			DueDate:       v.DueDate,
			CisaDateAdded: v.CisaDateAdded,
			DateAdded:     v.DateAdded,
		})
	}
	return vs, nil
}
