package vulncheck

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/xerrors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/vulsio/go-kev/models"
)

// Fetch :
func Fetch() ([]models.VulnCheck, error) {
	dir, err := os.MkdirTemp("", "go-kev")
	if err != nil {
		return nil, xerrors.Errorf("Failed to create temp directory. err: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := fetch(dir); err != nil {
		return nil, xerrors.Errorf("Failed to fetch vuls-data-raw-vulncheck-kev. err: %w", err)
	}

	var vs []models.VulnCheck

	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("Failed to open %s. err: %w", path, err)
		}
		defer f.Close()

		var v vulncheck
		if err := json.NewDecoder(f).Decode(&v); err != nil {
			return xerrors.Errorf("Failed to decode %s", path)
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
						XDBID:  x.XDBID,
						XDBURL: x.XDBURL,
						DateAdded: func() time.Time {
							if x.DateAdded.Equal(time.Time{}) {
								return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
							}
							return x.DateAdded
						}(),
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
						URL: e.URL,
						DateAdded: func() time.Time {
							if e.DateAdded.Equal(time.Time{}) {
								return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
							}
							return e.DateAdded
						}(),
					})
				}
				return es
			}(),

			DueDate: func() *time.Time {
				if v.DueDate == nil || (*v.DueDate).Equal(time.Time{}) {
					return nil
				}
				return v.DueDate
			}(),
			CisaDateAdded: func() *time.Time {
				if v.CisaDateAdded == nil || (*v.CisaDateAdded).Equal(time.Time{}) {
					return nil
				}
				return v.CisaDateAdded
			}(),
			DateAdded: func() time.Time {
				if v.DateAdded.Equal(time.Time{}) {
					return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
				}
				return v.DateAdded
			}(),
		})

		return nil
	}); err != nil {
		return nil, xerrors.Errorf("Failed to walk %s. err: %w", dir, err)
	}

	return vs, nil
}

func fetch(dir string) error {
	ctx := context.TODO()
	repo, err := remote.NewRepository("ghcr.io/vulsio/vuls-data-db:vuls-data-raw-vulncheck-kev")
	if err != nil {
		return xerrors.Errorf("Failed to create client for ghcr.io/vulsio/vuls-data-db:vuls-data-raw-vulncheck-kev. err: %w", err)
	}

	_, r, err := oras.Fetch(ctx, repo, repo.Reference.Reference, oras.DefaultFetchOptions)
	if err != nil {
		return xerrors.Errorf("Failed to fetch manifest. err: %w", err)
	}
	defer r.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(r).Decode(&manifest); err != nil {
		return xerrors.Errorf("Failed to decode manifest. err: %w", err)
	}

	l := func() *ocispec.Descriptor {
		for _, l := range manifest.Layers {
			if l.MediaType == "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd" {
				return &l
			}
		}
		return nil
	}()
	if l == nil {
		return xerrors.Errorf("Failed to find digest and filename from layers, actual layers: %#v", manifest.Layers)
	}

	r, err = repo.Fetch(ctx, *l)
	if err != nil {
		return xerrors.Errorf("Failed to fetch content. err: %w", err)
	}
	defer r.Close()

	zr, err := zstd.NewReader(r)
	if err != nil {
		return xerrors.Errorf("Failed to new zstd reader. err: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.Errorf("Failed to next tar reader. err: %w", err)
		}

		p := filepath.Join(dir, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0755); err != nil {
				return xerrors.Errorf("Failed to mkdir %s. err: %w", p, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				return xerrors.Errorf("Failed to mkdir %s. err: %w", p, err)
			}

			if err := func() error {
				f, err := os.Create(p)
				if err != nil {
					return xerrors.Errorf("Failed to create %s. err: %w", p, err)
				}
				defer f.Close()

				if _, err := io.Copy(f, tr); err != nil {
					return xerrors.Errorf("Failed to copy to %s. err: %w", p, err)
				}

				return nil
			}(); err != nil {
				return xerrors.Errorf("Failed to create %s. err: %w", p, err)
			}
		}
	}

	cmd := exec.Command("git", "-C", filepath.Join(dir, "vuls-data-raw-vulncheck-kev"), "restore", ".")
	if err := cmd.Run(); err != nil {
		return xerrors.Errorf("Failed to exec %q. err: %w", cmd.String(), err)
	}

	return nil
}
