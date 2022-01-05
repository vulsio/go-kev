package convert

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/go-kev/utils"
	"golang.org/x/xerrors"
)

// ConvertCmd :
var ConvertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert the data of vulnerabilities",
	Long:  `Convert the data of vulnerabilities`,
}

func init() {
	// subcommands
	ConvertCmd.AddCommand(convertKEVulnCmd)

	// flags
	ConvertCmd.PersistentFlags().String("vuln-dir", utils.GetDefaultVulnDir(), "root directory to output Vuln data")
}

func setLastUpdatedDate(key string) error {
	lastUpdatedFilePath := filepath.Join(filepath.Dir(filepath.Clean(viper.GetString("vuln-dir"))), "last_updated.json")
	f, err := os.OpenFile(lastUpdatedFilePath, os.O_CREATE|os.O_RDWR, 0664)
	if err != nil {
		return xerrors.Errorf("Failed to open last updated file. err: %w", err)
	}

	lastUpdated := map[string]time.Time{}
	if err := json.NewDecoder(f).Decode(&lastUpdated); err != nil {
		if !errors.Is(err, io.EOF) {
			_ = f.Close() // ignore error; Write error takes precedence
			return xerrors.Errorf("Failed to decode last updated file. err: %w", err)
		}
	}
	lastUpdated[key] = time.Now()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err = enc.Encode(lastUpdated); err != nil {
		_ = f.Close() // ignore error; Write error takes precedence
		return xerrors.Errorf("Failed to encode last updated file. err: %w", err)
	}

	if err := f.Close(); err != nil {
		return xerrors.Errorf("Failed to close last updated file. err: %w", err)
	}

	return nil
}
