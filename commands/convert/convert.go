package convert

import (
	"github.com/spf13/cobra"
	"github.com/vulsio/go-kev/utils"
)

// ConvertCmd :
var ConvertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert the data of vulnerabilities",
	Long:  `Convert the data of vulnerabilities`,
}

func init() {
	// subcommands
	ConvertCmd.AddCommand(convertCatalogCmd)

	// flags
	ConvertCmd.PersistentFlags().String("vuln-dir", utils.GetDefaultVulnDir(), "root directory to output Vuln data")
}
