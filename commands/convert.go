package commands

import (
	"github.com/spf13/cobra"
	"github.com/vulsio/go-kev/utils"
)

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert the data of vulnerabilities",
	Long:  `Convert the data of vulnerabilities`,
}

func init() {
	RootCmd.AddCommand(convertCmd)

	convertCmd.PersistentFlags().String("vuln-dir", utils.GetDefaultVulnDir(), "root directory to output Vuln data")
}
