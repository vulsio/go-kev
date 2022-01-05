package fetch

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// FetchCmd :
var FetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the data of vulnerabilities",
	Long:  `Fetch the data of vulnerabilities`,
}

func init() {
	// subcommands
	FetchCmd.AddCommand(fetchKEVulnCmd)

	// flags
	FetchCmd.PersistentFlags().Bool("debug-sql", false, "SQL debug mode")
	FetchCmd.PersistentFlags().String("dbpath", filepath.Join(os.Getenv("PWD"), "go-kev.sqlite3"), "/path/to/sqlite3 or SQL connection string")
	FetchCmd.PersistentFlags().String("dbtype", "sqlite3", "Database type to store data in (sqlite3, mysql, postgres or redis supported)")
	FetchCmd.PersistentFlags().Int("batch-size", 50, "The number of batch size to insert.")
}
