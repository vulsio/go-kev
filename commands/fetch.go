package commands

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the data of vulnerabilities",
	Long:  `Fetch the data of vulnerabilities`,
}

func init() {
	RootCmd.AddCommand(fetchCmd)

	fetchCmd.PersistentFlags().Bool("debug-sql", false, "SQL debug mode")
	fetchCmd.PersistentFlags().String("dbpath", filepath.Join(os.Getenv("PWD"), "go-kev.sqlite3"), "/path/to/sqlite3 or SQL connection string")
	fetchCmd.PersistentFlags().String("dbtype", "sqlite3", "Database type to store data in (sqlite3, mysql, postgres or redis supported)")
	fetchCmd.PersistentFlags().Int("batch-size", 50, "The number of batch size to insert.")
}
