package main

import (
	"fmt"
	"os"

	"github.com/vulsio/go-kev/commands"
)

func main() {
	if err := commands.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}
