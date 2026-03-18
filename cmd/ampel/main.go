package main

import (
	"os"

	"github.com/carabiner-labs/ampel-stable/internal/cmd"
)

func main() {
	cmdline := cmd.New()
	if err := cmdline.Execute(); err != nil {
		os.Exit(1)
	}
}
