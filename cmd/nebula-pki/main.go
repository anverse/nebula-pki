// Command nebula-pki is the declarative wrapper around nebula-cert.
//
// This binary is a thin entrypoint: all command wiring lives in
// internal/cli so it can be unit-tested without spawning processes.
package main

import (
	"fmt"
	"os"

	"github.com/anverse/nebula-pki/internal/cli"
)

func main() {
	root := cli.New(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
