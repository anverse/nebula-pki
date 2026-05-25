package e2e

import (
	"fmt"
	"os"

	"github.com/anverse/nebula-pki/internal/cli"
)

// nebulaPkiMain is registered with testscript.RunMain so scripts can
// invoke `nebula-pki ...` against the in-process binary. Mirrors the
// behaviour of cmd/nebula-pki/main.go so testscript scenarios observe
// the same stdout/stderr/exit-code surface that real users see.
func nebulaPkiMain() int {
	root := cli.New(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}
