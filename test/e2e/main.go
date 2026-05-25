package e2e

import (
	"github.com/anverse/nebula-pki/internal/cli"
	"os"
)

// nebulaPkiMain is registered with testscript.RunMain so scripts can
// invoke `nebula-pki ...` against the in-process binary.
func nebulaPkiMain() int {
	root := cli.New(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		return 1
	}
	return 0
}
