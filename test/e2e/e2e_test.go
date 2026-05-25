// Package e2e runs testscript scenarios against the nebula-pki binary.
//
// Scenarios live in testdata/script/*.txtar. Each scenario invokes
// `nebula-pki` (the binary built and registered by TestMain) and asserts
// stdout/stderr, exit codes, and filesystem state.
package e2e

import (
	"os"
	"testing"

	"github.com/anverse/nebula-pki/internal/buildinfo"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	// Pin the version that the in-process binary reports so scripts can
	// assert against a known string instead of whatever ldflags injected
	// into the real build.
	buildinfo.Version = "v0.0.1-test"
	buildinfo.Commit = "testcommit"
	buildinfo.Date = "1970-01-01T00:00:00Z"

	os.Exit(testscript.RunMain(m, map[string]func() int{
		"nebula-pki": nebulaPkiMain,
	}))
}

func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
	})
}
