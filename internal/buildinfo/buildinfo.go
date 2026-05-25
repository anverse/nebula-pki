// Package buildinfo carries release metadata injected at build time via
// -ldflags. Defaults are placeholders used by `go build` without ldflags
// (developer builds) and by `go test`.
package buildinfo

// These values are overridden by -ldflags="-X ..." in release builds.
// See .goreleaser.yaml and taskfile.yml.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns the canonical one-line representation used by `--version`.
//
// Format: "<version> <commit> <date>"
func String() string {
	return Version + " " + Commit + " " + Date
}
