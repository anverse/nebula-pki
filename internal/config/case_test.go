package config

import (
	"strings"
	"testing"
)

// TestLabels_UniqueIgnoringCase checks that labels within one block group,
// and cert names, must be unique ignoring case: they name files, and on a
// case-insensitive filesystem "main" and "Main" are one file.
func TestLabels_UniqueIgnoringCase(t *testing.T) {
	tests := []struct{ name, src, want string }{
		{
			name: "ca labels differ only in case",
			src: `
ca "mesh" {
  name    = "mesh"
  default = true
}
ca "Mesh" { name = "mesh2" }
`,
			want: `ca "Mesh": label differs only in case from ca "mesh"; labels must be unique ignoring case`,
		},
		{
			name: "trust_bundle labels differ only in case",
			src: `
ca "a" { name = "a" }
trust_bundle "main" { ca_refs = [ca.a] }
trust_bundle "Main" { ca_refs = [ca.a] }
`,
			want: `trust_bundle "Main": label differs only in case from trust_bundle "main"; labels must be unique ignoring case`,
		},
		{
			name: "cert labels differ only in case",
			src: `
ca "a" { name = "a" }
cert "app" {
  networks = ["10.0.0.1/16"]
  name     = "one"
}
cert "APP" {
  networks = ["10.0.0.2/16"]
  name     = "two"
}
`,
			want: `cert "APP": label differs only in case from cert "app"; labels must be unique ignoring case`,
		},
		{
			name: "cert names differ only in case",
			src: `
ca "a" { name = "a" }
cert "a" {
  networks = ["10.0.0.1/16"]
  name     = "app"
}
cert "b" {
  networks = ["10.0.0.2/16"]
  name     = "App"
}
`,
			want: `cert "b": certificate name "App" differs only in case from the name "app" of cert "a"; names must be unique ignoring case`,
		},
		{
			name: "cert name defaulted from label differs only in case",
			src: `
ca "a" { name = "a" }
cert "node" { networks = ["10.0.0.1/16"] }
cert "other" {
  networks = ["10.0.0.2/16"]
  name     = "Node"
}
`,
			want: `cert "other": certificate name "Node" differs only in case from the name "node" of cert "node"`,
		},
		// Exact repeats keep their own messages.
		{
			name: "exact duplicate ca label",
			src: `
ca "a" { name = "a" }
ca "a" { name = "b" }
`,
			want: `ca "a": duplicate label`,
		},
		{
			name: "exact duplicate trust_bundle label",
			src: `
ca "a" { name = "a" }
trust_bundle "main" { ca_refs = [ca.a] }
trust_bundle "main" { ca_refs = [ca.a] }
`,
			want: `trust_bundle "main": duplicate label`,
		},
		{
			name: "exact duplicate cert name",
			src: `
ca "a" { name = "a" }
cert "x" {
  networks = ["10.0.0.1/16"]
  name     = "app"
}
cert "y" {
  networks = ["10.0.0.2/16"]
  name     = "app"
}
`,
			want: `cert "y": certificate name "app" already used by cert "x"`,
		},
		// The same label in different groups names different files.
		{
			name: "same label across groups",
			src: `
ca "main" { name = "main" }
trust_bundle "main" { ca_refs = [ca.main] }
cert "main" { networks = ["10.0.0.1/16"] }
`,
		},
		// References stay exact-case.
		{
			name: "reference differing in case is not declared",
			src: `
ca "main" { name = "main" }
cert "c" {
  networks = ["10.0.0.1/16"]
  ca       = ca.Main
}
`,
			want: `ca "Main" is not declared`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("t.hcl", []byte(tt.src))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.want)
			}
		})
	}
}

// TestArtifactPaths_UniqueIgnoringCase checks that written paths differing
// only in case clash, whichever field produces them.
func TestArtifactPaths_UniqueIgnoringCase(t *testing.T) {
	tests := []struct{ name, src, want string }{
		{
			name: "bundle paths",
			src: `
ca "a" { name = "a" }
trust_bundle "x" {
  ca_refs = [ca.a]
  path    = "out/T.crt"
}
trust_bundle "y" {
  ca_refs = [ca.a]
  path    = "out/t.crt"
}
`,
			want: `path out/T.crt is used by trust_bundle "x" (path) and trust_bundle "y" (path)`,
		},
		{
			name: "ca out_crt and cert out_crt",
			src: `
ca "a" {
  name    = "a"
  out_crt = "out/Shared.crt"
}
cert "c" {
  networks   = ["10.0.0.1/16"]
  output_dir = "out"
  out_crt    = "shared.crt"
}
`,
			want: `path out/Shared.crt is used by ca "a" (cert) and cert "c" (cert)`,
		},
		{
			name: "link_crt directories in one list",
			src: `
ca "a" {
  name     = "a"
  link_crt = ["out/L", "out/l"]
}
`,
			want: `ca "a": link_crt[1]: duplicate directory "out/l"`,
		},
		{
			name: "link_crt symlinks across blocks",
			src: `
ca "main" {
  name     = "main"
  link_crt = ["out/Shared"]
}
trust_bundle "main" {
  ca_refs  = [ca.main]
  link_crt = ["out/shared"]
}
`,
			want: `path out/Shared/main.crt is used by ca "main" (link_crt) and trust_bundle "main" (link_crt)`,
		},
		{
			name: "file used as directory, differing in case",
			src: `
ca "a" { name = "a" }
trust_bundle "main" {
  ca_refs = [ca.a]
  path    = "out/Certs"
}
cert "c" { networks = ["10.0.0.1/16"] }
`,
			want: `path out/Certs is a file for trust_bundle "main" (path) but a directory holding out/certs/c.crt for cert "c" (cert)`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("t.hcl", []byte(tt.src))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.want)
			}
		})
	}
}
