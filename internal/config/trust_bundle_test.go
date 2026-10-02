package config

// Tests for the trust_bundle block (ADR-026).

import (
	"reflect"
	"strings"
	"testing"
)

func TestTrustBundle_Decoded(t *testing.T) {
	cfg := mustParse(t, "t.hcl", `
trust_bundle "main" {
  ca_refs  = [ca.next, ca.current]
  path     = "out/trust.crt"
  link_crt = ["out/a", "out/b"]
}
ca "current" { name = "old" }
ca "next" {
  name    = "new"
  default = true
}
`)
	tb := cfg.TrustBundle
	if tb == nil {
		t.Fatal("TrustBundle = nil, want the declared block")
	}
	if tb.Label != "main" {
		t.Errorf("Label = %q, want main", tb.Label)
	}
	if want := []string{"next", "current"}; !reflect.DeepEqual(tb.CARefs, want) {
		t.Errorf("CARefs = %v, want %v (declaration order)", tb.CARefs, want)
	}
	if tb.Path != "out/trust.crt" {
		t.Errorf("Path = %q, want out/trust.crt", tb.Path)
	}
	if want := []string{"out/a", "out/b"}; !reflect.DeepEqual(tb.LinkCrt, want) {
		t.Errorf("LinkCrt = %v, want %v", tb.LinkCrt, want)
	}
	if !tb.Has("current") || tb.Has("other") {
		t.Error("Has() does not reflect membership")
	}
}

func TestTrustBundle_NoBlockMeansNoBundle(t *testing.T) {
	cfg := mustParse(t, "t.hcl", `
ca "current" {
  name    = "old"
  default = true
}
ca "next" { name = "new" }
cert "alpha" {
  ca       = ca.next
  networks = ["10.0.0.1/16"]
}
`)
	if cfg.TrustBundle != nil {
		t.Fatalf("TrustBundle = %+v, want nil without a trust_bundle block", cfg.TrustBundle)
	}
}

func TestTrustBundle_NonMemberCAIsValid(t *testing.T) {
	cfg := mustParse(t, "t.hcl", `
trust_bundle "main" { ca_refs = [ca.next] }
ca "current" { name = "old" }
ca "next" {
  name    = "new"
  default = true
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	if got := cfg.SigningCA(cfg.Certs[0]); got == nil || got.Label != "next" {
		t.Errorf("SigningCA = %v, want next", got)
	}
}

func TestTrustBundle_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "duplicate member",
			src: `
trust_bundle "main" { ca_refs = [ca.a, ca.a] }
ca "a" { name = "a" }
`,
			want: `t.hcl:2,40-44: trust_bundle "main": ca_refs[1]: duplicate member ca "a"`,
		},
		{
			name: "dangling reference",
			src: `
trust_bundle "main" { ca_refs = [ca.b] }
ca "a" { name = "a" }
`,
			want: `t.hcl:2,34-38: trust_bundle "main": ca_refs[0]: ca "b" is not declared`,
		},
		{
			name: "string element",
			src: `
trust_bundle "main" { ca_refs = ["a"] }
ca "a" { name = "a" }
`,
			want: `t.hcl:2,34-37: trust_bundle "main": ca_refs[0] must be a CA reference of the form ca.<label>`,
		},
		{
			name: "index form",
			src: `
trust_bundle "main" { ca_refs = [ca["a"]] }
ca "a" { name = "a" }
`,
			want: `trust_bundle "main": ca_refs[0] must be a CA reference of the form ca.<label>`,
		},
		{
			name: "null element",
			src: `
trust_bundle "main" { ca_refs = [null] }
ca "a" { name = "a" }
`,
			want: `trust_bundle "main": ca_refs[0] must be a CA reference of the form ca.<label>`,
		},
		{
			name: "foreign root",
			src: `
trust_bundle "main" { ca_refs = [cert.a] }
ca "a" { name = "a" }
`,
			want: `trust_bundle "main": ca_refs[0]: unknown reference root "cert"`,
		},
		{
			name: "empty list",
			src: `
trust_bundle "main" { ca_refs = [] }
ca "a" { name = "a" }
`,
			want: `trust_bundle "main": ca_refs must list at least one CA`,
		},
		{
			name: "not a list",
			src: `
trust_bundle "main" { ca_refs = ca.a }
ca "a" { name = "a" }
`,
			want: `trust_bundle "main": ca_refs must be a list of ca.<label> references`,
		},
		{
			name: "missing ca_refs",
			src: `
trust_bundle "main" {}
ca "a" { name = "a" }
`,
			want: `t.hcl:2,1-20: trust_bundle "main": missing required argument ca_refs`,
		},
		{
			name: "two blocks",
			src: `
trust_bundle "main" { ca_refs = [ca.a] }
trust_bundle "other" { ca_refs = [ca.a] }
ca "a" { name = "a" }
`,
			want: `t.hcl:3,1-21: trust_bundle "other": only one trust_bundle block is allowed`,
		},
		{
			name: "bad label",
			src: `
trust_bundle "1bad" { ca_refs = [ca.a] }
ca "a" { name = "a" }
`,
			want: `trust_bundle "1bad": label must match`,
		},
		{
			name: "non-member default",
			src: `
trust_bundle "main" { ca_refs = [ca.a] }
ca "a" { name = "a" }
ca "b" {
  name    = "b"
  default = true
}
`,
			want: `ca "b": default = true requires the CA to be in trust_bundle "main" ca_refs`,
		},
		{
			name: "non-member signing CA via reference",
			src: `
trust_bundle "main" { ca_refs = [ca.a] }
ca "a" {
  name    = "a"
  default = true
}
ca "b" { name = "b" }
cert "x" {
  ca       = ca.b
  networks = ["10.0.0.1/16"]
}
`,
			want: `t.hcl:9,14-18: cert "x": ca "b" is not in trust_bundle "main" ca_refs and may not sign certs`,
		},
		{
			name: "removed archived field",
			src: `
ca "a" {
  name     = "a"
  archived = true
}
`,
			want: `Unsupported argument`,
		},
		{
			name: "removed trust_bundle_file field",
			src: `
ca "a" { name = "a" }
storage { trust_bundle_file = "x.crt" }
`,
			want: `Unsupported argument`,
		},
		{
			name: "empty bundle link_crt entry",
			src: `
trust_bundle "main" {
  ca_refs  = [ca.a]
  link_crt = [""]
}
ca "a" { name = "a" }
`,
			want: `trust_bundle "main": link_crt[0]: directory path must not be empty`,
		},
		{
			name: "duplicate bundle link_crt entry",
			src: `
trust_bundle "main" {
  ca_refs  = [ca.a]
  link_crt = ["out/x", "out/x"]
}
ca "a" { name = "a" }
`,
			want: `trust_bundle "main": link_crt[1]: duplicate directory "out/x"`,
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

func TestLinkPaths_Collisions(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string // empty: valid
	}{
		{
			name: "ca vs ca",
			src: `
ca "one" {
  name     = "one"
  default  = true
  out_crt  = "out/one/ca.crt"
  out_key  = "out/one/ca.key"
  link_crt = ["out/shared"]
}
ca "two" {
  name     = "two"
  out_crt  = "out/two/ca.crt"
  out_key  = "out/two/ca.key"
  link_crt = ["out/shared"]
}
`,
			want: `link_crt: ca "one" and ca "two" both write symlink out/shared/ca.crt`,
		},
		{
			name: "ca vs bundle",
			src: `
trust_bundle "main" {
  ca_refs  = [ca.a]
  link_crt = ["out/shared"]
}
ca "a" {
  name     = "a"
  out_crt  = "out/x/bundle.crt"
  out_key  = "out/x/bundle.key"
  link_crt = ["out/shared"]
}
`,
			want: `link_crt: ca "a" and trust_bundle "main" both write symlink out/shared/bundle.crt`,
		},
		{
			name: "bundle vs ca",
			src: `
trust_bundle "main" {
  ca_refs  = [ca.a]
  path     = "out/trust/a.crt"
  link_crt = ["out/shared"]
}
ca "a" {
  name     = "a"
  link_crt = ["out/shared"]
}
`,
			want: `link_crt: ca "a" and trust_bundle "main" both write symlink out/shared/a.crt`,
		},
		{
			name: "cleaned directories collide",
			src: `
trust_bundle "main" {
  ca_refs  = [ca.a]
  link_crt = ["out/shared/"]
}
ca "a" {
  name     = "a"
  out_crt  = "out/x/bundle.crt"
  out_key  = "out/x/bundle.key"
  link_crt = ["./out/shared"]
}
`,
			want: `link_crt: ca "a" and trust_bundle "main" both write symlink out/shared/bundle.crt`,
		},
		{
			name: "same source spelled twice",
			src: `
ca "a" {
  name     = "a"
  link_crt = ["out/shared", "out/shared/"]
}
`,
			want: `ca "a": link_crt: directory "out/shared/" repeats another entry`,
		},
		{
			name: "shared directory with different file names",
			src: `
trust_bundle "main" {
  ca_refs  = [ca.a]
  link_crt = ["out/shared"]
}
ca "a" {
  name     = "a"
  link_crt = ["out/shared"]
}
`,
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
