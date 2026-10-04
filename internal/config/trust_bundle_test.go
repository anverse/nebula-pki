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
	if len(cfg.TrustBundles) != 1 {
		t.Fatalf("TrustBundles = %+v, want the declared block", cfg.TrustBundles)
	}
	tb := cfg.TrustBundles[0]
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
	if len(cfg.TrustBundles) != 0 {
		t.Fatalf("TrustBundles = %+v, want none without a trust_bundle block", cfg.TrustBundles)
	}
}

func TestTrustBundle_NonMemberCAMaySign(t *testing.T) {
	// Bundles do not restrict signing (ADR-026 §3): the default CA and a
	// cert's explicit CA may both be outside every bundle.
	cfg := mustParse(t, "t.hcl", `
trust_bundle "main" { ca_refs = [ca.next] }
ca "current" {
  name    = "old"
  default = true
}
ca "next" { name = "new" }
ca "solo" { name = "solo" }
cert "alpha" { networks = ["10.0.0.1/16"] }
cert "beta" {
  ca       = ca.solo
  networks = ["10.0.0.2/16"]
}
`)
	if got := cfg.SigningCA(cfg.Certs[0]); got == nil || got.Label != "current" {
		t.Errorf("SigningCA(alpha) = %v, want current", got)
	}
	if got := cfg.SigningCA(cfg.Certs[1]); got == nil || got.Label != "solo" {
		t.Errorf("SigningCA(beta) = %v, want solo", got)
	}
}

func TestTrustBundle_Multiple(t *testing.T) {
	cfg := mustParse(t, "t.hcl", `
trust_bundle "lighthouses" { ca_refs = [ca.a, ca.b] }
trust_bundle "clients" { ca_refs = [ca.b] }
ca "a" { name = "a" }
ca "b" {
  name    = "b"
  default = true
}
`)
	if len(cfg.TrustBundles) != 2 {
		t.Fatalf("TrustBundles = %d, want 2", len(cfg.TrustBundles))
	}
	if tb := cfg.TrustBundleByLabel("clients"); tb == nil || !reflect.DeepEqual(tb.CARefs, []string{"b"}) {
		t.Errorf("TrustBundleByLabel(clients) = %+v, want members [b]", tb)
	}
	if cfg.TrustBundleByLabel("missing") != nil {
		t.Error("TrustBundleByLabel(missing) != nil")
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
			name: "duplicate bundle label",
			src: `
trust_bundle "main" { ca_refs = [ca.a] }
trust_bundle "main" { ca_refs = [ca.a] }
ca "a" { name = "a" }
`,
			want: `trust_bundle "main": duplicate label`,
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

func TestArtifactPaths_Collisions(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string // empty: valid
	}{
		{
			name: "ca vs ca symlink",
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
			want: `path out/shared/ca.crt is used by ca "one" (link_crt) and ca "two" (link_crt)`,
		},
		{
			name: "three owners",
			src: `
trust_bundle "main" {
  ca_refs  = [ca.a]
  link_crt = ["out/s"]
}
ca "a" {
  name     = "a"
  default  = true
  out_crt  = "out/a/main.crt"
  out_key  = "out/a/main.key"
  link_crt = ["out/s"]
}
ca "b" {
  name     = "b"
  out_crt  = "out/b/main.crt"
  out_key  = "out/b/main.key"
  link_crt = ["out/s"]
}
`,
			want: `path out/s/main.crt is used by ca "a" (link_crt), ca "b" (link_crt) and trust_bundle "main" (link_crt)`,
		},
		{
			name: "cleaned directories collide",
			src: `
trust_bundle "main" {
  ca_refs  = [ca.main]
  link_crt = ["out/shared/"]
}
ca "main" {
  name     = "a"
  link_crt = ["./out/shared"]
}
`,
			want: `path out/shared/main.crt is used by ca "main" (link_crt) and trust_bundle "main" (link_crt)`,
		},
		{
			name: "same source spelled twice",
			src: `
ca "a" {
  name     = "a"
  link_crt = ["out/shared", "out/shared/"]
}
`,
			want: `path out/shared/a.crt is used by ca "a" (link_crt) and ca "a" (link_crt)`,
		},
		{
			name: "bundle onto ca cert",
			src: `
trust_bundle "main" {
  ca_refs = [ca.a]
  path    = "out/ca/a.crt"
}
ca "a" { name = "a" }
`,
			want: `path out/ca/a.crt is used by ca "a" (cert) and trust_bundle "main" (path)`,
		},
		{
			name: "bundle symlink onto its own file",
			src: `
trust_bundle "main" {
  ca_refs  = [ca.a]
  link_crt = ["out/bundles"]
}
ca "a" { name = "a" }
`,
			want: `path out/bundles/main.crt is used by trust_bundle "main" (path) and trust_bundle "main" (link_crt)`,
		},
		{
			name: "ca symlink onto its own cert",
			src: `
ca "a" {
  name     = "a"
  link_crt = ["out/ca"]
}
`,
			want: `path out/ca/a.crt is used by ca "a" (cert) and ca "a" (link_crt)`,
		},
		{
			name: "bundle onto referenced cert_file",
			src: `
trust_bundle "main" {
  ca_refs = [ca.r]
  path    = "ref/ca.crt"
}
ca "r" {
  cert_file = "ref/ca.crt"
  key_file  = "ref/ca.key"
}
`,
			want: `path ref/ca.crt is used by ca "r" (cert_file) and trust_bundle "main" (path)`,
		},
		{
			name: "two reference cas may share input files",
			src: `
ca "r1" {
  cert_file = "ref/ca.crt"
  key_file  = "ref/ca.key"
  default   = true
}
ca "r2" {
  cert_file = "ref/ca.crt"
  key_file  = "ref/ca.key"
}
`,
		},
		{
			name: "cert onto ca cert",
			src: `
ca "a" { name = "a" }
cert "a" {
  networks   = ["10.0.0.1/16"]
  output_dir = "out/ca"
}
`,
			want: `path out/ca/a.crt is used by ca "a" (cert) and cert "a" (cert)`,
		},
		{
			name: "encrypted key suffix compared",
			src: `
ca "a" {
  name    = "a"
  out_key = "out/x.key"
}
cert "c" {
  networks   = ["10.0.0.1/16"]
  output_dir = "out"
  out_key    = "x.key"
}
storage {
  encryption "external" {
    encrypt_command = ["cat"]
    decrypt_command = ["cat"]
    output_suffix   = ".enc"
  }
}
`,
			want: `path out/x.key.enc is used by ca "a" (key) and cert "c" (key)`,
		},
		{
			name: "bundle onto manifest",
			src: `
trust_bundle "main" {
  ca_refs = [ca.a]
  path    = "out/nebula-pki.json"
}
ca "a" { name = "a" }
`,
			want: `path out/nebula-pki.json is used by trust_bundle "main" (path) and storage (manifest_file)`,
		},
		{
			name: "two bundles writing one file",
			src: `
trust_bundle "x" {
  ca_refs = [ca.a]
  path    = "out/t.crt"
}
trust_bundle "y" {
  ca_refs = [ca.a]
  path    = "out/t.crt"
}
ca "a" { name = "a" }
`,
			want: `path out/t.crt is used by trust_bundle "x" (path) and trust_bundle "y" (path)`,
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
