package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// minimalGenerate is the smallest HCL that should parse cleanly in
// generate mode. Tests append/override on top of this.
const minimalGenerate = `
ca {
  name = "test-mesh"
}
`

func TestParse_MinimalGenerateMode(t *testing.T) {
	cfg, err := Parse("test.hcl", []byte(minimalGenerate))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := cfg.CA.Mode, CAModeGenerate; got != want {
		t.Errorf("CA.Mode = %v, want %v", got, want)
	}
	if got, want := cfg.CA.Name, "test-mesh"; got != want {
		t.Errorf("CA.Name = %q, want %q", got, want)
	}
	if got, want := cfg.Storage.OutDir, "out"; got != want {
		t.Errorf("Storage.OutDir = %q, want %q", got, want)
	}
	if got, want := cfg.Storage.ManifestFile, "out/nebula-pki.json"; got != want {
		t.Errorf("Storage.ManifestFile = %q, want %q", got, want)
	}
}

func TestParse_ReferenceMode(t *testing.T) {
	src := `
ca {
  cert_file = "/path/ca.crt"
  key_file  = "/path/ca.key"
}
`
	cfg, err := Parse("test.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := cfg.CA.Mode, CAModeReference; got != want {
		t.Errorf("CA.Mode = %v, want %v", got, want)
	}
}

func TestParse_FullSurface(t *testing.T) {
	src := `
ca {
  name             = "full-mesh"
  duration         = "26280h"
  version          = 2
  curve            = "25519"
  groups           = ["lighthouse", "app"]
  networks         = ["10.42.0.0/16"]
  unsafe_networks  = ["192.168.0.0/16"]
  encrypt          = true
  argon_memory     = 1024
  argon_iterations = 2
  argon_parallelism = 3
  out_crt          = "ca/ca.crt"
  out_key          = "ca/ca.key"
}

storage {
  out_dir       = "build"
  manifest_file = "build/manifest.json"
}

host "edge" {
  name            = "edge.mesh"
  networks        = ["10.42.1.1/16"]
  groups          = ["app"]
  unsafe_networks = ["192.168.10.0/24"]
  duration        = "1h"
  output_dir      = "a"
  out_qr          = "yes"
  in_pub          = "edge.pub"
}
`
	cfg, err := Parse("test.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CA.Duration != 26280*time.Hour {
		t.Errorf("CA.Duration = %v", cfg.CA.Duration)
	}
	if len(cfg.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(cfg.Hosts))
	}
	h := cfg.Hosts[0]
	if h.Label != "edge" || h.Name != "edge.mesh" {
		t.Errorf("Label=%q Name=%q", h.Label, h.Name)
	}
	if got, want := cfg.Storage.ManifestFile, "build/manifest.json"; got != want {
		t.Errorf("ManifestFile = %q, want %q", got, want)
	}
}

func TestParse_HostNameDefaultsToLabel(t *testing.T) {
	src := minimalGenerate + `
host "alpha" {
  networks = ["10.0.0.1/16"]
}
`
	cfg, err := Parse("test.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := cfg.Hosts[0].Name, "alpha"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
}

// TestParse_ValidationRules walks every rule listed in
// spec/hcl-schema.md#validation-rules and confirms it fires.
func TestParse_ValidationRules(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr string // substring
	}{
		{
			name:    "missing_ca_block",
			src:     `host "a" { networks = ["10.0.0.1/16"] }`,
			wantErr: "missing required `ca` block",
		},
		{
			name: "duplicate_host_label",
			src: minimalGenerate + `
host "a" { networks = ["10.0.0.1/16"] }
host "a" { networks = ["10.0.0.2/16"] }
`,
			wantErr: "duplicate label",
		},
		{
			name: "duplicate_host_name",
			src: minimalGenerate + `
host "a" {
  name = "shared"
  networks = ["10.0.0.1/16"]
}
host "b" {
  name = "shared"
  networks = ["10.0.0.2/16"]
}
`,
			wantErr: "certificate name \"shared\" already used",
		},
		{
			name: "duplicate_overlay_address",
			src: minimalGenerate + `
host "a" { networks = ["10.0.0.1/16"] }
host "b" { networks = ["10.0.0.1/24"] }
`,
			wantErr: "overlay address 10.0.0.1 already used",
		},
		{
			name: "invalid_cidr",
			src: minimalGenerate + `
host "a" { networks = ["not-a-cidr"] }
`,
			wantErr: "invalid CIDR",
		},
		{
			name: "reference_mode_half_set",
			src: `
ca { cert_file = "x" }
`,
			wantErr: "reference mode requires both",
		},
		{
			name: "reference_mode_with_generate_field",
			src: `
ca {
  cert_file = "ca.crt"
  key_file  = "ca.key"
  duration  = "1h"
}
`,
			wantErr: "generate-only fields",
		},
		{
			name: "host_group_not_in_ca_groups",
			src: `
ca {
  name   = "m"
  groups = ["app"]
}
host "a" {
  networks = ["10.0.0.1/16"]
  groups   = ["app", "rogue"]
}
`,
			wantErr: "not permitted by ca.groups",
		},
		{
			name: "host_network_outside_ca_networks",
			src: `
ca {
  name     = "m"
  networks = ["10.0.0.0/8"]
}
host "a" {
  networks = ["192.168.0.1/16"]
}
`,
			wantErr: "not contained by any ca.networks",
		},
		{
			name: "host_unsafe_network_outside_ca",
			src: `
ca {
  name            = "m"
  unsafe_networks = ["192.168.0.0/16"]
}
host "a" {
  networks        = ["10.0.0.1/16"]
  unsafe_networks = ["172.16.0.0/24"]
}
`,
			wantErr: "not contained by any ca.unsafe_networks",
		},
		{
			name: "group_with_comma",
			src: minimalGenerate + `
host "a" {
  networks = ["10.0.0.1/16"]
  groups   = ["bad,group"]
}
`,
			wantErr: "contains a comma",
		},
		{
			name: "group_with_whitespace",
			src: minimalGenerate + `
host "a" {
  networks = ["10.0.0.1/16"]
  groups   = [" trim "]
}
`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name: "group_empty",
			src: minimalGenerate + `
host "a" {
  networks = ["10.0.0.1/16"]
  groups   = [""]
}
`,
			wantErr: "non-empty",
		},
		{
			name:    "missing_ca_name_in_generate_mode",
			src:     `ca {}`,
			wantErr: "`name` is required",
		},
		{
			name: "invalid_curve",
			src: `
ca {
  name  = "m"
  curve = "P521"
}
`,
			wantErr: "curve must be",
		},
		{
			name: "invalid_version",
			src: `
ca {
  name    = "m"
  version = 9
}
`,
			wantErr: "version must be",
		},
		{
			name: "host_duration_exceeds_ca",
			src: `
ca {
  name     = "m"
  duration = "1h"
}
host "a" {
  networks = ["10.0.0.1/16"]
  duration = "2h"
}
`,
			wantErr: "exceeds ca.duration",
		},
		{
			name: "encryption_not_implemented",
			src: minimalGenerate + `
storage {
  encryption "sops" {}
}
`,
			wantErr: "encryption ships in a later release",
		},
		{
			name: "encryption_none_is_allowed",
			src: minimalGenerate + `
storage {
  encryption "none" {}
}
`,
			wantErr: "", // happy case
		},
		{
			name: "multiple_encryption_blocks",
			src: minimalGenerate + `
storage {
  encryption "none" {}
  encryption "sops" {}
}
`,
			wantErr: "multiple `encryption` blocks",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("test.hcl", []byte(tc.src))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestPrefixContains(t *testing.T) {
	cases := []struct {
		outer, inner string
		want         bool
	}{
		{"10.0.0.0/8", "10.42.0.0/16", true},
		{"10.0.0.0/8", "10.42.1.0/24", true},
		{"10.0.0.0/8", "192.168.0.0/16", false},
		{"10.0.0.0/16", "10.0.0.0/8", false}, // outer narrower
		{"fd00::/8", "fd42::/16", true},
		{"10.0.0.0/8", "fd00::/8", false}, // family mismatch
	}
	for _, c := range cases {
		o := mustPrefix(t, c.outer)
		i := mustPrefix(t, c.inner)
		if got := prefixContains(o, i); got != c.want {
			t.Errorf("prefixContains(%s, %s) = %v, want %v", c.outer, c.inner, got, c.want)
		}
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return p
}
