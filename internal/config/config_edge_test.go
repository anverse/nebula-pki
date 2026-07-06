package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
)

// These tests extend config_test.go with edge-case coverage. They are
// intentionally focused on boundaries, error-only paths and type
// translation that the baseline table tests skip.

// --- Load -------------------------------------------------------------------

func TestLoad_ReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(path, []byte(minimalGenerate), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := cfg.Path, path; got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.hcl"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "read ") {
		t.Errorf("error = %q, want it to mention `read`", err.Error())
	}
}

func TestLoad_HCLSyntaxError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.hcl")
	// Unterminated block; guaranteed parse error.
	if err := os.WriteFile(path, []byte(`ca "m" { name = "x"`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

// --- CA enum translation ----------------------------------------------------

func TestParse_CurveAliases(t *testing.T) {
	cases := []struct {
		alias string
		want  cert.Curve
	}{
		{"25519", cert.Curve_CURVE25519},
		{"P256", cert.Curve_P256},
	}
	for _, c := range cases {
		t.Run(c.alias, func(t *testing.T) {
			src := "ca \"m\" {\n  name = \"m\"\n  curve = \"" + c.alias + "\"\n}\n"
			cfg, err := Parse("t.hcl", []byte(src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got, want := cfg.CAs[0].Curve, c.want; got != want {
				t.Errorf("Curve = %v, want %v", got, want)
			}
			if !cfg.CAs[0].HasCurve {
				t.Error("HasCurve = false, want true")
			}
		})
	}
}

func TestParse_VersionMapping(t *testing.T) {
	for _, v := range []int{1, 2} {
		t.Run("v"+string(rune('0'+v)), func(t *testing.T) {
			src := "ca \"m\" {\n  name = \"m\"\n  version = " + string(rune('0'+v)) + "\n}\n"
			cfg, err := Parse("t.hcl", []byte(src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !cfg.CAs[0].HasVersion {
				t.Error("HasVersion = false, want true")
			}
			if got, want := int(cfg.CAs[0].Version), v; got != want {
				t.Errorf("Version = %d, want %d", got, want)
			}
		})
	}
}

func TestCAModeString(t *testing.T) {
	cases := []struct {
		mode CAMode
		want string
	}{
		{CAModeGenerate, "generate"},
		{CAModeReference, "reference"},
		{CAMode(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.mode.String(); got != c.want {
			t.Errorf("CAMode(%d).String() = %q, want %q", c.mode, got, c.want)
		}
	}
}

// --- Argon parameters -------------------------------------------------------

func TestParse_ArgonDefaultsWhenPartiallySet(t *testing.T) {
	src := `
ca "m" {
  name = "m"
  encrypt = true
  argon_iterations = 7
}`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CAs[0].Argon == nil {
		t.Fatal("Argon = nil, want non-nil")
	}
	if got, want := cfg.CAs[0].Argon.Iterations, uint32(7); got != want {
		t.Errorf("Iterations = %d, want %d", got, want)
	}
	if got, want := cfg.CAs[0].Argon.Memory, uint32(2*1024*1024); got != want {
		t.Errorf("Memory default = %d, want %d", got, want)
	}
	if got, want := cfg.CAs[0].Argon.Parallelism, uint8(4); got != want {
		t.Errorf("Parallelism default = %d, want %d", got, want)
	}
}

func TestParse_ArgonNilWhenNoneSet(t *testing.T) {
	cfg, err := Parse("t.hcl", []byte(minimalGenerate))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CAs[0].Argon != nil {
		t.Errorf("Argon = %+v, want nil", cfg.CAs[0].Argon)
	}
}

func TestParse_ArgonRangeErrors(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name: "memory_zero",
			src: `
ca "m" {
  name = "m"
  argon_memory = 0
}`,
			wantErr: "argon_memory must be positive",
		},
		{
			name: "iterations_negative",
			src: `
ca "m" {
  name = "m"
  argon_iterations = -1
}`,
			wantErr: "argon_iterations must be positive",
		},
		{
			name: "parallelism_zero",
			src: `
ca "m" {
  name = "m"
  argon_parallelism = 0
}`,
			wantErr: "argon_parallelism must be between 1 and 255",
		},
		{
			name: "parallelism_too_large",
			src: `
ca "m" {
  name = "m"
  argon_parallelism = 256
}`,
			wantErr: "argon_parallelism must be between 1 and 255",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("t.hcl", []byte(tc.src))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// --- Duration / version error reporting -------------------------------------

func TestParse_InvalidDurations(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			name: "ca_duration",
			src: `
ca "m" {
  name = "m"
  duration = "not-a-duration"
}`,
		},
		{
			name: "host_duration",
			src: minimalGenerate + `
host "a" {
  networks = ["10.0.0.1/16"]
  duration = "??"
}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("t.hcl", []byte(tc.src))
			if err == nil {
				t.Fatal("expected duration parse error, got nil")
			}
		})
	}
}

// --- Storage / manifest defaulting ------------------------------------------

func TestParse_ManifestDefaultsToCustomOutDir(t *testing.T) {
	src := `
ca "m" { name = "m" }
storage { out_dir = "build/dev" }
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := filepath.Join("build/dev", "nebula-pki.json")
	if got := cfg.Storage.ManifestFile; got != want {
		t.Errorf("ManifestFile = %q, want %q", got, want)
	}
}

func TestParse_StorageOmittedKeepsDefaults(t *testing.T) {
	cfg, err := Parse("t.hcl", []byte(minimalGenerate))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := cfg.Storage.OutDir, "out"; got != want {
		t.Errorf("OutDir = %q, want %q", got, want)
	}
}

// --- Reference mode: each generate-only field individually ------------------

func TestParse_ReferenceModeRejectsEachGenerateField(t *testing.T) {
	base := `
ca "ref" {
  cert_file = "ca.crt"
  key_file  = "ca.key"
  %s
}`
	cases := map[string]string{
		"name":              `name = "x"`,
		"duration":          `duration = "1h"`,
		"version":           `version = 1`,
		"curve":             `curve = "25519"`,
		"encrypt":           `encrypt = true`,
		"argon_memory":      `argon_memory = 1024`,
		"argon_iterations":  `argon_iterations = 1`,
		"argon_parallelism": `argon_parallelism = 1`,
		"out_crt":           `out_crt = "x"`,
		"out_key":           `out_key = "x"`,
		"out_qr":            `out_qr = "x"`,
	}
	for label, line := range cases {
		t.Run(label, func(t *testing.T) {
			src := strings.Replace(base, "%s", line, 1)
			_, err := Parse("t.hcl", []byte(src))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "generate-only fields") &&
				!strings.Contains(err.Error(), "reference mode requires both") {
				t.Errorf("error = %q, want a reference-mode rejection", err.Error())
			}
		})
	}
}

// --- Missing host networks --------------------------------------------------

func TestParse_HostWithoutNetworks(t *testing.T) {
	src := minimalGenerate + `
host "a" {}
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "`networks` is required") {
		t.Errorf("error = %q, want networks-required error", err.Error())
	}
}

func TestParse_HostWithEmptyNetworks(t *testing.T) {
	src := minimalGenerate + `
host "a" { networks = [] }
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "`networks` is required") {
		t.Errorf("error = %q, want networks-required error", err.Error())
	}
}

// --- IPv6 happy path + family-mismatch error path --------------------------

func TestParse_IPv6ContainmentHappyPath(t *testing.T) {
	src := `
ca "m" {
  name     = "m"
  networks = ["fd42::/16"]
}
host "a" {
  networks = ["fd42::1/64"]
}`
	if _, err := Parse("t.hcl", []byte(src)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

func TestParse_HostNetworkFamilyMismatchAgainstCA(t *testing.T) {
	src := `
ca "m" {
  name     = "m"
  networks = ["10.0.0.0/8"]
}
host "a" {
  networks = ["fd00::1/64"]
}`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("expected containment error, got nil")
	}
	if !strings.Contains(err.Error(), "not contained by any ca") {
		t.Errorf("error = %q, want containment error", err.Error())
	}
}

// --- CA.groups with comma is also rejected ----------------------------------

func TestParse_CAGroupsWithComma(t *testing.T) {
	src := `
ca "m" {
  name = "m"
  groups = ["bad,group"]
}`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "contains a comma") {
		t.Errorf("error = %q, want comma error", err.Error())
	}
}

// --- Multi-CA per-CA restriction scoping -----------------------------------

// TestParse_HostValidatedAgainstItsSigningCA ensures that host restriction
// checks use the host's signing CA, not some other CA in the config.
func TestParse_HostValidatedAgainstItsSigningCA(t *testing.T) {
	src := `
ca "permissive" {
  name    = "permissive"
  default = true
  groups  = ["any"]
}
ca "strict" {
  name   = "strict"
  groups = ["only-this"]
}
host "h" {
  networks = ["10.0.0.1/16"]
  groups   = ["any"]
  ca       = "permissive"
}
`
	// h uses "permissive" which allows "any", should succeed even though
	// "strict" does not allow "any".
	if _, err := Parse("t.hcl", []byte(src)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

// --- in_pub validation ------------------------------------------------------

func TestValidate_InPub_PlusOutKey_Rejected(t *testing.T) {
	src := `
ca "mesh" { name = "m" }
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "phone.pub"
  out_key  = "phone.key"
}
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("expected validation error for in_pub + out_key, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error = %q, want it to mention 'mutually exclusive'", err.Error())
	}
}

func TestValidate_InPub_WithoutOutKey_Accepted(t *testing.T) {
	src := `
ca "mesh" { name = "m" }
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "phone.pub"
}
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Hosts[0].InPub != "phone.pub" {
		t.Errorf("InPub = %q, want phone.pub", cfg.Hosts[0].InPub)
	}
}

func TestValidate_InPub_WithOutCRT_Accepted(t *testing.T) {
	// out_crt is fine together with in_pub; it just changes the cert filename.
	src := `
ca "mesh" { name = "m" }
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "phone.pub"
  out_crt  = "phone.crt"
}
`
	if _, err := Parse("t.hcl", []byte(src)); err != nil {
		t.Fatalf("Parse: %v (out_crt + in_pub should be accepted)", err)
	}
}
