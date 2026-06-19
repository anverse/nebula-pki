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
	// Unterminated block — guaranteed parse error.
	if err := os.WriteFile(path, []byte(`ca { name = "x"`), 0o600); err != nil {
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
			src := "ca {\n  name = \"m\"\n  curve = \"" + c.alias + "\"\n}\n"
			cfg, err := Parse("t.hcl", []byte(src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got, want := cfg.CA.Curve, c.want; got != want {
				t.Errorf("Curve = %v, want %v", got, want)
			}
			if !cfg.CA.HasCurve {
				t.Error("HasCurve = false, want true")
			}
		})
	}
}

func TestParse_VersionMapping(t *testing.T) {
	for _, v := range []int{1, 2} {
		t.Run("v"+string(rune('0'+v)), func(t *testing.T) {
			src := "ca {\n  name = \"m\"\n  version = " + string(rune('0'+v)) + "\n}\n"
			cfg, err := Parse("t.hcl", []byte(src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !cfg.CA.HasVersion {
				t.Error("HasVersion = false, want true")
			}
			if got, want := int(cfg.CA.Version), v; got != want {
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
	// Only iterations set: the other two should fall back to the upstream
	// defaults encoded in decodeArgon.
	src := `
ca {
  name = "m"
  encrypt = true
  argon_iterations = 7
}`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CA.Argon == nil {
		t.Fatal("Argon = nil, want non-nil")
	}
	if got, want := cfg.CA.Argon.Iterations, uint32(7); got != want {
		t.Errorf("Iterations = %d, want %d", got, want)
	}
	if got, want := cfg.CA.Argon.Memory, uint32(2*1024*1024); got != want {
		t.Errorf("Memory default = %d, want %d", got, want)
	}
	if got, want := cfg.CA.Argon.Parallelism, uint8(4); got != want {
		t.Errorf("Parallelism default = %d, want %d", got, want)
	}
}

func TestParse_ArgonNilWhenNoneSet(t *testing.T) {
	cfg, err := Parse("t.hcl", []byte(minimalGenerate))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CA.Argon != nil {
		t.Errorf("Argon = %+v, want nil", cfg.CA.Argon)
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
ca {
  name = "m"
  argon_memory = 0
}`,
			wantErr: "argon_memory must be positive",
		},
		{
			name: "iterations_negative",
			src: `
ca {
  name = "m"
  argon_iterations = -1
}`,
			wantErr: "argon_iterations must be positive",
		},
		{
			name: "parallelism_zero",
			src: `
ca {
  name = "m"
  argon_parallelism = 0
}`,
			wantErr: "argon_parallelism must be between 1 and 255",
		},
		{
			name: "parallelism_too_large",
			src: `
ca {
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
ca {
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
ca { name = "m" }
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
ca {
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
ca {
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
ca {
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
	if !strings.Contains(err.Error(), "not contained by any ca.networks") {
		t.Errorf("error = %q, want containment error", err.Error())
	}
}

// --- CA.groups with comma is also rejected ----------------------------------

func TestParse_CAGroupsWithComma(t *testing.T) {
	src := `
ca {
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

// --- Full multi-host happy path ---------------------------------------------

func TestParse_MultipleHostsHappyPath(t *testing.T) {
	src := `
ca {
  name     = "m"
  groups   = ["app", "lh"]
  networks = ["10.0.0.0/8"]
}
host "a" {
  networks = ["10.0.0.1/16"]
  groups   = ["app"]
}
host "b" {
  networks = ["10.0.0.2/16"]
  groups   = ["lh"]
}
host "c" {
  networks = ["10.0.0.3/16"]
  groups   = ["app", "lh"]
}
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := len(cfg.Hosts), 3; got != want {
		t.Fatalf("len(Hosts) = %d, want %d", got, want)
	}
	for i, label := range []string{"a", "b", "c"} {
		if got, want := cfg.Hosts[i].Label, label; got != want {
			t.Errorf("Hosts[%d].Label = %q, want %q", i, got, want)
		}
		if got, want := cfg.Hosts[i].Name, label; got != want {
			t.Errorf("Hosts[%d].Name = %q (default to label), want %q", i, got, want)
		}
	}
}

// --- groupsNotIn helper deterministic ordering ------------------------------

func TestGroupsNotIn_Sorted(t *testing.T) {
	got := groupsNotIn([]string{"z", "a", "m"}, []string{"x"})
	want := []string{"a", "m", "z"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
