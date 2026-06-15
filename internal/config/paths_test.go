package config

import (
	"path/filepath"
	"testing"
)

func mustParse(t *testing.T, filename, src string) *Config {
	t.Helper()
	cfg, err := Parse(filename, []byte(src))
	if err != nil {
		t.Fatalf("Parse(%s): %v", filename, err)
	}
	return cfg
}

func TestCADefaultPaths(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `ca { name = "m" }`)

	if got, want := cfg.CACertPath(), filepath.Join("out", "ca", "ca.crt"); got != want {
		t.Errorf("CACertPath() = %q, want %q", got, want)
	}
	if got, want := cfg.CAKeyPath(), filepath.Join("out", "ca", "ca.key"); got != want {
		t.Errorf("CAKeyPath() = %q, want %q", got, want)
	}
	if got, want := cfg.ManifestPath(), filepath.Join("out", "nebula-pki.json"); got != want {
		t.Errorf("ManifestPath() = %q, want %q", got, want)
	}
}

func TestCAPathOverridesAndOutDir(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca {
  name    = "m"
  out_crt = "certs/root.crt"
}
storage { out_dir = "artifacts" }
`)

	if got, want := cfg.CACertPath(), "certs/root.crt"; got != want {
		t.Errorf("CACertPath() = %q, want explicit %q", got, want)
	}
	// out_key not overridden: defaults under the custom out_dir.
	if got, want := cfg.CAKeyPath(), filepath.Join("artifacts", "ca", "ca.key"); got != want {
		t.Errorf("CAKeyPath() = %q, want %q", got, want)
	}
	if got, want := cfg.ManifestPath(), filepath.Join("artifacts", "nebula-pki.json"); got != want {
		t.Errorf("ManifestPath() = %q, want %q", got, want)
	}
}

// TestCAKeyOverrideOnly is the mirror of the cert-override case: the
// operator overrides only `out_key` and keeps the cert at the default.
// Without this test the `c.CA.OutKey != ""` branch in CAKeyPath is
// dead-coded as far as the suite is concerned, and a regression that
// swaps the two helpers (returning OutCRT from CAKeyPath, say) would
// silently pass.
func TestCAKeyOverrideOnly(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca {
  name    = "m"
  out_key = "secrets/root.key"
}
`)

	if got, want := cfg.CAKeyPath(), "secrets/root.key"; got != want {
		t.Errorf("CAKeyPath() = %q, want explicit %q", got, want)
	}
	// Cert keeps the default location.
	if got, want := cfg.CACertPath(), filepath.Join("out", "ca", "ca.crt"); got != want {
		t.Errorf("CACertPath() = %q, want default %q", got, want)
	}
}

func TestResolve(t *testing.T) {
	cfg := mustParse(t, filepath.Join("project", "nebula.hcl"), `ca { name = "m" }`)

	// Relative logical path joins onto the config's directory.
	if got, want := cfg.Resolve("out/ca/ca.crt"), filepath.Join("project", "out", "ca", "ca.crt"); got != want {
		t.Errorf("Resolve(rel) = %q, want %q", got, want)
	}

	// Absolute logical path is returned unchanged.
	abs := filepath.Join(string(filepath.Separator), "etc", "ca.crt")
	if got := cfg.Resolve(abs); got != abs {
		t.Errorf("Resolve(abs) = %q, want %q", got, abs)
	}
}
