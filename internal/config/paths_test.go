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

// TestCAReferencePaths checks that in reference mode the CA path helpers
// return the operator-supplied cert_file/key_file verbatim, not the
// generate-mode defaults under out_dir. apply uses these both to probe
// for the files and to record them in the manifest, so they must point at
// the source files the operator named.
func TestCAReferencePaths(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}
storage { out_dir = "artifacts" }
`)

	if got, want := cfg.CACertPath(), "pki/root.crt"; got != want {
		t.Errorf("CACertPath() = %q, want reference cert_file %q", got, want)
	}
	if got, want := cfg.CAKeyPath(), "pki/root.key"; got != want {
		t.Errorf("CAKeyPath() = %q, want reference key_file %q", got, want)
	}
}

func TestHostArtifactPaths_Default(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca { name = "m" }
host "node" { networks = ["10.0.0.1/16"] }
`)
	h := cfg.Hosts[0]
	got := cfg.HostArtifactPaths(h)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Dir != "" {
		t.Errorf("Dir = %q, want empty for default path", got[0].Dir)
	}
	if want := cfg.HostCertPath(h); got[0].CertPath != want {
		t.Errorf("CertPath = %q, want %q", got[0].CertPath, want)
	}
	if want := cfg.HostKeyPath(h); got[0].KeyPath != want {
		t.Errorf("KeyPath = %q, want %q", got[0].KeyPath, want)
	}
}

func TestHostArtifactPaths_ExplicitPaths(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca { name = "m" }
host "node" {
  networks = ["10.0.0.1/16"]
  out_crt  = "custom/node.crt"
  out_key  = "custom/node.key"
}
`)
	h := cfg.Hosts[0]
	got := cfg.HostArtifactPaths(h)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Dir != "" {
		t.Errorf("Dir = %q, want empty for explicit paths", got[0].Dir)
	}
	if got[0].CertPath != "custom/node.crt" {
		t.Errorf("CertPath = %q, want custom/node.crt", got[0].CertPath)
	}
	if got[0].KeyPath != "custom/node.key" {
		t.Errorf("KeyPath = %q, want custom/node.key", got[0].KeyPath)
	}
}

func TestHostArtifactPaths_OutputDirs(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca { name = "m" }
host "node" {
  networks    = ["10.0.0.1/16"]
  output_dirs = ["dir-a", "dir-b"]
}
`)
	h := cfg.Hosts[0]
	got := cfg.HostArtifactPaths(h)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for i, want := range []struct{ dir, cert, key string }{
		{"dir-a", filepath.Join("dir-a", "node.crt"), filepath.Join("dir-a", "node.key")},
		{"dir-b", filepath.Join("dir-b", "node.crt"), filepath.Join("dir-b", "node.key")},
	} {
		if got[i].Dir != want.dir {
			t.Errorf("[%d] Dir = %q, want %q", i, got[i].Dir, want.dir)
		}
		if got[i].CertPath != want.cert {
			t.Errorf("[%d] CertPath = %q, want %q", i, got[i].CertPath, want.cert)
		}
		if got[i].KeyPath != want.key {
			t.Errorf("[%d] KeyPath = %q, want %q", i, got[i].KeyPath, want.key)
		}
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
