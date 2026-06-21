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
	cfg := mustParse(t, "nebula.hcl", `ca "m" { name = "m" }`)
	ca := cfg.CAs[0]

	if got, want := cfg.CACertPathForCA(ca), filepath.Join("out", "ca", "m.crt"); got != want {
		t.Errorf("CACertPathForCA() = %q, want %q", got, want)
	}
	if got, want := cfg.CAKeyPathForCA(ca), filepath.Join("out", "ca", "m.key"); got != want {
		t.Errorf("CAKeyPathForCA() = %q, want %q", got, want)
	}
	if got, want := cfg.ManifestPath(), filepath.Join("out", "nebula-pki.json"); got != want {
		t.Errorf("ManifestPath() = %q, want %q", got, want)
	}
}

func TestCAPathOverridesAndOutDir(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca "m" {
  name    = "m"
  out_crt = "certs/root.crt"
}
storage { out_dir = "artifacts" }
`)
	ca := cfg.CAs[0]

	if got, want := cfg.CACertPathForCA(ca), "certs/root.crt"; got != want {
		t.Errorf("CACertPathForCA() = %q, want explicit %q", got, want)
	}
	// out_key not overridden: defaults under the custom out_dir.
	if got, want := cfg.CAKeyPathForCA(ca), filepath.Join("artifacts", "ca", "m.key"); got != want {
		t.Errorf("CAKeyPathForCA() = %q, want %q", got, want)
	}
	if got, want := cfg.ManifestPath(), filepath.Join("artifacts", "nebula-pki.json"); got != want {
		t.Errorf("ManifestPath() = %q, want %q", got, want)
	}
}

// TestCAKeyOverrideOnly is the mirror of the cert-override case.
func TestCAKeyOverrideOnly(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca "m" {
  name    = "m"
  out_key = "secrets/root.key"
}
`)
	ca := cfg.CAs[0]

	if got, want := cfg.CAKeyPathForCA(ca), "secrets/root.key"; got != want {
		t.Errorf("CAKeyPathForCA() = %q, want explicit %q", got, want)
	}
	if got, want := cfg.CACertPathForCA(ca), filepath.Join("out", "ca", "m.crt"); got != want {
		t.Errorf("CACertPathForCA() = %q, want default %q", got, want)
	}
}

// TestCAReferencePaths checks that in reference mode the CA path helpers
// return the operator-supplied cert_file/key_file verbatim.
func TestCAReferencePaths(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca "ref" {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}
storage { out_dir = "artifacts" }
`)
	ca := cfg.CAs[0]

	if got, want := cfg.CACertPathForCA(ca), "pki/root.crt"; got != want {
		t.Errorf("CACertPathForCA() = %q, want reference cert_file %q", got, want)
	}
	if got, want := cfg.CAKeyPathForCA(ca), "pki/root.key"; got != want {
		t.Errorf("CAKeyPathForCA() = %q, want reference key_file %q", got, want)
	}
}

func TestHostArtifactPath_Default(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca "m" { name = "m" }
host "node" { networks = ["10.0.0.1/16"] }
`)
	h := cfg.Hosts[0]
	got := cfg.HostArtifactPath(h)

	if got.Dir != "" {
		t.Errorf("Dir = %q, want empty for default path", got.Dir)
	}
	if want := filepath.Join("out", "hosts", "node.crt"); got.CertPath != want {
		t.Errorf("CertPath = %q, want %q", got.CertPath, want)
	}
	if want := filepath.Join("out", "hosts", "node.key"); got.KeyPath != want {
		t.Errorf("KeyPath = %q, want %q", got.KeyPath, want)
	}
}

func TestHostArtifactPath_ExplicitPaths(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca "m" { name = "m" }
host "node" {
  networks = ["10.0.0.1/16"]
  out_crt  = "custom/node.crt"
  out_key  = "custom/node.key"
}
`)
	h := cfg.Hosts[0]
	got := cfg.HostArtifactPath(h)

	if got.Dir != "" {
		t.Errorf("Dir = %q, want empty for out_crt/out_key-only paths", got.Dir)
	}
	if want := filepath.Join("out", "hosts", "custom/node.crt"); got.CertPath != want {
		t.Errorf("CertPath = %q, want %q", got.CertPath, want)
	}
	if want := filepath.Join("out", "hosts", "custom/node.key"); got.KeyPath != want {
		t.Errorf("KeyPath = %q, want %q", got.KeyPath, want)
	}
}

func TestHostArtifactPath_OutputDir(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca "m" { name = "m" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
}
`)
	h := cfg.Hosts[0]
	got := cfg.HostArtifactPath(h)

	if got.Dir != "dir-a" {
		t.Errorf("Dir = %q, want dir-a", got.Dir)
	}
	if want := filepath.Join("dir-a", "node.crt"); got.CertPath != want {
		t.Errorf("CertPath = %q, want %q", got.CertPath, want)
	}
	if want := filepath.Join("dir-a", "node.key"); got.KeyPath != want {
		t.Errorf("KeyPath = %q, want %q", got.KeyPath, want)
	}
}

func TestHostArtifactPath_OutputDirAndOutCrt(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca "m" { name = "m" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
  out_crt    = "renamed.crt"
}
`)
	h := cfg.Hosts[0]
	got := cfg.HostArtifactPath(h)

	if got.Dir != "dir-a" {
		t.Errorf("Dir = %q, want dir-a", got.Dir)
	}
	if want := filepath.Join("dir-a", "renamed.crt"); got.CertPath != want {
		t.Errorf("CertPath = %q, want %q", got.CertPath, want)
	}
	if want := filepath.Join("dir-a", "node.key"); got.KeyPath != want {
		t.Errorf("KeyPath = %q, want %q", got.KeyPath, want)
	}
}

func TestHostArtifactPath_OutputDirAndOutKey(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca "m" { name = "m" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
  out_key    = "renamed.key"
}
`)
	h := cfg.Hosts[0]
	got := cfg.HostArtifactPath(h)

	if got.Dir != "dir-a" {
		t.Errorf("Dir = %q, want dir-a", got.Dir)
	}
	if want := filepath.Join("dir-a", "node.crt"); got.CertPath != want {
		t.Errorf("CertPath = %q, want %q", got.CertPath, want)
	}
	if want := filepath.Join("dir-a", "renamed.key"); got.KeyPath != want {
		t.Errorf("KeyPath = %q, want %q", got.KeyPath, want)
	}
}

func TestHostArtifactPath_OutputDirAndBoth(t *testing.T) {
	cfg := mustParse(t, "nebula.hcl", `
ca "m" { name = "m" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
  out_crt    = "node.crt"
  out_key    = "node.key"
}
`)
	h := cfg.Hosts[0]
	got := cfg.HostArtifactPath(h)

	if got.Dir != "dir-a" {
		t.Errorf("Dir = %q, want dir-a", got.Dir)
	}
	if want := filepath.Join("dir-a", "node.crt"); got.CertPath != want {
		t.Errorf("CertPath = %q, want %q", got.CertPath, want)
	}
	if want := filepath.Join("dir-a", "node.key"); got.KeyPath != want {
		t.Errorf("KeyPath = %q, want %q", got.KeyPath, want)
	}
}

func TestResolve(t *testing.T) {
	cfg := mustParse(t, filepath.Join("project", "nebula.hcl"), `ca "m" { name = "m" }`)

	if got, want := cfg.Resolve("out/ca/m.crt"), filepath.Join("project", "out", "ca", "m.crt"); got != want {
		t.Errorf("Resolve(rel) = %q, want %q", got, want)
	}

	abs := filepath.Join(string(filepath.Separator), "etc", "ca.crt")
	if got := cfg.Resolve(abs); got != abs {
		t.Errorf("Resolve(abs) = %q, want %q", got, abs)
	}
}
