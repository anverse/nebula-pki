package apply

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/crypto"
	"github.com/anverse/nebula-pki/internal/manifest"
	"github.com/anverse/nebula-pki/internal/pki"
	"github.com/anverse/nebula-pki/internal/plan"
	"github.com/slackhq/nebula/cert"
)

// emptyEncryptor is a test stub that implements crypto.Backend. It reports a
// non-empty suffix (so writeKeyFile takes the encryption branch) but returns
// empty ciphertext without an error, simulating a sops bug where the process
// exits 0 with no stdout.
type emptyEncryptor struct{}

func (e *emptyEncryptor) Encrypt(_ []byte, _ string) ([]byte, error) { return []byte{}, nil }
func (e *emptyEncryptor) Decrypt(c []byte) ([]byte, error)           { return c, nil }
func (e *emptyEncryptor) Suffix() string                             { return ".enc" }
func (e *emptyEncryptor) BackendName() string                        { return "test" }
func (e *emptyEncryptor) RecipientsHash() string                     { return "" }

var _ crypto.Backend = (*emptyEncryptor)(nil) // compile-time interface check

// fakeBackend is a configurable crypto.Backend stub for mismatch tests.
type fakeBackend struct {
	suffix         string
	backendName    string
	recipientsHash string
}

func (f *fakeBackend) Encrypt(p []byte, _ string) ([]byte, error) { return p, nil }
func (f *fakeBackend) Decrypt(c []byte) ([]byte, error)           { return c, nil }
func (f *fakeBackend) Suffix() string                             { return f.suffix }
func (f *fakeBackend) BackendName() string                        { return f.backendName }
func (f *fakeBackend) RecipientsHash() string                     { return f.recipientsHash }

var _ crypto.Backend = (*fakeBackend)(nil)

// fixedNow is a deterministic issuance time for assertions.
var fixedNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

const genVersion = "v0.0.3-test"

// writeConfig writes src as nebula.hcl into a fresh temp dir and loads it,
// so cfg.Path is absolute under that dir and every resolved artifact lands
// inside it.
func writeConfig(t *testing.T, src string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func TestReconcile_FreshGeneratesCAAndManifest(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true on a fresh tree")
	}
	if len(rep.SignedHosts) != 0 {
		t.Errorf("SignedHosts = %v, want none (no host blocks)", rep.SignedHosts)
	}
	if len(rep.CAs) != 1 {
		t.Fatalf("CAs = %d, want 1", len(rep.CAs))
	}

	ca0 := cfg.CAs[0]
	certReal := cfg.Resolve(cfg.CACertPathForCA(ca0))
	keyReal := cfg.Resolve(cfg.CAKeyPathForCA(ca0))
	manReal := cfg.Resolve(cfg.ManifestPath())

	// File modes per spec/adr/002.
	assertMode(t, certReal, 0o600)
	assertMode(t, keyReal, 0o600)
	assertMode(t, manReal, 0o644)

	// Manifest round-trips and records the CA.
	m, err := manifest.Load(manReal)
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.SchemaVersion != manifest.SchemaVersion {
		t.Errorf("schema_version = %d, want %d", m.SchemaVersion, manifest.SchemaVersion)
	}
	if m.Generator.Name != manifest.GeneratorName || m.Generator.Version != genVersion {
		t.Errorf("generator = %+v, want {%s %s}", m.Generator, manifest.GeneratorName, genVersion)
	}
	mCA := m.CAs["mesh"]
	if mCA == nil {
		t.Fatal("manifest CAs[mesh] is nil")
	}
	if mCA.Mode != "generate" || mCA.Name != "mesh" {
		t.Errorf("CA mode/name = %q/%q, want generate/mesh", mCA.Mode, mCA.Name)
	}
	if mCA.Curve != "25519" || mCA.Version != 2 {
		t.Errorf("CA curve/version = %q/%d, want 25519/2", mCA.Curve, mCA.Version)
	}
	if mCA.Fingerprint == "" {
		t.Error("CA fingerprint is empty")
	}
	if !mCA.NotBefore.Equal(fixedNow) {
		t.Errorf("not_before = %s, want %s", mCA.NotBefore, fixedNow)
	}
	if want := fixedNow.Add(8760 * time.Hour); !mCA.NotAfter.Equal(want) {
		t.Errorf("not_after = %s, want %s", mCA.NotAfter, want)
	}
	if mCA.CertPath != cfg.CACertPathForCA(ca0) || mCA.KeyPath != cfg.CAKeyPathForCA(ca0) {
		t.Errorf("CA paths = %q/%q, want %q/%q", mCA.CertPath, mCA.KeyPath,
			cfg.CACertPathForCA(ca0), cfg.CAKeyPathForCA(ca0))
	}
	// config_path is relative to the manifest's directory (out/ -> ..).
	if want := filepath.Join("..", "nebula.hcl"); m.ConfigPath != want {
		t.Errorf("config_path = %q, want %q", m.ConfigPath, want)
	}
}

func TestReconcile_SecondRunIsNoopAndByteIdentical(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	ca0 := cfg.CAs[0]
	certReal := cfg.Resolve(cfg.CACertPathForCA(ca0))
	keyReal := cfg.Resolve(cfg.CAKeyPathForCA(ca0))
	manReal := cfg.Resolve(cfg.ManifestPath())

	cert1, key1, man1 := mustRead(t, certReal), mustRead(t, keyReal), mustRead(t, manReal)

	rep, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep.Changed {
		t.Fatal("Changed = true on an up-to-date tree, want false")
	}

	if got := mustRead(t, certReal); string(got) != string(cert1) {
		t.Error("CA cert changed on no-op run")
	}
	if got := mustRead(t, keyReal); string(got) != string(key1) {
		t.Error("CA key changed on no-op run")
	}
	if got := mustRead(t, manReal); string(got) != string(man1) {
		t.Error("manifest changed on no-op run")
	}
}

func TestReconcile_UntrackedCAErrors(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)
	ca0 := cfg.CAs[0]

	// Pre-seed CA files with no manifest: the tool must refuse to clobber.
	mustSeed(t, cfg.Resolve(cfg.CACertPathForCA(ca0)))
	mustSeed(t, cfg.Resolve(cfg.CAKeyPathForCA(ca0)))

	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("Reconcile: want error for untracked CA, got nil")
	}
}

// Reference-mode reconcile tests live in reference_test.go.

// TestReconcile_PartialPairRefused covers the half-present pair case.
func TestReconcile_PartialPairRefused(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)
	ca0 := cfg.CAs[0]

	// Only the cert pre-exists; key and manifest are absent.
	mustSeed(t, cfg.Resolve(cfg.CACertPathForCA(ca0)))

	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("Reconcile: want error for half-present untracked pair, got nil")
	}
}

// TestReconcile_CorruptManifestAbortsBeforePlan exercises the early
// error path: manifest.Load surfaces the parse error and Reconcile must
// abort before calling plan.Build or pki.GenerateCA.
func TestReconcile_CorruptManifestAbortsBeforePlan(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)
	ca0 := cfg.CAs[0]

	manReal := cfg.Resolve(cfg.ManifestPath())
	if err := os.MkdirAll(filepath.Dir(manReal), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(manReal, []byte(`{"schema_version": 1, "hosts": {`), 0o644); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}

	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("Reconcile: want error for corrupt manifest, got nil")
	}
	if !strings.Contains(err.Error(), "parse manifest") {
		t.Errorf("error = %q, want it to wrap 'parse manifest'", err.Error())
	}

	if _, err := os.Stat(cfg.Resolve(cfg.CACertPathForCA(ca0))); err == nil {
		t.Error("CA cert was written despite manifest-load failure")
	}
	if _, err := os.Stat(cfg.Resolve(cfg.CAKeyPathForCA(ca0))); err == nil {
		t.Error("CA key was written despite manifest-load failure")
	}
}

// TestReconcile_SchemaMismatchRejected pins the schema-version contract.
func TestReconcile_SchemaMismatchRejected(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)
	manReal := cfg.Resolve(cfg.ManifestPath())
	if err := os.MkdirAll(filepath.Dir(manReal), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(manReal, []byte(`{"schema_version": 2, "hosts": {}}`), 0o644); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("Reconcile: want error for unsupported schema_version, got nil")
	}
	if !strings.Contains(err.Error(), "schema_version 2") {
		t.Errorf("error = %q, want it to mention 'schema_version 2'", err.Error())
	}
}

// TestReconcile_ManifestWriteFailsAfterCAWritten covers the failure path
// where pki.GenerateCA succeeded but the manifest write itself fails.
func TestReconcile_ManifestWriteFailsAfterCAWritten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: 0500 dirs are still writable")
	}
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")
	manDir := filepath.Join(root, "manifest")
	cfgDir := filepath.Join(root, "cfg")
	for _, d := range []string{caDir, manDir, cfgDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	cfgPath := filepath.Join(cfgDir, "nebula.hcl")
	src := `
ca "mesh" {
  name    = "mesh"
  out_crt = "` + filepath.Join(caDir, "ca.crt") + `"
  out_key = "` + filepath.Join(caDir, "ca.key") + `"
}
storage {
  manifest_file = "` + filepath.Join(manDir, "nebula-pki.json") + `"
}`
	if err := os.WriteFile(cfgPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	if err := os.Chmod(manDir, 0o500); err != nil {
		t.Fatalf("chmod manDir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(manDir, 0o755) })

	_, err = Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("Reconcile: want error when manifest write fails, got nil")
	}
	if !strings.Contains(err.Error(), "write manifest") {
		t.Errorf("error = %q, want it to wrap 'write manifest'", err.Error())
	}

	if err := os.Chmod(manDir, 0o755); err != nil {
		t.Fatalf("chmod restore: %v", err)
	}

	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); err != nil {
		t.Errorf("CA cert missing after manifest-write failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca.key")); err != nil {
		t.Errorf("CA key missing after manifest-write failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(manDir, "nebula-pki.json")); err == nil {
		t.Error("manifest exists despite write failure")
	}

	_, err = Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("second Reconcile: want untracked-CA error, got nil")
	}
}

// TestReconcile_SignsHostsAfterCA verifies that host certs are signed,
// written to disk, and recorded in the manifest on a fresh run.
func TestReconcile_SignsHostsAfterCA(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }

host "alpha" { networks = ["10.0.0.1/16"] }
host "beta"  { networks = ["10.0.0.2/16"] }
`)
	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true on first run")
	}
	if len(rep.SignedHosts) != 2 {
		t.Fatalf("SignedHosts = %d, want 2", len(rep.SignedHosts))
	}
	if rep.SignedHosts[0].Label != "alpha" || rep.SignedHosts[1].Label != "beta" {
		t.Errorf("SignedHosts labels = %v, want [alpha beta]",
			[]string{rep.SignedHosts[0].Label, rep.SignedHosts[1].Label})
	}

	for _, h := range rep.SignedHosts {
		for _, a := range h.Artifacts {
			if _, err := os.Stat(cfg.Resolve(a.CertPath)); err != nil {
				t.Errorf("host %q cert %q missing: %v", h.Label, a.CertPath, err)
			}
			if _, err := os.Stat(cfg.Resolve(a.KeyPath)); err != nil {
				t.Errorf("host %q key %q missing: %v", h.Label, a.KeyPath, err)
			}
		}
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if len(m.Hosts) != 2 {
		t.Fatalf("manifest hosts = %d, want 2", len(m.Hosts))
	}
	for _, label := range []string{"alpha", "beta"} {
		h, ok := m.Hosts[label]
		if !ok {
			t.Fatalf("manifest missing host %q", label)
		}
		if h.CAFingerprint == "" {
			t.Errorf("host %q: ca_fingerprint is empty", label)
		}
		if h.Fingerprint == "" {
			t.Errorf("host %q: fingerprint is empty", label)
		}
		if len(h.Artifacts) != 1 {
			t.Errorf("host %q: artifacts = %d, want 1", label, len(h.Artifacts))
		}
		if h.CA != "mesh" {
			t.Errorf("host %q: ca = %q, want mesh", label, h.CA)
		}
	}
	// CA fingerprints must match.
	meshCA := m.CAs["mesh"]
	if meshCA == nil {
		t.Fatal("manifest missing CAs[mesh]")
	}
	if m.Hosts["alpha"].CAFingerprint != meshCA.Fingerprint {
		t.Errorf("host alpha ca_fingerprint %q != ca fingerprint %q",
			m.Hosts["alpha"].CAFingerprint, meshCA.Fingerprint)
	}
}

// TestReconcile_HostIdempotency verifies that a second reconcile writes nothing.
func TestReconcile_HostIdempotency(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
host "alpha" { networks = ["10.0.0.1/16"] }
`)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	ca0 := cfg.CAs[0]
	certReal := cfg.Resolve(cfg.CACertPathForCA(ca0))
	keyReal := cfg.Resolve(cfg.CAKeyPathForCA(ca0))
	manReal := cfg.Resolve(cfg.ManifestPath())
	hostCertReal := cfg.Resolve(cfg.HostArtifactPath(cfg.Hosts[0]).CertPath)
	hostKeyReal := cfg.Resolve(cfg.HostArtifactPath(cfg.Hosts[0]).KeyPath)

	snapshots := map[string][]byte{
		certReal:     mustRead(t, certReal),
		keyReal:      mustRead(t, keyReal),
		manReal:      mustRead(t, manReal),
		hostCertReal: mustRead(t, hostCertReal),
		hostKeyReal:  mustRead(t, hostKeyReal),
	}

	rep, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep.Changed {
		t.Fatal("Changed = true on second run, want false (full idempotency)")
	}
	if len(rep.SignedHosts) != 0 {
		t.Errorf("SignedHosts non-empty on noop run: %v", rep.SignedHosts)
	}

	for path, before := range snapshots {
		after := mustRead(t, path)
		if string(after) != string(before) {
			t.Errorf("%s changed on no-op run", path)
		}
	}
}

// TestReconcile_AbsoluteConfigPathStillRecordsRelativeManifest exercises
// manifestRelConfigPath with an absolute config path.
func TestReconcile_AbsoluteConfigPathStillRecordsRelativeManifest(t *testing.T) {
	dir := t.TempDir()
	absConfig := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(absConfig, []byte(`ca "mesh" { name = "mesh" }`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(absConfig)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if want := filepath.Join("..", "nebula.hcl"); m.ConfigPath != want {
		t.Errorf("config_path = %q, want %q (relative even though cfg.Path was absolute)",
			m.ConfigPath, want)
	}
}

// TestReconcile_OutputDir verifies that output_dir writes cert/key to the
// configured directory, the manifest records it with dir set, and the
// second run is a noop.
func TestReconcile_OutputDir(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
}
`)
	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true on first run")
	}
	if len(rep.SignedHosts) != 1 {
		t.Fatalf("SignedHosts = %d, want 1", len(rep.SignedHosts))
	}
	sh := rep.SignedHosts[0]
	if sh.Label != "node" {
		t.Errorf("Label = %q, want node", sh.Label)
	}
	if len(sh.Artifacts) != 1 {
		t.Fatalf("Artifacts = %d, want 1", len(sh.Artifacts))
	}

	a := sh.Artifacts[0]
	if _, err := os.Stat(cfg.Resolve(a.CertPath)); err != nil {
		t.Errorf("cert %q missing: %v", a.CertPath, err)
	}
	if _, err := os.Stat(cfg.Resolve(a.KeyPath)); err != nil {
		t.Errorf("key %q missing: %v", a.KeyPath, err)
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	node, ok := m.Hosts["node"]
	if !ok {
		t.Fatal("manifest missing host node")
	}
	if len(node.Artifacts) != 1 {
		t.Fatalf("manifest artifacts = %d, want 1", len(node.Artifacts))
	}
	if node.Artifacts[0].Dir != "dir-a" {
		t.Errorf("artifact.Dir = %q, want dir-a", node.Artifacts[0].Dir)
	}

	certSnap := mustRead(t, cfg.Resolve(a.CertPath))
	manSnap := mustRead(t, cfg.Resolve(cfg.ManifestPath()))

	rep2, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.Changed {
		t.Fatal("Changed = true on second run, want false (full idempotency)")
	}
	if got := mustRead(t, cfg.Resolve(a.CertPath)); string(got) != string(certSnap) {
		t.Error("cert changed on no-op run")
	}
	if got := mustRead(t, cfg.Resolve(cfg.ManifestPath())); string(got) != string(manSnap) {
		t.Error("manifest changed on no-op run")
	}
}

// TestReconcile_StaleArtifacts verifies that when output_dir changes between
// runs, the report includes the old paths as stale.
func TestReconcile_StaleArtifacts(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nebula.hcl")

	loadHCL := func(src string) *config.Config {
		t.Helper()
		if err := os.WriteFile(configPath, []byte(src), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		return cfg
	}

	cfg1 := loadHCL(`
ca "mesh" { name = "mesh" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
}
`)
	if _, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	oldCert := filepath.Join(tmpDir, "dir-a", "node.crt")
	oldKey := filepath.Join(tmpDir, "dir-a", "node.key")
	if _, err := os.Stat(oldCert); err != nil {
		t.Fatalf("expected old cert to exist: %v", err)
	}

	cfg2 := loadHCL(`
ca "mesh" { name = "mesh" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-b"
}
`)
	rep2, err := Reconcile(cfg2, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(rep2.StaleArtifacts) != 2 {
		t.Fatalf("StaleArtifacts = %v, want 2 paths (old cert + key)", rep2.StaleArtifacts)
	}
	for _, p := range rep2.StaleArtifacts {
		if !strings.HasPrefix(p, "dir-a") {
			t.Errorf("stale path %q does not start with dir-a", p)
		}
	}
	if _, err := os.Stat(oldCert); err != nil {
		t.Errorf("old cert was deleted, want it preserved: %v", err)
	}
	if _, err := os.Stat(oldKey); err != nil {
		t.Errorf("old key was deleted, want it preserved: %v", err)
	}

	if err := os.Remove(oldCert); err != nil {
		t.Fatalf("remove old cert: %v", err)
	}
	if err := os.Remove(oldKey); err != nil {
		t.Fatalf("remove old key: %v", err)
	}
	rep3, err := Reconcile(cfg2, Options{Now: fixedNow.Add(2 * time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	if rep3.Changed {
		t.Fatal("third run: Changed = true, want false (noop)")
	}
	if len(rep3.StaleArtifacts) != 0 {
		t.Errorf("third run: StaleArtifacts = %v, want none (old files gone)", rep3.StaleArtifacts)
	}
}

// TestReconcile_OutputDirChange verifies that changing output_dir between
// runs triggers a re-sign to the new location.
func TestReconcile_OutputDirChange(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nebula.hcl")

	loadHCL := func(src string) *config.Config {
		t.Helper()
		if err := os.WriteFile(configPath, []byte(src), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		return cfg
	}

	cfg1 := loadHCL(`
ca "mesh" { name = "mesh" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
}
`)
	rep1, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if !rep1.Changed {
		t.Fatal("first run: Changed = false, want true")
	}

	cfg2 := loadHCL(`
ca "mesh" { name = "mesh" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-b"
}
`)
	rep2, err := Reconcile(cfg2, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if !rep2.Changed {
		t.Fatal("second run: Changed = false, want true (dir-b is new destination)")
	}
	if len(rep2.SignedHosts) != 1 {
		t.Fatalf("second run: SignedHosts = %d, want 1", len(rep2.SignedHosts))
	}
	if len(rep2.SignedHosts[0].Artifacts) != 1 {
		t.Fatalf("second run: Artifacts = %d, want 1", len(rep2.SignedHosts[0].Artifacts))
	}

	for _, p := range []string{
		filepath.Join(tmpDir, "dir-b", "node.crt"),
		filepath.Join(tmpDir, "dir-b", "node.key"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s missing: %v", p, err)
		}
	}

	m, err := manifest.Load(cfg2.Resolve(cfg2.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if len(m.Hosts["node"].Artifacts) != 1 {
		t.Fatalf("manifest artifacts = %d, want 1", len(m.Hosts["node"].Artifacts))
	}
	if m.Hosts["node"].Artifacts[0].Dir != "dir-b" {
		t.Errorf("artifact.Dir = %q, want dir-b", m.Hosts["node"].Artifacts[0].Dir)
	}

	rep3, err := Reconcile(cfg2, Options{Now: fixedNow.Add(2 * time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	if rep3.Changed {
		t.Fatal("third run: Changed = true, want false (full noop after dir change)")
	}
}

// TestReconcile_OutputDirWithOutCrt verifies that output_dir and out_crt
// compose correctly.
func TestReconcile_OutputDirWithOutCrt(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "deploy"
  out_crt    = "nebula.crt"
}
`)
	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true on first run")
	}
	if len(rep.SignedHosts) != 1 {
		t.Fatalf("SignedHosts = %d, want 1", len(rep.SignedHosts))
	}
	a := rep.SignedHosts[0].Artifacts[0]

	wantCert := filepath.Join("deploy", "nebula.crt")
	wantKey := filepath.Join("deploy", "node.key")
	if a.CertPath != wantCert {
		t.Errorf("CertPath = %q, want %q", a.CertPath, wantCert)
	}
	if a.KeyPath != wantKey {
		t.Errorf("KeyPath = %q, want %q", a.KeyPath, wantKey)
	}

	if _, err := os.Stat(cfg.Resolve(a.CertPath)); err != nil {
		t.Errorf("cert %q missing: %v", a.CertPath, err)
	}
	if _, err := os.Stat(cfg.Resolve(a.KeyPath)); err != nil {
		t.Errorf("key %q missing: %v", a.KeyPath, err)
	}

	rep2, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.Changed {
		t.Fatal("second run: Changed = true, want false (noop)")
	}
}

// TestReconcile_DryRunWritesNothing verifies that DryRun=true previews
// without creating any files.
func TestReconcile_DryRunWritesNothing(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
host "alpha" { networks = ["10.0.0.1/16"] }
host "beta"  { networks = ["10.0.0.2/16"] }
`)
	ca0 := cfg.CAs[0]
	var out bytes.Buffer
	rep, err := Reconcile(cfg, Options{
		Now:              fixedNow,
		GeneratorVersion: genVersion,
		DryRun:           true,
		Out:              &out,
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if rep.Changed {
		t.Fatal("Changed = true for dry run, want false")
	}

	for _, path := range []string{
		cfg.Resolve(cfg.CACertPathForCA(ca0)),
		cfg.Resolve(cfg.CAKeyPathForCA(ca0)),
		cfg.Resolve(cfg.ManifestPath()),
		cfg.Resolve(cfg.HostArtifactPath(cfg.Hosts[0]).CertPath),
		cfg.Resolve(cfg.HostArtifactPath(cfg.Hosts[0]).KeyPath),
		cfg.Resolve(cfg.HostArtifactPath(cfg.Hosts[1]).CertPath),
		cfg.Resolve(cfg.HostArtifactPath(cfg.Hosts[1]).KeyPath),
	} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s was written during dry run", path)
		}
	}

	preview := out.String()
	for _, want := range []string{
		"+ write " + cfg.CACertPathForCA(ca0),
		"+ write " + cfg.CAKeyPathForCA(ca0),
		"+ write " + cfg.HostArtifactPath(cfg.Hosts[0]).CertPath,
		"+ write " + cfg.HostArtifactPath(cfg.Hosts[0]).KeyPath,
		"+ write " + cfg.HostArtifactPath(cfg.Hosts[1]).CertPath,
		"+ write " + cfg.HostArtifactPath(cfg.Hosts[1]).KeyPath,
		"+ write " + cfg.ManifestPath(),
	} {
		if !strings.Contains(preview, want) {
			t.Errorf("dry-run output = %q, want it to contain %q", preview, want)
		}
	}
}

// TestReconcile_DryRunOnUpToDateTree verifies dry-run on a reconciled
// tree prints "up to date; nothing to do".
func TestReconcile_DryRunOnUpToDateTree(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
host "alpha" { networks = ["10.0.0.1/16"] }
`)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	manSnap := mustRead(t, cfg.Resolve(cfg.ManifestPath()))

	var out bytes.Buffer
	rep, err := Reconcile(cfg, Options{
		Now:              fixedNow.Add(time.Hour),
		GeneratorVersion: genVersion,
		DryRun:           true,
		Out:              &out,
	})
	if err != nil {
		t.Fatalf("dry-run Reconcile: %v", err)
	}
	if rep.Changed {
		t.Fatal("Changed = true for dry run, want false")
	}
	if !strings.Contains(out.String(), "up to date; nothing to do") {
		t.Errorf("dry-run output = %q, want 'up to date; nothing to do'", out.String())
	}
	if got := mustRead(t, cfg.Resolve(cfg.ManifestPath())); string(got) != string(manSnap) {
		t.Error("manifest changed during dry run")
	}
}

// TestReconcile_DryRunCAOnly verifies the preview for a config with no hosts.
func TestReconcile_DryRunCAOnly(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)
	ca0 := cfg.CAs[0]
	var out bytes.Buffer
	if _, err := Reconcile(cfg, Options{
		Now:              fixedNow,
		GeneratorVersion: genVersion,
		DryRun:           true,
		Out:              &out,
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	preview := out.String()
	for _, want := range []string{
		"+ write " + cfg.CACertPathForCA(ca0),
		"+ write " + cfg.CAKeyPathForCA(ca0),
		"+ write " + cfg.ManifestPath(),
	} {
		if !strings.Contains(preview, want) {
			t.Errorf("dry-run output = %q, want it to contain %q", preview, want)
		}
	}
	if strings.Contains(preview, "host") {
		t.Errorf("dry-run output = %q, must not mention hosts for CA-only config", preview)
	}
}

// --- Multi-CA reconcile ---------------------------------------------------

// TestReconcile_MultiCA_TwoCAsHostsUnderEach verifies a two-CA config: both
// CAs are generated, each host is signed under its designated CA (confirmed
// via ca_fingerprint in the manifest), and a second run is a full noop.
func TestReconcile_MultiCA_TwoCAsHostsUnderEach(t *testing.T) {
	cfg := writeConfig(t, `
ca "primary" {
  name    = "primary-mesh"
  default = true
}
ca "secondary" { name = "secondary-mesh" }

host "h1" { networks = ["10.0.0.1/16"] }
host "h2" {
  networks = ["10.0.0.2/16"]
  ca       = "secondary"
}
`)
	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true on first run")
	}
	if len(rep.CAs) != 2 {
		t.Fatalf("CAs = %d, want 2", len(rep.CAs))
	}
	if len(rep.SignedHosts) != 2 {
		t.Fatalf("SignedHosts = %d, want 2", len(rep.SignedHosts))
	}

	// Both CA pairs must exist on disk.
	for _, ca := range cfg.CAs {
		if _, err := os.Stat(cfg.Resolve(cfg.CACertPathForCA(ca))); err != nil {
			t.Errorf("CA %q cert missing: %v", ca.Label, err)
		}
		if _, err := os.Stat(cfg.Resolve(cfg.CAKeyPathForCA(ca))); err != nil {
			t.Errorf("CA %q key missing: %v", ca.Label, err)
		}
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}

	// Manifest has both CAs in the `cas` map.
	if len(m.CAs) != 2 {
		t.Fatalf("manifest CAs = %d, want 2", len(m.CAs))
	}
	primaryRec := m.CAs["primary"]
	secondaryRec := m.CAs["secondary"]
	if primaryRec == nil {
		t.Fatal("manifest missing CAs[primary]")
	}
	if secondaryRec == nil {
		t.Fatal("manifest missing CAs[secondary]")
	}
	if primaryRec.Fingerprint == secondaryRec.Fingerprint {
		t.Error("primary and secondary share a fingerprint; CAs were not generated independently")
	}

	// Each host's manifest record names the correct signing CA and its
	// ca_fingerprint matches that CA's fingerprint.
	h1 := m.Hosts["h1"]
	if h1.CA != "primary" {
		t.Errorf("h1.CA = %q, want primary", h1.CA)
	}
	if h1.CAFingerprint != primaryRec.Fingerprint {
		t.Errorf("h1.CAFingerprint = %q, want primary fingerprint %q", h1.CAFingerprint, primaryRec.Fingerprint)
	}

	h2 := m.Hosts["h2"]
	if h2.CA != "secondary" {
		t.Errorf("h2.CA = %q, want secondary", h2.CA)
	}
	if h2.CAFingerprint != secondaryRec.Fingerprint {
		t.Errorf("h2.CAFingerprint = %q, want secondary fingerprint %q", h2.CAFingerprint, secondaryRec.Fingerprint)
	}

	// Snapshot for idempotency check.
	snapshots := map[string][]byte{
		cfg.Resolve(cfg.ManifestPath()): mustRead(t, cfg.Resolve(cfg.ManifestPath())),
	}
	for _, ca := range cfg.CAs {
		p := cfg.Resolve(cfg.CACertPathForCA(ca))
		snapshots[p] = mustRead(t, p)
	}
	for _, h := range cfg.Hosts {
		a := cfg.HostArtifactPath(h)
		snapshots[cfg.Resolve(a.CertPath)] = mustRead(t, cfg.Resolve(a.CertPath))
		snapshots[cfg.Resolve(a.KeyPath)] = mustRead(t, cfg.Resolve(a.KeyPath))
	}

	rep2, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.Changed {
		t.Fatal("second run: Changed = true, want false (full idempotency)")
	}
	for path, before := range snapshots {
		if after := mustRead(t, path); string(after) != string(before) {
			t.Errorf("%s changed on no-op run", path)
		}
	}
}

// TestReconcile_MultiCA_HostResignsWhenCAChanges verifies that when a host's
// signing CA label changes between runs (manifest records old CA, config now
// points at a different one), the host is re-signed under the new CA.
func TestReconcile_MultiCA_HostResignsWhenCAChanges(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nebula.hcl")

	loadHCL := func(src string) *config.Config {
		t.Helper()
		if err := os.WriteFile(configPath, []byte(src), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		return cfg
	}

	// First run: h1 signed by primary (default), h2 by secondary.
	cfg1 := loadHCL(`
ca "primary" {
  name    = "primary-mesh"
  default = true
}
ca "secondary" { name = "secondary-mesh" }
host "h1" { networks = ["10.0.0.1/16"] }
host "h2" {
  networks = ["10.0.0.2/16"]
  ca       = "secondary"
}
`)
	if _, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	m1, _ := manifest.Load(cfg1.Resolve(cfg1.ManifestPath()))
	h1FPBefore := m1.Hosts["h1"].CAFingerprint

	// Second run: move h1 to secondary by adding explicit `ca = "secondary"`.
	cfg2 := loadHCL(`
ca "primary" {
  name    = "primary-mesh"
  default = true
}
ca "secondary" { name = "secondary-mesh" }
host "h1" {
  networks = ["10.0.0.1/16"]
  ca       = "secondary"
}
host "h2" {
  networks = ["10.0.0.2/16"]
  ca       = "secondary"
}
`)
	rep2, err := Reconcile(cfg2, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if !rep2.Changed {
		t.Fatal("second run: Changed = false, want true (h1 signing CA changed)")
	}

	signedLabels := make(map[string]bool, len(rep2.SignedHosts))
	for _, sh := range rep2.SignedHosts {
		signedLabels[sh.Label] = true
	}
	if !signedLabels["h1"] {
		t.Error("h1 not in SignedHosts, expected re-sign after CA change")
	}
	if signedLabels["h2"] {
		t.Error("h2 in SignedHosts, expected noop (CA unchanged)")
	}

	m2, _ := manifest.Load(cfg2.Resolve(cfg2.ManifestPath()))
	h1FPAfter := m2.Hosts["h1"].CAFingerprint
	secondaryFP := m2.CAs["secondary"].Fingerprint
	if h1FPAfter != secondaryFP {
		t.Errorf("h1.CAFingerprint = %q after re-sign, want secondary fingerprint %q", h1FPAfter, secondaryFP)
	}
	if h1FPAfter == h1FPBefore {
		t.Error("h1.CAFingerprint unchanged after CA switch, expected different fingerprint")
	}
}

// ---------------------------------------------------------------------------
// Trust bundle tests
// ---------------------------------------------------------------------------

// TestReconcile_BundleWritten verifies that bundle.crt is created on a fresh
// run and has the expected file mode.
func TestReconcile_BundleWritten(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.TrustBundleWritten {
		t.Error("TrustBundleWritten = false, want true on first run")
	}
	if rep.TrustBundlePath == "" {
		t.Error("TrustBundlePath is empty")
	}

	bundleReal := cfg.Resolve(cfg.TrustBundlePath())
	if _, err := os.Stat(bundleReal); err != nil {
		t.Fatalf("bundle.crt missing: %v", err)
	}
	assertMode(t, bundleReal, 0o600)
}

// TestReconcile_BundleEqualsCACert verifies that a single-CA bundle contains
// exactly the CA cert PEM bytes.
func TestReconcile_BundleEqualsCACert(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	ca0 := cfg.CAs[0]
	caCert := mustRead(t, cfg.Resolve(cfg.CACertPathForCA(ca0)))
	bundle := mustRead(t, cfg.Resolve(cfg.TrustBundlePath()))

	if !bytes.Equal(caCert, bundle) {
		t.Error("single-CA bundle does not equal CA cert PEM")
	}
}

// TestReconcile_BundleManifestRecord verifies that manifest.TrustBundle is
// populated with the correct path and a matching fingerprint.
func TestReconcile_BundleManifestRecord(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.TrustBundle == nil {
		t.Fatal("manifest.TrustBundle = nil")
	}
	if m.TrustBundle.Path != cfg.TrustBundlePath() {
		t.Errorf("TrustBundle.Path = %q, want %q", m.TrustBundle.Path, cfg.TrustBundlePath())
	}
	if len(m.TrustBundle.CAFingerprints) != 1 {
		t.Fatalf("TrustBundle.CAFingerprints len = %d, want 1", len(m.TrustBundle.CAFingerprints))
	}
	caFP := m.CAs["mesh"].Fingerprint
	if m.TrustBundle.CAFingerprints[0] != caFP {
		t.Errorf("TrustBundle.CAFingerprints[0] = %q, want CA fingerprint %q", m.TrustBundle.CAFingerprints[0], caFP)
	}
}

// TestReconcile_BundleIdempotent verifies that a second run leaves
// bundle.crt byte-identical and does not set TrustBundleWritten.
func TestReconcile_BundleIdempotent(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	bundle1 := mustRead(t, cfg.Resolve(cfg.TrustBundlePath()))

	rep, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep.Changed {
		t.Error("Changed = true on idempotent run, want false")
	}
	if rep.TrustBundleWritten {
		t.Error("TrustBundleWritten = true on idempotent run, want false")
	}

	bundle2 := mustRead(t, cfg.Resolve(cfg.TrustBundlePath()))
	if !bytes.Equal(bundle1, bundle2) {
		t.Error("bundle.crt changed on idempotent run")
	}
}

// TestReconcile_BundleCustomPath verifies that storage.trust_bundle_file
// redirects the bundle to the custom path.
func TestReconcile_BundleCustomPath(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
storage { trust_bundle_file = "out/ca/mesh-trust.crt" }
`)
	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.TrustBundleWritten {
		t.Error("TrustBundleWritten = false, want true")
	}
	if rep.TrustBundlePath != "out/ca/mesh-trust.crt" {
		t.Errorf("TrustBundlePath = %q, want out/ca/mesh-trust.crt", rep.TrustBundlePath)
	}
	if _, err := os.Stat(cfg.Resolve("out/ca/mesh-trust.crt")); err != nil {
		t.Fatalf("custom bundle path missing: %v", err)
	}
	// Default path must not exist.
	if _, err := os.Stat(cfg.Resolve("out/ca/bundle.crt")); err == nil {
		t.Error("default bundle.crt exists but should not when trust_bundle_file is set")
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.TrustBundle == nil || m.TrustBundle.Path != "out/ca/mesh-trust.crt" {
		t.Errorf("manifest TrustBundle.Path = %v, want out/ca/mesh-trust.crt", m.TrustBundle)
	}
}

// TestReconcile_TwoCAsBundleConcatenates verifies that a two-CA config
// writes a bundle containing both CA certs in declaration order and that
// the manifest records both fingerprints.
func TestReconcile_TwoCAsBundleConcatenates(t *testing.T) {
	cfg := writeConfig(t, `
ca "primary" {
  name    = "primary-mesh"
  default = true
}
ca "secondary" {
  name = "secondary-mesh"
}
host "h1" { networks = ["10.0.0.1/16"] }
host "h2" {
  networks = ["10.0.0.2/16"]
  ca       = "secondary"
}
`)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	bundle := mustRead(t, cfg.Resolve(cfg.TrustBundlePath()))
	primaryCert := mustRead(t, cfg.Resolve(cfg.CACertPathForCA(cfg.CAs[0])))
	secondaryCert := mustRead(t, cfg.Resolve(cfg.CACertPathForCA(cfg.CAs[1])))

	// Bundle must be exactly primary || secondary in declaration order.
	want := append(primaryCert, secondaryCert...)
	if !bytes.Equal(bundle, want) {
		t.Error("two-CA bundle content does not match primary+secondary concatenation")
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.TrustBundle == nil {
		t.Fatal("TrustBundle = nil")
	}
	if len(m.TrustBundle.CAFingerprints) != 2 {
		t.Fatalf("CAFingerprints len = %d, want 2", len(m.TrustBundle.CAFingerprints))
	}
	if m.TrustBundle.CAFingerprints[0] != m.CAs["primary"].Fingerprint {
		t.Errorf("CAFingerprints[0] = %q, want primary fingerprint %q", m.TrustBundle.CAFingerprints[0], m.CAs["primary"].Fingerprint)
	}
	if m.TrustBundle.CAFingerprints[1] != m.CAs["secondary"].Fingerprint {
		t.Errorf("CAFingerprints[1] = %q, want secondary fingerprint %q", m.TrustBundle.CAFingerprints[1], m.CAs["secondary"].Fingerprint)
	}
}

// TestReconcile_BundleReport verifies the TrustBundlePath and
// TrustBundleWritten fields on the Report struct across two runs.
func TestReconcile_BundleReport(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)
	expected := cfg.TrustBundlePath()

	rep1, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if rep1.TrustBundlePath != expected {
		t.Errorf("first run TrustBundlePath = %q, want %q", rep1.TrustBundlePath, expected)
	}
	if !rep1.TrustBundleWritten {
		t.Error("first run TrustBundleWritten = false, want true")
	}

	rep2, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.TrustBundlePath != expected {
		t.Errorf("second run TrustBundlePath = %q, want %q", rep2.TrustBundlePath, expected)
	}
	if rep2.TrustBundleWritten {
		t.Error("second run TrustBundleWritten = true, want false")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
}

func mustSeed(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("pre-existing\n"), 0o600); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
}

// --- in_pub (air-gapped signing) tests --------------------------------------

// writeInPubFixture generates a Curve25519 device keypair and writes the
// public key PEM to dir/filename. Returns the PEM bytes so callers can
// verify the cert embeds the same public key.
func writeInPubFixture(t *testing.T, dir, filename string) []byte {
	t.Helper()
	// Generate an Ed25519 keypair (Nebula's CURVE25519 host keypair).
	pub, _, err := generateKeypairForTest()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, pub, 0o600); err != nil {
		t.Fatalf("write pub key: %v", err)
	}
	return pub
}

func TestReconcile_InPub_CertOnly(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "inbox/phone.pub"
}
`)
	writeInPubFixture(t, filepath.Join(filepath.Dir(cfg.Path), "inbox"), "phone.pub")

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true on first run")
	}

	// Only the cert must exist; the key must not be written.
	art := cfg.HostArtifactPath(cfg.Hosts[0])
	certReal := cfg.Resolve(art.CertPath)
	keyReal := cfg.Resolve(art.KeyPath)
	if _, err := os.Stat(certReal); err != nil {
		t.Errorf("cert file missing: %v", err)
	}
	if _, err := os.Stat(keyReal); err == nil {
		t.Error("key file exists; in_pub hosts must not write a private key")
	}

	// Manifest must record in_pub = true and omit key_path from artifacts.
	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	mh := m.Hosts["phone"]
	if !mh.InPub {
		t.Error("manifest Host.InPub = false, want true")
	}
	if len(mh.Artifacts) != 1 {
		t.Fatalf("len(Artifacts) = %d, want 1", len(mh.Artifacts))
	}
	if mh.Artifacts[0].CertPath == "" {
		t.Error("Artifacts[0].CertPath is empty")
	}
	if mh.Artifacts[0].KeyPath != "" {
		t.Errorf("Artifacts[0].KeyPath = %q, want empty for in_pub host", mh.Artifacts[0].KeyPath)
	}
}

func TestReconcile_InPub_Idempotent(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "inbox/phone.pub"
}
`)
	writeInPubFixture(t, filepath.Join(filepath.Dir(cfg.Path), "inbox"), "phone.pub")

	rep1, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if !rep1.Changed {
		t.Fatal("first run: Changed = false")
	}

	rep2, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.Changed {
		t.Error("second run: Changed = true; in_pub host should be a noop on unchanged tree")
	}
}

func TestReconcile_InPub_MissingPubFile(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "inbox/no-such-file.pub"
}
`)
	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("expected error for missing in_pub file, got nil")
	}
	if !strings.Contains(err.Error(), "in_pub") {
		t.Errorf("error = %q, want it to mention 'in_pub'", err.Error())
	}
}

func TestReconcile_InPub_CurveMismatch(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" {
  name = "mesh"
}
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "inbox/phone.pub"
}
`)
	// Write a P256 public key, but the CA uses Curve25519 (default).
	dir := filepath.Join(filepath.Dir(cfg.Path), "inbox")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p256PEM, err := generateP256PubPEM()
	if err != nil {
		t.Fatalf("generate P256 key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "phone.pub"), p256PEM, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("expected curve mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "curve") {
		t.Errorf("error = %q, want it to mention 'curve'", err.Error())
	}
}

func TestReconcile_InPub_RenewalResignsWithSamePubKey(t *testing.T) {
	src := `
ca "mesh" {
  name         = "mesh"
  renew_before = "720h"
}
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "inbox/phone.pub"
}
`
	cfg := writeConfig(t, src)
	pubPEM := writeInPubFixture(t, filepath.Join(filepath.Dir(cfg.Path), "inbox"), "phone.pub")

	// First sign.
	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	// Second run: advance the clock so the cert is inside its renewal window
	// (notAfter = fixedNow + 8760h; renewal at notAfter - 720h = fixedNow + 8040h).
	insideWindow := fixedNow.Add(8100 * time.Hour)
	rep2, err := Reconcile(cfg, Options{Now: insideWindow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile (renewal): %v", err)
	}
	if !rep2.Changed {
		t.Fatal("second run: Changed = false; cert should have been renewed")
	}

	// The renewed cert must embed the same public key.
	art := cfg.HostArtifactPath(cfg.Hosts[0])
	certPEM := mustRead(t, cfg.Resolve(art.CertPath))
	pubRaw, _, err := parsePubPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse pub PEM: %v", err)
	}
	certObj := parseCertBytes(t, certPEM)
	if !bytes.Equal(certObj.PublicKey(), pubRaw) {
		t.Error("renewed cert embeds a different public key than the original in_pub file")
	}

	// Key file must still not exist.
	keyReal := cfg.Resolve(art.KeyPath)
	if _, err := os.Stat(keyReal); err == nil {
		t.Error("key file appeared after renewal; in_pub hosts must never write a key")
	}
}

func TestReconcile_InPub_DryRun_NoCertOrKeyWritten(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "inbox/phone.pub"
}
`)
	writeInPubFixture(t, filepath.Join(filepath.Dir(cfg.Path), "inbox"), "phone.pub")

	var out bytes.Buffer
	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion, DryRun: true, Out: &out})
	if err != nil {
		t.Fatalf("Reconcile dry-run: %v", err)
	}

	preview := out.String()
	art := cfg.HostArtifactPath(cfg.Hosts[0])

	if !strings.Contains(preview, art.CertPath) {
		t.Errorf("dry-run output %q does not list cert path %s", preview, art.CertPath)
	}
	if strings.Contains(preview, art.KeyPath) {
		t.Errorf("dry-run output %q lists key path %s; in_pub hosts write no key", preview, art.KeyPath)
	}

	// Dry-run must not create files.
	certReal := cfg.Resolve(art.CertPath)
	if _, err := os.Stat(certReal); err == nil {
		t.Error("cert file was created during dry-run; dry-run must not write anything")
	}
}

func TestReconcile_InPub_StaleKeyFlaggedOnRegularToInPubTransition(t *testing.T) {
	// First run: regular host (generates cert + key).
	regularSrc := `
ca "mesh" { name = "mesh" }
host "phone" {
  networks = ["10.0.0.1/16"]
}
`
	cfg := writeConfig(t, regularSrc)
	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("regular Reconcile: %v", err)
	}

	// Confirm key exists.
	art0 := cfg.HostArtifactPath(cfg.Hosts[0])
	keyReal := cfg.Resolve(art0.KeyPath)
	if _, err := os.Stat(keyReal); err != nil {
		t.Fatalf("key file missing after regular sign: %v", err)
	}

	// Second run: switch to in_pub (same config dir, rewritten nebula.hcl).
	inPubSrc := `
ca "mesh" { name = "mesh" }
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "inbox/phone.pub"
}
`
	cfgDir := filepath.Dir(cfg.Path)
	if err := os.WriteFile(cfg.Path, []byte(inPubSrc), 0o644); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	writeInPubFixture(t, filepath.Join(cfgDir, "inbox"), "phone.pub")

	cfg2, err := config.Load(cfg.Path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	rep2, err := Reconcile(cfg2, Options{Now: fixedNow.Add(time.Second), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("in_pub Reconcile: %v", err)
	}

	// The old key path must appear in StaleArtifacts.
	found := false
	for _, p := range rep2.StaleArtifacts {
		if p == art0.KeyPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("StaleArtifacts = %v, want it to contain the old key path %s", rep2.StaleArtifacts, art0.KeyPath)
	}
}

// --- helpers for in_pub tests -----------------------------------------------

// generateKeypairForTest generates a Curve25519 keypair and returns the
// public key as a PEM-encoded byte slice (as nebula-cert keygen would output).
func generateKeypairForTest() (pubPEM []byte, privRaw []byte, err error) {
	pub, priv, err := generateEd25519()
	if err != nil {
		return nil, nil, err
	}
	pem := marshalPubPEM(pub)
	return pem, priv, nil
}

// generateP256PubPEM generates a P256 keypair and returns the public key PEM.
func generateP256PubPEM() ([]byte, error) {
	pub, err := generateP256Pub()
	if err != nil {
		return nil, err
	}
	return marshalP256PubPEM(pub), nil
}

// parsePubPEM parses a PEM-encoded public key, returning the raw bytes.
func parsePubPEM(pem []byte) (raw []byte, _ string, err error) {
	raw, curveStr, err := pki.ParseHostPublicKeyPEM(pem)
	return raw, curveStr, err
}

// parseCertBytes parses a PEM certificate for inspection in tests.
func parseCertBytes(t *testing.T, pemBytes []byte) nebulaPublicKeyer {
	t.Helper()
	c, _, err := cert.UnmarshalCertificateFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("UnmarshalCertificateFromPEM: %v", err)
	}
	return c
}

// nebulaPublicKeyer is the subset of cert.Certificate we use in tests.
type nebulaPublicKeyer interface {
	PublicKey() []byte
}

// TestSweepPlaintextTemps verifies that sweepPlaintextTemps removes
// .nebula-pki-plain-* files and leaves unrelated files untouched.
func TestSweepPlaintextTemps(t *testing.T) {
	dir := t.TempDir()

	write := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}

	plain1 := write(".nebula-pki-plain-abc123")
	plain2 := write(".nebula-pki-plain-def456")
	unrelated := write("mesh.key.enc")

	sweepPlaintextTemps(dir, nil)

	for _, p := range []string{plain1, plain2} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("expected %s to be removed, but it still exists", filepath.Base(p))
		}
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("unrelated file %s was unexpectedly removed", filepath.Base(unrelated))
	}
}

// TestWriteKeyFile_EmptyCiphertextError verifies that writeKeyFile rejects
// a zero-byte ciphertext returned by the encryption backend. This guards
// against sops exiting 0 with empty stdout, which would otherwise silently
// write a zero-byte file and permanently lose the private key.
func TestWriteKeyFile_EmptyCiphertextError(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)
	enc := &emptyEncryptor{}

	_, _, err := writeKeyFile(cfg, enc, "out/ca/mesh.key", []byte("fake key PEM"), "CA \"mesh\" key")
	if err == nil {
		t.Fatal("writeKeyFile: want error for empty ciphertext, got nil")
	}
	if !strings.Contains(err.Error(), "empty ciphertext") {
		t.Errorf("error = %q, want it to mention 'empty ciphertext'", err.Error())
	}
}

func TestCheckEncryptionMismatches_WarnWhenHashesDiffer(t *testing.T) {
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{
		Encryption: &manifest.EncryptionRecord{Backend: "sops", RecipientsHash: "aabbcc"},
	}
	enc := &fakeBackend{backendName: "sops", suffix: ".enc", recipientsHash: "ddeeff"}

	var buf bytes.Buffer
	checkEncryptionMismatches(m, enc, &buf)

	out := buf.String()
	if !strings.Contains(out, `CA "mesh"`) {
		t.Errorf("want mismatch warning for CA mesh, got: %q", out)
	}
	if !strings.Contains(out, "nebula-pki rekey") {
		t.Errorf("want rekey hint in warning, got: %q", out)
	}
}

func TestCheckEncryptionMismatches_NoWarnWhenHashesMatch(t *testing.T) {
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{
		Encryption: &manifest.EncryptionRecord{Backend: "sops", RecipientsHash: "aabbcc"},
	}
	enc := &fakeBackend{backendName: "sops", suffix: ".enc", recipientsHash: "aabbcc"}

	var buf bytes.Buffer
	checkEncryptionMismatches(m, enc, &buf)

	if buf.Len() != 0 {
		t.Errorf("want no warning when hashes match, got: %q", buf.String())
	}
}

func TestCheckEncryptionMismatches_NoWarnWhenStoredHashEmpty(t *testing.T) {
	// Stored hash empty means the previous run used .sops.yaml discovery; no comparison possible.
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{
		Encryption: &manifest.EncryptionRecord{Backend: "sops", RecipientsHash: ""},
	}
	enc := &fakeBackend{backendName: "sops", suffix: ".enc", recipientsHash: "ddeeff"}

	var buf bytes.Buffer
	checkEncryptionMismatches(m, enc, &buf)

	if buf.Len() != 0 {
		t.Errorf("want no warning for empty stored hash, got: %q", buf.String())
	}
}

func TestCheckEncryptionMismatches_NoWarnWhenCurrentHashEmpty(t *testing.T) {
	// Current config has no inline recipients (.sops.yaml mode); no comparison possible.
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{
		Encryption: &manifest.EncryptionRecord{Backend: "sops", RecipientsHash: "aabbcc"},
	}
	enc := &fakeBackend{backendName: "sops", suffix: ".enc", recipientsHash: ""}

	var buf bytes.Buffer
	checkEncryptionMismatches(m, enc, &buf)

	if buf.Len() != 0 {
		t.Errorf("want no warning when current hash is empty, got: %q", buf.String())
	}
}

func TestCheckEncryptionMismatches_HostArtifact(t *testing.T) {
	m := manifest.New()
	m.Hosts["alpha"] = manifest.Host{
		Name: "alpha",
		Artifacts: []manifest.Artifact{
			{
				CertPath:   "out/hosts/alpha.crt",
				KeyPath:    "out/hosts/alpha.key.enc",
				Encryption: &manifest.EncryptionRecord{Backend: "sops", RecipientsHash: "oldoldold"},
			},
		},
	}
	enc := &fakeBackend{backendName: "sops", suffix: ".enc", recipientsHash: "newnewnew"}

	var buf bytes.Buffer
	checkEncryptionMismatches(m, enc, &buf)

	out := buf.String()
	if !strings.Contains(out, `host "alpha"`) {
		t.Errorf("want mismatch warning for host alpha, got: %q", out)
	}
}

// ── link_crt apply tests ──────────────────────────────────────────────────────

const linkCrtConfig = `
ca "mesh" {
  name     = "mesh"
  link_crt = ["out/hetzner"]
}
`

func TestReconcile_LinkCrt_CreatesSymlink(t *testing.T) {
	cfg := writeConfig(t, linkCrtConfig)

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true")
	}

	linkPath := cfg.Resolve("out/hetzner/mesh.crt")
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Lstat link: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symlink (mode %v)", linkPath, info.Mode())
	}

	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != "../ca/mesh.crt" {
		t.Errorf("symlink target = %q, want ../ca/mesh.crt", target)
	}

	// Report reflects the created link.
	if len(rep.CreatedLinks) != 1 {
		t.Fatalf("CreatedLinks = %d, want 1", len(rep.CreatedLinks))
	}
	if rep.CreatedLinks[0].Path != "out/hetzner/mesh.crt" {
		t.Errorf("CreatedLinks[0].Path = %q, want out/hetzner/mesh.crt", rep.CreatedLinks[0].Path)
	}

	// Manifest records the link.
	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("Load manifest: %v", err)
	}
	if len(m.CAs["mesh"].Links) != 1 {
		t.Fatalf("manifest CAs[mesh].Links = %d, want 1", len(m.CAs["mesh"].Links))
	}
	if m.CAs["mesh"].Links[0].Path != "out/hetzner/mesh.crt" {
		t.Errorf("manifest link path = %q", m.CAs["mesh"].Links[0].Path)
	}
}

func TestReconcile_LinkCrt_SecondRunIsNoop(t *testing.T) {
	cfg := writeConfig(t, linkCrtConfig)

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep.Changed {
		t.Error("Changed = true on second run, want noop")
	}
	if len(rep.CreatedLinks) != 0 {
		t.Errorf("CreatedLinks = %v on noop run, want empty", rep.CreatedLinks)
	}
}

func TestReconcile_LinkCrt_WrongTargetRecreated(t *testing.T) {
	cfg := writeConfig(t, linkCrtConfig)

	// First run to generate CA and manifest.
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	// Break the symlink.
	linkPath := cfg.Resolve("out/hetzner/mesh.crt")
	if err := os.Remove(linkPath); err != nil {
		t.Fatalf("remove symlink: %v", err)
	}
	if err := os.Symlink("/wrong/target.crt", linkPath); err != nil {
		t.Fatalf("create wrong symlink: %v", err)
	}

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Error("Changed = false after recreating wrong symlink, want true")
	}
	target, _ := os.Readlink(linkPath)
	if target != "../ca/mesh.crt" {
		t.Errorf("symlink target after fix = %q, want ../ca/mesh.crt", target)
	}
}

func TestApplyLinks_CorrectSymlinkSkipsRecreate(t *testing.T) {
	// Run Reconcile once to generate CA artifacts and the correct symlink.
	cfg := writeConfig(t, linkCrtConfig)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	linkPath := cfg.Resolve("out/hetzner/mesh.crt")
	correctTarget, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}

	// Call applyLinks directly with OpCreateSymlink even though the symlink
	// already has the correct target. This simulates the TOCTOU window where
	// the planner saw a wrong/missing target but the disk was corrected before
	// applyLinks ran.
	action := plan.Action{
		Op:         plan.OpCreateSymlink,
		Kind:       plan.KindLink,
		Label:      "mesh",
		Path:       "out/hetzner/mesh.crt",
		LinkTarget: correctTarget,
		LinkDir:    "out/hetzner",
		Desc:       "create link out/hetzner/mesh.crt → " + correctTarget,
	}
	next := &manifest.Manifest{}
	created, _, err := applyLinks(cfg, []plan.Action{action}, next, nil)
	if err != nil {
		t.Fatalf("applyLinks: %v", err)
	}
	if len(created) != 0 {
		t.Errorf("created = %v, want empty; symlink with correct target must not be recreated", created)
	}

	// Symlink must still resolve to the correct target.
	got, rerr := os.Readlink(linkPath)
	if rerr != nil {
		t.Fatalf("Readlink after applyLinks: %v", rerr)
	}
	if got != correctTarget {
		t.Errorf("symlink target = %q after applyLinks, want %q", got, correctTarget)
	}
}

func TestReconcile_LinkCrt_StaleDeleted(t *testing.T) {
	// Run 1: link_crt = ["out/hetzner"].
	cfg1 := writeConfig(t, linkCrtConfig)
	if _, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	// Verify the symlink exists.
	linkPath := cfg1.Resolve("out/hetzner/mesh.crt")
	if _, err := os.Lstat(linkPath); err != nil {
		t.Fatalf("Lstat after first run: %v", err)
	}

	// Run 2: link_crt removed. Re-use the same dir (same files on disk).
	dir := filepath.Dir(cfg1.Path)
	cfgPath := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(cfgPath, []byte(`ca "mesh" { name = "mesh" }`), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	cfg2, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load config: %v", err)
	}

	rep, err := Reconcile(cfg2, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Error("Changed = false after link deletion, want true")
	}
	if len(rep.DeletedLinks) != 1 || rep.DeletedLinks[0] != "out/hetzner/mesh.crt" {
		t.Errorf("DeletedLinks = %v, want [out/hetzner/mesh.crt]", rep.DeletedLinks)
	}
	if _, err := os.Lstat(linkPath); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Lstat after deletion: got %v, want ErrNotExist", err)
	}
}

func TestReconcile_LinkCrt_RegularFileErrors(t *testing.T) {
	cfg := writeConfig(t, linkCrtConfig)

	// Pre-create a regular file where the symlink would go.
	if err := os.MkdirAll(cfg.Resolve("out/hetzner"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(cfg.Resolve("out/hetzner/mesh.crt"), []byte("not a symlink"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("Reconcile: want error for regular file at link path, got nil")
	}
	if !strings.Contains(err.Error(), "is not a symlink") {
		t.Errorf("error = %q, want to contain \"is not a symlink\"", err.Error())
	}

	// Regular file must be untouched.
	b, readErr := os.ReadFile(cfg.Resolve("out/hetzner/mesh.crt"))
	if readErr != nil || string(b) != "not a symlink" {
		t.Error("regular file was modified/deleted — should have been left alone")
	}
}

func TestReconcile_LinkCrt_StaleRegularFileNoticed(t *testing.T) {
	// Run 1: create symlink.
	cfg1 := writeConfig(t, linkCrtConfig)
	if _, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	linkPath := cfg1.Resolve("out/hetzner/mesh.crt")

	// Replace symlink with a regular file.
	if err := os.Remove(linkPath); err != nil {
		t.Fatalf("remove symlink: %v", err)
	}
	if err := os.WriteFile(linkPath, []byte("regular"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	// Run 2: remove link_crt from config so the link becomes stale.
	dir := filepath.Dir(cfg1.Path)
	cfgPath := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(cfgPath, []byte(`ca "mesh" { name = "mesh" }`), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	cfg2, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load config: %v", err)
	}

	var warnBuf strings.Builder
	rep, err := Reconcile(cfg2, Options{Now: fixedNow, GeneratorVersion: genVersion, Warn: &warnBuf})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	// The file is not deleted (notice only).
	if len(rep.DeletedLinks) != 0 {
		t.Errorf("DeletedLinks = %v, want empty (file not deleted)", rep.DeletedLinks)
	}
	if !strings.Contains(warnBuf.String(), "not a symlink") {
		t.Errorf("warning = %q, want to mention \"not a symlink\"", warnBuf.String())
	}
	// Regular file still present.
	if _, statErr := os.Lstat(linkPath); statErr != nil {
		t.Errorf("Lstat: %v — regular file should still exist", statErr)
	}
}

func TestReconcile_LinkCrt_StaleAlreadyGoneManifestCleared(t *testing.T) {
	// Run 1: create symlink.
	cfg1 := writeConfig(t, linkCrtConfig)
	if _, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	linkPath := cfg1.Resolve("out/hetzner/mesh.crt")

	// Simulate external deletion — symlink gone from disk but still in manifest.
	if err := os.Remove(linkPath); err != nil {
		t.Fatalf("remove symlink: %v", err)
	}

	// Run 2: remove link_crt from config so the link becomes stale in the manifest.
	dir := filepath.Dir(cfg1.Path)
	cfgPath := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(cfgPath, []byte(`ca "mesh" { name = "mesh" }`), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	cfg2, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load config: %v", err)
	}

	rep, err := Reconcile(cfg2, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Error("Changed = false; stale manifest record was not cleared")
	}
	if len(rep.DeletedLinks) != 1 || rep.DeletedLinks[0] != "out/hetzner/mesh.crt" {
		t.Errorf("DeletedLinks = %v, want [out/hetzner/mesh.crt]", rep.DeletedLinks)
	}

	// Run 3: idempotent — stale record cleared, no further changes.
	rep2, err := Reconcile(cfg2, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	if rep2.Changed {
		t.Error("Changed = true on third run, want idempotent no-op")
	}
	if len(rep2.DeletedLinks) != 0 {
		t.Errorf("DeletedLinks = %v on third run, want empty", rep2.DeletedLinks)
	}
}

func TestReconcile_LinkCrt_MkdirCreatesDir(t *testing.T) {
	// The link dir does not exist; Reconcile should create it.
	cfg := writeConfig(t, `
ca "mesh" {
  name     = "mesh"
  link_crt = ["out/new-dir/nested"]
}`)

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true")
	}
	if _, err := os.Lstat(cfg.Resolve("out/new-dir/nested/mesh.crt")); err != nil {
		t.Fatalf("Lstat new dir link: %v", err)
	}
}

func TestReconcile_DryRun_LinkCrt_NoSideEffects(t *testing.T) {
	cfg := writeConfig(t, linkCrtConfig)

	var out bytes.Buffer
	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion, DryRun: true, Out: &out})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if rep.Changed {
		t.Fatal("Changed = true for dry run, want false")
	}

	// Symlink must not exist — dry run must not write anything.
	linkPath := cfg.Resolve("out/hetzner/mesh.crt")
	if _, err := os.Lstat(linkPath); err == nil {
		t.Error("symlink was created during dry run; dry run must not write anything")
	}

	preview := out.String()
	if !strings.Contains(preview, "create link out/hetzner/mesh.crt") {
		t.Errorf("dry-run output %q missing link line", preview)
	}
}

func TestReconcile_DryRun_LinkCrt_WrongTargetShowsWas(t *testing.T) {
	// Run 1: create the correct symlink.
	cfg1 := writeConfig(t, linkCrtConfig)
	if _, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	linkPath := cfg1.Resolve("out/hetzner/mesh.crt")

	// Replace with a wrong-target symlink.
	if err := os.Remove(linkPath); err != nil {
		t.Fatalf("remove: %v", err)
	}
	const wrongTarget = "/wrong/absolute/target.crt"
	if err := os.Symlink(wrongTarget, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	var out bytes.Buffer
	rep, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion, DryRun: true, Out: &out})
	if err != nil {
		t.Fatalf("dry-run Reconcile: %v", err)
	}
	if rep.Changed {
		t.Fatal("Changed = true for dry run, want false")
	}

	preview := out.String()
	if !strings.Contains(preview, "update link") || !strings.Contains(preview, "was "+wrongTarget) {
		t.Errorf("dry-run output %q missing 'update link ... (was ...)' line", preview)
	}

	// Symlink must still point to the wrong target — dry run must not fix it.
	got, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if got != wrongTarget {
		t.Errorf("symlink target = %q after dry run, want %q (dry run must not modify disk)", got, wrongTarget)
	}
}

func TestReconcile_DryRun_LinkCrt_UpToDate(t *testing.T) {
	cfg := writeConfig(t, linkCrtConfig)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	var out bytes.Buffer
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion, DryRun: true, Out: &out}); err != nil {
		t.Fatalf("dry-run Reconcile: %v", err)
	}
	preview := out.String()
	if !strings.Contains(preview, "up to date; nothing to do") {
		t.Errorf("dry-run output = %q, want 'up to date; nothing to do'", preview)
	}
	if strings.Contains(preview, "link") {
		t.Errorf("dry-run output %q mentions 'link' for up-to-date tree, want none", preview)
	}
}

func TestReconcile_DryRun_LinkCrt_StaleDelete(t *testing.T) {
	// Run 1: create symlink.
	cfg1 := writeConfig(t, linkCrtConfig)
	if _, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	linkPath := cfg1.Resolve("out/hetzner/mesh.crt")

	// Run 2: remove link_crt from config; dry-run the stale cleanup.
	dir := filepath.Dir(cfg1.Path)
	cfgPath := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(cfgPath, []byte(`ca "mesh" { name = "mesh" }`), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	cfg2, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load config: %v", err)
	}

	var out bytes.Buffer
	rep, err := Reconcile(cfg2, Options{Now: fixedNow, GeneratorVersion: genVersion, DryRun: true, Out: &out})
	if err != nil {
		t.Fatalf("dry-run Reconcile: %v", err)
	}
	if rep.Changed {
		t.Fatal("Changed = true for dry run, want false")
	}

	preview := out.String()
	if !strings.Contains(preview, "delete stale link") {
		t.Errorf("dry-run output %q missing 'delete stale link' line", preview)
	}

	// Symlink must still exist — dry run must not delete it.
	if _, err := os.Lstat(linkPath); err != nil {
		t.Errorf("symlink was deleted during dry run: %v", err)
	}
}
