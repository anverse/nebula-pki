package apply

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/manifest"
)

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
	cfg := writeConfig(t, `ca { name = "mesh" }`)

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

	certReal := cfg.Resolve(cfg.CACertPath())
	keyReal := cfg.Resolve(cfg.CAKeyPath())
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
	if m.CA == nil {
		t.Fatal("manifest CA is nil")
	}
	if m.CA.Mode != "generate" || m.CA.Name != "mesh" {
		t.Errorf("CA mode/name = %q/%q, want generate/mesh", m.CA.Mode, m.CA.Name)
	}
	if m.CA.Curve != "25519" || m.CA.Version != 2 {
		t.Errorf("CA curve/version = %q/%d, want 25519/2", m.CA.Curve, m.CA.Version)
	}
	if m.CA.Fingerprint == "" {
		t.Error("CA fingerprint is empty")
	}
	if !m.CA.NotBefore.Equal(fixedNow) {
		t.Errorf("not_before = %s, want %s", m.CA.NotBefore, fixedNow)
	}
	if want := fixedNow.Add(8760 * time.Hour); !m.CA.NotAfter.Equal(want) {
		t.Errorf("not_after = %s, want %s", m.CA.NotAfter, want)
	}
	if m.CA.CertPath != cfg.CACertPath() || m.CA.KeyPath != cfg.CAKeyPath() {
		t.Errorf("CA paths = %q/%q, want %q/%q", m.CA.CertPath, m.CA.KeyPath, cfg.CACertPath(), cfg.CAKeyPath())
	}
	// config_path is relative to the manifest's directory (out/ -> ..).
	if want := filepath.Join("..", "nebula.hcl"); m.ConfigPath != want {
		t.Errorf("config_path = %q, want %q", m.ConfigPath, want)
	}
}

func TestReconcile_SecondRunIsNoopAndByteIdentical(t *testing.T) {
	cfg := writeConfig(t, `ca { name = "mesh" }`)

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	certReal := cfg.Resolve(cfg.CACertPath())
	keyReal := cfg.Resolve(cfg.CAKeyPath())
	manReal := cfg.Resolve(cfg.ManifestPath())

	cert1, key1, man1 := mustRead(t, certReal), mustRead(t, keyReal), mustRead(t, manReal)

	// Second run at a *later* time: a no-op must still write nothing, so the
	// new timestamp must not leak into any artifact.
	rep, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep.Changed {
		t.Fatal("Changed = true on an up-to-date tree, want false")
	}
	if rep.CAName != "mesh" {
		t.Errorf("CAName = %q, want mesh (read back from manifest on noop)", rep.CAName)
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
	cfg := writeConfig(t, `ca { name = "mesh" }`)

	// Pre-seed CA files with no manifest: the tool must refuse to clobber.
	mustSeed(t, cfg.Resolve(cfg.CACertPath()))
	mustSeed(t, cfg.Resolve(cfg.CAKeyPath()))

	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("Reconcile: want error for untracked CA, got nil")
	}
}

// Reference-mode reconcile tests live in reference_test.go.

// TestReconcile_PartialPairRefused covers the half-present pair case:
// the CA cert exists on disk but the key does not (or vice versa) and
// the manifest knows nothing about it. plan.Build classifies this as a
// CA-state error rather than silently regenerating, because regenerating
// would leak whichever artifact survived. v0.0.3 surfaces the failure
// here (apply propagates the plan error).
func TestReconcile_PartialPairRefused(t *testing.T) {
	cfg := writeConfig(t, `ca { name = "mesh" }`)

	// Only the cert pre-exists; key and manifest are absent.
	mustSeed(t, cfg.Resolve(cfg.CACertPath()))

	_, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("Reconcile: want error for half-present untracked pair, got nil")
	}
}

// TestReconcile_CorruptManifestAbortsBeforePlan exercises the early
// error path at apply.go:84-87: manifest.Load surfaces the parse error
// and Reconcile must abort *before* calling plan.Build or pki.GenerateCA.
// We verify the abort is clean by checking that no CA files were
// written.
func TestReconcile_CorruptManifestAbortsBeforePlan(t *testing.T) {
	cfg := writeConfig(t, `ca { name = "mesh" }`)

	// Pre-seed a malformed manifest at the resolved path.
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

	// CA files must not have been written: the abort happened before
	// any pki.GenerateCA call.
	if _, err := os.Stat(cfg.Resolve(cfg.CACertPath())); err == nil {
		t.Error("CA cert was written despite manifest-load failure")
	}
	if _, err := os.Stat(cfg.Resolve(cfg.CAKeyPath())); err == nil {
		t.Error("CA key was written despite manifest-load failure")
	}
}

// TestReconcile_SchemaMismatchRejected pins the schema-version contract
// at the apply boundary (the manifest package is tested in isolation,
// but operators see this through Reconcile, so cover the user-facing
// path explicitly).
func TestReconcile_SchemaMismatchRejected(t *testing.T) {
	cfg := writeConfig(t, `ca { name = "mesh" }`)
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

// TestReconcile_ManifestWriteFailsAfterCAWritten covers the failure
// branch at apply.go:142 — pki.GenerateCA succeeded, both CA artifacts
// were written, but the manifest write itself fails. The contract from
// spec/adr/013 is that the manifest is the commit record: a missing
// manifest after a partial run means the next reconcile must refuse to
// touch the orphaned CA files (they're untracked from its perspective).
//
// We arrange this by pointing the CA artifacts at one writable dir and
// the manifest at a different dir that we make read-only just before
// the call. Reconcile must surface the error; the next run must then
// refuse to clobber the orphan.
func TestReconcile_ManifestWriteFailsAfterCAWritten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: 0500 dirs are still writable")
	}
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")        // CA artifacts land here
	manDir := filepath.Join(root, "manifest") // manifest lands here
	cfgDir := filepath.Join(root, "cfg")      // config file lives here
	for _, d := range []string{caDir, manDir, cfgDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	cfgPath := filepath.Join(cfgDir, "nebula.hcl")
	src := `
ca {
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

	// Make the manifest directory read-only so fsutil.WriteFile fails
	// at the CreateTemp step. CA writes still succeed because their
	// parent directory is untouched.
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

	// Restore permission so we can inspect.
	if err := os.Chmod(manDir, 0o755); err != nil {
		t.Fatalf("chmod restore: %v", err)
	}

	// The CA files were written before the manifest step.
	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); err != nil {
		t.Errorf("CA cert missing after manifest-write failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca.key")); err != nil {
		t.Errorf("CA key missing after manifest-write failure: %v", err)
	}
	// And no manifest landed.
	if _, err := os.Stat(filepath.Join(manDir, "nebula-pki.json")); err == nil {
		t.Error("manifest exists despite write failure")
	}

	// A subsequent reconcile must refuse: the orphan CA files are
	// untracked (no manifest) and overwriting them would leak the prior
	// run's key. This is the safety property the manifest-last ordering
	// is designed to preserve.
	_, err = Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("second Reconcile: want untracked-CA error, got nil")
	}
}

// TestReconcile_SignsHostsAfterCA verifies that host certs are signed,
// written to disk, and recorded in the manifest on a fresh run.
func TestReconcile_SignsHostsAfterCA(t *testing.T) {
	cfg := writeConfig(t, `
ca { name = "mesh" }

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

	// Files must exist.
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

	// Manifest must record both hosts.
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
	}
	// CA fingerprints must match.
	if m.Hosts["alpha"].CAFingerprint != m.CA.Fingerprint {
		t.Errorf("host alpha ca_fingerprint %q != ca fingerprint %q",
			m.Hosts["alpha"].CAFingerprint, m.CA.Fingerprint)
	}
}

// TestReconcile_HostIdempotency verifies that a second reconcile with an
// unchanged config writes nothing — not a single byte, including the
// manifest.
func TestReconcile_HostIdempotency(t *testing.T) {
	cfg := writeConfig(t, `
ca { name = "mesh" }
host "alpha" { networks = ["10.0.0.1/16"] }
`)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	certReal := cfg.Resolve(cfg.CACertPath())
	keyReal := cfg.Resolve(cfg.CAKeyPath())
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

	// Second run at a different time; everything must be byte-identical.
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
// manifestRelConfigPath with an absolute config path. The output tree
// will normally be loaded with a relative path (the CLI uses ./nebula.hcl
// by default), but a user invoking with an absolute -c must still get a
// reproducible, manifest-relative config_path so the committed manifest
// is portable across checkouts. filepath.Rel must succeed because the
// config and the manifest share a common parent (the t.TempDir).
func TestReconcile_AbsoluteConfigPathStillRecordsRelativeManifest(t *testing.T) {
	dir := t.TempDir()
	absConfig := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(absConfig, []byte(`ca { name = "mesh" }`), 0o644); err != nil {
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
	// The manifest is one level deeper than the config (out/), so the
	// relative path is "../nebula.hcl" regardless of where dir lives.
	if want := filepath.Join("..", "nebula.hcl"); m.ConfigPath != want {
		t.Errorf("config_path = %q, want %q (relative even though cfg.Path was absolute)",
			m.ConfigPath, want)
	}
}

// TestReconcile_OutputDir verifies that output_dir writes cert/key to the
// configured directory, that the manifest records the artifact with dir set,
// and that a second run is a noop.
func TestReconcile_OutputDir(t *testing.T) {
	cfg := writeConfig(t, `
ca { name = "mesh" }
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

	// Files must exist on disk under dir-a.
	a := sh.Artifacts[0]
	if _, err := os.Stat(cfg.Resolve(a.CertPath)); err != nil {
		t.Errorf("cert %q missing: %v", a.CertPath, err)
	}
	if _, err := os.Stat(cfg.Resolve(a.KeyPath)); err != nil {
		t.Errorf("key %q missing: %v", a.KeyPath, err)
	}

	// Manifest must record exactly 1 artifact with dir = "dir-a".
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

	// Second run must be a noop.
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
// runs, the report includes the old paths as stale — but only when the old
// files are still present on disk.
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

	// Run 1: write to dir-a.
	cfg1 := loadHCL(`
ca { name = "mesh" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
}
`)
	if _, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	// Verify the old files are on disk.
	oldCert := filepath.Join(tmpDir, "dir-a", "node.crt")
	oldKey := filepath.Join(tmpDir, "dir-a", "node.key")
	if _, err := os.Stat(oldCert); err != nil {
		t.Fatalf("expected old cert to exist: %v", err)
	}

	// Run 2: change to dir-b while old files remain.
	cfg2 := loadHCL(`
ca { name = "mesh" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-b"
}
`)
	rep2, err := Reconcile(cfg2, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	// Both old cert and key should be reported as stale.
	if len(rep2.StaleArtifacts) != 2 {
		t.Fatalf("StaleArtifacts = %v, want 2 paths (old cert + key)", rep2.StaleArtifacts)
	}
	for _, p := range rep2.StaleArtifacts {
		if !strings.HasPrefix(p, "dir-a") {
			t.Errorf("stale path %q does not start with dir-a", p)
		}
	}
	// Old files are still on disk — the tool never deletes them.
	if _, err := os.Stat(oldCert); err != nil {
		t.Errorf("old cert was deleted, want it preserved: %v", err)
	}
	if _, err := os.Stat(oldKey); err != nil {
		t.Errorf("old key was deleted, want it preserved: %v", err)
	}

	// Run 3: old files manually deleted before run — no stale notice.
	if err := os.Remove(oldCert); err != nil {
		t.Fatalf("remove old cert: %v", err)
	}
	if err := os.Remove(oldKey); err != nil {
		t.Fatalf("remove old key: %v", err)
	}
	// cfg2 is unchanged and dir-b files exist → noop, so no re-sign, no stale.
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
// runs triggers a re-sign to the new location, and the third run is a noop.
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

	// Run 1: output_dir = dir-a.
	cfg1 := loadHCL(`
ca { name = "mesh" }
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

	// Run 2: change to dir-b. Plan sees dir-b cert absent → re-sign.
	cfg2 := loadHCL(`
ca { name = "mesh" }
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

	// dir-b must have the new cert/key.
	for _, p := range []string{
		filepath.Join(tmpDir, "dir-b", "node.crt"),
		filepath.Join(tmpDir, "dir-b", "node.key"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s missing: %v", p, err)
		}
	}

	// Manifest records exactly one artifact pointing at dir-b.
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

	// Run 3: must be a noop.
	rep3, err := Reconcile(cfg2, Options{Now: fixedNow.Add(2 * time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	if rep3.Changed {
		t.Fatal("third run: Changed = true, want false (full noop after dir change)")
	}
}

// TestReconcile_OutputDirWithOutCrt verifies that output_dir and out_crt
// compose correctly: the cert lands at <output_dir>/<out_crt> and the key
// at the default <output_dir>/<name>.key.
func TestReconcile_OutputDirWithOutCrt(t *testing.T) {
	cfg := writeConfig(t, `
ca { name = "mesh" }
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

	// Cert uses the overridden filename under output_dir.
	wantCert := filepath.Join("deploy", "nebula.crt")
	wantKey := filepath.Join("deploy", "node.key")
	if a.CertPath != wantCert {
		t.Errorf("CertPath = %q, want %q", a.CertPath, wantCert)
	}
	if a.KeyPath != wantKey {
		t.Errorf("KeyPath = %q, want %q", a.KeyPath, wantKey)
	}

	// Both files exist on disk.
	if _, err := os.Stat(cfg.Resolve(a.CertPath)); err != nil {
		t.Errorf("cert %q missing: %v", a.CertPath, err)
	}
	if _, err := os.Stat(cfg.Resolve(a.KeyPath)); err != nil {
		t.Errorf("key %q missing: %v", a.KeyPath, err)
	}

	// Second run must be a noop.
	rep2, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.Changed {
		t.Fatal("second run: Changed = true, want false (noop)")
	}
}

// TestReconcile_DryRunWritesNothing verifies that DryRun=true builds the plan
// and writes a preview without creating any files on disk.
func TestReconcile_DryRunWritesNothing(t *testing.T) {
	cfg := writeConfig(t, `
ca { name = "mesh" }
host "alpha" { networks = ["10.0.0.1/16"] }
host "beta"  { networks = ["10.0.0.2/16"] }
`)
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

	// No files must exist — check CA, manifest, and every host.
	for _, path := range []string{
		cfg.Resolve(cfg.CACertPath()),
		cfg.Resolve(cfg.CAKeyPath()),
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

	// Preview must list CA, both hosts, and the manifest.
	preview := out.String()
	for _, want := range []string{
		"+ write " + cfg.CACertPath(),
		"+ write " + cfg.CAKeyPath(),
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

// TestReconcile_DryRunOnUpToDateTree verifies that dry-run on a reconciled
// tree prints "up to date; nothing to do" and leaves every file byte-identical.
func TestReconcile_DryRunOnUpToDateTree(t *testing.T) {
	cfg := writeConfig(t, `
ca { name = "mesh" }
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

// TestReconcile_DryRunCAOnly verifies the preview for a config with no hosts:
// only CA cert, key, and manifest lines appear.
func TestReconcile_DryRunCAOnly(t *testing.T) {
	cfg := writeConfig(t, `ca { name = "mesh" }`)
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
		"+ write " + cfg.CACertPath(),
		"+ write " + cfg.CAKeyPath(),
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
