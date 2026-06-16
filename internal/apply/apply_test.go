package apply

import (
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
	if rep.HostsParsed != 0 {
		t.Errorf("HostsParsed = %d, want 0", rep.HostsParsed)
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

// TestReconcile_HostsParsedCount surfaces v0.0.3's parse-but-don't-sign
// behaviour. The number of host blocks in HCL must show up in
// Report.HostsParsed verbatim — that is the signal the CLI relies on
// for the "N host(s) parsed but not yet reconciled" warning.
func TestReconcile_HostsParsedCount(t *testing.T) {
	cfg := writeConfig(t, `
ca { name = "mesh" }

host "alpha" { networks = ["10.0.0.1/16"] }
host "beta"  { networks = ["10.0.0.2/16"] }
host "gamma" { networks = ["10.0.0.3/16"] }
`)
	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if rep.HostsParsed != 3 {
		t.Errorf("HostsParsed = %d, want 3", rep.HostsParsed)
	}
	// And: hosts must NOT appear in the manifest yet (v0.0.3 stops at the
	// CA). Schema-stability is enforced by manifest.New() initialising
	// Hosts to an empty (non-nil) map.
	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if len(m.Hosts) != 0 {
		t.Errorf("manifest hosts populated in v0.0.3: %+v", m.Hosts)
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
