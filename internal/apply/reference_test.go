package apply

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/manifest"
	"github.com/anverse/nebula-pki/internal/pki"
)

// seedReferenceCA mints a real CA via the production pki path and writes
// the cert/key PEM into dir as ca.crt / ca.key. It returns the result so
// tests can assert the recorded fingerprint matches the source CA.
func seedReferenceCA(t *testing.T, dir, src string) *pki.CAResult {
	t.Helper()
	cfg, err := config.Parse("seed.hcl", []byte(src))
	if err != nil {
		t.Fatalf("parse seed CA: %v", err)
	}
	res, err := pki.GenerateCA(cfg.CA, fixedNow)
	if err != nil {
		t.Fatalf("GenerateCA seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), res.CertPEM, 0o600); err != nil {
		t.Fatalf("write seed cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), res.KeyPEM, 0o600); err != nil {
		t.Fatalf("write seed key: %v", err)
	}
	return res
}

// writeRefConfig writes a reference-mode config that points at ca.crt /
// ca.key in the same directory, plus a seeded CA there, and loads it.
func writeRefConfig(t *testing.T, seedSrc string) (*config.Config, *pki.CAResult) {
	t.Helper()
	dir := t.TempDir()
	seed := seedReferenceCA(t, dir, seedSrc)

	path := filepath.Join(dir, "nebula.hcl")
	src := `
ca {
  cert_file = "ca.crt"
  key_file  = "ca.key"
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg, seed
}

func TestReconcile_ReferenceRecordsManifestWithoutTouchingFiles(t *testing.T) {
	cfg, seed := writeRefConfig(t, `ca { name = "ref-mesh" }`)

	certReal := cfg.Resolve(cfg.CACertPath())
	keyReal := cfg.Resolve(cfg.CAKeyPath())
	certBefore := mustRead(t, certReal)
	keyBefore := mustRead(t, keyReal)
	certStatBefore := mustStat(t, certReal)
	keyStatBefore := mustStat(t, keyReal)

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true on the first reference run")
	}
	if rep.CAMode != "reference" {
		t.Errorf("CAMode = %q, want reference", rep.CAMode)
	}
	if rep.CAName != "ref-mesh" {
		t.Errorf("CAName = %q, want ref-mesh", rep.CAName)
	}

	// The referenced files must be byte-for-byte untouched, and their
	// modtimes unchanged (the tool never rewrote them).
	if !bytes.Equal(mustRead(t, certReal), certBefore) {
		t.Error("referenced CA cert was modified")
	}
	if !bytes.Equal(mustRead(t, keyReal), keyBefore) {
		t.Error("referenced CA key was modified")
	}
	if !mustStat(t, certReal).ModTime().Equal(certStatBefore.ModTime()) {
		t.Error("referenced CA cert modtime changed; the file was rewritten")
	}
	if !mustStat(t, keyReal).ModTime().Equal(keyStatBefore.ModTime()) {
		t.Error("referenced CA key modtime changed; the file was rewritten")
	}

	// No out/ tree was created for the CA.
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfg.Path), "out", "ca")); err == nil {
		t.Error("out/ca exists; reference mode must not write under out/")
	}

	// The manifest records the reference CA.
	manReal := cfg.Resolve(cfg.ManifestPath())
	assertMode(t, manReal, 0o644)
	m, err := manifest.Load(manReal)
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.CA == nil {
		t.Fatal("manifest CA is nil")
	}
	if m.CA.Mode != "reference" {
		t.Errorf("CA mode = %q, want reference", m.CA.Mode)
	}
	if m.CA.Name != "ref-mesh" {
		t.Errorf("CA name = %q, want ref-mesh", m.CA.Name)
	}
	if m.CA.Fingerprint != seed.Fingerprint {
		t.Errorf("CA fingerprint = %q, want %q (the source CA's)", m.CA.Fingerprint, seed.Fingerprint)
	}
	// Paths point at the referenced files, not out/ca defaults.
	if m.CA.CertPath != "ca.crt" || m.CA.KeyPath != "ca.key" {
		t.Errorf("CA paths = %q/%q, want ca.crt/ca.key", m.CA.CertPath, m.CA.KeyPath)
	}
	if !m.CA.NotAfter.Equal(seed.NotAfter.UTC()) {
		t.Errorf("CA not_after = %s, want %s", m.CA.NotAfter, seed.NotAfter.UTC())
	}
}

// TestReconcile_ReferenceIdempotentRerun is the central idempotency
// property for reference mode: a second run against an unchanged
// referenced CA writes nothing and leaves the manifest byte-identical.
func TestReconcile_ReferenceIdempotentRerun(t *testing.T) {
	cfg, _ := writeRefConfig(t, `ca { name = "ref-mesh" }`)

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	manReal := cfg.Resolve(cfg.ManifestPath())
	first := mustRead(t, manReal)

	// Second run at a *different* wall-clock time. generated_at must not
	// drift, because nothing changed.
	rep, err := Reconcile(cfg, Options{Now: fixedNow.Add(48 * time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep.Changed {
		t.Error("Changed = true on an unchanged reference rerun, want false")
	}
	if !bytes.Equal(mustRead(t, manReal), first) {
		t.Error("manifest changed on an idempotent reference rerun; not byte-identical")
	}
}

// TestReconcile_ReferenceDetectsSwappedCA confirms the rebuild-and-compare
// idempotency check is not blind to a changed referenced file: if the
// operator points cert_file/key_file at a different CA, the manifest's
// fingerprint must update.
func TestReconcile_ReferenceDetectsSwappedCA(t *testing.T) {
	cfg, first := writeRefConfig(t, `ca { name = "first-ca" }`)

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	// Swap the referenced files for a different CA in place.
	dir := filepath.Dir(cfg.Path)
	second := seedReferenceCA(t, dir, `ca { name = "second-ca" }`)
	if first.Fingerprint == second.Fingerprint {
		t.Fatal("test setup: the two CAs share a fingerprint")
	}

	rep, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false after the referenced CA was swapped, want true")
	}
	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.CA.Fingerprint != second.Fingerprint {
		t.Errorf("CA fingerprint = %q, want the swapped-in CA's %q", m.CA.Fingerprint, second.Fingerprint)
	}
	if m.CA.Name != "second-ca" {
		t.Errorf("CA name = %q, want second-ca", m.CA.Name)
	}
}

func TestReconcile_ReferenceMissingFilesErrors(t *testing.T) {
	// Reference config whose files do not exist.
	dir := t.TempDir()
	path := filepath.Join(dir, "nebula.hcl")
	src := `
ca {
  cert_file = "absent.crt"
  key_file  = "absent.key"
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	_, err = Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err == nil {
		t.Fatal("Reconcile: want error when referenced files are absent, got nil")
	}
	if !strings.Contains(err.Error(), "referenced CA not found") {
		t.Errorf("error = %q, want it to mention 'referenced CA not found'", err.Error())
	}
	// Nothing was written.
	if _, err := os.Stat(cfg.Resolve(cfg.ManifestPath())); err == nil {
		t.Error("manifest written despite missing referenced CA")
	}
}

// TestReconcile_ReferenceInvalidCAErrors confirms a structurally valid
// file that is not a usable CA pair (here: a corrupt cert) fails the run
// rather than producing a bogus manifest.
func TestReconcile_ReferenceInvalidCAErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("not pem\n"), 0o600); err != nil {
		t.Fatalf("write bad cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("not pem\n"), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	path := filepath.Join(dir, "nebula.hcl")
	src := `
ca {
  cert_file = "ca.crt"
  key_file  = "ca.key"
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err == nil {
		t.Fatal("Reconcile: want error for an invalid referenced CA, got nil")
	}
}

// TestReconcile_ReferenceExpiredWarnsButRecords drives the expiry path:
// the CA is recorded (Changed=true, manifest written) and a warning is
// emitted to the configured Warn writer. Expiry is decided against
// Options.Now (threaded into pki.LoadReferenceCA), so this is deterministic
// and does not depend on the wall clock advancing.
func TestReconcile_ReferenceExpiredWarnsButRecords(t *testing.T) {
	cfg, seed := writeRefConfig(t, `
ca {
  name     = "old-mesh"
  duration = "1h"
}`)

	// Reconcile two hours after issuance: the 1h CA is expired.
	var warn bytes.Buffer
	rep, err := Reconcile(cfg, Options{
		Now:              fixedNow.Add(2 * time.Hour),
		GeneratorVersion: genVersion,
		Warn:             &warn,
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Error("Changed = false, want true (an expired reference CA is still recorded)")
	}
	if !strings.Contains(warn.String(), "expired") {
		t.Errorf("warn output = %q, want it to mention 'expired'", warn.String())
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.CA == nil || m.CA.Fingerprint != seed.Fingerprint {
		t.Error("expired CA not recorded with its fingerprint")
	}
}

// TestReconcile_ReferenceValidEmitsNoExpiryWarning is the deterministic
// counterpart to the expired case and the regression guard for the
// clock-injection fix: a CA evaluated at an Options.Now inside its
// validity window must never be flagged expired, regardless of the real
// wall-clock time when the test runs. Before expiry was threaded through
// Options.Now, this verdict depended on time.Now() and would have started
// warning once real time passed the fixture's NotAfter.
func TestReconcile_ReferenceValidEmitsNoExpiryWarning(t *testing.T) {
	// 1h CA, evaluated 30 minutes after issuance: comfortably valid.
	cfg, _ := writeRefConfig(t, `
ca {
  name     = "fresh-mesh"
  duration = "1h"
}`)

	var warn bytes.Buffer
	rep, err := Reconcile(cfg, Options{
		Now:              fixedNow.Add(30 * time.Minute),
		GeneratorVersion: genVersion,
		Warn:             &warn,
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Error("Changed = false, want true on the first reference run")
	}
	if warn.Len() != 0 {
		t.Errorf("warn output = %q, want empty for a valid CA", warn.String())
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info
}
