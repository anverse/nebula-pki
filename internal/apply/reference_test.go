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
	res, err := pki.GenerateCA(cfg.CAs[0], fixedNow)
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
ca "ref" {
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
	cfg, seed := writeRefConfig(t, `ca "mesh" { name = "ref-mesh" }`)

	certReal := cfg.Resolve(cfg.CACertPathForCA(cfg.CAs[0]))
	keyReal := cfg.Resolve(cfg.CAKeyPathForCA(cfg.CAs[0]))
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
	if len(rep.CAs) != 1 {
		t.Fatalf("CAs = %d, want 1", len(rep.CAs))
	}
	if rep.CAs[0].Mode != "reference" {
		t.Errorf("CAs[0].Mode = %q, want reference", rep.CAs[0].Mode)
	}
	if rep.CAs[0].Name != "ref-mesh" {
		t.Errorf("CAs[0].Name = %q, want ref-mesh", rep.CAs[0].Name)
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

	// The reference CA cert/key must not be written to the default out/ca/
	// location; reference mode reads the operator's files in place.
	outCA := filepath.Join(filepath.Dir(cfg.Path), "out", "ca")
	if _, err := os.Stat(filepath.Join(outCA, "ref.crt")); err == nil {
		t.Error("out/ca/ref.crt exists; reference mode must not write default CA paths")
	}
	if _, err := os.Stat(filepath.Join(outCA, "ref.key")); err == nil {
		t.Error("out/ca/ref.key exists; reference mode must not write default CA paths")
	}

	// The manifest records the reference CA.
	manReal := cfg.Resolve(cfg.ManifestPath())
	assertMode(t, manReal, 0o644)
	m, err := manifest.Load(manReal)
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	mCA := m.CAs["ref"]
	if mCA == nil {
		t.Fatal("manifest CAs[ref] is nil")
	}
	if mCA.Mode != "reference" {
		t.Errorf("CA mode = %q, want reference", mCA.Mode)
	}
	if mCA.Name != "ref-mesh" {
		t.Errorf("CA name = %q, want ref-mesh", mCA.Name)
	}
	if mCA.Fingerprint != seed.Fingerprint {
		t.Errorf("CA fingerprint = %q, want %q (the source CA's)", mCA.Fingerprint, seed.Fingerprint)
	}
	// Paths point at the referenced files, not out/ca defaults.
	if mCA.CertPath != "ca.crt" || mCA.KeyPath != "ca.key" {
		t.Errorf("CA paths = %q/%q, want ca.crt/ca.key", mCA.CertPath, mCA.KeyPath)
	}
	if !mCA.NotAfter.Equal(seed.NotAfter.UTC()) {
		t.Errorf("CA not_after = %s, want %s", mCA.NotAfter, seed.NotAfter.UTC())
	}
}

// TestReconcile_ReferenceBundleContent verifies that the trust bundle is
// written when a reference-mode CA is used, that it contains exactly the
// referenced CA cert, that the manifest records the fingerprint, and that a
// second run is idempotent (bundle not rewritten).
func TestReconcile_ReferenceBundleContent(t *testing.T) {
	cfg, seed := writeRefConfig(t, `ca "mesh" { name = "ref-mesh" }`)

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.TrustBundleWritten {
		t.Error("TrustBundleWritten = false on first reference run, want true")
	}

	// Bundle content must equal the referenced CA cert exactly.
	bundleReal := cfg.Resolve(cfg.TrustBundlePath())
	if _, err := os.Stat(bundleReal); err != nil {
		t.Fatalf("bundle.crt missing: %v", err)
	}
	bundleBytes := mustRead(t, bundleReal)
	refCertBytes := mustRead(t, cfg.Resolve(cfg.CACertPathForCA(cfg.CAs[0])))
	if !bytes.Equal(bundleBytes, refCertBytes) {
		t.Error("trust bundle does not equal the referenced CA cert")
	}

	// Manifest must record the trust bundle with the reference CA fingerprint.
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
	if len(m.TrustBundle.CAFingerprints) != 1 || m.TrustBundle.CAFingerprints[0] != seed.Fingerprint {
		t.Errorf("TrustBundle.CAFingerprints = %v, want [%s]", m.TrustBundle.CAFingerprints, seed.Fingerprint)
	}

	// Second run: bundle must not be rewritten (idempotent).
	rep2, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.TrustBundleWritten {
		t.Error("TrustBundleWritten = true on second reference run, want false (idempotent)")
	}
	if !bytes.Equal(mustRead(t, bundleReal), bundleBytes) {
		t.Error("bundle.crt changed on idempotent reference rerun")
	}
}

// TestReconcile_ReferenceIdempotentRerun is the central idempotency
// property for reference mode: a second run against an unchanged
// referenced CA writes nothing and leaves the manifest byte-identical.
func TestReconcile_ReferenceIdempotentRerun(t *testing.T) {
	cfg, _ := writeRefConfig(t, `ca "mesh" { name = "ref-mesh" }`)

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
	cfg, first := writeRefConfig(t, `ca "mesh" { name = "first-ca" }`)

	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	// Swap the referenced files for a different CA in place.
	dir := filepath.Dir(cfg.Path)
	second := seedReferenceCA(t, dir, `ca "mesh" { name = "second-ca" }`)
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
	mCA := m.CAs["ref"]
	if mCA == nil {
		t.Fatal("manifest CAs[ref] is nil")
	}
	if mCA.Fingerprint != second.Fingerprint {
		t.Errorf("CA fingerprint = %q, want the swapped-in CA's %q", mCA.Fingerprint, second.Fingerprint)
	}
	if mCA.Name != "second-ca" {
		t.Errorf("CA name = %q, want second-ca", mCA.Name)
	}

	// The trust bundle must have been rewritten to contain the second CA's cert.
	if !rep.TrustBundleWritten {
		t.Error("TrustBundleWritten = false after CA swap, want true")
	}
	bundleBytes := mustRead(t, cfg.Resolve(cfg.TrustBundlePath()))
	secondCertBytes := mustRead(t, cfg.Resolve(cfg.CACertPathForCA(cfg.CAs[0])))
	if !bytes.Equal(bundleBytes, secondCertBytes) {
		t.Error("trust bundle does not contain the swapped-in CA cert")
	}
}

func TestReconcile_ReferenceMissingFilesErrors(t *testing.T) {
	// Reference config whose files do not exist.
	dir := t.TempDir()
	path := filepath.Join(dir, "nebula.hcl")
	src := `
ca "ref" {
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
ca "ref" {
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
ca "mesh" {
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
	mCA := m.CAs["ref"]
	if mCA == nil || mCA.Fingerprint != seed.Fingerprint {
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
ca "mesh" {
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

// TestReconcile_ReferenceWithHosts verifies that reference mode signs host
// certs using the operator-supplied CA (the CA files themselves are never
// rewritten) and that a second run is byte-identical.
func TestReconcile_ReferenceWithHosts(t *testing.T) {
	dir := t.TempDir()
	seed := seedReferenceCA(t, dir, `ca "mesh" { name = "ref-mesh" }`)

	path := filepath.Join(dir, "nebula.hcl")
	src := `
ca "ref" {
  cert_file = "ca.crt"
  key_file  = "ca.key"
}
host "alpha" {
  networks = ["10.0.0.1/16"]
}
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false on first reference+host run, want true")
	}
	if len(rep.SignedHosts) != 1 || rep.SignedHosts[0].Label != "alpha" {
		t.Errorf("SignedHosts = %v, want [{alpha ...}]", rep.SignedHosts)
	}

	// Host cert and key must exist.
	hostCertReal := cfg.Resolve(rep.SignedHosts[0].Artifacts[0].CertPath)
	hostKeyReal := cfg.Resolve(rep.SignedHosts[0].Artifacts[0].KeyPath)
	if _, err := os.Stat(hostCertReal); err != nil {
		t.Errorf("host cert missing: %v", err)
	}
	if _, err := os.Stat(hostKeyReal); err != nil {
		t.Errorf("host key missing: %v", err)
	}

	// Manifest host record must carry the CA fingerprint.
	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if h, ok := m.Hosts["alpha"]; !ok {
		t.Fatal("manifest missing host alpha")
	} else if h.CAFingerprint != seed.Fingerprint {
		t.Errorf("host ca_fingerprint = %q, want %q", h.CAFingerprint, seed.Fingerprint)
	}

	// Second run must be a noop; files and manifest byte-identical.
	manBefore := mustRead(t, cfg.Resolve(cfg.ManifestPath()))
	certBefore := mustRead(t, hostCertReal)
	keyBefore := mustRead(t, hostKeyReal)

	rep2, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.Changed {
		t.Fatal("Changed = true on second reference+host run, want false")
	}
	if !bytes.Equal(mustRead(t, cfg.Resolve(cfg.ManifestPath())), manBefore) {
		t.Error("manifest changed on idempotent reference+host rerun")
	}
	if !bytes.Equal(mustRead(t, hostCertReal), certBefore) {
		t.Error("host cert changed on idempotent reference+host rerun")
	}
	if !bytes.Equal(mustRead(t, hostKeyReal), keyBefore) {
		t.Error("host key changed on idempotent reference+host rerun")
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
