package apply

// Tests for trust bundle membership, RenewBefore in manifest,
// deadline computation, and the full CA-rotation scenario.

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/crypto"
	"github.com/anverse/nebula-pki/internal/manifest"
	"github.com/anverse/nebula-pki/internal/plan"
)

// ---------------------------------------------------------------------------
// Trust bundle: explicit membership
// ---------------------------------------------------------------------------

func TestReconcile_NonMemberCA_ExcludedFromBundle(t *testing.T) {
	// Two CAs: "current" not listed in ca_refs, "next" listed and default.
	// The bundle must contain only "next"'s cert.
	src := `
trust_bundle "main" { ca_refs = [ca.next] }
ca "current" {
  name = "old-mesh"
}
ca "next" {
  name    = "new-mesh"
  default = true
}
`
	cfg := writeConfig(t, src)

	rep, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !rep.Changed {
		t.Fatal("Changed = false, want true on first run")
	}

	// The non-member CA keeps its manifest record.
	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.CAs["current"] == nil {
		t.Error("manifest CAs[current] = nil, want the non-member CA recorded")
	}
	if m.TrustBundle == nil || m.TrustBundle.Label != "main" {
		t.Errorf("TrustBundle = %+v, want label main", m.TrustBundle)
	}

	// Bundle fingerprints must list only "next".
	if m.TrustBundle == nil {
		t.Fatal("TrustBundle is nil")
	}
	if len(m.TrustBundle.CAFingerprints) != 1 {
		t.Fatalf("CAFingerprints len = %d, want 1 (only 'next')", len(m.TrustBundle.CAFingerprints))
	}
	if m.TrustBundle.CAFingerprints[0] != m.CAs["next"].Fingerprint {
		t.Errorf("CAFingerprints[0] = %q, want 'next' fingerprint %q",
			m.TrustBundle.CAFingerprints[0], m.CAs["next"].Fingerprint)
	}
}

func TestReconcile_NonMemberCA_BundleIdempotent(t *testing.T) {
	src := `
trust_bundle "main" { ca_refs = [ca.next] }
ca "current" {
  name = "old-mesh"
}
ca "next" {
  name    = "new-mesh"
  default = true
}
`
	cfg := writeConfig(t, src)

	// First run
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	// Second run must be a noop
	rep2, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.Changed {
		t.Error("Changed = true on second run, want false (idempotent)")
	}
}

// ---------------------------------------------------------------------------
// RenewBefore recorded in manifest
// ---------------------------------------------------------------------------

func TestReconcile_RenewBefore_RecordedInManifest(t *testing.T) {
	src := `
ca "mesh" { name = "mesh" }
cert "alpha" {
  networks     = ["10.0.0.1/16"]
  renew_before = "720h"
}
`
	cfg := writeConfig(t, src)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.Certs["alpha"].RenewBefore != "720h0m0s" {
		t.Errorf("RenewBefore = %q, want '720h0m0s'", m.Certs["alpha"].RenewBefore)
	}
}

func TestReconcile_RenewBefore_InheritedFromCA_RecordedInManifest(t *testing.T) {
	src := `
ca "mesh" {
  name         = "mesh"
  renew_before = "48h"
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`
	cfg := writeConfig(t, src)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.Certs["alpha"].RenewBefore != "48h0m0s" {
		t.Errorf("RenewBefore = %q, want '48h0m0s'", m.Certs["alpha"].RenewBefore)
	}
}

func TestReconcile_NoRenewBefore_OmittedFromManifest(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	m, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m.Certs["alpha"].RenewBefore != "" {
		t.Errorf("RenewBefore = %q, want empty when not configured", m.Certs["alpha"].RenewBefore)
	}
}

// ---------------------------------------------------------------------------
// Renewal re-sign
// ---------------------------------------------------------------------------

func TestReconcile_RenewalWindow_CertResigned(t *testing.T) {
	// Sign a cert with duration = 100h, renew_before = 50h.
	// On the first run at T=0 the cert is fresh.
	// At T=60h (inside window) the cert must be re-signed.
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	src := `
ca "mesh" { name = "mesh" }
cert "alpha" {
  networks     = ["10.0.0.1/16"]
  duration     = "100h"
  renew_before = "50h"
}
`
	cfg := writeConfig(t, src)

	// First run: sign at T=0.
	if _, err := Reconcile(cfg, Options{Now: baseTime, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	m1, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load after first run: %v", err)
	}
	notAfter1 := m1.Certs["alpha"].NotAfter

	// Second run at T+10h: outside window (not_after=T+100h, window=T+50h).
	rep2, err := Reconcile(cfg, Options{Now: baseTime.Add(10 * time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if rep2.Changed {
		t.Error("Changed = true at T+10h, want false (still outside renewal window)")
	}

	// Third run at T+60h: inside window → must re-sign.
	rep3, err := Reconcile(cfg, Options{Now: baseTime.Add(60 * time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	if !rep3.Changed {
		t.Fatal("Changed = false at T+60h, want true (inside renewal window)")
	}
	m3, err := manifest.Load(cfg.Resolve(cfg.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load after third run: %v", err)
	}
	notAfter3 := m3.Certs["alpha"].NotAfter
	if !notAfter3.After(notAfter1) {
		t.Errorf("not_after after re-sign (%v) is not later than original (%v)", notAfter3, notAfter1)
	}

	// Fourth run at T+60h again: just re-signed, now outside window again → noop.
	rep4, err := Reconcile(cfg, Options{Now: baseTime.Add(60 * time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("fourth Reconcile: %v", err)
	}
	if rep4.Changed {
		t.Error("Changed = true on immediate re-run, want false (just renewed)")
	}
}

// ---------------------------------------------------------------------------
// computeDeadlines unit tests
// ---------------------------------------------------------------------------

func TestComputeDeadlines_NoCerts_CAExpiryIsDeadline(t *testing.T) {
	caExpiry := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{NotAfter: caExpiry}

	d := computeDeadlines(cfg, m, now)
	if d.NextDeadline.IsZero() {
		t.Fatal("NextDeadline is zero, want CA expiry")
	}
	if !d.NextDeadline.Equal(caExpiry) {
		t.Errorf("NextDeadline = %v, want %v", d.NextDeadline, caExpiry)
	}
	if !strings.Contains(d.NextDeadlineDesc, "expires") {
		t.Errorf("NextDeadlineDesc = %q, want it to mention 'expires'", d.NextDeadlineDesc)
	}
}

func TestComputeDeadlines_CertWithRenewBefore_WindowEntryIsDeadline(t *testing.T) {
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC) // cert not_after
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// renew_before = 720h (30 days) → window entry = notAfter - 30d
	windowEntry := notAfter.Add(-720 * time.Hour)

	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
cert "alpha" {
  networks     = ["10.0.0.1/16"]
  renew_before = "720h"
}
`)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{NotAfter: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)}
	m.Certs["alpha"] = manifest.Cert{Name: "alpha", CA: "mesh", NotAfter: notAfter}

	d := computeDeadlines(cfg, m, now)
	if !d.NextDeadline.Equal(windowEntry) {
		t.Errorf("NextDeadline = %v, want window entry %v", d.NextDeadline, windowEntry)
	}
	if !strings.Contains(d.NextDeadlineDesc, "renewal window") {
		t.Errorf("NextDeadlineDesc = %q, want it to mention 'renewal window'", d.NextDeadlineDesc)
	}
}

func TestComputeDeadlines_SoonItems_WithinWindow(t *testing.T) {
	// Cert expires in 30 days, within the 60-day soon window.
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	certExpiry := now.Add(30 * 24 * time.Hour)

	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	m.Certs["alpha"] = manifest.Cert{Name: "alpha", CA: "mesh", NotAfter: certExpiry}

	d := computeDeadlines(cfg, m, now)
	// SoonItems should include alpha.
	found := false
	for _, item := range d.SoonItems {
		if item.Label == "alpha" {
			found = true
		}
	}
	if !found {
		t.Errorf("SoonItems = %+v, want 'alpha' in the list (expires in 30d < 60d window)", d.SoonItems)
	}
}

func TestComputeDeadlines_OverdueItem_PastWindowEntry(t *testing.T) {
	// Cert's window entry is in the past but it wasn't re-signed (e.g. noop run).
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	windowEntry := notAfter.Add(-720 * time.Hour)
	// now is 1 day after window entry
	now := windowEntry.Add(24 * time.Hour)

	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
cert "alpha" {
  networks     = ["10.0.0.1/16"]
  renew_before = "720h"
}
`)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{NotAfter: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)}
	m.Certs["alpha"] = manifest.Cert{Name: "alpha", CA: "mesh", NotAfter: notAfter}

	d := computeDeadlines(cfg, m, now)
	found := false
	for _, item := range d.OverdueItems {
		if item.Label == "alpha" {
			found = true
		}
	}
	if !found {
		t.Errorf("OverdueItems = %+v, want 'alpha' (past window entry and not re-signed)", d.OverdueItems)
	}
}

func TestComputeDeadlines_NonMemberCA_Counts(t *testing.T) {
	// Every declared CA counts in the deadline report, independent of trust
	// bundle membership (ADR-017 2026-10-02 amendment).
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	oldExpiry := now.Add(10 * 24 * time.Hour)
	newExpiry := now.Add(365 * 24 * time.Hour)

	cfg := writeConfig(t, `
trust_bundle "main" { ca_refs = [ca.new] }
ca "old" {
  name = "old"
}
ca "new" {
  name    = "new"
  default = true
}
`)
	m := manifest.New()
	m.CAs["old"] = &manifest.CA{NotAfter: oldExpiry}
	m.CAs["new"] = &manifest.CA{NotAfter: newExpiry}

	d := computeDeadlines(cfg, m, now)
	if !d.NextDeadline.Equal(oldExpiry) {
		t.Errorf("NextDeadline = %v, want non-member CA expiry %v", d.NextDeadline, oldExpiry)
	}
}

func TestComputeDeadlines_EmptyManifest_ZeroDeadline(t *testing.T) {
	cfg := writeConfig(t, `ca "mesh" { name = "mesh" }`)
	m := manifest.New() // no CA record yet
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	d := computeDeadlines(cfg, m, now)
	if !d.NextDeadline.IsZero() {
		t.Errorf("NextDeadline = %v, want zero (no certificates yet)", d.NextDeadline)
	}
}

// ---------------------------------------------------------------------------
// CA rotation: full scenario
// ---------------------------------------------------------------------------

func TestReconcile_CARotation_FullScenario(t *testing.T) {
	// Step 1: single CA "current"
	src1 := `
trust_bundle "main" { ca_refs = [ca.current] }
ca "current" {
  name    = "mesh-2026"
  default = true
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`
	cfg1 := writeConfig(t, src1)
	rep1, err := Reconcile(cfg1, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("step1 Reconcile: %v", err)
	}
	if !rep1.Changed {
		t.Fatal("step1: Changed = false, want true")
	}
	m1, _ := manifest.Load(cfg1.Resolve(cfg1.ManifestPath()))
	alphaFP1 := m1.Certs["alpha"].CAFingerprint

	// Step 2: add "next" CA (default stays on "current")
	// We simulate this as a new config in the same dir.
	// To keep this test self-contained, we write a separate config.
	// Step 2 adds "next" with no default change; certs stay on "current".
	src2 := `
trust_bundle "main" { ca_refs = [ca.current, ca.next] }
ca "current" {
  name    = "mesh-2026"
  default = true
}
ca "next" {
  name = "mesh-2027"
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`
	// Reload from same dir (same manifest, same artifacts).
	cfg2 := reloadConfig(t, cfg1, src2)
	rep2, err := Reconcile(cfg2, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("step2 Reconcile: %v", err)
	}
	if !rep2.Changed {
		t.Fatal("step2: Changed = false, want true (new CA 'next' generated)")
	}
	m2, _ := manifest.Load(cfg2.Resolve(cfg2.ManifestPath()))
	if m2.CAs["next"] == nil {
		t.Fatal("step2: 'next' CA not in manifest")
	}
	// Bundle must contain both CAs.
	if len(m2.TrustBundle.CAFingerprints) != 2 {
		t.Fatalf("step2: bundle has %d fingerprints, want 2", len(m2.TrustBundle.CAFingerprints))
	}
	// alpha still signed under "current"
	m2alpha := m2.Certs["alpha"]
	if m2alpha.CA != "current" {
		t.Errorf("step2: alpha.ca = %q, want 'current'", m2alpha.CA)
	}

	// Step 3: move default = true to "next" → certs re-signed.
	src3 := `
trust_bundle "main" { ca_refs = [ca.current, ca.next] }
ca "current" {
  name = "mesh-2026"
}
ca "next" {
  name    = "mesh-2027"
  default = true
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`
	cfg3 := reloadConfig(t, cfg2, src3)
	rep3, err := Reconcile(cfg3, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("step3 Reconcile: %v", err)
	}
	if !rep3.Changed {
		t.Fatal("step3: Changed = false, want true (certs re-signed under 'next')")
	}
	m3, _ := manifest.Load(cfg3.Resolve(cfg3.ManifestPath()))
	if m3.Certs["alpha"].CA != "next" {
		t.Errorf("step3: alpha.ca = %q, want 'next'", m3.Certs["alpha"].CA)
	}
	alphaFP3 := m3.Certs["alpha"].CAFingerprint
	if alphaFP3 == alphaFP1 {
		t.Error("step3: alpha CA fingerprint unchanged, want new fingerprint (signed under 'next')")
	}

	// Step 4: drop "current" from ca_refs → bundle shrinks to just "next".
	src4 := `
trust_bundle "main" { ca_refs = [ca.next] }
ca "current" {
  name = "mesh-2026"
}
ca "next" {
  name    = "mesh-2027"
  default = true
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`
	cfg4 := reloadConfig(t, cfg3, src4)
	rep4, err := Reconcile(cfg4, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("step4 Reconcile: %v", err)
	}
	if !rep4.Changed {
		t.Fatal("step4: Changed = false, want true (bundle dropped 'current')")
	}
	m4, _ := manifest.Load(cfg4.Resolve(cfg4.ManifestPath()))
	if len(m4.TrustBundle.CAFingerprints) != 1 {
		t.Fatalf("step4: bundle has %d fingerprints, want 1 (only 'next')", len(m4.TrustBundle.CAFingerprints))
	}
	if m4.TrustBundle.CAFingerprints[0] != m4.CAs["next"].Fingerprint {
		t.Error("step4: bundle fingerprint is not 'next', want 'next' only")
	}
	if m4.CAs["current"] == nil {
		t.Error("step4: manifest CAs[current] = nil, want the dropped CA still recorded")
	}

	// Step 5: idempotency; re-run step 4 config must be a noop.
	cfg5 := reloadConfig(t, cfg4, src4)
	rep5, err := Reconcile(cfg5, Options{Now: fixedNow, GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("step5 Reconcile: %v", err)
	}
	if rep5.Changed {
		t.Error("step5: Changed = true, want false (idempotent after dropping 'current')")
	}
}

// ---------------------------------------------------------------------------
// writeDryRunPlan: dropping a bundle member rewrites the bundle
// ---------------------------------------------------------------------------

func TestWriteDryRunPlan_BundleMemberDropped(t *testing.T) {
	// Walk through the rotation steps so that by step 4 (drop the old CA from
	// ca_refs) all certs are already signed with the new CA and no CA or cert
	// changes. The dry run must still list the bundle rewrite.

	// Step 1: single CA "current" as default.
	cfg := writeConfig(t, `
trust_bundle "main" { ca_refs = [ca.current] }
ca "current" {
  name    = "mesh-2026"
  default = true
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("step1 Reconcile: %v", err)
	}

	// Step 2: add "next" (default stays on "current"); bundle grows to 2 CAs.
	cfg = reloadConfig(t, cfg, `
trust_bundle "main" { ca_refs = [ca.current, ca.next] }
ca "current" {
  name    = "mesh-2026"
  default = true
}
ca "next" { name = "mesh-2027" }
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("step2 Reconcile: %v", err)
	}

	// Step 3: promote "next" to default; certs are re-signed with "next".
	cfg = reloadConfig(t, cfg, `
trust_bundle "main" { ca_refs = [ca.current, ca.next] }
ca "current" { name = "mesh-2026" }
ca "next" {
  name    = "mesh-2027"
  default = true
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("step3 Reconcile: %v", err)
	}

	// Step 4 config: drop "current" from ca_refs. Certs are already on
	// "next", yet the bundle must shrink from 2 to 1 CA.
	cfgDrop := reloadConfig(t, cfg, `
trust_bundle "main" { ca_refs = [ca.next] }
ca "current" {
  name = "mesh-2026"
}
ca "next" {
  name    = "mesh-2027"
  default = true
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`)

	current, err := manifest.Load(cfgDrop.Resolve(cfgDrop.ManifestPath()))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	exists := func(p string) bool {
		_, statErr := os.Stat(cfgDrop.Resolve(p))
		return statErr == nil
	}
	p, err := plan.Build(cfgDrop, current, fixedNow, exists, plan.Options{})
	if err != nil {
		t.Fatalf("plan.Build: %v", err)
	}
	// Dry-run must list the bundle write because membership changed 2→1.
	dropEnc, err := crypto.New(cfgDrop.Storage.Encryption)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	var buf bytes.Buffer
	writeDryRunPlan(&buf, cfgDrop, dropEnc, p, current, exists)
	out := buf.String()
	if strings.Contains(out, "up to date; nothing to do") {
		t.Errorf("dry-run = %q; want bundle write listed (dropped member shrinks bundle)", out)
	}
	if !strings.Contains(out, cfgDrop.TrustBundlePath()) {
		t.Errorf("dry-run = %q; want %q in output", out, cfgDrop.TrustBundlePath())
	}

	// After the real run the manifest records 1 member; dry-run must be a noop.
	if _, err := Reconcile(cfgDrop, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("drop Reconcile: %v", err)
	}
	current2, _ := manifest.Load(cfgDrop.Resolve(cfgDrop.ManifestPath()))

	p2, err := plan.Build(cfgDrop, current2, fixedNow, exists, plan.Options{})
	if err != nil {
		t.Fatalf("plan.Build: %v", err)
	}
	var buf2 bytes.Buffer
	writeDryRunPlan(&buf2, cfgDrop, dropEnc, p2, current2, exists)
	if !strings.Contains(buf2.String(), "up to date; nothing to do") {
		t.Errorf("post-run dry-run = %q; want 'up to date; nothing to do'", buf2.String())
	}
}

// reloadConfig writes a new HCL into the same directory as an existing cfg
// and returns the re-loaded config (same output dir, same manifest path).
func reloadConfig(t *testing.T, base *config.Config, src string) *config.Config {
	t.Helper()
	import_path := base.Path
	if err := os.WriteFile(import_path, []byte(src), 0o644); err != nil {
		t.Fatalf("reloadConfig: write: %v", err)
	}
	cfg, err := config.Load(import_path)
	if err != nil {
		t.Fatalf("reloadConfig: Load: %v", err)
	}
	return cfg
}
