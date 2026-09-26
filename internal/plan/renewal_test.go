package plan

// Tests for renewal-window and CA-rotation plan decisions.

import (
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/manifest"
)

// ---------------------------------------------------------------------------
// certInRenewalWindow unit tests
// ---------------------------------------------------------------------------

func TestCertInRenewalWindow_ZeroRenewBefore_NeverInWindow(t *testing.T) {
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	now := notAfter.Add(-24 * time.Hour) // well before expiry
	if certInRenewalWindow(0, notAfter, now) {
		t.Error("certInRenewalWindow(0, ...) = true, want false (no threshold configured)")
	}
}

func TestCertInRenewalWindow_OutsideWindow(t *testing.T) {
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	renewBefore := 720 * time.Hour // 30 days
	// now is 31 days before notAfter, outside the window
	now := notAfter.Add(-31 * 24 * time.Hour)
	if certInRenewalWindow(renewBefore, notAfter, now) {
		t.Error("certInRenewalWindow = true, want false (now is before window entry)")
	}
}

func TestCertInRenewalWindow_AtWindowBoundary(t *testing.T) {
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	renewBefore := 720 * time.Hour    // 30 days
	now := notAfter.Add(-renewBefore) // exactly at the window boundary
	if !certInRenewalWindow(renewBefore, notAfter, now) {
		t.Error("certInRenewalWindow = false at boundary, want true (now == window entry)")
	}
}

func TestCertInRenewalWindow_InsideWindow(t *testing.T) {
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	renewBefore := 720 * time.Hour // 30 days
	// now is 10 days before notAfter, deep inside the window
	now := notAfter.Add(-10 * 24 * time.Hour)
	if !certInRenewalWindow(renewBefore, notAfter, now) {
		t.Error("certInRenewalWindow = false, want true (now inside window)")
	}
}

func TestCertInRenewalWindow_AfterExpiry(t *testing.T) {
	notAfter := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	renewBefore := 720 * time.Hour
	now := notAfter.Add(24 * time.Hour) // already expired
	if !certInRenewalWindow(renewBefore, notAfter, now) {
		t.Error("certInRenewalWindow = false after expiry, want true")
	}
}

// ---------------------------------------------------------------------------
// planCert renewal-window integration via Build
// ---------------------------------------------------------------------------

const renewHCL = `
ca "mesh" { name = "m" }
cert "alpha" {
  networks     = ["10.0.0.1/16"]
  renew_before = "720h"
}
`

func TestBuild_CertNoopOutsideRenewalWindow(t *testing.T) {
	cfg := parseCfg(t, renewHCL)
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	// now is 31 days before notAfter, outside the 30-day window
	now := notAfter.Add(-31 * 24 * time.Hour)

	m := trackedCertManifest(cfg, notAfter)
	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.CertArtifactPath(cfg.Certs[0]).CertPath,
		cfg.CertArtifactPath(cfg.Certs[0]).KeyPath,
	)
	p, err := Build(cfg, m, now, exists, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Changes() {
		t.Fatalf("Changes() = true, want false (outside renewal window); actions = %+v", p.Actions)
	}
	for _, a := range p.CertActions() {
		if a.Op != OpNoop {
			t.Errorf("cert %q: Op = %q, want noop", a.Label, a.Op)
		}
	}
}

func TestBuild_CertSignInsideRenewalWindow(t *testing.T) {
	cfg := parseCfg(t, renewHCL)
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	// now is 10 days before notAfter, inside the 30-day window
	now := notAfter.Add(-10 * 24 * time.Hour)

	m := trackedCertManifest(cfg, notAfter)
	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.CertArtifactPath(cfg.Certs[0]).CertPath,
		cfg.CertArtifactPath(cfg.Certs[0]).KeyPath,
	)
	p, err := Build(cfg, m, now, exists, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true (cert inside renewal window)")
	}
	for _, a := range p.CertActions() {
		if a.Op != OpSign {
			t.Errorf("cert %q: Op = %q, want sign (inside renewal window)", a.Label, a.Op)
		}
	}
}

func TestBuild_CertNoRenewBefore_AlwaysNoop(t *testing.T) {
	// No renew_before on cert or CA: time-based renewal is disabled.
	cfg := parseCfg(t, `
ca "mesh" { name = "m" }
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	// now is 1 second before notAfter, would renew with any threshold, but
	// no threshold is set.
	now := notAfter.Add(-time.Second)

	m := trackedCertManifest(cfg, notAfter)
	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.CertArtifactPath(cfg.Certs[0]).CertPath,
		cfg.CertArtifactPath(cfg.Certs[0]).KeyPath,
	)
	p, err := Build(cfg, m, now, exists, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Changes() {
		t.Fatalf("Changes() = true, want false (no renew_before → no time-based renewal); actions = %+v", p.Actions)
	}
}

func TestBuild_CertInheritedRenewBefore_InsideWindow_Signs(t *testing.T) {
	// renew_before is on the CA, not the cert; the cert should still renew.
	cfg := parseCfg(t, `
ca "mesh" {
  name         = "m"
  renew_before = "720h"
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	// now is 15 days before notAfter, inside the 30-day window
	now := notAfter.Add(-15 * 24 * time.Hour)

	m := trackedCertManifest(cfg, notAfter)
	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.CertArtifactPath(cfg.Certs[0]).CertPath,
		cfg.CertArtifactPath(cfg.Certs[0]).KeyPath,
	)
	p, err := Build(cfg, m, now, exists, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true (inherited renew_before, inside window)")
	}
	for _, a := range p.CertActions() {
		if a.Op != OpSign {
			t.Errorf("cert %q: Op = %q, want sign", a.Label, a.Op)
		}
	}
}

func TestBuild_CARotation_DefaultChange_ResignsCerts(t *testing.T) {
	// Before rotation: certs were signed under "current".
	// After moving default = true to "next": certs must be re-signed.
	cfg := parseCfg(t, `
ca "current" {
  name     = "old-mesh"
  archived = true
}
ca "next" {
  name    = "new-mesh"
  default = true
}
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	m := manifest.New()
	m.CAs["current"] = &manifest.CA{Mode: "generate", Name: "old-mesh"}
	m.CAs["next"] = &manifest.CA{Mode: "generate", Name: "new-mesh"}
	// alpha was previously signed under "current"
	m.Certs["alpha"] = manifest.Cert{Name: "alpha", CA: "current", NotAfter: time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)}

	ca0 := cfg.CAs[0]
	ca1 := cfg.CAs[1]
	exists := existsSet(
		cfg.CACertPathForCA(ca0), cfg.CAKeyPathForCA(ca0),
		cfg.CACertPathForCA(ca1), cfg.CAKeyPathForCA(ca1),
		cfg.CertArtifactPath(cfg.Certs[0]).CertPath,
		cfg.CertArtifactPath(cfg.Certs[0]).KeyPath,
	)
	p, err := Build(cfg, m, testNow, exists, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true (alpha must be re-signed under 'next')")
	}
	for _, a := range p.CertActions() {
		if a.Label == "alpha" && a.Op != OpSign {
			t.Errorf("alpha: Op = %q, want sign (CA rotation: was 'current', now 'next')", a.Op)
		}
	}
}

// ---------------------------------------------------------------------------
// NoRenewal option tests
// ---------------------------------------------------------------------------

func TestBuild_NoRenewal_InsideWindow_Noop(t *testing.T) {
	cfg := parseCfg(t, renewHCL)
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	now := notAfter.Add(-10 * 24 * time.Hour) // inside the 30-day window

	m := trackedCertManifest(cfg, notAfter)
	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.CertArtifactPath(cfg.Certs[0]).CertPath,
		cfg.CertArtifactPath(cfg.Certs[0]).KeyPath,
	)
	p, err := Build(cfg, m, now, exists, Options{NoRenewal: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Changes() {
		t.Fatalf("Changes() = true with NoRenewal=true, want false (renewal suppressed); actions = %+v", p.Actions)
	}
	for _, a := range p.CertActions() {
		if a.Op != OpNoop {
			t.Errorf("cert %q: Op = %q, want noop (NoRenewal suppresses window check)", a.Label, a.Op)
		}
	}
}

func TestBuild_NoRenewal_NewCert_StillSigns(t *testing.T) {
	cfg := parseCfg(t, renewHCL)

	// No cert record in manifest: untracked → must sign regardless of NoRenewal.
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	ca := cfg.CAs[0]
	exists := existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca))

	p, err := Build(cfg, m, testNow, exists, Options{NoRenewal: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, a := range p.CertActions() {
		if a.Op != OpSign {
			t.Errorf("cert %q: Op = %q, want sign (new cert, NoRenewal does not suppress)", a.Label, a.Op)
		}
	}
}

func TestBuild_NoRenewal_CAMismatch_StillSigns(t *testing.T) {
	cfg := parseCfg(t, renewHCL)
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)

	// alpha was previously signed under a different CA label.
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	m.Certs["alpha"] = manifest.Cert{Name: "alpha", CA: "old-mesh", NotAfter: notAfter}

	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.CertArtifactPath(cfg.Certs[0]).CertPath,
		cfg.CertArtifactPath(cfg.Certs[0]).KeyPath,
	)
	p, err := Build(cfg, m, testNow, exists, Options{NoRenewal: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, a := range p.CertActions() {
		if a.Op != OpSign {
			t.Errorf("cert %q: Op = %q, want sign (CA mismatch, NoRenewal does not suppress)", a.Label, a.Op)
		}
	}
}

func TestBuild_NoRenewal_ZeroRenewBefore_StillNoop(t *testing.T) {
	// No renew_before on cert or CA; NoRenewal=true must not change the outcome.
	cfg := parseCfg(t, `
ca "mesh" { name = "m" }
cert "alpha" { networks = ["10.0.0.1/16"] }
`)
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	now := notAfter.Add(-time.Second) // one second before expiry

	m := trackedCertManifest(cfg, notAfter)
	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.CertArtifactPath(cfg.Certs[0]).CertPath,
		cfg.CertArtifactPath(cfg.Certs[0]).KeyPath,
	)
	p, err := Build(cfg, m, now, exists, Options{NoRenewal: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Changes() {
		t.Fatalf("Changes() = true with NoRenewal=true + zero renew_before, want false; actions = %+v", p.Actions)
	}
}

// trackedCertManifest builds a manifest with the mesh CA tracked and alpha
// signed with the given notAfter.
func trackedCertManifest(cfg *config.Config, notAfter time.Time) *manifest.Manifest {
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	m.Certs["alpha"] = manifest.Cert{
		Name:     "alpha",
		CA:       "mesh",
		NotAfter: notAfter,
	}
	return m
}
