package pki

import (
	"net/netip"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/slackhq/nebula/cert"
)

// fixedTime is an arbitrary but stable issuance time so validity-window
// assertions are deterministic.
var fixedTime = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

func TestGenerateCA_Curve25519(t *testing.T) {
	cfg := mustParseCA(t, `
ca {
  name     = "test-mesh"
  groups   = ["lighthouse", "app"]
  networks = ["10.42.0.0/16"]
}`)

	res, err := GenerateCA(cfg.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if res.Curve != "25519" {
		t.Errorf("Curve = %q, want 25519", res.Curve)
	}
	if res.Version != 2 {
		t.Errorf("Version = %d, want 2 (default)", res.Version)
	}

	c := parseCert(t, res.CertPEM)
	if !c.IsCA() {
		t.Error("IsCA() = false, want true")
	}
	if c.Name() != "test-mesh" {
		t.Errorf("Name() = %q, want test-mesh", c.Name())
	}
	if c.Curve() != cert.Curve_CURVE25519 {
		t.Errorf("Curve() = %v, want CURVE25519", c.Curve())
	}
	if !c.NotBefore().Equal(fixedTime) {
		t.Errorf("NotBefore() = %v, want %v", c.NotBefore(), fixedTime)
	}
	if want := fixedTime.Add(defaultCADuration); !c.NotAfter().Equal(want) {
		t.Errorf("NotAfter() = %v, want %v (default 8760h)", c.NotAfter(), want)
	}

	// Metadata returned must match the signed certificate exactly.
	if !res.NotBefore.Equal(c.NotBefore()) || !res.NotAfter.Equal(c.NotAfter()) {
		t.Error("CAResult validity window does not match the certificate")
	}
	fp, _ := c.Fingerprint()
	if res.Fingerprint != fp {
		t.Errorf("Fingerprint = %q, want %q", res.Fingerprint, fp)
	}

	// The key must round-trip as a plaintext Ed25519 signing key.
	_, _, kcurve, err := cert.UnmarshalSigningPrivateKeyFromPEM(res.KeyPEM)
	if err != nil {
		t.Fatalf("UnmarshalSigningPrivateKeyFromPEM: %v", err)
	}
	if kcurve != cert.Curve_CURVE25519 {
		t.Errorf("key curve = %v, want CURVE25519", kcurve)
	}
}

func TestGenerateCA_CurveP256AndDuration(t *testing.T) {
	cfg := mustParseCA(t, `
ca {
  name     = "p256-mesh"
  curve    = "P256"
  version  = 2
  duration = "26280h"
}`)

	res, err := GenerateCA(cfg.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if res.Curve != "P256" {
		t.Errorf("Curve = %q, want P256", res.Curve)
	}

	c := parseCert(t, res.CertPEM)
	if c.Curve() != cert.Curve_P256 {
		t.Errorf("Curve() = %v, want P256", c.Curve())
	}
	if want := fixedTime.Add(26280 * time.Hour); !c.NotAfter().Equal(want) {
		t.Errorf("NotAfter() = %v, want %v", c.NotAfter(), want)
	}

	_, _, kcurve, err := cert.UnmarshalSigningPrivateKeyFromPEM(res.KeyPEM)
	if err != nil {
		t.Fatalf("UnmarshalSigningPrivateKeyFromPEM: %v", err)
	}
	if kcurve != cert.Curve_P256 {
		t.Errorf("key curve = %v, want P256", kcurve)
	}
}

// TestGenerateCA_NetworksRoundTrip confirms CA constraint networks land
// on the certificate.
func TestGenerateCA_NetworksRoundTrip(t *testing.T) {
	cfg := mustParseCA(t, `
ca {
  name     = "m"
  networks = ["10.42.0.0/16"]
}`)
	res, err := GenerateCA(cfg.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	c := parseCert(t, res.CertPEM)
	nets := c.Networks()
	if len(nets) != 1 || nets[0] != netip.MustParsePrefix("10.42.0.0/16") {
		t.Errorf("Networks() = %v, want [10.42.0.0/16]", nets)
	}
}

// TestGenerateCA_GroupsAndUnsafeNetworksRoundTrip pins the two
// constraint fields that the manifest will eventually mirror back into
// host certs. Without this test, a regression that drops `Groups:` or
// `UnsafeNetworks:` from the TBSCertificate would silently produce a
// permissive CA — which is the worst kind of bug for a tool whose job
// is restricting trust.
func TestGenerateCA_GroupsAndUnsafeNetworksRoundTrip(t *testing.T) {
	cfg := mustParseCA(t, `
ca {
  name            = "m"
  groups          = ["lighthouse", "edge", "app"]
  networks        = ["10.42.0.0/16"]
  unsafe_networks = ["192.168.10.0/24", "192.168.11.0/24"]
}`)
	res, err := GenerateCA(cfg.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	c := parseCert(t, res.CertPEM)

	gotGroups := c.Groups()
	if len(gotGroups) != 3 ||
		gotGroups[0] != "lighthouse" ||
		gotGroups[1] != "edge" ||
		gotGroups[2] != "app" {
		t.Errorf("Groups() = %v, want [lighthouse edge app]", gotGroups)
	}

	gotUnsafe := c.UnsafeNetworks()
	if len(gotUnsafe) != 2 ||
		gotUnsafe[0] != netip.MustParsePrefix("192.168.10.0/24") ||
		gotUnsafe[1] != netip.MustParsePrefix("192.168.11.0/24") {
		t.Errorf("UnsafeNetworks() = %v, want [192.168.10.0/24 192.168.11.0/24]", gotUnsafe)
	}
}

func TestGenerateCA_EncryptRejected(t *testing.T) {
	cfg := mustParseCA(t, `
ca {
  name    = "m"
  encrypt = true
}`)
	_, err := GenerateCA(cfg.CA, fixedTime)
	if err == nil {
		t.Fatal("GenerateCA: want error for ca.encrypt, got nil")
	}
}

// TestGenerateCA_Distinct ensures key material is freshly generated each
// call (no accidental determinism / shared buffer).
func TestGenerateCA_Distinct(t *testing.T) {
	cfg := mustParseCA(t, `ca { name = "m" }`)
	a, err := GenerateCA(cfg.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA a: %v", err)
	}
	b, err := GenerateCA(cfg.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA b: %v", err)
	}
	if a.Fingerprint == b.Fingerprint {
		t.Error("two CA generations share a fingerprint; key material is not unique")
	}
}

// TestGenerateCA_DistinctNamesProduceDistinctCerts complements
// TestGenerateCA_Distinct by varying the CA name as well as the random
// material. The fingerprint is content-addressed (SHA256 of the cert
// blob), so this is mostly a redundant sanity check — but it catches a
// regression where a future refactor caches the TBSCertificate across
// calls and reuses the previous Name.
func TestGenerateCA_DistinctNamesProduceDistinctCerts(t *testing.T) {
	cfgA := mustParseCA(t, `ca { name = "alpha" }`)
	cfgB := mustParseCA(t, `ca { name = "beta" }`)

	a, err := GenerateCA(cfgA.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA alpha: %v", err)
	}
	b, err := GenerateCA(cfgB.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA beta: %v", err)
	}
	if a.Name == b.Name {
		t.Errorf("CA names collapsed: a=%q b=%q", a.Name, b.Name)
	}
	if a.Fingerprint == b.Fingerprint {
		t.Error("two distinct CAs share a fingerprint")
	}
}

func mustParseCA(t *testing.T, src string) *config.Config {
	t.Helper()
	cfg, err := config.Parse("nebula.hcl", []byte(src))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	return cfg
}

func parseCert(t *testing.T, pemBytes []byte) cert.Certificate {
	t.Helper()
	c, _, err := cert.UnmarshalCertificateFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("UnmarshalCertificateFromPEM: %v", err)
	}
	return c
}
