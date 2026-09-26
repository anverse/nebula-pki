package pki

import (
	"bytes"
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/slackhq/nebula/cert"
)

// makeCertPubPEM generates a fresh keypair for the given curve and returns the
// PEM-encoded public key as the device would export it via nebula-cert keygen.
// The returned privRaw can be used in subsequent assertions on the cert's
// embedded public key.
func makeCertPubPEM(t *testing.T, curve cert.Curve) (pubPEM, pubRaw []byte) {
	t.Helper()
	pub, _, err := generateCertKeypair(curve)
	if err != nil {
		t.Fatalf("generateCertKeypair: %v", err)
	}
	pem := cert.MarshalPublicKeyToPEM(curve, pub)
	if pem == nil {
		t.Fatalf("MarshalPublicKeyToPEM returned nil for curve %v", curve)
	}
	return pem, pub
}

// makeCA generates a CA for the given HCL snippet.
func makeCA(t *testing.T, src string) *CAResult {
	t.Helper()
	cfg := mustParseCA(t, src)
	res, err := GenerateCA(cfg.CAs[0], fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return res
}

// --- ParseCertPublicKeyPEM --------------------------------------------------

func TestParseCertPublicKeyPEM_Curve25519(t *testing.T) {
	pubPEM, pubRaw := makeCertPubPEM(t, cert.Curve_CURVE25519)

	got, curveStr, err := ParseCertPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParseCertPublicKeyPEM: %v", err)
	}
	if curveStr != "25519" {
		t.Errorf("curveStr = %q, want 25519", curveStr)
	}
	if !bytes.Equal(got, pubRaw) {
		t.Error("parsed public key bytes do not match the original")
	}
}

func TestParseCertPublicKeyPEM_P256(t *testing.T) {
	pubPEM, pubRaw := makeCertPubPEM(t, cert.Curve_P256)

	got, curveStr, err := ParseCertPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParseCertPublicKeyPEM: %v", err)
	}
	if curveStr != "P256" {
		t.Errorf("curveStr = %q, want P256", curveStr)
	}
	if !bytes.Equal(got, pubRaw) {
		t.Error("parsed public key bytes do not match the original")
	}
}

func TestParseCertPublicKeyPEM_InvalidPEM(t *testing.T) {
	_, _, err := ParseCertPublicKeyPEM([]byte("not a pem block"))
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestParseCertPublicKeyPEM_WrongType(t *testing.T) {
	// A CA certificate PEM is not a cert public key.
	ca := makeCA(t, `ca "m" { name = "m" }`)
	_, _, err := ParseCertPublicKeyPEM(ca.CertPEM)
	if err == nil {
		t.Fatal("expected error when parsing a CA cert PEM as a cert public key, got nil")
	}
}

// --- SignCertFromPub ---------------------------------------------------------

const inPubCertHCL = `
ca "mesh" { name = "mesh" }
cert "phone" {
  name     = "alice-phone"
  networks = ["10.0.0.1/16"]
  groups   = ["mobile"]
  in_pub   = "alice.pub"
}
`

func mustParseInPubCert(t *testing.T) config.Cert {
	t.Helper()
	cfg, err := config.Parse("nebula.hcl", []byte(inPubCertHCL))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	return cfg.Certs[0]
}

func TestSignCertFromPub_Curve25519(t *testing.T) {
	ca := makeCA(t, `ca "mesh" { name = "mesh" }`)
	pubPEM, pubRaw := makeCertPubPEM(t, cert.Curve_CURVE25519)
	h := mustParseInPubCert(t)

	res, err := SignCertFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, h, fixedTime)
	if err != nil {
		t.Fatalf("SignCertFromPub: %v", err)
	}

	// No private key must be returned.
	if res.KeyPEM != nil {
		t.Error("KeyPEM is non-nil; in_pub certs must not produce a private key")
	}

	// Cert must parse and carry the expected metadata.
	c := parseCert(t, res.CertPEM)
	if c.IsCA() {
		t.Error("IsCA() = true, want false")
	}
	if c.Name() != "alice-phone" {
		t.Errorf("Name() = %q, want alice-phone", c.Name())
	}
	if grps := c.Groups(); len(grps) != 1 || grps[0] != "mobile" {
		t.Errorf("Groups() = %v, want [mobile]", grps)
	}
	nets := c.Networks()
	if len(nets) != 1 || nets[0].String() != "10.0.0.1/16" {
		t.Errorf("Networks() = %v, want [10.0.0.1/16]", nets)
	}

	// The cert must embed the device's public key, not a freshly generated one.
	if !bytes.Equal(c.PublicKey(), pubRaw) {
		t.Error("cert PublicKey() does not match the device-supplied public key")
	}

	// CAFingerprint must match.
	if res.CAFingerprint != ca.Fingerprint {
		t.Errorf("CAFingerprint = %q, want %q", res.CAFingerprint, ca.Fingerprint)
	}

	if res.Curve != "25519" {
		t.Errorf("Curve = %q, want 25519", res.Curve)
	}
}

func TestSignCertFromPub_P256(t *testing.T) {
	ca := makeCA(t, `
ca "p256" {
  name  = "p256-mesh"
  curve = "P256"
}`)
	pubPEM, pubRaw := makeCertPubPEM(t, cert.Curve_P256)

	cfg, err := config.Parse("n.hcl", []byte(`
ca "p256" {
  name  = "p256-mesh"
  curve = "P256"
}
cert "device" {
  networks = ["10.1.0.1/16"]
  in_pub   = "d.pub"
}
`))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}

	res, err := SignCertFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, cfg.Certs[0], fixedTime)
	if err != nil {
		t.Fatalf("SignCertFromPub: %v", err)
	}
	if res.KeyPEM != nil {
		t.Error("KeyPEM is non-nil for in_pub cert")
	}
	c := parseCert(t, res.CertPEM)
	if !bytes.Equal(c.PublicKey(), pubRaw) {
		t.Error("cert PublicKey() does not match the device-supplied P256 public key")
	}
	if res.Curve != "P256" {
		t.Errorf("Curve = %q, want P256", res.Curve)
	}
}

func TestSignCertFromPub_CurveMismatch(t *testing.T) {
	// Curve25519 CA, P256 device pubkey → error.
	ca := makeCA(t, `ca "mesh" { name = "mesh" }`)
	pubPEM, _ := makeCertPubPEM(t, cert.Curve_P256)
	h := mustParseInPubCert(t)

	_, err := SignCertFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, h, fixedTime)
	if err == nil {
		t.Fatal("expected curve mismatch error, got nil")
	}
	if msg := err.Error(); !strings.Contains(msg, "curve") {
		t.Errorf("error %q does not mention 'curve'", msg)
	}
}

func TestSignCertFromPub_CurveMismatch_P256CAWith25519Key(t *testing.T) {
	// P256 CA, Curve25519 device pubkey → error.
	ca := makeCA(t, `
ca "p256" {
  name  = "p256-mesh"
  curve = "P256"
}`)
	pubPEM, _ := makeCertPubPEM(t, cert.Curve_CURVE25519)

	cfg, _ := config.Parse("n.hcl", []byte(`
ca "p256" {
  name  = "p256-mesh"
  curve = "P256"
}
cert "device" {
  networks = ["10.1.0.1/16"]
  in_pub   = "d.pub"
}
`))

	_, err := SignCertFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, cfg.Certs[0], fixedTime)
	if err == nil {
		t.Fatal("expected curve mismatch error, got nil")
	}
	if msg := err.Error(); !strings.Contains(msg, "curve") {
		t.Errorf("error %q does not mention 'curve'", msg)
	}
}

func TestSignCertFromPub_InvalidPEM(t *testing.T) {
	ca := makeCA(t, `ca "mesh" { name = "mesh" }`)
	h := mustParseInPubCert(t)

	_, err := SignCertFromPub(ca.CertPEM, ca.KeyPEM, []byte("not a pub key"), h, fixedTime)
	if err == nil {
		t.Fatal("expected error for invalid pubkey PEM, got nil")
	}
}

func TestSignCertFromPub_ValidityCapAtCA(t *testing.T) {
	// Cert duration exceeds CA lifetime → cert notAfter capped at CA notAfter.
	// We use a short CA (2h) and a cert duration that fits within it (1h30m)
	// for config validation, then manually build a cert with an even shorter
	// duration to test the capping path in SignCertFromPub.
	ca := makeCA(t, `
ca "mesh" {
  name     = "mesh"
  duration = "2h"
}`)
	pubPEM, _ := makeCertPubPEM(t, cert.Curve_CURVE25519)

	// Build a cert config that is valid (duration < ca.duration) but pass a
	// longer duration directly to the signing call to exercise the cap logic.
	cfg, err := config.Parse("n.hcl", []byte(`
ca "mesh" {
  name     = "mesh"
  duration = "2h"
}
cert "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "p.pub"
  duration = "1h"
}
`))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}

	// Override the duration to 100h to trigger the cap.
	h := cfg.Certs[0]
	h.Duration = 100 * 3600 * 1_000_000_000 // 100h as nanoseconds
	h.HasDuration = true

	res, err := SignCertFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, h, fixedTime)
	if err != nil {
		t.Fatalf("SignCertFromPub: %v", err)
	}
	if res.NotAfter.After(ca.NotAfter) {
		t.Errorf("cert NotAfter %v exceeds CA NotAfter %v; cert must be capped", res.NotAfter, ca.NotAfter)
	}
}

func TestSignCertFromPub_SamePubKeyProducesSameCertShape(t *testing.T) {
	// Two calls with the same public key produce certs with the same embedded
	// public key (but may differ in signing entropy if any). The embedded
	// public key must always equal the device-supplied one.
	ca := makeCA(t, `ca "mesh" { name = "mesh" }`)
	pubPEM, pubRaw := makeCertPubPEM(t, cert.Curve_CURVE25519)
	h := mustParseInPubCert(t)

	for i := range 2 {
		res, err := SignCertFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, h, fixedTime)
		if err != nil {
			t.Fatalf("call %d: SignCertFromPub: %v", i+1, err)
		}
		c := parseCert(t, res.CertPEM)
		if !bytes.Equal(c.PublicKey(), pubRaw) {
			t.Errorf("call %d: cert PublicKey() does not match device public key", i+1)
		}
	}
}
