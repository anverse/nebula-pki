package pki

import (
	"bytes"
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/slackhq/nebula/cert"
)

// makeHostPubPEM generates a fresh keypair for the given curve and returns the
// PEM-encoded public key as the device would export it via nebula-cert keygen.
// The returned privRaw can be used in subsequent assertions on the cert's
// embedded public key.
func makeHostPubPEM(t *testing.T, curve cert.Curve) (pubPEM, pubRaw []byte) {
	t.Helper()
	pub, _, err := generateKeypair(curve)
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
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

// --- ParseHostPublicKeyPEM --------------------------------------------------

func TestParseHostPublicKeyPEM_Curve25519(t *testing.T) {
	pubPEM, pubRaw := makeHostPubPEM(t, cert.Curve_CURVE25519)

	got, curveStr, err := ParseHostPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParseHostPublicKeyPEM: %v", err)
	}
	if curveStr != "25519" {
		t.Errorf("curveStr = %q, want 25519", curveStr)
	}
	if !bytes.Equal(got, pubRaw) {
		t.Error("parsed public key bytes do not match the original")
	}
}

func TestParseHostPublicKeyPEM_P256(t *testing.T) {
	pubPEM, pubRaw := makeHostPubPEM(t, cert.Curve_P256)

	got, curveStr, err := ParseHostPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParseHostPublicKeyPEM: %v", err)
	}
	if curveStr != "P256" {
		t.Errorf("curveStr = %q, want P256", curveStr)
	}
	if !bytes.Equal(got, pubRaw) {
		t.Error("parsed public key bytes do not match the original")
	}
}

func TestParseHostPublicKeyPEM_InvalidPEM(t *testing.T) {
	_, _, err := ParseHostPublicKeyPEM([]byte("not a pem block"))
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestParseHostPublicKeyPEM_WrongType(t *testing.T) {
	// A CA certificate PEM is not a host public key.
	ca := makeCA(t, `ca "m" { name = "m" }`)
	_, _, err := ParseHostPublicKeyPEM(ca.CertPEM)
	if err == nil {
		t.Fatal("expected error when parsing a CA cert PEM as a host public key, got nil")
	}
}

// --- SignHostFromPub ---------------------------------------------------------

const inPubHostHCL = `
ca "mesh" { name = "mesh" }
host "phone" {
  name     = "alice-phone"
  networks = ["10.0.0.1/16"]
  groups   = ["mobile"]
  in_pub   = "alice.pub"
}
`

func mustParseInPubHost(t *testing.T) config.Host {
	t.Helper()
	cfg, err := config.Parse("nebula.hcl", []byte(inPubHostHCL))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	return cfg.Hosts[0]
}

func TestSignHostFromPub_Curve25519(t *testing.T) {
	ca := makeCA(t, `ca "mesh" { name = "mesh" }`)
	pubPEM, pubRaw := makeHostPubPEM(t, cert.Curve_CURVE25519)
	h := mustParseInPubHost(t)

	res, err := SignHostFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, h, fixedTime)
	if err != nil {
		t.Fatalf("SignHostFromPub: %v", err)
	}

	// No private key must be returned.
	if res.KeyPEM != nil {
		t.Error("KeyPEM is non-nil; in_pub hosts must not produce a private key")
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

func TestSignHostFromPub_P256(t *testing.T) {
	ca := makeCA(t, `
ca "p256" {
  name  = "p256-mesh"
  curve = "P256"
}`)
	pubPEM, pubRaw := makeHostPubPEM(t, cert.Curve_P256)

	cfg, err := config.Parse("n.hcl", []byte(`
ca "p256" {
  name  = "p256-mesh"
  curve = "P256"
}
host "device" {
  networks = ["10.1.0.1/16"]
  in_pub   = "d.pub"
}
`))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}

	res, err := SignHostFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, cfg.Hosts[0], fixedTime)
	if err != nil {
		t.Fatalf("SignHostFromPub: %v", err)
	}
	if res.KeyPEM != nil {
		t.Error("KeyPEM is non-nil for in_pub host")
	}
	c := parseCert(t, res.CertPEM)
	if !bytes.Equal(c.PublicKey(), pubRaw) {
		t.Error("cert PublicKey() does not match the device-supplied P256 public key")
	}
	if res.Curve != "P256" {
		t.Errorf("Curve = %q, want P256", res.Curve)
	}
}

func TestSignHostFromPub_CurveMismatch(t *testing.T) {
	// Curve25519 CA, P256 device pubkey → error.
	ca := makeCA(t, `ca "mesh" { name = "mesh" }`)
	pubPEM, _ := makeHostPubPEM(t, cert.Curve_P256)
	h := mustParseInPubHost(t)

	_, err := SignHostFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, h, fixedTime)
	if err == nil {
		t.Fatal("expected curve mismatch error, got nil")
	}
	if msg := err.Error(); !strings.Contains(msg, "curve") {
		t.Errorf("error %q does not mention 'curve'", msg)
	}
}

func TestSignHostFromPub_CurveMismatch_P256CAWith25519Key(t *testing.T) {
	// P256 CA, Curve25519 device pubkey → error.
	ca := makeCA(t, `
ca "p256" {
  name  = "p256-mesh"
  curve = "P256"
}`)
	pubPEM, _ := makeHostPubPEM(t, cert.Curve_CURVE25519)

	cfg, _ := config.Parse("n.hcl", []byte(`
ca "p256" {
  name  = "p256-mesh"
  curve = "P256"
}
host "device" {
  networks = ["10.1.0.1/16"]
  in_pub   = "d.pub"
}
`))

	_, err := SignHostFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, cfg.Hosts[0], fixedTime)
	if err == nil {
		t.Fatal("expected curve mismatch error, got nil")
	}
	if msg := err.Error(); !strings.Contains(msg, "curve") {
		t.Errorf("error %q does not mention 'curve'", msg)
	}
}

func TestSignHostFromPub_InvalidPEM(t *testing.T) {
	ca := makeCA(t, `ca "mesh" { name = "mesh" }`)
	h := mustParseInPubHost(t)

	_, err := SignHostFromPub(ca.CertPEM, ca.KeyPEM, []byte("not a pub key"), h, fixedTime)
	if err == nil {
		t.Fatal("expected error for invalid pubkey PEM, got nil")
	}
}

func TestSignHostFromPub_ValidityCapAtCA(t *testing.T) {
	// Host duration exceeds CA lifetime → cert notAfter capped at CA notAfter.
	// We use a short CA (2h) and a host duration that fits within it (1h30m)
	// for config validation, then manually build a host with an even shorter
	// duration to test the capping path in SignHostFromPub.
	ca := makeCA(t, `
ca "mesh" {
  name     = "mesh"
  duration = "2h"
}`)
	pubPEM, _ := makeHostPubPEM(t, cert.Curve_CURVE25519)

	// Build a host config that is valid (duration < ca.duration) but pass a
	// longer duration directly to the signing call to exercise the cap logic.
	cfg, err := config.Parse("n.hcl", []byte(`
ca "mesh" {
  name     = "mesh"
  duration = "2h"
}
host "phone" {
  networks = ["10.0.0.1/16"]
  in_pub   = "p.pub"
  duration = "1h"
}
`))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}

	// Override the duration to 100h to trigger the cap.
	h := cfg.Hosts[0]
	h.Duration = 100 * 3600 * 1_000_000_000 // 100h as nanoseconds
	h.HasDuration = true

	res, err := SignHostFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, h, fixedTime)
	if err != nil {
		t.Fatalf("SignHostFromPub: %v", err)
	}
	if res.NotAfter.After(ca.NotAfter) {
		t.Errorf("host NotAfter %v exceeds CA NotAfter %v; cert must be capped", res.NotAfter, ca.NotAfter)
	}
}

func TestSignHostFromPub_SamePubKeyProducesSameCertShape(t *testing.T) {
	// Two calls with the same public key produce certs with the same embedded
	// public key (but may differ in signing entropy if any). The embedded
	// public key must always equal the device-supplied one.
	ca := makeCA(t, `ca "mesh" { name = "mesh" }`)
	pubPEM, pubRaw := makeHostPubPEM(t, cert.Curve_CURVE25519)
	h := mustParseInPubHost(t)

	for i := range 2 {
		res, err := SignHostFromPub(ca.CertPEM, ca.KeyPEM, pubPEM, h, fixedTime)
		if err != nil {
			t.Fatalf("call %d: SignHostFromPub: %v", i+1, err)
		}
		c := parseCert(t, res.CertPEM)
		if !bytes.Equal(c.PublicKey(), pubRaw) {
			t.Errorf("call %d: cert PublicKey() does not match device public key", i+1)
		}
	}
}
