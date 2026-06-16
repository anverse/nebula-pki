package pki

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// generateCAForRef mints a CA via the production GenerateCA path and
// returns its result (cert + key PEM) for reference-mode round-trip
// tests. Using the real path keeps the fixtures honest: whatever
// GenerateCA writes, LoadReferenceCA must be able to read back.
func generateCAForRef(t *testing.T, src string) *CAResult {
	t.Helper()
	cfg := mustParseCA(t, src)
	res, err := GenerateCA(cfg.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return res
}

func TestLoadReferenceCA_RoundTripCurve25519(t *testing.T) {
	gen := generateCAForRef(t, `
ca {
  name     = "ref-mesh"
  groups   = ["lighthouse"]
  networks = ["10.42.0.0/16"]
}`)

	got, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM)
	if err != nil {
		t.Fatalf("LoadReferenceCA: %v", err)
	}

	if got.CertPEM != nil || got.KeyPEM != nil {
		t.Error("LoadReferenceCA must not return PEM bytes; reference mode never rewrites files")
	}
	if got.Name != "ref-mesh" {
		t.Errorf("Name = %q, want ref-mesh", got.Name)
	}
	if got.Curve != "25519" {
		t.Errorf("Curve = %q, want 25519", got.Curve)
	}
	if got.Version != gen.Version {
		t.Errorf("Version = %d, want %d", got.Version, gen.Version)
	}
	if got.Fingerprint != gen.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, gen.Fingerprint)
	}
	if !got.NotBefore.Equal(gen.NotBefore) || !got.NotAfter.Equal(gen.NotAfter) {
		t.Errorf("validity = [%s, %s], want [%s, %s]", got.NotBefore, got.NotAfter, gen.NotBefore, gen.NotAfter)
	}
}

func TestLoadReferenceCA_RoundTripP256(t *testing.T) {
	gen := generateCAForRef(t, `
ca {
  name  = "ref-p256"
  curve = "P256"
}`)

	got, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM)
	if err != nil {
		t.Fatalf("LoadReferenceCA: %v", err)
	}
	if got.Curve != "P256" {
		t.Errorf("Curve = %q, want P256", got.Curve)
	}
	if got.Fingerprint != gen.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, gen.Fingerprint)
	}
}

func TestLoadReferenceCA_CorruptCertPEM(t *testing.T) {
	gen := generateCAForRef(t, `ca { name = "x" }`)
	if _, err := LoadReferenceCA([]byte("not a pem block"), gen.KeyPEM); err == nil {
		t.Fatal("LoadReferenceCA: want error for corrupt cert PEM, got nil")
	}
}

func TestLoadReferenceCA_CorruptKeyPEM(t *testing.T) {
	gen := generateCAForRef(t, `ca { name = "x" }`)
	if _, err := LoadReferenceCA(gen.CertPEM, []byte("not a pem block")); err == nil {
		t.Fatal("LoadReferenceCA: want error for corrupt key PEM, got nil")
	}
}

// TestLoadReferenceCA_NotACA points the loader at a host (non-CA)
// certificate. The schema lets an operator typo any path into cert_file;
// the loader must reject a leaf cert rather than later mis-signing under
// a non-CA.
func TestLoadReferenceCA_NotACA(t *testing.T) {
	hostCertPEM, _ := mintHostCert(t)
	// Pair it with any syntactically valid signing key so the failure is
	// the IsCA check, not a key parse error.
	gen := generateCAForRef(t, `ca { name = "x" }`)

	_, err := LoadReferenceCA(hostCertPEM, gen.KeyPEM)
	if err == nil {
		t.Fatal("LoadReferenceCA: want error for non-CA certificate, got nil")
	}
	if !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("error = %q, want it to mention 'not a CA'", err.Error())
	}
}

// TestLoadReferenceCA_CurveMismatch pairs a 25519 cert with a P256 key.
func TestLoadReferenceCA_CurveMismatch(t *testing.T) {
	ca25519 := generateCAForRef(t, `ca { name = "a" }`)
	caP256 := generateCAForRef(t, `
ca {
  name  = "b"
  curve = "P256"
}`)

	_, err := LoadReferenceCA(ca25519.CertPEM, caP256.KeyPEM)
	if err == nil {
		t.Fatal("LoadReferenceCA: want error for curve mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "curve") {
		t.Errorf("error = %q, want it to mention 'curve'", err.Error())
	}
}

// TestLoadReferenceCA_KeyDoesNotMatchCert pairs a cert with a same-curve
// key from a different CA. Curves agree, so this exercises the public-key
// equality check specifically.
func TestLoadReferenceCA_KeyDoesNotMatchCert(t *testing.T) {
	caA := generateCAForRef(t, `ca { name = "a" }`)
	caB := generateCAForRef(t, `ca { name = "b" }`)

	_, err := LoadReferenceCA(caA.CertPEM, caB.KeyPEM)
	if err == nil {
		t.Fatal("LoadReferenceCA: want error for mismatched key/cert, got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error = %q, want it to mention 'does not match'", err.Error())
	}
}

// TestLoadReferenceCA_Expired drives the clock past the CA's NotAfter via
// the timeNow seam. The loader must still return a fully populated result
// (so apply can record it) but flag ErrReferenceCAExpired.
func TestLoadReferenceCA_Expired(t *testing.T) {
	gen := generateCAForRef(t, `
ca {
  name     = "old-mesh"
  duration = "1h"
}`)

	restore := timeNow
	timeNow = func() time.Time { return fixedTime.Add(2 * time.Hour) }
	defer func() { timeNow = restore }()

	got, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM)
	if !errors.Is(err, ErrReferenceCAExpired) {
		t.Fatalf("err = %v, want ErrReferenceCAExpired", err)
	}
	if got == nil {
		t.Fatal("result = nil for expired CA, want populated result so the caller can record + warn")
	}
	if got.Fingerprint != gen.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q even when expired", got.Fingerprint, gen.Fingerprint)
	}
}

// TestLoadReferenceCA_NotExpiredWhenValid guards the happy path against a
// false-positive expiry: a freshly generated CA evaluated at issuance
// time must not be flagged.
func TestLoadReferenceCA_NotExpiredWhenValid(t *testing.T) {
	gen := generateCAForRef(t, `ca { name = "fresh" }`)

	restore := timeNow
	timeNow = func() time.Time { return fixedTime.Add(time.Hour) }
	defer func() { timeNow = restore }()

	if _, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM); err != nil {
		t.Fatalf("LoadReferenceCA: %v", err)
	}
}

// mintHostCert produces a non-CA (leaf) certificate signed by a throwaway
// CA, plus its key PEM, for negative tests that need a real-but-not-CA
// certificate.
func mintHostCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	ca := mustParseCA(t, `ca { name = "issuer" }`)
	caRes, err := GenerateCA(ca.CA, fixedTime)
	if err != nil {
		t.Fatalf("GenerateCA issuer: %v", err)
	}
	caCert, _, err := cert.UnmarshalCertificateFromPEM(caRes.CertPEM)
	if err != nil {
		t.Fatalf("unmarshal issuer cert: %v", err)
	}
	caKey, _, caCurve, err := cert.UnmarshalSigningPrivateKeyFromPEM(caRes.KeyPEM)
	if err != nil {
		t.Fatalf("unmarshal issuer key: %v", err)
	}

	hostPub, _, err := generateKeypair(caCurve)
	if err != nil {
		t.Fatalf("generate host keypair: %v", err)
	}

	hostNet, err := netip.ParsePrefix("10.0.0.9/24")
	if err != nil {
		t.Fatalf("parse host network: %v", err)
	}
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "a-host",
		Networks:  []netip.Prefix{hostNet},
		NotBefore: fixedTime,
		NotAfter:  fixedTime.Add(time.Hour),
		PublicKey: hostPub,
		IsCA:      false,
		Curve:     caCurve,
	}
	hostCert, err := tbs.Sign(caCert, caCurve, caKey)
	if err != nil {
		t.Fatalf("sign host cert: %v", err)
	}
	hostCertPEM, err := hostCert.MarshalPEM()
	if err != nil {
		t.Fatalf("marshal host cert: %v", err)
	}
	return hostCertPEM, nil
}
