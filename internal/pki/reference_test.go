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

	got, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM, fixedTime)
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

	got, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM, fixedTime)
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
	if _, err := LoadReferenceCA([]byte("not a pem block"), gen.KeyPEM, fixedTime); err == nil {
		t.Fatal("LoadReferenceCA: want error for corrupt cert PEM, got nil")
	}
}

func TestLoadReferenceCA_CorruptKeyPEM(t *testing.T) {
	gen := generateCAForRef(t, `ca { name = "x" }`)
	if _, err := LoadReferenceCA(gen.CertPEM, []byte("not a pem block"), fixedTime); err == nil {
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

	_, err := LoadReferenceCA(hostCertPEM, gen.KeyPEM, fixedTime)
	if err == nil {
		t.Fatal("LoadReferenceCA: want error for non-CA certificate, got nil")
	}
	if !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("error = %q, want it to mention 'not a CA'", err.Error())
	}
}

// TestLoadReferenceCA_BadSelfSignature covers the self-signature
// verification guarantee (pki.go CheckSignature). It mints a CA
// certificate whose body was signed by one key but whose embedded public
// key belongs to a *different* key, so the IsCA check passes but the
// self-signature does not verify against the certificate's own public
// key. This is the tampered/re-encoded-CA case an operator could hit by
// pointing cert_file at a doctored certificate; without this test the
// branch is uncovered even though it is a stated security property.
func TestLoadReferenceCA_BadSelfSignature(t *testing.T) {
	certPEM, keyPEM := mintBadSelfSignedCA(t)

	_, err := LoadReferenceCA(certPEM, keyPEM, fixedTime)
	if err == nil {
		t.Fatal("LoadReferenceCA: want error for invalid self-signature, got nil")
	}
	if !strings.Contains(err.Error(), "self-signature") {
		t.Errorf("error = %q, want it to mention 'self-signature'", err.Error())
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

	_, err := LoadReferenceCA(ca25519.CertPEM, caP256.KeyPEM, fixedTime)
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

	_, err := LoadReferenceCA(caA.CertPEM, caB.KeyPEM, fixedTime)
	if err == nil {
		t.Fatal("LoadReferenceCA: want error for mismatched key/cert, got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error = %q, want it to mention 'does not match'", err.Error())
	}
}

// TestLoadReferenceCA_Expired evaluates the CA at an instant past its
// NotAfter. The loader must still return a fully populated result (so
// apply can record it) but flag ErrReferenceCAExpired. The instant is
// passed explicitly, so the verdict never depends on the wall clock.
func TestLoadReferenceCA_Expired(t *testing.T) {
	gen := generateCAForRef(t, `
ca {
  name     = "old-mesh"
  duration = "1h"
}`)

	// Two hours after issuance the 1h CA is expired.
	now := fixedTime.Add(2 * time.Hour)

	got, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM, now)
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
// false-positive expiry: a freshly generated CA evaluated inside its
// validity window must not be flagged.
func TestLoadReferenceCA_NotExpiredWhenValid(t *testing.T) {
	gen := generateCAForRef(t, `ca { name = "fresh" }`)

	if _, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM, fixedTime.Add(time.Hour)); err != nil {
		t.Fatalf("LoadReferenceCA: %v", err)
	}
}

// TestLoadReferenceCA_ExpiresExactlyAtNotAfter pins the boundary: the
// validity window is inclusive of NotAfter (the check is
// NotAfter.Before(now), so the cert is expired only once now is strictly
// past NotAfter). This is the edge the explicit-clock change makes
// testable without racing wall-clock time.
func TestLoadReferenceCA_ExpiresExactlyAtNotAfter(t *testing.T) {
	gen := generateCAForRef(t, `
ca {
  name     = "boundary"
  duration = "1h"
}`)

	// Exactly at NotAfter: still valid (the window includes its endpoint).
	if _, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM, gen.NotAfter); err != nil {
		t.Errorf("at NotAfter: err = %v, want valid (window is inclusive)", err)
	}

	// One nanosecond past NotAfter: expired.
	justPast := gen.NotAfter.Add(time.Nanosecond)
	if _, err := LoadReferenceCA(gen.CertPEM, gen.KeyPEM, justPast); !errors.Is(err, ErrReferenceCAExpired) {
		t.Errorf("at NotAfter+1ns: err = %v, want ErrReferenceCAExpired", err)
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

// mintBadSelfSignedCA produces a CA certificate whose self-signature does
// not verify against its own public key, plus a syntactically valid
// signing key PEM. It does this by signing a CA TBSCertificate with key A
// while setting the certificate's embedded PublicKey to key B's public
// key: the signature is valid over the marshalled bytes, but
// CheckSignature(cert.PublicKey()) verifies against B's key, which never
// signed anything, so it fails. IsCA is true, so the loader reaches the
// self-signature check rather than bailing earlier.
//
// The returned key PEM is key A. LoadReferenceCA verifies the
// self-signature before the key/cert match, so this exercises the
// signature branch specifically (the curve still matches, so we do not
// trip the curve check either).
func mintBadSelfSignedCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	// Key A signs; key B's public key is embedded in the certificate.
	caA := generateCAForRef(t, `ca { name = "signer-a" }`)
	caB := generateCAForRef(t, `ca { name = "victim-b" }`)

	keyA, _, curveA, err := cert.UnmarshalSigningPrivateKeyFromPEM(caA.KeyPEM)
	if err != nil {
		t.Fatalf("unmarshal key A: %v", err)
	}
	certB, _, err := cert.UnmarshalCertificateFromPEM(caB.CertPEM)
	if err != nil {
		t.Fatalf("unmarshal cert B: %v", err)
	}

	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "mismatched-ca",
		NotBefore: fixedTime,
		NotAfter:  fixedTime.Add(time.Hour),
		PublicKey: certB.PublicKey(), // B's public key ...
		IsCA:      true,
		Curve:     curveA,
	}
	// ... signed by A's private key. A self-signed CA passes nil as the
	// signer certificate.
	badCert, err := tbs.Sign(nil, curveA, keyA)
	if err != nil {
		t.Fatalf("sign mismatched CA: %v", err)
	}
	badPEM, err := badCert.MarshalPEM()
	if err != nil {
		t.Fatalf("marshal mismatched CA: %v", err)
	}
	return badPEM, caA.KeyPEM
}
