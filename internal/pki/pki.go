// Package pki wraps the upstream github.com/slackhq/nebula/cert library
// to produce nebula-pki's certificate artifacts. It is pure on the input
// side: configuration and an issuance time in, certificate and key bytes
// out. It performs no filesystem access — callers persist the returned
// bytes (see internal/apply + internal/fsutil).
//
// It supports two CA paths: GenerateCA mints a fresh self-signed CA, and
// LoadReferenceCA reads and verifies an operator-supplied existing CA
// without rewriting it. Host signing arrives in a later milestone step.
package pki

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/slackhq/nebula/cert"
)

// defaultCADuration mirrors nebula-cert's own default validity window for
// a CA (8760h = 365 days) and is applied when ca.duration is omitted.
const defaultCADuration = 8760 * time.Hour

// CAResult is the output of GenerateCA and LoadReferenceCA: the resolved
// metadata the manifest records, plus (for GenerateCA only) the PEM bytes
// to persist. Curve and Version are returned in their user-facing HCL
// spellings ("25519"/"P256", 1/2) so callers do not need to translate
// upstream enum values. NotBefore/NotAfter are read back from the
// certificate, so they match the on-disk artifact exactly (the wire
// format stores second precision).
//
// LoadReferenceCA leaves CertPEM and KeyPEM nil: reference mode reads the
// operator's existing files in place and never rewrites them.
type CAResult struct {
	CertPEM []byte
	KeyPEM  []byte

	Name        string
	Curve       string
	Version     int
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
}

// GenerateCA creates a self-signed Nebula CA from the generate-mode CA
// configuration, using now as the certificate's NotBefore. The caller is
// responsible for having validated that ca is in generate mode.
func GenerateCA(ca config.CA, now time.Time) (*CAResult, error) {
	if ca.Encrypt {
		return nil, fmt.Errorf("ca.encrypt (passphrase-encrypted CA key) is not implemented in this release; remove `encrypt` or leave it false")
	}

	curve := cert.Curve_CURVE25519
	if ca.HasCurve {
		curve = ca.Curve
	}
	version := cert.Version2
	if ca.HasVersion {
		version = ca.Version
	}
	duration := defaultCADuration
	if ca.HasDuration {
		duration = ca.Duration
	}

	pub, rawPriv, err := generateKeypair(curve)
	if err != nil {
		return nil, err
	}

	tbs := &cert.TBSCertificate{
		Version:        version,
		Name:           ca.Name,
		Groups:         ca.Groups,
		Networks:       ca.Networks,
		UnsafeNetworks: ca.UnsafeNetworks,
		NotBefore:      now,
		NotAfter:       now.Add(duration),
		PublicKey:      pub,
		IsCA:           true,
		Curve:          curve,
	}

	// A CA is self-signed: the signer certificate is nil and the key used
	// to sign is the CA's own freshly generated private key.
	c, err := tbs.Sign(nil, curve, rawPriv)
	if err != nil {
		return nil, fmt.Errorf("sign CA certificate: %w", err)
	}

	certPEM, err := c.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal CA certificate: %w", err)
	}
	keyPEM := cert.MarshalSigningPrivateKeyToPEM(curve, rawPriv)
	if keyPEM == nil {
		return nil, fmt.Errorf("marshal CA private key: unsupported curve %s", curve)
	}
	fp, err := c.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("compute CA fingerprint: %w", err)
	}

	return &CAResult{
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Name:        c.Name(),
		Curve:       curveString(curve),
		Version:     int(version),
		Fingerprint: fp,
		NotBefore:   c.NotBefore(),
		NotAfter:    c.NotAfter(),
	}, nil
}

// ErrReferenceCAExpired signals that a loaded reference CA's validity
// window has already ended. It is returned by LoadReferenceCA alongside a
// fully populated *CAResult so callers can decide policy: the apply layer
// records the CA and warns rather than aborting (the operator owns the CA
// in reference mode). Test for it with errors.Is.
var ErrReferenceCAExpired = errors.New("reference CA is expired")

// LoadReferenceCA parses and verifies an operator-supplied existing CA
// from its certificate and private-key PEM bytes. It performs no
// filesystem access; the caller reads the files. On success it returns
// the same CAResult shape as GenerateCA, but with CertPEM/KeyPEM nil —
// reference mode never rewrites the source files.
//
// Verification is deliberately strict so a misconfigured pair fails now,
// at load time, rather than later when the first host is signed:
//
//   - the certificate must be a CA (IsCA);
//   - its self-signature must verify against its own public key;
//   - the private key's curve must match the certificate's curve;
//   - the public key derived from the private key must equal the
//     certificate's public key (i.e. the key really is this CA's key).
//
// The now argument is the instant the validity window is evaluated
// against. It is an explicit parameter rather than a call to time.Now so
// the expiry verdict is a pure function of (cert, now): the same inputs
// always produce the same result. apply passes its injected issuance
// clock (Options.Now) so a reconcile is fully deterministic; the `check`
// command passes the real time.Now (it is asking "is this expired right
// now?"); tests pass a fixed instant.
//
// An expired certificate is not a hard failure: the populated result is
// returned together with ErrReferenceCAExpired so the caller can warn and
// proceed. Every other problem returns a nil result and a descriptive
// error.
func LoadReferenceCA(certPEM, keyPEM []byte, now time.Time) (*CAResult, error) {
	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse reference CA certificate: %w", err)
	}
	if !c.IsCA() {
		return nil, fmt.Errorf("reference CA certificate %q is not a CA certificate (IsCA=false)", c.Name())
	}
	if !c.CheckSignature(c.PublicKey()) {
		return nil, fmt.Errorf("reference CA certificate %q has an invalid self-signature", c.Name())
	}

	rawKey, _, keyCurve, err := cert.UnmarshalSigningPrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse reference CA key: %w", err)
	}
	if keyCurve != c.Curve() {
		return nil, fmt.Errorf(
			"reference CA key curve %s does not match certificate curve %s",
			curveString(keyCurve), curveString(c.Curve()),
		)
	}

	derivedPub, err := publicFromSigningKey(keyCurve, rawKey)
	if err != nil {
		return nil, fmt.Errorf("reference CA key: %w", err)
	}
	if !bytes.Equal(derivedPub, c.PublicKey()) {
		return nil, fmt.Errorf("reference CA key does not match certificate %q (public keys differ)", c.Name())
	}

	fp, err := c.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("compute reference CA fingerprint: %w", err)
	}

	res := &CAResult{
		Name:        c.Name(),
		Curve:       curveString(c.Curve()),
		Version:     int(c.Version()),
		Fingerprint: fp,
		NotBefore:   c.NotBefore(),
		NotAfter:    c.NotAfter(),
	}

	// Expiry is a policy decision left to the caller; surface it as a
	// sentinel rather than swallowing it or aborting here. A non-positive
	// validity window (NotAfter not after NotBefore) is treated the same
	// way — the cert can never be valid. The comparison uses the caller's
	// now so the verdict is deterministic and never depends on wall-clock
	// time advancing between runs.
	if !c.NotAfter().After(c.NotBefore()) || c.NotAfter().Before(now) {
		return res, ErrReferenceCAExpired
	}
	return res, nil
}

// publicFromSigningKey derives the public key bytes for a raw signing
// private key, in the same byte layout cert stores in the certificate's
// PublicKey(). It is the inverse of generateKeypair and lets
// LoadReferenceCA confirm a key/cert pair really belong together.
func publicFromSigningKey(curve cert.Curve, rawPriv []byte) ([]byte, error) {
	switch curve {
	case cert.Curve_CURVE25519:
		if len(rawPriv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("ed25519 key has length %d, want %d", len(rawPriv), ed25519.PrivateKeySize)
		}
		priv := ed25519.PrivateKey(rawPriv)
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("ed25519 key did not yield an ed25519 public key")
		}
		return pub, nil

	case cert.Curve_P256:
		priv, err := ecdh.P256().NewPrivateKey(rawPriv)
		if err != nil {
			return nil, fmt.Errorf("invalid P256 key: %w", err)
		}
		return priv.PublicKey().Bytes(), nil

	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// generateKeypair returns the public key and the raw signing private key
// for the given curve, in the byte layouts the cert library's Sign and
// MarshalSigningPrivateKeyToPEM expect (64-byte Ed25519 private key, or
// the 32-byte P256 scalar via the ECDH encoding).
func generateKeypair(curve cert.Curve) (pub, rawPriv []byte, err error) {
	switch curve {
	case cert.Curve_CURVE25519:
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		return pubKey, privKey, nil

	case cert.Curve_P256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ecdsa P256 key: %w", err)
		}
		// ecdh.PrivateKey exposes the raw encoded bytes the cert library
		// works with, even though we are not performing ECDH here.
		ek, err := key.ECDH()
		if err != nil {
			return nil, nil, fmt.Errorf("convert ecdsa P256 key: %w", err)
		}
		return ek.PublicKey().Bytes(), ek.Bytes(), nil

	default:
		return nil, nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// HostResult is the output of SignHost: the signed certificate and its
// freshly generated private key, plus the metadata the manifest records.
// Curve and Version are returned in their HCL spellings ("25519"/"P256",
// 1/2) for consistency with CAResult and the manifest format.
type HostResult struct {
	CertPEM []byte
	KeyPEM  []byte

	Name          string
	Fingerprint   string
	Curve         string
	Version       int
	NotBefore     time.Time
	NotAfter      time.Time
	CAFingerprint string
}

// SignHost signs a host certificate under the given CA, returning the cert
// PEM and a freshly generated private key PEM. It is pure on the input
// side (no filesystem access) and inherits the curve and certificate
// version from the signing CA so callers do not need to specify them.
//
// If h.HasDuration is true, the host cert expires now+h.Duration.
// Otherwise it co-expires with the CA (mirrors nebula-cert sign's default
// behaviour when no -duration flag is given).
func SignHost(caCertPEM, caKeyPEM []byte, h config.Host, now time.Time) (*HostResult, error) {
	caCert, _, err := cert.UnmarshalCertificateFromPEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate for host signing: %w", err)
	}

	rawKey, _, keyCurve, err := cert.UnmarshalSigningPrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA key for host signing: %w", err)
	}

	curve := caCert.Curve()
	version := caCert.Version()

	notAfter := caCert.NotAfter()
	if h.HasDuration {
		notAfter = now.Add(h.Duration)
	}

	pub, rawPriv, err := generateKeypair(curve)
	if err != nil {
		return nil, fmt.Errorf("generate host keypair: %w", err)
	}

	tbs := &cert.TBSCertificate{
		Version:        version,
		Name:           h.Name,
		Groups:         h.Groups,
		Networks:       h.Networks,
		UnsafeNetworks: h.UnsafeNetworks,
		NotBefore:      now,
		NotAfter:       notAfter,
		PublicKey:      pub,
		IsCA:           false,
		Curve:          curve,
	}

	c, err := tbs.Sign(caCert, keyCurve, rawKey)
	if err != nil {
		return nil, fmt.Errorf("sign host certificate %q: %w", h.Name, err)
	}

	certPEM, err := c.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal host certificate %q: %w", h.Name, err)
	}
	keyPEM := cert.MarshalSigningPrivateKeyToPEM(curve, rawPriv)
	if keyPEM == nil {
		return nil, fmt.Errorf("marshal host private key %q: unsupported curve %s", h.Name, curve)
	}

	fp, err := c.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("compute host certificate fingerprint %q: %w", h.Name, err)
	}
	caFP, err := caCert.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("compute CA fingerprint while signing host %q: %w", h.Name, err)
	}

	return &HostResult{
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		Name:          c.Name(),
		Fingerprint:   fp,
		Curve:         curveString(curve),
		Version:       int(version),
		NotBefore:     c.NotBefore(),
		NotAfter:      c.NotAfter(),
		CAFingerprint: caFP,
	}, nil
}

// curveString maps an upstream curve enum back to the HCL spelling used
// throughout the config surface and the manifest.
func curveString(cv cert.Curve) string {
	switch cv {
	case cert.Curve_CURVE25519:
		return "25519"
	case cert.Curve_P256:
		return "P256"
	default:
		return cv.String()
	}
}
