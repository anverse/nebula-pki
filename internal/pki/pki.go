// Package pki wraps the upstream github.com/slackhq/nebula/cert library
// to produce nebula-pki's certificate artifacts. It is pure on the input
// side: configuration and an issuance time in, certificate and key bytes
// out. It performs no filesystem access — callers persist the returned
// bytes (see internal/apply + internal/fsutil).
//
// v0.0.3 implements CA generation only. Host signing arrives in a later
// milestone step.
package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/slackhq/nebula/cert"
)

// defaultCADuration mirrors nebula-cert's own default validity window for
// a CA (8760h = 365 days) and is applied when ca.duration is omitted.
const defaultCADuration = 8760 * time.Hour

// CAResult is the output of GenerateCA: the PEM bytes to persist plus the
// resolved metadata the manifest records. Curve and Version are returned
// in their user-facing HCL spellings ("25519"/"P256", 1/2) so callers do
// not need to translate upstream enum values. NotBefore/NotAfter are read
// back from the signed certificate, so they match the on-disk artifact
// exactly (the wire format stores second precision).
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
