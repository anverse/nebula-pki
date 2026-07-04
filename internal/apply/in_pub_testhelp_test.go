package apply

// in_pub_testhelp_test.go — low-level keypair generation helpers used by the
// in_pub apply tests. These helpers are test-only; they model what a device
// (or nebula-cert keygen) would produce and are never shipped.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"

	"github.com/slackhq/nebula/cert"
)

// generateEd25519 generates an Ed25519 keypair and returns the raw public and
// private key bytes. Nebula uses Ed25519 for CURVE25519 host certificates.
func generateEd25519() (pub, priv []byte, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	return pubKey, privKey, err
}

// marshalPubPEM encodes a raw Curve25519 (Ed25519) public key to the PEM
// format that nebula-cert keygen writes.
func marshalPubPEM(pub []byte) []byte {
	return cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub)
}

// generateP256Pub generates a P256 keypair and returns the raw public key bytes.
func generateP256Pub() ([]byte, error) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

// marshalP256PubPEM encodes a raw P256 public key to PEM format.
func marshalP256PubPEM(pub []byte) []byte {
	return cert.MarshalPublicKeyToPEM(cert.Curve_P256, pub)
}
