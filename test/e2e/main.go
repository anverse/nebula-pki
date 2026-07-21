package e2e

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anverse/nebula-pki/internal/cli"
	"github.com/rogpeppe/go-internal/testscript"
	"github.com/slackhq/nebula/cert"
)

// nebulaPkiMain is registered with testscript.RunMain so scripts can
// invoke `nebula-pki ...` against the in-process binary. Mirrors the
// behaviour of cmd/nebula-pki/main.go so testscript scenarios observe
// the same stdout/stderr/exit-code surface that real users see.
func nebulaPkiMain() int {
	root := cli.New(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// genHostPub is a testscript command that generates a device keypair and
// writes the public key PEM to the given path. This is TEST INFRASTRUCTURE
// only; it is never shipped as a subcommand (see ADR-018 on why nebula-pki
// does not include a keygen command).
//
// Usage in txtar scripts:
//
//	gen-host-pub [-key <key-path>] <output-path> [curve]
//
// curve is "25519" (default) or "P256". With -key, the device private key
// PEM is also written, so smoke tests can assemble a full nebula config
// for an in_pub-signed certificate.
func genHostPub(ts *testscript.TestScript, neg bool, args []string) {
	const usage = "gen-host-pub: usage: gen-host-pub [-key <key-path>] <output-path> [25519|P256]"

	keyPath := ""
	if len(args) >= 2 && args[0] == "-key" {
		keyPath = ts.MkAbs(args[1])
		args = args[2:]
	}
	if len(args) < 1 {
		ts.Fatalf(usage)
	}
	outPath := ts.MkAbs(args[0])

	curve := cert.Curve_CURVE25519
	if len(args) >= 2 && args[1] == "P256" {
		curve = cert.Curve_P256
	}

	var pubRaw, privRaw []byte
	switch curve {
	case cert.Curve_CURVE25519:
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		ts.Check(err)
		pubRaw = key.PublicKey().Bytes()
		privRaw = key.Bytes()
	case cert.Curve_P256:
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		ts.Check(err)
		pubRaw = key.PublicKey().Bytes()
		privRaw = key.Bytes()
	}

	pubPEM := cert.MarshalPublicKeyToPEM(curve, pubRaw)
	if pubPEM == nil {
		ts.Fatalf("gen-host-pub: MarshalPublicKeyToPEM returned nil")
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		ts.Fatalf("gen-host-pub: mkdir: %v", err)
	}
	ts.Check(os.WriteFile(outPath, pubPEM, 0o600))

	if keyPath != "" {
		keyPEM := cert.MarshalPrivateKeyToPEM(curve, privRaw)
		if keyPEM == nil {
			ts.Fatalf("gen-host-pub: MarshalPrivateKeyToPEM returned nil")
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
			ts.Fatalf("gen-host-pub: mkdir: %v", err)
		}
		ts.Check(os.WriteFile(keyPath, keyPEM, 0o600))
	}
}
