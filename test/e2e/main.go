package e2e

import (
	"crypto/ecdh"
	"crypto/ed25519"
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
// only — it is never shipped as a subcommand (see ADR-018 on why nebula-pki
// does not include a keygen command).
//
// Usage in txtar scripts:
//
//	gen-host-pub <output-path> [curve]
//
// curve is "25519" (default) or "P256".
func genHostPub(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) < 1 {
		ts.Fatalf("gen-host-pub: usage: gen-host-pub <output-path> [25519|P256]")
	}
	outPath := ts.MkAbs(args[0])

	curve := cert.Curve_CURVE25519
	if len(args) >= 2 && args[1] == "P256" {
		curve = cert.Curve_P256
	}

	var pubRaw []byte
	switch curve {
	case cert.Curve_CURVE25519:
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		ts.Check(err)
		pubRaw = pub
	case cert.Curve_P256:
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		ts.Check(err)
		pubRaw = key.PublicKey().Bytes()
	}

	pubPEM := cert.MarshalPublicKeyToPEM(curve, pubRaw)
	if pubPEM == nil {
		ts.Fatalf("gen-host-pub: MarshalPublicKeyToPEM returned nil")
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		ts.Fatalf("gen-host-pub: mkdir: %v", err)
	}
	ts.Check(os.WriteFile(outPath, pubPEM, 0o600))
}
