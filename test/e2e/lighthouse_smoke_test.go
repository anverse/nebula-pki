package e2e

// lighthouse_smoke_test.go — dynamic smoke test that runs the real nebula
// binary against freshly generated artifacts: an unprivileged lighthouse
// (tun.disabled) plus a client node on loopback, asserting that a Noise
// handshake completes on both curves. This is the only test that proves
// the generated X25519/P256 key material works for actual DH, not just
// parsing.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/apply"
	"github.com/anverse/nebula-pki/internal/config"
)

// syncBuffer is a goroutine-safe bytes.Buffer for capturing process output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freeUDPPort reserves an ephemeral UDP port on loopback and returns it.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

// startNebula launches `nebula -config cfgPath` with combined output captured
// into the returned buffer. The process is killed via t.Cleanup.
func startNebula(t *testing.T, ctx context.Context, nebulaPath, cfgPath string) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	cmd := exec.CommandContext(ctx, nebulaPath, "-config", cfgPath)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start nebula (%s): %v", cfgPath, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return out
}

// nodePKI holds the pki paths of one node, relative to the test directory.
type nodePKI struct {
	CA, Cert, Key string
}

func nodeConfig(dir string, pki nodePKI, extra string) string {
	return fmt.Sprintf(`pki:
  ca: %[1]s/%[2]s
  cert: %[1]s/%[3]s
  key: %[1]s/%[4]s
tun:
  disabled: true
logging:
  level: info
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
%[5]s`, dir, pki.CA, pki.Cert, pki.Key, extra)
}

// requireBinary returns the path to the named binary, failing the test if
// it is missing. The nebula toolchain is a hard requirement for the smoke
// tests, not an optional extra: the nix dev shell provides it and CI
// installs it, so a missing binary means a broken environment, not a
// reason to silently skip.
func requireBinary(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s not in PATH (the nix dev shell provides it; see development.md)", name)
	}
	return p
}

// TestSmoke_BinariesPresent guards the txtar smoke scripts, whose
// [!exec:...] guards would otherwise let every smoke-nebula-*.txtar script
// skip silently when the toolchain is missing. This test fails instead.
// sops is required by smoke-nebula-sops.txtar.
func TestSmoke_BinariesPresent(t *testing.T) {
	requireBinary(t, "nebula")
	requireBinary(t, "nebula-cert")
	requireBinary(t, "sops")
}

func TestSmoke_LighthouseHandshake(t *testing.T) {
	nebulaPath := requireBinary(t, "nebula")
	for _, curve := range []string{"25519", "P256"} {
		t.Run(curve, func(t *testing.T) {
			testLighthouseHandshake(t, nebulaPath, curve)
		})
	}
}

func testLighthouseHandshake(t *testing.T, nebulaPath, curve string) {
	hcl := fmt.Sprintf(`
ca "mesh" {
  name  = "smoke-mesh"
  curve = %q
}

cert "lh" {
  networks = ["172.31.0.1/24"]
  groups   = ["lighthouse"]
}

cert "client" {
  networks = ["172.31.0.2/24"]
}
`, curve)
	runHandshake(t, nebulaPath, hcl,
		nodePKI{CA: "out/ca/mesh.crt", Cert: "out/certs/lh.crt", Key: "out/certs/lh.key"},
		nodePKI{CA: "out/ca/mesh.crt", Cert: "out/certs/client.crt", Key: "out/certs/client.key"},
	)
}

// TestSmoke_TrustBundleHandshake proves the emitted trust bundle works with
// the real nebula binary: the lighthouse and the client are signed by two
// different CAs, so the handshake only completes when each node trusts both
// CAs through the bundle. Each node reads pki.ca through the trust_bundle
// link_crt symlink in its own output directory, the fan-out pattern ADR-026
// exists for.
func TestSmoke_TrustBundleHandshake(t *testing.T) {
	nebulaPath := requireBinary(t, "nebula")
	hcl := `
trust_bundle "main" {
  ca_refs  = [ca.old, ca.new]
  link_crt = ["out/lh", "out/client"]
}

ca "old" {
  name = "smoke-mesh-old"
}

ca "new" {
  name    = "smoke-mesh-new"
  default = true
}

cert "lh" {
  ca         = ca.old
  networks   = ["172.31.0.1/24"]
  groups     = ["lighthouse"]
  output_dir = "out/lh"
}

cert "client" {
  networks   = ["172.31.0.2/24"]
  output_dir = "out/client"
}
`
	runHandshake(t, nebulaPath, hcl,
		nodePKI{CA: "out/lh/main.crt", Cert: "out/lh/lh.crt", Key: "out/lh/lh.key"},
		nodePKI{CA: "out/client/main.crt", Cert: "out/client/client.crt", Key: "out/client/client.key"},
	)
}

// runHandshake reconciles hcl in a fresh directory, starts a lighthouse and a
// client with the given pki paths, and waits for a completed handshake.
func runHandshake(t *testing.T, nebulaPath, hcl string, lhPKI, clientPKI nodePKI) {
	// Generate the CAs and cert/key pairs in-process, the same way
	// `nebula-pki` does (apply.Reconcile is the CLI's whole write path).
	dir := t.TempDir()
	hclPath := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(hclPath, []byte(hcl), 0o644); err != nil {
		t.Fatalf("write nebula.hcl: %v", err)
	}
	cfg, err := config.Load(hclPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if _, err := apply.Reconcile(cfg, apply.Options{Now: time.Now(), GeneratorVersion: "smoke-test"}); err != nil {
		t.Fatalf("apply.Reconcile: %v", err)
	}

	port := freeUDPPort(t)

	lhCfg := filepath.Join(dir, "lh.yml")
	lhYAML := nodeConfig(dir, lhPKI, fmt.Sprintf(`listen:
  host: 127.0.0.1
  port: %d
lighthouse:
  am_lighthouse: true
`, port))
	if err := os.WriteFile(lhCfg, []byte(lhYAML), 0o644); err != nil {
		t.Fatalf("write lh.yml: %v", err)
	}

	clientCfg := filepath.Join(dir, "client.yml")
	clientYAML := nodeConfig(dir, clientPKI, fmt.Sprintf(`listen:
  host: 127.0.0.1
  port: 0
static_host_map:
  "172.31.0.1": ["127.0.0.1:%d"]
lighthouse:
  am_lighthouse: false
  interval: 1
  hosts:
    - "172.31.0.1"
`, port))
	if err := os.WriteFile(clientCfg, []byte(clientYAML), 0o644); err != nil {
		t.Fatalf("write client.yml: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	lhOut := startNebula(t, ctx, nebulaPath, lhCfg)
	clientOut := startNebula(t, ctx, nebulaPath, clientCfg)

	// The client handshakes with its lighthouse on startup. The responder's
	// stage-1 "Handshake message received" is not enough: Noise IX message 1
	// is just `e, s`, no DH has happened yet. The initiator logs "Handshake
	// message received" at stage 2 (nebula handshake_ix.go) only after
	// decrypting the responder's reply, which requires both sides to derive
	// identical keys from the ee/es/se DH — the actual proof that the
	// generated private keys pair with the certificates.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if strings.Contains(clientOut.String(), "Handshake message received") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no completed handshake within deadline\n--- lighthouse log ---\n%s\n--- client log ---\n%s",
				lhOut.String(), clientOut.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
