package apply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
)

// TestReconcile_RecordedSpellingNotStale checks that a cert path recorded in
// another spelling of the same file (e.g. by a run before paths were
// cleaned) is not reported as a stale artifact when the cert is re-signed.
func TestReconcile_RecordedSpellingNotStale(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nebula.hcl")
	src := `
ca "mesh" { name = "mesh" }
cert "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
}
`
	if err := os.WriteFile(configPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	// Respell the recorded cert and key paths, as an older manifest would.
	manifestReal := cfg.Resolve(cfg.ManifestPath())
	data, err := os.ReadFile(manifestReal)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	respelled := strings.ReplaceAll(string(data), `"dir-a/node.`, `"./dir-a/node.`)
	if respelled == string(data) {
		t.Fatal("manifest does not record dir-a/node.* paths")
	}
	if err := os.WriteFile(manifestReal, []byte(respelled), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Force a re-sign while the cert file is still there.
	if err := os.Remove(filepath.Join(tmpDir, "dir-a", "node.key")); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	rep, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(rep.SignedCerts) != 1 {
		t.Fatalf("SignedCerts = %v, want node re-signed", rep.SignedCerts)
	}
	if len(rep.StaleArtifacts) != 0 {
		t.Errorf("StaleArtifacts = %v, want none for the same files", rep.StaleArtifacts)
	}
}
