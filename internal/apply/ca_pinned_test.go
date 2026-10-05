package apply

// Tests for generate-mode CAs pinned to their label (ADR-027): deleted CA
// files and a swapped encrypted key are errors, and nothing is written.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
)

// catEncryption is an external backend that stores keys unchanged, so tests
// can swap "encrypted" key files without a real encryption tool.
const catEncryption = `
storage {
  encryption "external" {
    encrypt_command = ["cat"]
    decrypt_command = ["cat"]
  }
}
`

// rewriteConfig replaces the config at cfg.Path with src and reloads it.
func rewriteConfig(t *testing.T, cfg *config.Config, src string) *config.Config {
	t.Helper()
	if err := os.WriteFile(cfg.Path, []byte(src), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	next, err := config.Load(cfg.Path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return next
}

// snapshot reads every regular file under the config directory, keyed by
// path relative to it.
func snapshot(t *testing.T, cfg *config.Config) map[string][]byte {
	t.Helper()
	root := filepath.Dir(cfg.Path)
	files := make(map[string][]byte)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		files[rel] = mustRead(t, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return files
}

func assertUnchanged(t *testing.T, before, after map[string][]byte) {
	t.Helper()
	for path, b := range before {
		if a, ok := after[path]; !ok {
			t.Errorf("%s was removed", path)
		} else if !bytes.Equal(a, b) {
			t.Errorf("%s changed", path)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Errorf("%s was created", path)
		}
	}
}

func TestReconcile_GeneratedCAFilesDeletedIsAnError(t *testing.T) {
	cfg := writeConfig(t, `
ca "mesh" { name = "mesh" }
trust_bundle "main" { ca_refs = [ca.mesh] }
cert "app" { networks = ["10.0.0.1/16"] }
`)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	ca := cfg.CAs[0]
	for _, p := range []string{cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)} {
		if err := os.Remove(cfg.Resolve(p)); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshot(t, cfg)

	for _, dryRun := range []bool{true, false} {
		_, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion, DryRun: dryRun})
		if err == nil || !strings.Contains(err.Error(), `ca "mesh": CA files missing`) {
			t.Fatalf("Reconcile (dry run %v) error = %v, want the missing CA files error", dryRun, err)
		}
	}
	assertUnchanged(t, before, snapshot(t, cfg))
}

func TestReconcile_EncryptedCAKeySwapped(t *testing.T) {
	const base = `ca "mesh" { name = "mesh" }` + catEncryption + `
cert "app" { networks = ["10.0.0.1/16"] }
`
	cfg := writeConfig(t, base)
	if _, err := Reconcile(cfg, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	other := writeConfig(t, base)
	if _, err := Reconcile(other, Options{Now: fixedNow, GeneratorVersion: genVersion}); err != nil {
		t.Fatalf("other Reconcile: %v", err)
	}

	// Put the other CA's (cat-"encrypted") key next to this CA's cert.
	keyPath := cfg.CAKeyPathForCA(cfg.CAs[0]) + cfg.Storage.Encryption.KeySuffix()
	if err := os.WriteFile(cfg.Resolve(keyPath), mustRead(t, other.Resolve(keyPath)), 0o600); err != nil {
		t.Fatal(err)
	}

	// Every cert up to date: the key is never decrypted, nothing is signed,
	// so the swap goes unnoticed and the run stays a no-op.
	rep, err := Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err != nil {
		t.Fatalf("no-op Reconcile: %v", err)
	}
	if rep.Changed {
		t.Error("Changed = true, want a no-op run")
	}

	// A cert to sign: the decrypted key is checked against the CA cert first.
	cfg = rewriteConfig(t, cfg, base+`cert "new" { networks = ["10.0.0.2/16"] }`)
	before := snapshot(t, cfg)
	_, err = Reconcile(cfg, Options{Now: fixedNow.Add(time.Hour), GeneratorVersion: genVersion})
	if err == nil || !strings.Contains(err.Error(), `ca "mesh": CA key does not match certificate`) {
		t.Fatalf("Reconcile error = %v, want the key mismatch error", err)
	}
	assertUnchanged(t, before, snapshot(t, cfg))
}
