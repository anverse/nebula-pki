package crypto

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/anverse/nebula-pki/internal/config"
)

// testAgeKeypair is a throwaway age keypair used only in unit tests.
// It is not used to protect any real secret material.
const (
	testAgePub  = "age1rtertzj2zyt36nl3lp8cqlcjgq3e584lhfurv7rf7fmyld4ldcese49nj9"
	testAgePriv = "AGE-SECRET-KEY-1Y9PD7EAXE79XA5QEY04D7EM0X7A2F6UGQD3RAKENAYUPZQCH5ZFQ4DGP4N"
)

func TestNoneBackend(t *testing.T) {
	enc := &NoneBackend{}

	plain := []byte("NEBULA PRIVATE KEY PEM DATA")
	got, err := enc.Encrypt(plain, "/any/path.key")
	if err != nil {
		t.Fatalf("NoneBackend.Encrypt: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("NoneBackend.Encrypt mutated plaintext: got %q, want %q", got, plain)
	}
	if enc.Suffix() != "" {
		t.Errorf("NoneBackend.Suffix() = %q, want %q", enc.Suffix(), "")
	}
	if enc.BackendName() != "none" {
		t.Errorf("NoneBackend.BackendName() = %q, want %q", enc.BackendName(), "none")
	}
	if enc.RecipientsHash() != "" {
		t.Errorf("NoneBackend.RecipientsHash() = %q, want empty", enc.RecipientsHash())
	}
}

func TestSopsBackend_Defaults(t *testing.T) {
	b := newSopsBackend(nil)
	if b.Suffix() != ".enc" {
		t.Errorf("default Suffix() = %q, want %q", b.Suffix(), ".enc")
	}
	if b.BackendName() != "sops" {
		t.Errorf("BackendName() = %q, want %q", b.BackendName(), "sops")
	}
	if b.RecipientsHash() != "" {
		t.Errorf("empty config RecipientsHash() = %q, want empty", b.RecipientsHash())
	}
}

func TestSopsBackend_CustomSuffix(t *testing.T) {
	b := newSopsBackend(&config.SopsConfig{OutputSuffix: ".sops"})
	if b.Suffix() != ".sops" {
		t.Errorf("Suffix() = %q, want %q", b.Suffix(), ".sops")
	}
}

func TestSopsBackend_RecipientsHash(t *testing.T) {
	cfg := &config.SopsConfig{
		Age: []string{"age1abc", "age1xyz"},
		PGP: []string{"DEADBEEF"},
	}
	b := newSopsBackend(cfg)
	h1 := b.RecipientsHash()
	if h1 == "" {
		t.Fatal("RecipientsHash() returned empty for non-empty config")
	}

	// Same config in different order produces same hash (sorted).
	cfg2 := &config.SopsConfig{
		Age: []string{"age1xyz", "age1abc"},
		PGP: []string{"DEADBEEF"},
	}
	h2 := newSopsBackend(cfg2).RecipientsHash()
	if h1 != h2 {
		t.Errorf("RecipientsHash not stable across input order: %q vs %q", h1, h2)
	}

	// Different recipients produce a different hash.
	cfg3 := &config.SopsConfig{Age: []string{"age1different"}}
	h3 := newSopsBackend(cfg3).RecipientsHash()
	if h1 == h3 {
		t.Error("different recipients produced the same hash")
	}
}

func TestNew_NoneBackend(t *testing.T) {
	enc, err := New(config.EncryptionConfig{})
	if err != nil {
		t.Fatalf("New(empty): %v", err)
	}
	if enc.BackendName() != "none" {
		t.Errorf("BackendName() = %q, want %q", enc.BackendName(), "none")
	}

	enc2, err := New(config.EncryptionConfig{Backend: "none"})
	if err != nil {
		t.Fatalf("New(none): %v", err)
	}
	if enc2.BackendName() != "none" {
		t.Errorf("BackendName() = %q, want %q", enc2.BackendName(), "none")
	}
}

func TestNew_SopsBackend(t *testing.T) {
	enc, err := New(config.EncryptionConfig{Backend: "sops", Sops: nil})
	if err != nil {
		t.Fatalf("New(sops): %v", err)
	}
	if enc.BackendName() != "sops" {
		t.Errorf("BackendName() = %q, want %q", enc.BackendName(), "sops")
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	_, err := New(config.EncryptionConfig{Backend: "pkcs11"})
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}

func TestSopsBackend_Decrypt_RoundTrip(t *testing.T) {
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not in PATH")
	}
	t.Setenv("SOPS_AGE_KEY", testAgePriv)

	b := newSopsBackend(&config.SopsConfig{Age: []string{testAgePub}})
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "test.key.enc")
	plaintext := []byte("NEBULA ED25519 PRIVATE KEY TEST BYTES")

	ciphertext, err := b.Encrypt(plaintext, outputPath)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("Encrypt: ciphertext equals plaintext — encryption did not happen")
	}

	recovered, err := b.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", recovered, plaintext)
	}
}

func TestNoneBackend_Decrypt(t *testing.T) {
	enc := &NoneBackend{}
	data := []byte("plaintext key bytes")
	got, err := enc.Decrypt(data)
	if err != nil {
		t.Fatalf("NoneBackend.Decrypt: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("NoneBackend.Decrypt mutated input: got %q, want %q", got, data)
	}
}

// -- NewDecryptorForRecord ----------------------------------------------------

func TestNewDecryptorForRecord_Sops(t *testing.T) {
	dec, err := NewDecryptorForRecord("sops", config.EncryptionConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := dec.(*SopsBackend); !ok {
		t.Errorf("expected *SopsBackend, got %T", dec)
	}
}

func TestNewDecryptorForRecord_External(t *testing.T) {
	extCfg := &config.ExternalConfig{
		EncryptCommand: []string{"cat"},
		DecryptCommand: []string{"cat"},
	}
	dec, err := NewDecryptorForRecord("external", config.EncryptionConfig{
		Backend:  "external",
		External: extCfg,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := dec.(*ExternalBackend); !ok {
		t.Errorf("expected *ExternalBackend, got %T", dec)
	}
}

func TestNewDecryptorForRecord_ExternalMissingConfig(t *testing.T) {
	_, err := NewDecryptorForRecord("external", config.EncryptionConfig{Backend: "sops"})
	if err == nil {
		t.Fatal("expected error when external config is absent, got nil")
	}
}

func TestNewDecryptorForRecord_UnknownBackend(t *testing.T) {
	_, err := NewDecryptorForRecord("unknown", config.EncryptionConfig{})
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}
