package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anverse/nebula-pki/internal/config"
)

// SopsBackend encrypts key files by shelling out to the sops binary.
// The sops binary must be in PATH when this backend is active.
// See spec/adr/003-encryption-strategy.md.
type SopsBackend struct {
	cfg    *config.SopsConfig
	suffix string
}

func newSopsBackend(cfg *config.SopsConfig) *SopsBackend {
	suffix := ".enc"
	if cfg != nil && cfg.OutputSuffix != "" {
		suffix = cfg.OutputSuffix
	}
	return &SopsBackend{cfg: cfg, suffix: suffix}
}

func (b *SopsBackend) Suffix() string      { return b.suffix }
func (b *SopsBackend) BackendName() string { return "sops" }

// Encrypt writes plaintext to a temp file in filepath.Dir(outputPath) (so
// sops discovers .sops.yaml correctly), then runs sops --encrypt and returns
// the ciphertext from stdout. The temp file is removed regardless of outcome.
func (b *SopsBackend) Encrypt(plaintext []byte, outputPath string) ([]byte, error) {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sops encrypt: mkdir %s: %w", dir, err)
	}

	// Write plaintext to a temp file in the target directory so sops
	// discovers .sops.yaml by searching upward from that location.
	tmp, err := os.CreateTemp(dir, ".nebula-pki-plain-*")
	if err != nil {
		return nil, fmt.Errorf("sops encrypt: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(plaintext); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("sops encrypt: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("sops encrypt: close temp file: %w", err)
	}
	// Restrict permissions before sops sees the file.
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return nil, fmt.Errorf("sops encrypt: chmod temp file: %w", err)
	}

	args := b.encryptArgs(tmpName)
	cmd := exec.Command("sops", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("sops encrypt: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("sops encrypt: %w", err)
	}
	return stdout.Bytes(), nil
}

// encryptArgs builds the sops --encrypt argv for the given input file.
func (b *SopsBackend) encryptArgs(inputFile string) []string {
	args := []string{"--encrypt", "--input-type", "binary", "--output-type", "binary"}
	if b.cfg != nil {
		if len(b.cfg.Age) > 0 {
			args = append(args, "--age", strings.Join(b.cfg.Age, ","))
		}
		if len(b.cfg.PGP) > 0 {
			args = append(args, "--pgp", strings.Join(b.cfg.PGP, ","))
		}
		if len(b.cfg.KMS) > 0 {
			args = append(args, "--kms", strings.Join(b.cfg.KMS, ","))
		}
		if len(b.cfg.GCPKMS) > 0 {
			args = append(args, "--gcp-kms", strings.Join(b.cfg.GCPKMS, ","))
		}
		if len(b.cfg.AzureKV) > 0 {
			args = append(args, "--azure-kv", strings.Join(b.cfg.AzureKV, ","))
		}
		if len(b.cfg.HCVaultTransit) > 0 {
			args = append(args, "--hc-vault-transit", strings.Join(b.cfg.HCVaultTransit, ","))
		}
		if b.cfg.ShamirThreshold > 0 {
			args = append(args, "--shamir-secret-sharing-threshold",
				fmt.Sprintf("%d", b.cfg.ShamirThreshold))
		}
		if b.cfg.ConfigFile != "" {
			args = append(args, "--config", b.cfg.ConfigFile)
		}
	}
	return append(args, inputFile)
}

// Decrypt decrypts ciphertext previously produced by SopsBackend.Encrypt.
// It writes ciphertext to a temp file and invokes sops --decrypt; the
// plaintext is returned from stdout without ever being written to disk.
// The sops binary must be in PATH.
func (b *SopsBackend) Decrypt(ciphertext []byte) ([]byte, error) {
	tmp, err := os.CreateTemp("", ".nebula-pki-decrypt-*")
	if err != nil {
		return nil, fmt.Errorf("sops decrypt: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(ciphertext); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("sops decrypt: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("sops decrypt: close temp file: %w", err)
	}

	cmd := exec.Command("sops", "--decrypt", "--input-type", "binary", "--output-type", "binary", tmpName)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("sops decrypt: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("sops decrypt: %w", err)
	}
	return stdout.Bytes(), nil
}

// RecipientsHash returns a stable SHA-256 fingerprint of the configured
// inline recipients, or "" when no inline recipients are configured.
func (b *SopsBackend) RecipientsHash() string {
	if b.cfg == nil {
		return ""
	}
	var parts []string
	for _, a := range b.cfg.Age {
		parts = append(parts, "age:"+a)
	}
	for _, p := range b.cfg.PGP {
		parts = append(parts, "pgp:"+p)
	}
	for _, k := range b.cfg.KMS {
		parts = append(parts, "kms:"+k)
	}
	for _, g := range b.cfg.GCPKMS {
		parts = append(parts, "gcpkms:"+g)
	}
	for _, a := range b.cfg.AzureKV {
		parts = append(parts, "azurekv:"+a)
	}
	for _, v := range b.cfg.HCVaultTransit {
		parts = append(parts, "vault:"+v)
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(h[:])
}
