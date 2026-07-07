// Package crypto provides the encryption backend abstraction for nebula-pki.
// Only private key files are encrypted; certs, QRs, and the manifest stay
// plaintext (see spec/adr/003-encryption-strategy.md).
package crypto

import (
	"fmt"

	"github.com/anverse/nebula-pki/internal/config"
)

// Encryptor encrypts private key material before writing it to disk.
type Encryptor interface {
	// Encrypt encrypts plaintext key bytes. outputPath is the intended on-disk
	// path of the encrypted file (used for .sops.yaml creation-rule matching).
	Encrypt(plaintext []byte, outputPath string) ([]byte, error)

	// Suffix returns the file suffix appended to encrypted key filenames on
	// disk, e.g. ".enc". Returns "" for the none backend.
	Suffix() string

	// BackendName returns "none" or "sops".
	BackendName() string

	// RecipientsHash returns a stable SHA-256 fingerprint of the configured
	// inline recipients (sorted, one "type:value" entry per line). Returns ""
	// when no inline recipients are configured (i.e. .sops.yaml is
	// authoritative) or for the none backend.
	RecipientsHash() string
}

// New returns an Encryptor for the given encryption configuration.
func New(enc config.EncryptionConfig) (Encryptor, error) {
	switch enc.Backend {
	case "", "none":
		return &NoneBackend{}, nil
	case "sops":
		return newSopsBackend(enc.Sops), nil
	default:
		return nil, fmt.Errorf("unknown encryption backend %q", enc.Backend)
	}
}
