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

	// BackendName returns "none", "sops", or "external".
	BackendName() string

	// RecipientsHash returns a stable SHA-256 fingerprint of the configured
	// inline recipients (sorted, one "type:value" entry per line). Returns ""
	// when no inline recipients are configured (i.e. .sops.yaml is
	// authoritative) or for the none backend.
	RecipientsHash() string
}

// Decryptor decrypts private key material that was previously written by an
// Encryptor of the same backend type.
type Decryptor interface {
	Decrypt(ciphertext []byte) ([]byte, error)
}

// Backend is the full encryption/decryption capability of a storage backend.
// Every concrete backend (NoneBackend, SopsBackend) implements both sides.
type Backend interface {
	Encryptor
	Decryptor
}

// NewDecryptorForRecord builds a Decryptor for an artifact that was encrypted
// by storedBackend. For "sops", decryption relies on the operator's key ring
// and no recipient config is needed. For "external", currentEnc must still
// carry the External decrypt_command; if it was removed before running rekey,
// an error is returned directing the operator to keep it in place during migration.
func NewDecryptorForRecord(storedBackend string, currentEnc config.EncryptionConfig) (Decryptor, error) {
	switch storedBackend {
	case "sops":
		return newSopsBackend(nil), nil
	case "external":
		if currentEnc.External == nil {
			return nil, fmt.Errorf(
				"stored backend is \"external\" but no external config is present; " +
					"keep the external config while running 'nebula-pki rekey', " +
					"then switch to the new backend",
			)
		}
		return newExternalBackend(currentEnc.External), nil
	default:
		return nil, fmt.Errorf("unknown stored encryption backend %q", storedBackend)
	}
}

// New returns a Backend for the given encryption configuration.
func New(enc config.EncryptionConfig) (Backend, error) {
	switch enc.Backend {
	case "", "none":
		return &NoneBackend{}, nil
	case "sops":
		return newSopsBackend(enc.Sops), nil
	case "external":
		return newExternalBackend(enc.External), nil
	default:
		return nil, fmt.Errorf("unknown encryption backend %q", enc.Backend)
	}
}
