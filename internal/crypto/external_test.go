package crypto

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/config"
)

func newTestExternalBackend(encCmd, decCmd []string) *ExternalBackend {
	return newExternalBackend(&config.ExternalConfig{
		EncryptCommand: encCmd,
		DecryptCommand: decCmd,
	})
}

// TestExternalBackend_Defaults checks suffix and BackendName defaults.
func TestExternalBackend_Defaults(t *testing.T) {
	b := newExternalBackend(&config.ExternalConfig{
		EncryptCommand: []string{"cat"},
		DecryptCommand: []string{"cat"},
	})
	if b.Suffix() != ".enc" {
		t.Errorf("Suffix() = %q, want %q", b.Suffix(), ".enc")
	}
	if b.BackendName() != "external" {
		t.Errorf("BackendName() = %q, want %q", b.BackendName(), "external")
	}
}

// TestExternalBackend_CustomSuffix verifies output_suffix is honoured.
func TestExternalBackend_CustomSuffix(t *testing.T) {
	b := newExternalBackend(&config.ExternalConfig{
		EncryptCommand: []string{"cat"},
		DecryptCommand: []string{"cat"},
		OutputSuffix:   ".gpg",
	})
	if b.Suffix() != ".gpg" {
		t.Errorf("Suffix() = %q, want %q", b.Suffix(), ".gpg")
	}
}

// TestExternalBackend_RecipientsHash_NonEmpty checks a non-empty command
// produces a non-empty hash.
func TestExternalBackend_RecipientsHash_NonEmpty(t *testing.T) {
	b := newTestExternalBackend([]string{"myencrypt", "--key", "k1"}, []string{"mydecrypt"})
	h := b.RecipientsHash()
	if h == "" {
		t.Fatal("RecipientsHash() returned empty for non-empty encrypt_command")
	}
}

// TestExternalBackend_RecipientsHash_Stable checks the hash is stable
// across multiple calls with the same command.
func TestExternalBackend_RecipientsHash_Stable(t *testing.T) {
	b := newTestExternalBackend([]string{"myencrypt", "--key", "k1"}, []string{"mydecrypt"})
	h1 := b.RecipientsHash()
	h2 := b.RecipientsHash()
	if h1 != h2 {
		t.Errorf("RecipientsHash not stable: %q vs %q", h1, h2)
	}
}

// TestExternalBackend_RecipientsHash_ChangesOnCommandChange verifies that
// changing any element of encrypt_command produces a different hash.
func TestExternalBackend_RecipientsHash_ChangesOnCommandChange(t *testing.T) {
	b1 := newTestExternalBackend([]string{"encrypt", "--key", "k1"}, []string{"decrypt"})
	b2 := newTestExternalBackend([]string{"encrypt", "--key", "k2"}, []string{"decrypt"})
	if b1.RecipientsHash() == b2.RecipientsHash() {
		t.Error("different encrypt_commands produced the same hash")
	}
}

// TestExternalBackend_RecipientsHash_NullSeparation checks that arg boundary
// changes are detected (prevents "ab","c" hashing the same as "a","bc").
func TestExternalBackend_RecipientsHash_NullSeparation(t *testing.T) {
	b1 := newTestExternalBackend([]string{"ab", "c"}, []string{"d"})
	b2 := newTestExternalBackend([]string{"a", "bc"}, []string{"d"})
	if b1.RecipientsHash() == b2.RecipientsHash() {
		t.Error("arg boundary change not detected — missing null separator in hash input")
	}
}

// TestNew_ExternalBackend checks the factory returns an ExternalBackend.
func TestNew_ExternalBackend(t *testing.T) {
	enc, err := New(config.EncryptionConfig{
		Backend: "external",
		External: &config.ExternalConfig{
			EncryptCommand: []string{"cat"},
			DecryptCommand: []string{"cat"},
		},
	})
	if err != nil {
		t.Fatalf("New(external): %v", err)
	}
	if enc.BackendName() != "external" {
		t.Errorf("BackendName() = %q, want %q", enc.BackendName(), "external")
	}
}

// catPath returns the path to the cat binary, skipping the test if not found.
func catPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stdin/stdout round-trip tests require a POSIX cat binary")
	}
	p, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not in PATH")
	}
	return p
}

// TestExternalBackend_Encrypt_StdinStdout exercises the no-placeholder path:
// plaintext piped to stdin; ciphertext read from stdout. Uses cat as a
// trivial identity transform to verify the data-flow wiring.
func TestExternalBackend_Encrypt_StdinStdout(t *testing.T) {
	cat := catPath(t)
	b := newTestExternalBackend([]string{cat}, []string{cat})

	dir := t.TempDir()
	plaintext := []byte("test key bytes stdin/stdout")
	got, err := b.Encrypt(plaintext, dir+"/test.key.enc")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Encrypt output = %q, want %q", got, plaintext)
	}
}

// TestExternalBackend_Decrypt_Stdin exercises decrypt with ciphertext piped
// via stdin and plaintext captured from stdout.
func TestExternalBackend_Decrypt_Stdin(t *testing.T) {
	cat := catPath(t)
	b := newTestExternalBackend([]string{cat}, []string{cat})

	ciphertext := []byte("fake ciphertext via stdin")
	got, err := b.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, ciphertext) {
		t.Errorf("Decrypt output = %q, want %q", got, ciphertext)
	}
}

// TestExternalBackend_Encrypt_InPathOnly exercises {{.InPath}} present but no
// {{.OutPath}}: temp file for input, stdout for output.
func TestExternalBackend_Encrypt_InPathOnly(t *testing.T) {
	cat := catPath(t)
	b := newTestExternalBackend(
		[]string{cat, "{{.InPath}}"},
		[]string{cat, "{{.InPath}}"},
	)

	dir := t.TempDir()
	plaintext := []byte("test key bytes InPath-only")
	got, err := b.Encrypt(plaintext, dir+"/test.key.enc")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Encrypt output = %q, want %q", got, plaintext)
	}
}

// TestExternalBackend_Encrypt_BothPaths exercises {{.InPath}} + {{.OutPath}}.
// Uses cp to copy the input temp file to the output temp file.
func TestExternalBackend_Encrypt_BothPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cp not available on Windows")
	}
	cp, err := exec.LookPath("cp")
	if err != nil {
		t.Skip("cp not in PATH")
	}
	b := newTestExternalBackend(
		[]string{cp, "{{.InPath}}", "{{.OutPath}}"},
		[]string{catPath(t), "{{.InPath}}"},
	)

	dir := t.TempDir()
	plaintext := []byte("test key bytes both paths")
	got, err := b.Encrypt(plaintext, dir+"/test.key.enc")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Encrypt output = %q, want %q", got, plaintext)
	}
}

// TestExternalBackend_Decrypt_InPath exercises {{.InPath}} in decrypt_command.
func TestExternalBackend_Decrypt_InPath(t *testing.T) {
	cat := catPath(t)
	b := newTestExternalBackend(
		[]string{cat},
		[]string{cat, "{{.InPath}}"},
	)

	ciphertext := []byte("fake ciphertext via InPath")
	got, err := b.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, ciphertext) {
		t.Errorf("Decrypt output = %q, want %q", got, ciphertext)
	}
}

// TestExternalBackend_Decrypt_OutPathNotSubstituted verifies {{.OutPath}} in
// decrypt_command is left as a literal string (not substituted). Because the
// literal "{{.OutPath}}" is not a valid filesystem path, cat will fail trying
// to open it. The error comes from the command, not from our substitution
// code, which is the documented behaviour (ADR-023 §D-3).
func TestExternalBackend_Decrypt_OutPathNotSubstituted(t *testing.T) {
	cat := catPath(t)
	b := newTestExternalBackend(
		[]string{cat},
		[]string{cat, "{{.OutPath}}"},
	)
	ciphertext := []byte("test bytes")
	_, err := b.Decrypt(ciphertext)
	// The command fails because "{{.OutPath}}" is not a valid path. This is
	// the expected and documented outcome.
	if err == nil {
		t.Fatal("expected error when {{.OutPath}} appears literally in decrypt_command, got nil")
	}
}

// TestExternalBackend_Encrypt_CommandFailure checks that a nonzero exit
// is propagated as an error, including any stderr text.
func TestExternalBackend_Encrypt_CommandFailure(t *testing.T) {
	b := newTestExternalBackend(
		[]string{"sh", "-c", "echo 'bad things happened' >&2; exit 1"},
		[]string{"cat"},
	)
	dir := t.TempDir()
	_, err := b.Encrypt([]byte("key"), dir+"/test.key.enc")
	if err == nil {
		t.Fatal("expected error from failing command, got nil")
	}
	if !strings.Contains(err.Error(), "bad things happened") {
		t.Errorf("error does not include stderr: %v", err)
	}
}

// TestExternalBackend_RoundTrip_BothInPath exercises a full encrypt→decrypt
// round-trip using {{.InPath}} on both sides (cat as identity).
func TestExternalBackend_RoundTrip_BothInPath(t *testing.T) {
	cat := catPath(t)
	b := newTestExternalBackend(
		[]string{cat, "{{.InPath}}"},
		[]string{cat, "{{.InPath}}"},
	)

	dir := t.TempDir()
	plaintext := []byte("NEBULA PRIVATE KEY ROUND TRIP")

	ciphertext, err := b.Encrypt(plaintext, dir+"/test.key.enc")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	recovered, err := b.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", recovered, plaintext)
	}
}
