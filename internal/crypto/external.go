package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anverse/nebula-pki/internal/config"
)

// ExternalBackend encrypts and decrypts key files by shelling out to
// operator-supplied commands. See ADR-023 for the full protocol.
type ExternalBackend struct {
	cfg    *config.ExternalConfig
	suffix string
}

func newExternalBackend(cfg *config.ExternalConfig) *ExternalBackend {
	suffix := ".enc"
	if cfg != nil && cfg.OutputSuffix != "" {
		suffix = cfg.OutputSuffix
	}
	return &ExternalBackend{cfg: cfg, suffix: suffix}
}

func (b *ExternalBackend) Suffix() string      { return b.suffix }
func (b *ExternalBackend) BackendName() string { return "external" }

// RecipientsHash returns a SHA-256 fingerprint of the EncryptCommand slice
// (null-byte separated to prevent boundary ambiguity). A change to any
// element in the command triggers the mismatch warning in apply.
func (b *ExternalBackend) RecipientsHash() string {
	if b.cfg == nil || len(b.cfg.EncryptCommand) == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(strings.Join(b.cfg.EncryptCommand, "\x00")))
	return hex.EncodeToString(h[:])
}

// Encrypt runs the configured encrypt_command. {{.InPath}} is substituted
// with an absolute path to a temp file containing plaintext; if absent,
// plaintext is piped via stdin. {{.OutPath}} is substituted with an
// absolute path to a temp output file; if absent, ciphertext is read from
// stdout. See ADR-023 for the full data-flow matrix.
func (b *ExternalBackend) Encrypt(plaintext []byte, outputPath string) ([]byte, error) {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("external encrypt: mkdir %s: %w", dir, err)
	}

	args, inPath, outPath, cleanups, err := prepareArgs(b.cfg.EncryptCommand, dir, plaintext, true)
	defer runCleanups(cleanups)
	if err != nil {
		return nil, fmt.Errorf("external encrypt: %w", err)
	}

	var stdin io.Reader
	if inPath == "" {
		stdin = bytes.NewReader(plaintext)
	}

	var stdout bytes.Buffer
	if err := runCommand(args, stdin, &stdout); err != nil {
		return nil, fmt.Errorf("external encrypt: %w", err)
	}

	if outPath != "" {
		data, err := os.ReadFile(outPath)
		if err != nil {
			return nil, fmt.Errorf("external encrypt: read output file %s: %w", outPath, err)
		}
		return data, nil
	}
	return stdout.Bytes(), nil
}

// Decrypt runs the configured decrypt_command. {{.InPath}} is substituted
// with an absolute path to a temp file containing ciphertext; if absent,
// ciphertext is piped via stdin. Plaintext is always captured from stdout
// ({{.OutPath}} is not substituted in decrypt). See ADR-023.
func (b *ExternalBackend) Decrypt(ciphertext []byte) ([]byte, error) {
	args, inPath, _, cleanups, err := prepareArgs(b.cfg.DecryptCommand, "", ciphertext, false)
	defer runCleanups(cleanups)
	if err != nil {
		return nil, fmt.Errorf("external decrypt: %w", err)
	}

	var stdin io.Reader
	if inPath == "" {
		stdin = bytes.NewReader(ciphertext)
	}

	var stdout bytes.Buffer
	if err := runCommand(args, stdin, &stdout); err != nil {
		return nil, fmt.Errorf("external decrypt: %w", err)
	}
	return stdout.Bytes(), nil
}

// prepareArgs substitutes {{.InPath}} and {{.OutPath}} in args.
// When substituteIn is true and {{.InPath}} is present, it writes data to a
// temp file in dir and stores the path. When {{.OutPath}} is present (only
// meaningful for encrypt), it creates an empty temp file for the output.
// Returned cleanups must be called (via defer) to remove any temp files.
// outPath is empty when {{.OutPath}} was not present in args.
// inPath is empty when {{.InPath}} was not present in args.
func prepareArgs(tmpl []string, dir string, data []byte, supportOut bool) (
	args []string, inPath, outPath string, cleanups []func(), err error,
) {
	needIn := containsPlaceholder(tmpl, "{{.InPath}}")
	needOut := supportOut && containsPlaceholder(tmpl, "{{.OutPath}}")

	if needIn {
		var tmp *os.File
		if dir != "" {
			tmp, err = os.CreateTemp(dir, ".nebula-pki-ext-in-*")
		} else {
			tmp, err = os.CreateTemp("", ".nebula-pki-ext-in-*")
		}
		if err != nil {
			return nil, "", "", cleanups, fmt.Errorf("create input temp file: %w", err)
		}
		inPath = tmp.Name()
		cleanups = append(cleanups, func() { os.Remove(inPath) })

		if err := tmp.Chmod(0o600); err != nil {
			tmp.Close()
			return nil, "", "", cleanups, fmt.Errorf("chmod input temp file: %w", err)
		}
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			return nil, "", "", cleanups, fmt.Errorf("write input temp file: %w", err)
		}
		if err := tmp.Close(); err != nil {
			return nil, "", "", cleanups, fmt.Errorf("close input temp file: %w", err)
		}
	}

	if needOut {
		var tmp *os.File
		if dir != "" {
			tmp, err = os.CreateTemp(dir, ".nebula-pki-ext-out-*")
		} else {
			tmp, err = os.CreateTemp("", ".nebula-pki-ext-out-*")
		}
		if err != nil {
			return nil, "", "", cleanups, fmt.Errorf("create output temp file: %w", err)
		}
		outPath = tmp.Name()
		cleanups = append(cleanups, func() { os.Remove(outPath) })
		if err := tmp.Close(); err != nil {
			return nil, "", "", cleanups, fmt.Errorf("close output temp file: %w", err)
		}
	}

	args = make([]string, len(tmpl))
	for i, a := range tmpl {
		a = strings.ReplaceAll(a, "{{.InPath}}", inPath)
		if supportOut {
			a = strings.ReplaceAll(a, "{{.OutPath}}", outPath)
		}
		args[i] = a
	}
	return args, inPath, outPath, cleanups, nil
}

func containsPlaceholder(args []string, placeholder string) bool {
	for _, a := range args {
		if strings.Contains(a, placeholder) {
			return true
		}
	}
	return false
}

func runCommand(args []string, stdin io.Reader, stdout *bytes.Buffer) error {
	if len(args) == 0 {
		return fmt.Errorf("command is empty")
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

func runCleanups(fns []func()) {
	for _, fn := range fns {
		fn()
	}
}
