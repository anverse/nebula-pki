package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/buildinfo"
)

func TestVersionSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := strings.TrimSpace(stdout.String())
	want := buildinfo.String()
	if got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestVersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := strings.TrimSpace(stdout.String())
	want := buildinfo.String()
	if got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

// TestCheckSubcommand_HappyPath verifies that `check -c <path>` parses
// the file and prints the canonical "ok:" summary line.
func TestCheckSubcommand_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.hcl")
	if err := os.WriteFile(path, []byte(`
ca {
  name = "m"
}
host "a" {
  networks = ["10.0.0.1/16"]
}
`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"check", "-c", path})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr=%s", err, stderr.String())
	}

	got := stdout.String()
	if !strings.Contains(got, "ok: "+path) {
		t.Errorf("stdout = %q, want it to contain %q", got, "ok: "+path)
	}
	if !strings.Contains(got, "ca mode=generate") {
		t.Errorf("stdout = %q, want it to mention ca mode=generate", got)
	}
	if !strings.Contains(got, "hosts=1") {
		t.Errorf("stdout = %q, want it to mention hosts=1", got)
	}
}

// TestCheckSubcommand_ValidationError ensures a validation rule surfaces
// as a non-nil error from cobra (which the CLI maps to exit 1) and that
// no "ok:" line was printed.
func TestCheckSubcommand_ValidationError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.hcl")
	if err := os.WriteFile(path, []byte(`
ca { name = "m" }
host "a" { networks = ["10.0.0.1/16"] }
host "b" { networks = ["10.0.0.1/24"] }
`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"check", "-c", path})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute: want non-nil error, got nil")
	}
	if !strings.Contains(err.Error(), "overlay address") {
		t.Errorf("error = %q, want overlay address error", err.Error())
	}
	if strings.Contains(stdout.String(), "ok:") {
		t.Errorf("stdout = %q, must not contain 'ok:'", stdout.String())
	}
}

func TestCheckSubcommand_MissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"check", "-c", filepath.Join(t.TempDir(), "nope.hcl")})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute: want non-nil error, got nil")
	}
	if !strings.Contains(err.Error(), "read ") {
		t.Errorf("error = %q, want it to mention `read`", err.Error())
	}
}

func TestCheckSubcommand_RejectsArgs(t *testing.T) {
	// `check` is declared with cobra.NoArgs; trailing positional args
	// must be a usage error.
	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"check", "unexpected"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute: want non-nil error for stray arg, got nil")
	}
}

