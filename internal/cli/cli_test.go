package cli

import (
	"bytes"
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
