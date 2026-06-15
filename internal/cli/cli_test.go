package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/apply"
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

// TestWriteReconcileSummary documents the surface a user sees and pins
// the "host warning is silent on a no-op rerun" rule. This is the unit
// equivalent of the e2e idempotent-with-hosts script: regressions get
// caught here before they reach a script run.
func TestWriteReconcileSummary(t *testing.T) {
	tests := []struct {
		name        string
		rep         apply.Report
		wantContain []string
		wantNot     []string
	}{
		{
			name: "changed_no_hosts",
			rep: apply.Report{
				Changed:      true,
				ManifestPath: "out/nebula-pki.json",
				CACertPath:   "out/ca/ca.crt",
				CAKeyPath:    "out/ca/ca.key",
				CAName:       "mesh",
			},
			wantContain: []string{
				`generated CA "mesh"`,
				"cert: out/ca/ca.crt",
				"key:  out/ca/ca.key",
				"wrote manifest: out/nebula-pki.json",
			},
			wantNot: []string{"note:", "up to date"},
		},
		{
			name: "changed_with_hosts_prints_note",
			rep: apply.Report{
				Changed:      true,
				ManifestPath: "out/nebula-pki.json",
				CACertPath:   "out/ca/ca.crt",
				CAKeyPath:    "out/ca/ca.key",
				CAName:       "mesh",
				HostsParsed:  3,
			},
			wantContain: []string{
				`generated CA "mesh"`,
				"note: 3 host(s) parsed but not yet reconciled",
			},
			wantNot: []string{"up to date"},
		},
		{
			name: "noop_no_hosts",
			rep: apply.Report{
				Changed:      false,
				ManifestPath: "out/nebula-pki.json",
				CAName:       "mesh",
			},
			wantContain: []string{"up to date; nothing to write"},
			wantNot:     []string{"generated CA", "note:"},
		},
		{
			// The bug the priority list called out: a no-op rerun must
			// not re-print the host warning. If it did, every CI run of
			// an unchanged tree would emit noise until v0.0.5.
			name: "noop_with_hosts_is_silent",
			rep: apply.Report{
				Changed:      false,
				ManifestPath: "out/nebula-pki.json",
				CAName:       "mesh",
				HostsParsed:  3,
			},
			wantContain: []string{"up to date; nothing to write"},
			wantNot:     []string{"generated CA", "note:", "host(s)"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeReconcileSummary(&buf, &tc.rep)
			out := buf.String()
			for _, w := range tc.wantContain {
				if !strings.Contains(out, w) {
					t.Errorf("output = %q, want it to contain %q", out, w)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(out, w) {
					t.Errorf("output = %q, must not contain %q", out, w)
				}
			}
		})
	}
}
