package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/apply"
	"github.com/anverse/nebula-pki/internal/buildinfo"
	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/pki"
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
// the file and prints the canonical "config valid:" summary line.
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
	if !strings.Contains(got, "config valid: "+path) {
		t.Errorf("stdout = %q, want it to contain %q", got, "config valid: "+path)
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
// no "config valid:" line was printed.
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
	if strings.Contains(stdout.String(), "config valid:") {
		t.Errorf("stdout = %q, must not contain 'config valid:'", stdout.String())
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

// TestCheckSubcommand_ReferenceReportsFingerprint covers the reference
// path of `check`: it reads the operator-supplied CA files and prints the
// CA fingerprint after the "config valid:" line. This is the behaviour
// agents.md promises ("In CA reference mode, reads ca.cert_file /
// ca.key_file").
func TestCheckSubcommand_ReferenceReportsFingerprint(t *testing.T) {
	dir := t.TempDir()
	fp := seedRefCA(t, dir, `ca { name = "ext-mesh" }`)

	path := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(path, []byte(`
ca {
  cert_file = "ca.crt"
  key_file  = "ca.key"
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"check", "-c", path})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "ca mode=reference") {
		t.Errorf("stdout = %q, want it to mention ca mode=reference", out)
	}
	if !strings.Contains(out, "fingerprint="+fp) {
		t.Errorf("stdout = %q, want it to report fingerprint=%s", out, fp)
	}
}

// TestCheckSubcommand_ReferenceInvalidCAFails confirms `check` fails when
// the referenced files are not a usable CA, rather than printing the
// "config valid:" line and exiting 0.
func TestCheckSubcommand_ReferenceInvalidCAFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("nope\n"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("nope\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	path := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(path, []byte(`
ca {
  cert_file = "ca.crt"
  key_file  = "ca.key"
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"check", "-c", path})

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute: want error for invalid referenced CA, got nil")
	}
}

// TestCheckSubcommand_ReferenceMissingFileStillFails pins the reworded UX
// (#4): when the config is well-formed but the referenced cert_file is
// absent, `check` prints the "config valid:" line (the HCL really is
// valid) and *then* fails on the missing file. The line must not claim
// the whole check passed — it is scoped to the configuration, and the
// command still exits non-zero.
func TestCheckSubcommand_ReferenceMissingFileStillFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nebula.hcl")
	if err := os.WriteFile(path, []byte(`
ca {
  cert_file = "absent.crt"
  key_file  = "absent.key"
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"check", "-c", path})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute: want error for missing referenced cert, got nil")
	}
	// The config-validity line is present (the HCL parsed and validated)...
	if !strings.Contains(stdout.String(), "config valid: "+path) {
		t.Errorf("stdout = %q, want it to contain the config-valid line", stdout.String())
	}
	// ...but no "ca verified:" line, because verification never succeeded.
	if strings.Contains(stdout.String(), "ca verified:") {
		t.Errorf("stdout = %q, must not claim the CA was verified", stdout.String())
	}
	// And the error names the missing file.
	if !strings.Contains(err.Error(), "read referenced CA certificate") {
		t.Errorf("error = %q, want it to mention the missing cert read", err.Error())
	}
}

// seedRefCA mints a CA and writes ca.crt / ca.key into dir, returning the
// fingerprint so tests can assert it is surfaced.
func seedRefCA(t *testing.T, dir, src string) string {
	t.Helper()
	cfg, err := config.Parse("seed.hcl", []byte(src))
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	res, err := pki.GenerateCA(cfg.CA, time.Now())
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), res.CertPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), res.KeyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return res.Fingerprint
}

// TestWriteReconcileSummary documents the surface a user sees across the
// key output shapes: changed with CA only, changed with signed hosts,
// reference mode, and noop.
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
			wantNot: []string{"signed host", "up to date"},
		},
		{
			name: "changed_with_signed_hosts",
			rep: apply.Report{
				Changed:      true,
				ManifestPath: "out/nebula-pki.json",
				CACertPath:   "out/ca/ca.crt",
				CAKeyPath:    "out/ca/ca.key",
				CAName:       "mesh",
				SignedHosts: []apply.SignedHost{
					{Label: "alpha", Artifacts: []apply.SignedArtifact{
						{CertPath: "out/hosts/alpha.crt", KeyPath: "out/hosts/alpha.key"},
					}},
				},
			},
			wantContain: []string{
				`generated CA "mesh"`,
				`signed host "alpha"`,
				"cert: out/hosts/alpha.crt",
				"key:  out/hosts/alpha.key",
				"wrote manifest: out/nebula-pki.json",
			},
			wantNot: []string{"up to date", "not yet reconciled"},
		},
		{
			// Custom output_dir: host cert/key land in the configured directory.
			name: "changed_output_dir",
			rep: apply.Report{
				Changed:      true,
				ManifestPath: "out/nebula-pki.json",
				CACertPath:   "out/ca/ca.crt",
				CAKeyPath:    "out/ca/ca.key",
				CAName:       "mesh",
				SignedHosts: []apply.SignedHost{
					{Label: "node", Artifacts: []apply.SignedArtifact{
						{CertPath: "dir-a/node.crt", KeyPath: "dir-a/node.key"},
					}},
				},
			},
			wantContain: []string{
				`signed host "node"`,
				"cert: dir-a/node.crt",
				"key:  dir-a/node.key",
				"wrote manifest: out/nebula-pki.json",
			},
			wantNot: []string{"up to date"},
		},
		{
			// Reference mode reads the operator's CA in place; the summary
			// must say "using referenced CA", not "generated CA".
			name: "changed_reference_mode",
			rep: apply.Report{
				Changed:      true,
				CAMode:       "reference",
				ManifestPath: "out/nebula-pki.json",
				CACertPath:   "pki/root.crt",
				CAKeyPath:    "pki/root.key",
				CAName:       "ext-mesh",
			},
			wantContain: []string{
				`using referenced CA "ext-mesh"`,
				"cert: pki/root.crt",
				"key:  pki/root.key",
				"wrote manifest: out/nebula-pki.json",
			},
			wantNot: []string{"generated CA", "up to date"},
		},
		{
			// Stale artifacts: output_dir changed; old cert/key still on disk.
			name: "changed_with_stale_artifacts",
			rep: apply.Report{
				Changed:      true,
				ManifestPath: "out/nebula-pki.json",
				CACertPath:   "out/ca/ca.crt",
				CAKeyPath:    "out/ca/ca.key",
				CAName:       "mesh",
				SignedHosts: []apply.SignedHost{
					{Label: "node", Artifacts: []apply.SignedArtifact{
						{CertPath: "dir-b/node.crt", KeyPath: "dir-b/node.key"},
					}},
				},
				StaleArtifacts: []string{"dir-a/node.crt", "dir-a/node.key"},
			},
			wantContain: []string{
				`signed host "node"`,
				"cert: dir-b/node.crt",
				"notice: the following files are no longer managed",
				"dir-a/node.crt",
				"dir-a/node.key",
				"wrote manifest: out/nebula-pki.json",
			},
			wantNot: []string{"up to date"},
		},
		{
			name: "noop_run",
			rep: apply.Report{
				Changed:      false,
				ManifestPath: "out/nebula-pki.json",
				CAName:       "mesh",
			},
			wantContain: []string{"up to date; nothing to write"},
			wantNot:     []string{"generated CA", "signed host"},
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
