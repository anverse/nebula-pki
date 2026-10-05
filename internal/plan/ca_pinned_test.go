package plan

// Tests for generate-mode CAs pinned to their label (ADR-027).

import (
	"errors"
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/manifest"
)

func fingerprintProbe(fp string, err error) Options {
	return Options{Fingerprint: func(string) (string, error) { return fp, err }}
}

func wantErrContaining(t *testing.T, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Build succeeded, want an error containing %q", parts)
	}
	for _, part := range parts {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error = %q, want it to contain %q", err, part)
		}
	}
}

func TestBuild_TrackedCAFilesMissing(t *testing.T) {
	// A tracked CA whose files are both gone is not regenerated: a new CA
	// under the old label would leave its certs signed by the old one.
	tests := []struct {
		name    string
		src     string
		mode    string
		keyPath string
	}{
		{"plaintext key", `ca "mesh" { name = "m" }`, "generate", "out/ca/mesh.key"},
		{"encrypted key", `ca "mesh" { name = "m" }` + catStorage, "generate", "out/ca/mesh.key.enc"},
		// Switching a label from reference to generate mode would also put
		// a new CA under it.
		{"recorded in reference mode", `ca "mesh" { name = "m" }`, "reference", "out/ca/mesh.key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseCfg(t, tt.src)
			m := manifest.New()
			m.CAs["mesh"] = &manifest.CA{Mode: tt.mode, Name: "m", Fingerprint: "fp-old"}

			p, err := Build(cfg, m, testNow, existsSet(), fingerprintProbe("unused", nil))
			wantErrContaining(t, err, `ca "mesh": CA files missing`, "out/ca/mesh.crt", tt.keyPath, "fp-old", "new label")
			if len(p.Actions) != 0 {
				t.Errorf("Actions = %+v, want none", p.Actions)
			}
		})
	}
}

func TestBuild_TrackedCAFingerprint(t *testing.T) {
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	ca := cfg.CAs[0]
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m", Fingerprint: "fp-old"}
	exists := existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca))

	p, err := Build(cfg, m, testNow, exists, fingerprintProbe("fp-old", nil))
	if err != nil {
		t.Fatalf("Build with the recorded CA: %v", err)
	}
	if a := p.CAActions(); len(a) != 1 || a[0].Op != OpNoop {
		t.Errorf("CAActions = %+v, want one noop", a)
	}

	_, err = Build(cfg, m, testNow, exists, fingerprintProbe("fp-new", nil))
	wantErrContaining(t, err, `ca "mesh": CA certificate changed: out/ca/mesh.crt has fingerprint fp-new`, "records fp-old", "restore the recorded CA", "new label")

	_, err = Build(cfg, m, testNow, exists, fingerprintProbe("", errors.New("bad pem")))
	wantErrContaining(t, err, `ca "mesh": read out/ca/mesh.crt`, "bad pem")

	// Without a recorded fingerprint or without a probe there is nothing to
	// compare.
	unrecorded := manifest.New()
	unrecorded.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	if _, err := Build(cfg, unrecorded, testNow, exists, fingerprintProbe("fp-new", nil)); err != nil {
		t.Errorf("Build without a recorded fingerprint: %v", err)
	}
	if _, err := Build(cfg, m, testNow, exists, Options{}); err != nil {
		t.Errorf("Build without a probe: %v", err)
	}
}

func TestBuild_UntrackedCAWithoutFilesGenerates(t *testing.T) {
	// The check needs a record: a fresh tree, a missing manifest or a new
	// label still generates.
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	other := manifest.New()
	other.CAs["old"] = &manifest.CA{Mode: "generate", Name: "old", Fingerprint: "fp-old"}
	for name, m := range map[string]*manifest.Manifest{"empty manifest": manifest.New(), "no manifest": nil, "other label": other} {
		p, err := Build(cfg, m, testNow, existsSet(), fingerprintProbe("unused", nil))
		if err != nil {
			t.Fatalf("%s: Build: %v", name, err)
		}
		if a := p.CAActions(); len(a) != 1 || a[0].Op != OpGenerate {
			t.Errorf("%s: CAActions = %+v, want generate", name, a)
		}
	}
}

// catStorage enables an external encryption backend, so CA keys carry the
// default .enc suffix.
const catStorage = `
storage {
  encryption "external" {
    encrypt_command = ["cat"]
    decrypt_command = ["cat"]
  }
}
`
