package plan

// Tests for comparing manifest-recorded paths with configured ones by the
// file they name, not by their spelling (config.SamePath).

import (
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/manifest"
)

const spellingHCL = `
trust_bundle "main" {
  ca_refs = [ca.a]
  path    = "out/b.crt"
}
ca "a" {
  name    = "a"
  default = true
}
`

// spelledManifest returns an up-to-date manifest for cfg whose bundle path
// is recorded as recorded, plus an exists probe that knows the CA files and
// both spellings of the bundle file.
func spelledManifest(cfg *config.Config, recorded string) (*manifest.Manifest, func(string) bool) {
	ca := cfg.CAs[0]
	m := manifest.New()
	m.CAs["a"] = &manifest.CA{Mode: "generate", Name: "a", Fingerprint: "fp-a"}
	m.TrustBundles = map[string]*manifest.TrustBundle{
		"main": {Path: recorded, CAFingerprints: []string{"fp-a"}},
	}
	return m, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca), cfg.TrustBundlePath(cfg.TrustBundles[0]), recorded)
}

func TestBuild_TrustBundle_RecordedSpellingIsSameFile(t *testing.T) {
	tests := []struct {
		name, cfgPath, recorded string
	}{
		{"dot slash recorded by an older run", "nebula.hcl", "./out/b.crt"},
		{"doubled separator", "nebula.hcl", "out//b.crt"},
		{"absolute recorded, relative configured", "/proj/nebula.hcl", "/proj/out/b.crt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.Parse(tt.cfgPath, []byte(spellingHCL))
			if err != nil {
				t.Fatalf("config.Parse: %v", err)
			}
			m, exists := spelledManifest(cfg, tt.recorded)
			p, err := Build(cfg, m, testNow, exists, Options{})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if op := bundleOp(t, p, "main"); op != OpNoop {
				t.Errorf("bundle op = %q, want noop", op)
			}
			if rel := p.ReleaseActions(); len(rel) != 0 {
				t.Errorf("ReleaseActions = %+v, want none for the same file", rel)
			}
			if p.Changes() {
				t.Errorf("Changes() = true, want false; actions = %+v", p.Actions)
			}
		})
	}
}

// A real path change still writes the bundle and releases the old file.
func TestBuild_TrustBundle_RealPathChangeStillReleases(t *testing.T) {
	cfg := parseCfg(t, spellingHCL)
	m, exists := spelledManifest(cfg, "./out/old.crt")
	p, err := Build(cfg, m, testNow, exists, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if op := bundleOp(t, p, "main"); op != OpWrite {
		t.Errorf("bundle op = %q, want write", op)
	}
	rel := p.ReleaseActions()
	if len(rel) != 1 || len(rel[0].Paths) != 1 || rel[0].Paths[0] != "./out/old.crt" {
		t.Fatalf("ReleaseActions = %+v, want ./out/old.crt released", rel)
	}
}

// A removed CA whose recorded files are spelled differently from a current
// CA's files is not reported as released: the current CA still manages them.
func TestBuild_RemovedCA_SpelledManagedPathNotReleased(t *testing.T) {
	cfg := parseCfg(t, `
ca "b" {
  name    = "b"
  out_crt = "out/ca/shared.crt"
  out_key = "out/ca/shared.key"
}
`)
	m := manifest.New()
	m.CAs["b"] = &manifest.CA{Mode: "generate", Name: "b", Fingerprint: "fp-b"}
	m.CAs["old"] = &manifest.CA{Mode: "generate", Name: "old", CertPath: "./out/ca/shared.crt", KeyPath: "out//ca/shared.key"}
	exists := existsSet("out/ca/shared.crt", "out/ca/shared.key", "./out/ca/shared.crt", "out//ca/shared.key")
	p, err := Build(cfg, m, testNow, exists, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rel := p.ReleaseActions()
	if len(rel) != 1 || rel[0].Label != "old" || len(rel[0].Paths) != 0 {
		t.Fatalf("ReleaseActions = %+v, want ca \"old\" released without paths", rel)
	}
}

// A recorded key path that differs only in spelling is not an encryption
// change: the key is genuinely missing.
func TestBuild_MissingKeyRecordedSpellingNotEncryptionChange(t *testing.T) {
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	ca := cfg.CAs[0]
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m", KeyPath: "./" + cfg.CAKeyPathForCA(ca)}

	// cert present; the key is absent, but the exists probe answers yes for
	// the recorded spelling, as the filesystem would for the same file.
	_, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), "./"+cfg.CAKeyPathForCA(ca)), Options{})
	if err == nil {
		t.Fatal("Build: want error for missing key, got nil")
	}
	if strings.Contains(err.Error(), "encryption configuration changed") {
		t.Errorf("error = %q, want the missing-key error, not an encryption change", err.Error())
	}
}
