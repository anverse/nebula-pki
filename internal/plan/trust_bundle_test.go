package plan

// Tests for the trust bundle action, bundle links, and released artifacts
// (ADR-026 "Detailed rules", ADR-021 amendment).

import (
	"os"
	"testing"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/manifest"
)

const bundleHCL = `
trust_bundle "main" {
  ca_refs  = [ca.b, ca.a]
  link_crt = ["out/node"]
}
ca "a" {
  name    = "a"
  default = true
}
ca "b" { name = "b" }
`

// upToDate returns a manifest and exists probe for which bundleHCL's CAs
// and bundle are fully reconciled.
func upToDate(cfg *config.Config) (*manifest.Manifest, func(string) bool) {
	m := manifest.New()
	var present []string
	for i := range cfg.CAs {
		ca := cfg.CAs[i]
		m.CAs[ca.Label] = &manifest.CA{Mode: "generate", Name: ca.Name, Fingerprint: "fp-" + ca.Label}
		present = append(present, cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca))
	}
	m.TrustBundle = &manifest.TrustBundle{
		Label:          "main",
		Path:           cfg.TrustBundlePath(),
		CAFingerprints: []string{"fp-b", "fp-a"},
		Links:          []manifest.CertLink{{Path: "out/node/bundle.crt", Target: "../ca/bundle.crt"}},
	}
	present = append(present, cfg.TrustBundlePath())
	return m, existsSet(present...)
}

func bundleOpts(cfg *config.Config) Options {
	link := cfg.Resolve("out/node/bundle.crt")
	return Options{
		Lstat:    mockLstat(map[string]os.FileMode{link: os.ModeSymlink}),
		Readlink: mockReadlink(map[string]string{link: "../ca/bundle.crt"}),
	}
}

func bundleOp(t *testing.T, p Plan) Op {
	t.Helper()
	a, ok := p.TrustBundleAction()
	if !ok {
		t.Fatal("no trust bundle action planned")
	}
	return a.Op
}

func TestBuild_TrustBundle_UpToDateIsNoop(t *testing.T) {
	cfg := parseCfg(t, bundleHCL)
	m, exists := upToDate(cfg)
	p, err := Build(cfg, m, testNow, exists, bundleOpts(cfg))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if op := bundleOp(t, p); op != OpNoop {
		t.Errorf("bundle op = %q, want noop", op)
	}
	if p.Changes() {
		t.Errorf("Changes() = true, want false; actions = %+v", p.Actions)
	}
}

func TestBuild_TrustBundle_WriteTriggers(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(cfg *config.Config, m *manifest.Manifest) func(string) bool
	}{
		{"not recorded", func(cfg *config.Config, m *manifest.Manifest) func(string) bool {
			_, exists := upToDate(cfg)
			m.TrustBundle = nil
			return exists
		}},
		{"file missing", func(cfg *config.Config, m *manifest.Manifest) func(string) bool {
			var present []string
			for i := range cfg.CAs {
				present = append(present, cfg.CACertPathForCA(cfg.CAs[i]), cfg.CAKeyPathForCA(cfg.CAs[i]))
			}
			return existsSet(present...)
		}},
		{"members reordered", func(cfg *config.Config, m *manifest.Manifest) func(string) bool {
			_, exists := upToDate(cfg)
			m.TrustBundle.CAFingerprints = []string{"fp-a", "fp-b"}
			return exists
		}},
		{"member fingerprint changed", func(cfg *config.Config, m *manifest.Manifest) func(string) bool {
			_, exists := upToDate(cfg)
			m.CAs["a"].Fingerprint = "fp-a2"
			return exists
		}},
		{"path changed", func(cfg *config.Config, m *manifest.Manifest) func(string) bool {
			_, exists := upToDate(cfg)
			m.TrustBundle.Path = "out/old/bundle.crt"
			return exists
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseCfg(t, bundleHCL)
			m, _ := upToDate(cfg)
			exists := tt.mutate(cfg, m)
			p, err := Build(cfg, m, testNow, exists, bundleOpts(cfg))
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if op := bundleOp(t, p); op != OpWrite {
				t.Errorf("bundle op = %q, want write", op)
			}
		})
	}
}

func TestBuild_TrustBundle_MemberGeneratedWrites(t *testing.T) {
	cfg := parseCfg(t, bundleHCL)
	m, _ := upToDate(cfg)
	// CA "b" files are missing, so it is generated this run.
	a := cfg.CAs[0]
	exists := existsSet(cfg.CACertPathForCA(a), cfg.CAKeyPathForCA(a), cfg.TrustBundlePath())
	delete(m.CAs, "b")
	p, err := Build(cfg, m, testNow, exists, bundleOpts(cfg))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if op := bundleOp(t, p); op != OpWrite {
		t.Errorf("bundle op = %q, want write", op)
	}
}

func TestBuild_TrustBundle_LabelChangeIsRelabel(t *testing.T) {
	cfg := parseCfg(t, bundleHCL)
	m, exists := upToDate(cfg)
	m.TrustBundle.Label = "old"
	p, err := Build(cfg, m, testNow, exists, bundleOpts(cfg))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if op := bundleOp(t, p); op != OpRelabel {
		t.Errorf("bundle op = %q, want relabel", op)
	}
	for _, l := range p.LinkActions() {
		if l.Op != OpNoop {
			t.Errorf("link action %+v, want noop: a relabel touches no symlink", l)
		}
	}
	if len(p.ReleaseActions()) != 0 {
		t.Errorf("ReleaseActions = %+v, want none", p.ReleaseActions())
	}
}

func TestBuild_TrustBundle_LinksOwnedByBundle(t *testing.T) {
	// A CA and the bundle share the label "main"; their links stay apart.
	cfg := parseCfg(t, `
trust_bundle "main" {
  ca_refs  = [ca.main]
  link_crt = ["out/node"]
}
ca "main" {
  name     = "m"
  link_crt = ["out/node"]
}
`)
	p, err := Build(cfg, manifest.New(), testNow, existsSet(), Options{Lstat: mockLstat(nil)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	owners := map[string]Kind{}
	for _, l := range p.LinkActions() {
		owners[l.Path] = l.Owner
	}
	if owners["out/node/main.crt"] != KindCA {
		t.Errorf("out/node/main.crt owner = %q, want ca", owners["out/node/main.crt"])
	}
	if owners["out/node/bundle.crt"] != KindTrustBundle {
		t.Errorf("out/node/bundle.crt owner = %q, want trust_bundle", owners["out/node/bundle.crt"])
	}
}

func TestBuild_TrustBundle_RemovedBlockReleasesFileAndDeletesLinks(t *testing.T) {
	full := parseCfg(t, bundleHCL)
	m, exists := upToDate(full)
	cfg := parseCfg(t, `
ca "a" {
  name    = "a"
  default = true
}
ca "b" { name = "b" }
`)
	p, err := Build(cfg, m, testNow, exists, bundleOpts(cfg))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := p.TrustBundleAction(); ok {
		t.Error("trust bundle action planned without a trust_bundle block")
	}
	rel := p.ReleaseActions()
	if len(rel) != 1 || rel[0].Owner != KindTrustBundle || len(rel[0].Paths) != 1 || rel[0].Paths[0] != full.TrustBundlePath() {
		t.Fatalf("ReleaseActions = %+v, want the bundle file released", rel)
	}
	links := p.LinkActions()
	if len(links) != 1 || links[0].Op != OpDeleteSymlink || links[0].Owner != KindTrustBundle {
		t.Fatalf("LinkActions = %+v, want the bundle link deleted", links)
	}
}

func TestBuild_TrustBundle_PathChangeReleasesOldFile(t *testing.T) {
	cfg := parseCfg(t, bundleHCL)
	m, exists := upToDate(cfg)
	m.TrustBundle.Path = "out/old/bundle.crt"
	p, err := Build(cfg, m, testNow, exists, bundleOpts(cfg))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rel := p.ReleaseActions()
	if len(rel) != 1 || rel[0].Paths[0] != "out/old/bundle.crt" {
		t.Fatalf("ReleaseActions = %+v, want out/old/bundle.crt released", rel)
	}
}

func TestBuild_RemovedCA_ReleasesFilesAndDeletesLinks(t *testing.T) {
	cfg := parseCfg(t, `ca "new" { name = "new" }`)
	ca := cfg.CAs[0]
	m := manifest.New()
	m.CAs["new"] = &manifest.CA{Mode: "generate", Name: "new"}
	m.CAs["old"] = &manifest.CA{
		Mode: "generate", Name: "old",
		CertPath: "out/ca/old.crt", KeyPath: "out/ca/old.key",
		Links: []manifest.CertLink{{Path: "out/node/old.crt", Target: "../ca/old.crt"}},
	}
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)), Options{Lstat: mockLstat(nil)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	links := p.LinkActions()
	if len(links) != 1 || links[0].Op != OpDeleteSymlink || links[0].Path != "out/node/old.crt" || links[0].Label != "old" {
		t.Fatalf("LinkActions = %+v, want the removed CA's link deleted", links)
	}
	rel := p.ReleaseActions()
	if len(rel) != 1 || rel[0].Owner != KindCA || rel[0].Label != "old" {
		t.Fatalf("ReleaseActions = %+v, want ca old released", rel)
	}
	if got := rel[0].Paths; len(got) != 2 || got[0] != "out/ca/old.crt" || got[1] != "out/ca/old.key" {
		t.Errorf("released paths = %v, want old cert and key", got)
	}
	if len(p.CAActions()) != 1 {
		t.Errorf("CAActions = %+v, want only the declared CA", p.CAActions())
	}
}

func TestBuild_RemovedCA_StillManagedPathsNotReleased(t *testing.T) {
	// The CA was relabelled but writes to the same explicit paths: those
	// files are still managed and must not be reported as released.
	cfg := parseCfg(t, `
ca "renamed" {
  name    = "m"
  out_crt = "out/ca/ca.crt"
  out_key = "out/ca/ca.key"
}`)
	m := manifest.New()
	m.CAs["renamed"] = &manifest.CA{Mode: "generate", Name: "m"}
	m.CAs["orig"] = &manifest.CA{Mode: "generate", Name: "m", CertPath: "out/ca/ca.crt", KeyPath: "out/ca/ca.key"}
	ca := cfg.CAs[0]
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)), Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rel := p.ReleaseActions()
	if len(rel) != 1 || len(rel[0].Paths) != 0 {
		t.Fatalf("ReleaseActions = %+v, want one release with no paths", rel)
	}
}
