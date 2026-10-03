package plan

// Tests for trust bundle actions, bundle links, and released artifacts
// (ADR-026 "Detailed rules", ADR-021 amendment).

import (
	"errors"
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
	tb := cfg.TrustBundles[0]
	m.TrustBundles = map[string]*manifest.TrustBundle{
		"main": {
			Path:           cfg.TrustBundlePath(tb),
			CAFingerprints: []string{"fp-b", "fp-a"},
			Links:          []manifest.CertLink{{Path: "out/node/main.crt", Target: "../bundles/main.crt"}},
		},
	}
	present = append(present, cfg.TrustBundlePath(tb))
	return m, existsSet(present...)
}

func bundleOpts(cfg *config.Config) Options {
	link := cfg.Resolve("out/node/main.crt")
	return Options{
		Lstat:    mockLstat(map[string]os.FileMode{link: os.ModeSymlink}),
		Readlink: mockReadlink(map[string]string{link: "../bundles/main.crt"}),
	}
}

func bundleOp(t *testing.T, p Plan, label string) Op {
	t.Helper()
	for _, a := range p.TrustBundleActions() {
		if a.Label == label {
			return a.Op
		}
	}
	t.Fatalf("no trust bundle action planned for %q", label)
	return ""
}

func TestBuild_TrustBundle_UpToDateIsNoop(t *testing.T) {
	cfg := parseCfg(t, bundleHCL)
	m, exists := upToDate(cfg)
	p, err := Build(cfg, m, testNow, exists, bundleOpts(cfg))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if op := bundleOp(t, p, "main"); op != OpNoop {
		t.Errorf("bundle op = %q, want noop", op)
	}
	if p.Changes() {
		t.Errorf("Changes() = true, want false; actions = %+v", p.Actions)
	}
}

func TestBuild_TrustBundle_WriteTriggers(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(cfg *config.Config, m *manifest.Manifest, exists func(string) bool) func(string) bool
	}{
		{"label not recorded", func(cfg *config.Config, m *manifest.Manifest, exists func(string) bool) func(string) bool {
			m.TrustBundles = nil
			return exists
		}},
		{"file missing", func(cfg *config.Config, m *manifest.Manifest, exists func(string) bool) func(string) bool {
			path := cfg.TrustBundlePath(cfg.TrustBundles[0])
			return func(p string) bool { return p != path && exists(p) }
		}},
		{"members reordered", func(cfg *config.Config, m *manifest.Manifest, exists func(string) bool) func(string) bool {
			m.TrustBundles["main"].CAFingerprints = []string{"fp-a", "fp-b"}
			return exists
		}},
		{"member fingerprint changed", func(cfg *config.Config, m *manifest.Manifest, exists func(string) bool) func(string) bool {
			m.CAs["a"].Fingerprint = "fp-a2"
			return exists
		}},
		{"path changed", func(cfg *config.Config, m *manifest.Manifest, exists func(string) bool) func(string) bool {
			m.TrustBundles["main"].Path = "out/old/main.crt"
			return exists
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseCfg(t, bundleHCL)
			m, exists := upToDate(cfg)
			exists = tt.mutate(cfg, m, exists)
			p, err := Build(cfg, m, testNow, exists, bundleOpts(cfg))
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if op := bundleOp(t, p, "main"); op != OpWrite {
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
	exists := existsSet(cfg.CACertPathForCA(a), cfg.CAKeyPathForCA(a), cfg.TrustBundlePath(cfg.TrustBundles[0]))
	delete(m.CAs, "b")
	p, err := Build(cfg, m, testNow, exists, bundleOpts(cfg))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if op := bundleOp(t, p, "main"); op != OpWrite {
		t.Errorf("bundle op = %q, want write", op)
	}
}

func TestBuild_TrustBundle_ReferenceMemberSwapped(t *testing.T) {
	// A referenced CA file swapped since the last run is seen by the plan
	// through the Fingerprint probe, so --dry-run and the run agree.
	cfg := parseCfg(t, `
trust_bundle "main" { ca_refs = [ca.r] }
ca "r" {
  cert_file = "ref/ca.crt"
  key_file  = "ref/ca.key"
}
`)
	tb := cfg.TrustBundles[0]
	m := manifest.New()
	m.CAs["r"] = &manifest.CA{Mode: "reference", Fingerprint: "fp-old"}
	m.TrustBundles = map[string]*manifest.TrustBundle{"main": {Path: cfg.TrustBundlePath(tb), CAFingerprints: []string{"fp-old"}}}
	exists := existsSet("ref/ca.crt", "ref/ca.key", cfg.TrustBundlePath(tb))

	for _, tt := range []struct {
		fp   string
		want Op
	}{{"fp-old", OpNoop}, {"fp-new", OpWrite}} {
		fp := tt.fp
		p, err := Build(cfg, m, testNow, exists, Options{Fingerprint: func(string) (string, error) { return fp, nil }})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if op := bundleOp(t, p, "main"); op != tt.want {
			t.Errorf("fingerprint %s: bundle op = %q, want %q", fp, op, tt.want)
		}
	}

	_, err := Build(cfg, m, testNow, exists, Options{Fingerprint: func(string) (string, error) { return "", errors.New("boom") }})
	if err == nil {
		t.Error("Build succeeded, want the fingerprint error")
	}
}

func TestBuild_TrustBundle_Multiple(t *testing.T) {
	cfg := parseCfg(t, `
trust_bundle "x" { ca_refs = [ca.a] }
trust_bundle "y" {
  ca_refs  = [ca.a]
  link_crt = ["out/node"]
}
ca "a" { name = "a" }
`)
	p, err := Build(cfg, manifest.New(), testNow, existsSet(), Options{Lstat: mockLstat(nil)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tbs := p.TrustBundleActions()
	if len(tbs) != 2 || tbs[0].Path != "out/bundles/x.crt" || tbs[1].Path != "out/bundles/y.crt" {
		t.Fatalf("TrustBundleActions = %+v, want x and y at their label paths", tbs)
	}
	links := p.LinkActions()
	if len(links) != 1 || links[0].Path != "out/node/y.crt" || links[0].Label != "y" {
		t.Errorf("LinkActions = %+v, want out/node/y.crt owned by y", links)
	}
}

func TestBuild_TrustBundle_LinksOwnedByBundle(t *testing.T) {
	// A CA and a bundle may share a label; their links stay apart.
	cfg := parseCfg(t, `
trust_bundle "main" {
  ca_refs  = [ca.main]
  link_crt = ["out/node"]
}
ca "main" {
  name     = "m"
  out_crt  = "out/ca/m.crt"
  out_key  = "out/ca/m.key"
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
	if owners["out/node/m.crt"] != KindCA {
		t.Errorf("out/node/m.crt owner = %q, want ca", owners["out/node/m.crt"])
	}
	if owners["out/node/main.crt"] != KindTrustBundle {
		t.Errorf("out/node/main.crt owner = %q, want trust_bundle", owners["out/node/main.crt"])
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
	if len(p.TrustBundleActions()) != 0 {
		t.Error("trust bundle action planned without a trust_bundle block")
	}
	rel := p.ReleaseActions()
	if len(rel) != 1 || rel[0].Owner != KindTrustBundle || rel[0].Label != "main" || len(rel[0].Paths) != 1 || rel[0].Paths[0] != "out/bundles/main.crt" {
		t.Fatalf("ReleaseActions = %+v, want the bundle file released", rel)
	}
	links := p.LinkActions()
	if len(links) != 1 || links[0].Op != OpDeleteSymlink || links[0].Owner != KindTrustBundle {
		t.Fatalf("LinkActions = %+v, want the bundle link deleted", links)
	}
}

func TestBuild_TrustBundle_LabelRenameIsNewBundle(t *testing.T) {
	full := parseCfg(t, bundleHCL)
	m, exists := upToDate(full)
	cfg := parseCfg(t, `
trust_bundle "primary" {
  ca_refs  = [ca.b, ca.a]
  link_crt = ["out/node"]
}
ca "a" {
  name    = "a"
  default = true
}
ca "b" { name = "b" }
`)
	p, err := Build(cfg, m, testNow, exists, Options{Lstat: mockLstat(nil)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if op := bundleOp(t, p, "primary"); op != OpWrite {
		t.Errorf("bundle op = %q, want write for the renamed bundle", op)
	}
	rel := p.ReleaseActions()
	if len(rel) != 1 || rel[0].Label != "main" || rel[0].Paths[0] != "out/bundles/main.crt" {
		t.Fatalf("ReleaseActions = %+v, want the old main.crt released", rel)
	}
	var created, deleted []string
	for _, l := range p.LinkActions() {
		switch l.Op {
		case OpCreateSymlink:
			created = append(created, l.Path)
		case OpDeleteSymlink:
			deleted = append(deleted, l.Path)
		}
	}
	if len(created) != 1 || created[0] != "out/node/primary.crt" || len(deleted) != 1 || deleted[0] != "out/node/main.crt" {
		t.Errorf("created %v, deleted %v; want primary.crt created and main.crt deleted", created, deleted)
	}
}

func TestBuild_TrustBundle_LabelRenameSamePathKeepsLink(t *testing.T) {
	// With an explicit, unchanged path the renamed bundle owns the same file
	// and symlink: nothing is released and the symlink is not deleted.
	src := func(label string) string {
		return `
trust_bundle "` + label + `" {
  ca_refs  = [ca.a]
  path     = "out/pki.crt"
  link_crt = ["out/node"]
}
ca "a" { name = "a" }
`
	}
	cfg := parseCfg(t, src("new"))
	m := manifest.New()
	m.CAs["a"] = &manifest.CA{Mode: "generate", Name: "a", Fingerprint: "fp-a"}
	m.TrustBundles = map[string]*manifest.TrustBundle{"old": {
		Path: "out/pki.crt", CAFingerprints: []string{"fp-a"},
		Links: []manifest.CertLink{{Path: "out/node/pki.crt", Target: "../pki.crt"}},
	}}
	link := cfg.Resolve("out/node/pki.crt")
	ca := cfg.CAs[0]
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca), "out/pki.crt"), Options{
		Lstat:    mockLstat(map[string]os.FileMode{link: os.ModeSymlink}),
		Readlink: mockReadlink(map[string]string{link: "../pki.crt"}),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if op := bundleOp(t, p, "new"); op != OpWrite {
		t.Errorf("bundle op = %q, want write (new label)", op)
	}
	if rel := p.ReleaseActions(); len(rel) != 0 {
		t.Errorf("ReleaseActions = %+v, want none: the path is still managed", rel)
	}
	for _, l := range p.LinkActions() {
		if l.Op == OpDeleteSymlink {
			t.Errorf("link action %+v deletes a symlink the renamed bundle still declares", l)
		}
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

func TestBuild_RemovedReferenceCA_ReleasesNoPaths(t *testing.T) {
	// A reference CA's files were never managed: removing the block drops
	// the record and its links, but releases no paths (no notice).
	cfg := parseCfg(t, `ca "own" { name = "own" }`)
	ca := cfg.CAs[0]
	m := manifest.New()
	m.CAs["own"] = &manifest.CA{Mode: "generate", Name: "own"}
	m.CAs["ref"] = &manifest.CA{Mode: "reference", Name: "ext", CertPath: "pki/ca.crt", KeyPath: "pki/ca.key"}
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)), Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rel := p.ReleaseActions()
	if len(rel) != 1 || rel[0].Label != "ref" || len(rel[0].Paths) != 0 {
		t.Fatalf("ReleaseActions = %+v, want ref released without paths", rel)
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
