package plan

// Tests for paths renamed only in case. On a case-insensitive filesystem the
// old and new spelling name one file, so the old link must be deleted before
// the new one is created, and a renamed file is not reported as released.

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/manifest"
)

// foldedOpts answers like a case-insensitive filesystem holding one symlink
// at path with the given target.
func foldedOpts(path, target string) Options {
	lstat := mockLstat(map[string]os.FileMode{strings.ToLower(path): os.ModeSymlink})
	read := mockReadlink(map[string]string{strings.ToLower(path): target})
	return Options{
		Lstat:    func(p string) (os.FileMode, error) { return lstat(strings.ToLower(p)) },
		Readlink: func(p string) (string, error) { return read(strings.ToLower(p)) },
	}
}

// linkOrder returns the index in p.Actions of the delete of oldPath and of
// the create of newPath, failing when either is missing.
func linkOrder(t *testing.T, p Plan, oldPath, newPath string) (del, create int) {
	t.Helper()
	del, create = -1, -1
	for i, a := range p.Actions {
		switch {
		case a.Op == OpDeleteSymlink && a.Path == oldPath:
			del = i
		case a.Op == OpCreateSymlink && a.Path == newPath:
			create = i
		case a.Kind == KindLink && a.Op == OpNoop && a.Path == newPath:
			t.Errorf("link %s planned as noop; deleting %s would remove it", newPath, oldPath)
		}
	}
	if del < 0 || create < 0 {
		t.Fatalf("LinkActions = %+v, want delete of %s and create of %s", p.LinkActions(), oldPath, newPath)
	}
	return del, create
}

func TestBuild_LinkRenamedOnlyInCase(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		record    func(m *manifest.Manifest, links []manifest.CertLink)
		oldPath   string
		newPath   string
		oldTarget string
		newTarget string
	}{
		{
			name: "ca link",
			src: `
ca "a" {
  name     = "a"
  link_crt = ["out/node"]
}
`,
			record:    func(m *manifest.Manifest, links []manifest.CertLink) { m.CAs["a"].Links = links },
			oldPath:   "out/Node/a.crt",
			newPath:   "out/node/a.crt",
			oldTarget: "../ca/a.crt",
			newTarget: "../ca/a.crt",
		},
		{
			name: "bundle link",
			src: `
ca "a" { name = "a" }
trust_bundle "main" {
  ca_refs  = [ca.a]
  link_crt = ["out/node"]
}
`,
			record: func(m *manifest.Manifest, links []manifest.CertLink) {
				m.TrustBundles = map[string]*manifest.TrustBundle{"main": {
					Path: "out/bundles/main.crt", CAFingerprints: []string{"fp-a"}, Links: links,
				}}
			},
			oldPath:   "out/Node/main.crt",
			newPath:   "out/node/main.crt",
			oldTarget: "../bundles/main.crt",
			newTarget: "../bundles/main.crt",
		},
		{
			// The CA recorded the link, the bundle now declares it in other case.
			name: "hand over between owners",
			src: `
ca "main" { name = "main" }
trust_bundle "main" {
  ca_refs  = [ca.main]
  link_crt = ["out/node"]
}
`,
			record:    func(m *manifest.Manifest, links []manifest.CertLink) { m.CAs["main"].Links = links },
			oldPath:   "out/Node/main.crt",
			newPath:   "out/node/main.crt",
			oldTarget: "../ca/main.crt",
			newTarget: "../bundles/main.crt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseCfg(t, tt.src)
			ca := cfg.CAs[0]
			m := manifest.New()
			m.CAs[ca.Label] = &manifest.CA{Mode: "generate", Name: ca.Name, Fingerprint: "fp-" + ca.Label}
			tt.record(m, []manifest.CertLink{{Path: tt.oldPath, Target: tt.oldTarget}})
			present := []string{cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)}
			for _, tb := range cfg.TrustBundles {
				present = append(present, cfg.TrustBundlePath(tb))
			}
			// The new spelling resolves to the old link, which already points
			// at the new target: without the rule it would be a noop.
			p, err := Build(cfg, m, testNow, existsSet(present...), foldedOpts(cfg.Resolve(tt.oldPath), tt.newTarget))
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			del, create := linkOrder(t, p, tt.oldPath, tt.newPath)
			if del > create {
				t.Errorf("delete of %s planned after create of %s; it would remove the new link", tt.oldPath, tt.newPath)
			}
		})
	}
}

// An unchanged link with a removed link elsewhere stays a noop: only a path
// that matches a removed one ignoring case is created again.
func TestBuild_LinkUnrelatedRemovalKeepsNoop(t *testing.T) {
	cfg := parseCfg(t, `
ca "a" {
  name     = "a"
  link_crt = ["out/node"]
}
`)
	ca := cfg.CAs[0]
	m := manifest.New()
	m.CAs["a"] = &manifest.CA{Mode: "generate", Name: "a", Fingerprint: "fp-a", Links: []manifest.CertLink{
		{Path: "out/node/a.crt", Target: "../ca/a.crt"},
		{Path: "out/old/a.crt", Target: "../ca/a.crt"},
	}}
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)), foldedOpts(cfg.Resolve("out/node/a.crt"), "../ca/a.crt"))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var ops []string
	for _, a := range p.LinkActions() {
		ops = append(ops, string(a.Op)+" "+a.Path)
	}
	want := []string{string(OpDeleteSymlink) + " out/old/a.crt", string(OpNoop) + " out/node/a.crt"}
	if !slices.Equal(ops, want) {
		t.Errorf("link actions = %v, want %v", ops, want)
	}
}

// A bundle path renamed only in case names the same file: it is rewritten
// under the new spelling and not reported as released.
func TestBuild_TrustBundle_PathRenamedOnlyInCaseNotReleased(t *testing.T) {
	cfg := parseCfg(t, spellingHCL)
	m, exists := spelledManifest(cfg, "out/B.crt")
	p, err := Build(cfg, m, testNow, exists, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rel := p.ReleaseActions(); len(rel) != 0 {
		t.Errorf("ReleaseActions = %+v, want none: out/B.crt and out/b.crt are one file", rel)
	}
}
