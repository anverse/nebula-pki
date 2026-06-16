package plan

import (
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/manifest"
)

func parseCfg(t *testing.T, src string) *config.Config {
	t.Helper()
	cfg, err := config.Parse("nebula.hcl", []byte(src))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	return cfg
}

// existsSet builds an exists probe from a set of present logical paths.
func existsSet(paths ...string) func(string) bool {
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		set[p] = struct{}{}
	}
	return func(p string) bool {
		_, ok := set[p]
		return ok
	}
}

func TestBuild_FreshGeneratesCA(t *testing.T) {
	cfg := parseCfg(t, `ca { name = "m" }`)
	m := manifest.New() // no CA recorded

	p, err := Build(cfg, m, existsSet()) // nothing on disk
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true on a fresh tree")
	}
	if len(p.Actions) != 1 || p.Actions[0].Op != OpGenerate || p.Actions[0].Kind != KindCA {
		t.Fatalf("actions = %+v, want a single generate-ca", p.Actions)
	}
}

func TestBuild_TrackedAndPresentIsNoop(t *testing.T) {
	cfg := parseCfg(t, `ca { name = "m" }`)
	m := manifest.New()
	m.CA = &manifest.CA{Mode: "generate", Name: "m"}

	p, err := Build(cfg, m, existsSet(cfg.CACertPath(), cfg.CAKeyPath()))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Changes() {
		t.Fatalf("Changes() = true, want false; actions = %+v", p.Actions)
	}
	if p.Actions[0].Op != OpNoop {
		t.Errorf("op = %q, want noop", p.Actions[0].Op)
	}
}

func TestBuild_UntrackedFilesError(t *testing.T) {
	cfg := parseCfg(t, `ca { name = "m" }`)
	m := manifest.New() // no CA record, but files exist on disk

	_, err := Build(cfg, m, existsSet(cfg.CACertPath(), cfg.CAKeyPath()))
	if err == nil {
		t.Fatal("Build: want error for untracked CA on disk, got nil")
	}
	if !strings.Contains(err.Error(), "untracked CA") {
		t.Errorf("error = %q, want it to mention 'untracked CA'", err.Error())
	}
}

func TestBuild_PartialPairError(t *testing.T) {
	cfg := parseCfg(t, `ca { name = "m" }`)
	m := manifest.New()
	m.CA = &manifest.CA{Mode: "generate", Name: "m"}

	// Only the cert exists; the key vanished.
	_, err := Build(cfg, m, existsSet(cfg.CACertPath()))
	if err == nil {
		t.Fatal("Build: want error for half-present CA pair, got nil")
	}
	if !strings.Contains(err.Error(), "inconsistent CA state") {
		t.Errorf("error = %q, want it to mention 'inconsistent CA state'", err.Error())
	}
}

// TestBuild_KeyOnlyError mirrors the cert-only case from the other side
// of the partial-pair switch. Without this test the key-only arm of
// caStateError (line 123) is dead-coded as far as the suite is
// concerned, and a regression that swaps the two error messages would
// silently pass.
func TestBuild_KeyOnlyError(t *testing.T) {
	cfg := parseCfg(t, `ca { name = "m" }`)
	m := manifest.New()
	m.CA = &manifest.CA{Mode: "generate", Name: "m"}

	_, err := Build(cfg, m, existsSet(cfg.CAKeyPath()))
	if err == nil {
		t.Fatal("Build: want error for key-only CA pair, got nil")
	}
	// The error must name the *key* as the surviving file, not the
	// cert: that distinction is the only thing the user has to act on.
	if !strings.Contains(err.Error(), "key "+cfg.CAKeyPath()+" exists") {
		t.Errorf("error = %q, want it to identify the surviving key", err.Error())
	}
}

// TestBuild_UntrackedKeyOnlyError covers the half-present untracked
// case: file on disk, no manifest record. The error must still classify
// it as "inconsistent" (single file with nothing to validate it
// against), not "untracked" (which is reserved for the both-files case
// where the manifest has been lost wholesale).
func TestBuild_UntrackedKeyOnlyError(t *testing.T) {
	cfg := parseCfg(t, `ca { name = "m" }`)
	m := manifest.New() // no CA record

	_, err := Build(cfg, m, existsSet(cfg.CAKeyPath()))
	if err == nil {
		t.Fatal("Build: want error for half-present untracked CA, got nil")
	}
	if !strings.Contains(err.Error(), "inconsistent CA state") {
		t.Errorf("error = %q, want it to mention 'inconsistent CA state'", err.Error())
	}
}

// TestBuild_NilManifestTreatedAsUntracked exercises the `m != nil`
// guard at plan.go:94. apply.Reconcile always passes a non-nil manifest
// (manifest.Load returns an empty one for a missing file), but plan is
// a public-ish boundary inside the module and a future caller might
// pass nil intentionally. The contract is "treat nil as no CA recorded".
func TestBuild_NilManifestTreatedAsUntracked(t *testing.T) {
	cfg := parseCfg(t, `ca { name = "m" }`)

	// Nil manifest, nothing on disk: same outcome as a fresh tree.
	p, err := Build(cfg, nil, existsSet())
	if err != nil {
		t.Fatalf("Build(nil manifest, fresh): %v", err)
	}
	if !p.Changes() || p.Actions[0].Op != OpGenerate {
		t.Errorf("actions = %+v, want a single generate-ca", p.Actions)
	}

	// Nil manifest, both files on disk: treated as untracked, must error.
	_, err = Build(cfg, nil, existsSet(cfg.CACertPath(), cfg.CAKeyPath()))
	if err == nil {
		t.Fatal("Build(nil manifest, files present): want untracked error, got nil")
	}
	if !strings.Contains(err.Error(), "untracked CA") {
		t.Errorf("error = %q, want it to mention 'untracked CA'", err.Error())
	}
}

// --- Reference mode ---------------------------------------------------

func TestBuild_ReferenceWithFilesPresent(t *testing.T) {
	cfg := parseCfg(t, `
ca {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	// Both referenced files present, nothing recorded yet.
	p, err := Build(cfg, manifest.New(), existsSet(cfg.CACertPath(), cfg.CAKeyPath()))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true when a reference CA is not yet recorded")
	}
	if len(p.Actions) != 1 || p.Actions[0].Op != OpReference || p.Actions[0].Kind != KindCA {
		t.Fatalf("actions = %+v, want a single reference-ca", p.Actions)
	}
}

// TestBuild_ReferenceEmitsReferenceEvenWhenTracked documents that plan
// stays pure: it cannot read the cert to confirm the recorded fingerprint
// still matches, so it always emits OpReference and lets apply decide
// whether the manifest actually needs rewriting. (apply's own test
// asserts the byte-identical rerun.)
func TestBuild_ReferenceEmitsReferenceEvenWhenTracked(t *testing.T) {
	cfg := parseCfg(t, `
ca {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	m := manifest.New()
	m.CA = &manifest.CA{Mode: "reference", Name: "m"}

	p, err := Build(cfg, m, existsSet(cfg.CACertPath(), cfg.CAKeyPath()))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Actions[0].Op != OpReference {
		t.Errorf("op = %q, want reference (plan defers identity check to apply)", p.Actions[0].Op)
	}
}

func TestBuild_ReferenceMissingBothFiles(t *testing.T) {
	cfg := parseCfg(t, `
ca {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	_, err := Build(cfg, manifest.New(), existsSet()) // nothing on disk
	if err == nil {
		t.Fatal("Build: want error when referenced files are absent, got nil")
	}
	if !strings.Contains(err.Error(), "referenced CA not found") {
		t.Errorf("error = %q, want it to mention 'referenced CA not found'", err.Error())
	}
}

func TestBuild_ReferenceMissingKeyOnly(t *testing.T) {
	cfg := parseCfg(t, `
ca {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	// Cert present, key absent.
	_, err := Build(cfg, manifest.New(), existsSet(cfg.CACertPath()))
	if err == nil {
		t.Fatal("Build: want error when referenced key is absent, got nil")
	}
	if !strings.Contains(err.Error(), "key_file") {
		t.Errorf("error = %q, want it to identify the missing key_file", err.Error())
	}
}

func TestBuild_ReferenceMissingCertOnly(t *testing.T) {
	cfg := parseCfg(t, `
ca {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	// Key present, cert absent.
	_, err := Build(cfg, manifest.New(), existsSet(cfg.CAKeyPath()))
	if err == nil {
		t.Fatal("Build: want error when referenced cert is absent, got nil")
	}
	if !strings.Contains(err.Error(), "cert_file") {
		t.Errorf("error = %q, want it to identify the missing cert_file", err.Error())
	}
}
