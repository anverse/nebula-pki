package plan

import (
	"strings"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/manifest"
)

// testNow is a fixed issuance time used by all plan tests that do not
// exercise time-based renewal (it falls well before any certificate expiry
// in these tests).
var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

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
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	m := manifest.New() // no CA recorded

	p, err := Build(cfg, m, testNow, existsSet()) // nothing on disk
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
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}

	ca := cfg.CAs[0]
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)))
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
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	m := manifest.New() // no CA record, but files exist on disk

	ca := cfg.CAs[0]
	_, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)))
	if err == nil {
		t.Fatal("Build: want error for untracked CA on disk, got nil")
	}
	if !strings.Contains(err.Error(), "untracked CA") {
		t.Errorf("error = %q, want it to mention 'untracked CA'", err.Error())
	}
}

func TestBuild_PartialPairError(t *testing.T) {
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}

	// Only the cert exists; the key vanished.
	ca := cfg.CAs[0]
	_, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca)))
	if err == nil {
		t.Fatal("Build: want error for half-present CA pair, got nil")
	}
	if !strings.Contains(err.Error(), "inconsistent CA state") {
		t.Errorf("error = %q, want it to mention 'inconsistent CA state'", err.Error())
	}
}

// TestBuild_KeyOnlyError mirrors the cert-only case from the other side
// of the partial-pair switch.
func TestBuild_KeyOnlyError(t *testing.T) {
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}

	ca := cfg.CAs[0]
	_, err := Build(cfg, m, testNow, existsSet(cfg.CAKeyPathForCA(ca)))
	if err == nil {
		t.Fatal("Build: want error for key-only CA pair, got nil")
	}
	if !strings.Contains(err.Error(), "key "+cfg.CAKeyPathForCA(ca)+" exists") {
		t.Errorf("error = %q, want it to identify the surviving key", err.Error())
	}
}

// TestBuild_UntrackedKeyOnlyError covers the half-present untracked case.
func TestBuild_UntrackedKeyOnlyError(t *testing.T) {
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	m := manifest.New() // no CA record

	ca := cfg.CAs[0]
	_, err := Build(cfg, m, testNow, existsSet(cfg.CAKeyPathForCA(ca)))
	if err == nil {
		t.Fatal("Build: want error for half-present untracked CA, got nil")
	}
	if !strings.Contains(err.Error(), "inconsistent CA state") {
		t.Errorf("error = %q, want it to mention 'inconsistent CA state'", err.Error())
	}
}

// TestBuild_NilManifestTreatedAsUntracked exercises the `m != nil` guard.
func TestBuild_NilManifestTreatedAsUntracked(t *testing.T) {
	cfg := parseCfg(t, `ca "mesh" { name = "m" }`)
	ca := cfg.CAs[0]

	p, err := Build(cfg, nil, testNow, existsSet())
	if err != nil {
		t.Fatalf("Build(nil manifest, fresh): %v", err)
	}
	if !p.Changes() || p.Actions[0].Op != OpGenerate {
		t.Errorf("actions = %+v, want a single generate-ca", p.Actions)
	}

	_, err = Build(cfg, nil, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)))
	if err == nil {
		t.Fatal("Build(nil manifest, files present): want untracked error, got nil")
	}
	if !strings.Contains(err.Error(), "untracked CA") {
		t.Errorf("error = %q, want it to mention 'untracked CA'", err.Error())
	}
}

// --- Host planning ----------------------------------------------------

const hostHCL = `
ca "mesh" { name = "m" }
host "alpha" { networks = ["10.0.0.1/16"] }
host "beta"  { networks = ["10.0.0.2/16"] }
`

func TestBuild_HostSignWhenUntracked(t *testing.T) {
	cfg := parseCfg(t, hostHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}

	ca := cfg.CAs[0]
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true when hosts need signing")
	}
	ha := p.HostActions()
	if len(ha) != 2 {
		t.Fatalf("HostActions() = %d, want 2", len(ha))
	}
	for _, a := range ha {
		if a.Op != OpSign {
			t.Errorf("host %q: Op = %q, want sign", a.Label, a.Op)
		}
		if a.Kind != KindHost {
			t.Errorf("host %q: Kind = %q, want host", a.Label, a.Kind)
		}
	}
}

func TestBuild_HostNoopWhenTrackedAndPresent(t *testing.T) {
	cfg := parseCfg(t, hostHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	m.Hosts["alpha"] = manifest.Host{Name: "alpha", CA: "mesh"}
	m.Hosts["beta"] = manifest.Host{Name: "beta", CA: "mesh"}

	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.HostArtifactPath(cfg.Hosts[0]).CertPath, cfg.HostArtifactPath(cfg.Hosts[0]).KeyPath,
		cfg.HostArtifactPath(cfg.Hosts[1]).CertPath, cfg.HostArtifactPath(cfg.Hosts[1]).KeyPath,
	)
	p, err := Build(cfg, m, testNow, exists)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Changes() {
		t.Fatalf("Changes() = true, want false; actions = %+v", p.Actions)
	}
	for _, a := range p.HostActions() {
		if a.Op != OpNoop {
			t.Errorf("host %q: Op = %q, want noop", a.Label, a.Op)
		}
	}
}

func TestBuild_HostSignWhenFilesAbsent(t *testing.T) {
	cfg := parseCfg(t, hostHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	m.Hosts["alpha"] = manifest.Host{Name: "alpha", CA: "mesh"}
	m.Hosts["beta"] = manifest.Host{Name: "beta", CA: "mesh"}

	ca := cfg.CAs[0]
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true when tracked hosts are missing their files")
	}
	for _, a := range p.HostActions() {
		if a.Op != OpSign {
			t.Errorf("host %q: Op = %q, want sign (re-create missing files)", a.Label, a.Op)
		}
	}
}

func TestBuild_HostSignWhenCertPresentKeyMissing(t *testing.T) {
	cfg := parseCfg(t, hostHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	m.Hosts["alpha"] = manifest.Host{Name: "alpha", CA: "mesh"}

	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.HostArtifactPath(cfg.Hosts[0]).CertPath,
		// host key absent
	)
	p, err := Build(cfg, m, testNow, exists)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var alphaAction Action
	for _, a := range p.HostActions() {
		if a.Label == "alpha" {
			alphaAction = a
		}
	}
	if alphaAction.Op != OpSign {
		t.Errorf("alpha: Op = %q, want sign (key missing → re-sign whole pair)", alphaAction.Op)
	}
}

func TestBuild_HostSignWhenKeyPresentCertMissing(t *testing.T) {
	cfg := parseCfg(t, hostHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	m.Hosts["alpha"] = manifest.Host{Name: "alpha", CA: "mesh"}

	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		// host cert absent
		cfg.HostArtifactPath(cfg.Hosts[0]).KeyPath,
	)
	p, err := Build(cfg, m, testNow, exists)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var alphaAction Action
	for _, a := range p.HostActions() {
		if a.Label == "alpha" {
			alphaAction = a
		}
	}
	if alphaAction.Op != OpSign {
		t.Errorf("alpha: Op = %q, want sign (cert missing → re-sign whole pair)", alphaAction.Op)
	}
}

func TestBuild_MultipleHostsMixedActions(t *testing.T) {
	cfg := parseCfg(t, hostHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	// alpha is tracked and present; beta is untracked.
	m.Hosts["alpha"] = manifest.Host{Name: "alpha", CA: "mesh"}

	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.HostArtifactPath(cfg.Hosts[0]).CertPath, cfg.HostArtifactPath(cfg.Hosts[0]).KeyPath,
		// beta's files are absent
	)
	p, err := Build(cfg, m, testNow, exists)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true (beta needs signing)")
	}
	ha := p.HostActions()
	if len(ha) != 2 {
		t.Fatalf("HostActions() = %d, want 2", len(ha))
	}
	if ha[0].Label != "alpha" || ha[0].Op != OpNoop {
		t.Errorf("host[0]: label=%q op=%q, want alpha/noop", ha[0].Label, ha[0].Op)
	}
	if ha[1].Label != "beta" || ha[1].Op != OpSign {
		t.Errorf("host[1]: label=%q op=%q, want beta/sign", ha[1].Label, ha[1].Op)
	}
}

func TestBuild_CANoopHostSign_ChangesTrue(t *testing.T) {
	cfg := parseCfg(t, hostHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	// CA is tracked and both files present — CA action is noop.
	// Hosts are untracked.

	ca := cfg.CAs[0]
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.CAActions()[0].Op != OpNoop {
		t.Errorf("CAActions()[0].Op = %q, want noop", p.CAActions()[0].Op)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true (hosts need signing)")
	}
}

// --- Host CA label mismatch re-signs -------------------------------------

// TestBuild_HostResignsWhenCAChanged verifies that if the recorded CA label
// in the manifest differs from the current signing CA, planHost emits OpSign
// even when the files are present.
func TestBuild_HostResignsWhenCAChanged(t *testing.T) {
	cfg := parseCfg(t, hostHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	// Record alpha as having been signed by a different CA label.
	m.Hosts["alpha"] = manifest.Host{Name: "alpha", CA: "old-mesh"}

	ca := cfg.CAs[0]
	exists := existsSet(
		cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca),
		cfg.HostArtifactPath(cfg.Hosts[0]).CertPath, cfg.HostArtifactPath(cfg.Hosts[0]).KeyPath,
	)
	p, err := Build(cfg, m, testNow, exists)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var alphaAction Action
	for _, a := range p.HostActions() {
		if a.Label == "alpha" {
			alphaAction = a
		}
	}
	if alphaAction.Op != OpSign {
		t.Errorf("alpha: Op = %q, want sign (CA label mismatch → re-sign)", alphaAction.Op)
	}
}

// --- Custom output_dir ------------------------------------------------

const outputDirHCL = `
ca "mesh" { name = "m" }
host "node" {
  networks   = ["10.0.0.1/16"]
  output_dir = "dir-a"
}
`

func TestBuild_OutputDirNoopWhenPresent(t *testing.T) {
	cfg := parseCfg(t, outputDirHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	m.Hosts["node"] = manifest.Host{Name: "node", CA: "mesh"}

	ca := cfg.CAs[0]
	a := cfg.HostArtifactPath(cfg.Hosts[0])
	exists := existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca), a.CertPath, a.KeyPath)
	p, err := Build(cfg, m, testNow, exists)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Changes() {
		t.Fatalf("Changes() = true, want false when output_dir artifacts present; actions = %+v", p.Actions)
	}
	for _, act := range p.HostActions() {
		if act.Op != OpNoop {
			t.Errorf("host %q: Op = %q, want noop", act.Label, act.Op)
		}
	}
}

func TestBuild_OutputDirSignWhenFileMissing(t *testing.T) {
	cfg := parseCfg(t, outputDirHCL)
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", Name: "m"}
	m.Hosts["node"] = manifest.Host{Name: "node", CA: "mesh"}

	ca := cfg.CAs[0]
	a := cfg.HostArtifactPath(cfg.Hosts[0])
	exists := existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca), a.CertPath)
	p, err := Build(cfg, m, testNow, exists)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !p.Changes() {
		t.Fatal("Changes() = false, want true when output_dir key is missing")
	}
	for _, act := range p.HostActions() {
		if act.Op != OpSign {
			t.Errorf("host %q: Op = %q, want sign", act.Label, act.Op)
		}
	}
}

// --- Reference mode ---------------------------------------------------

func TestBuild_ReferenceWithFilesPresent(t *testing.T) {
	cfg := parseCfg(t, `
ca "ref" {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	ca := cfg.CAs[0]
	p, err := Build(cfg, manifest.New(), testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)))
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
// stays pure: it always emits OpReference and lets apply decide.
func TestBuild_ReferenceEmitsReferenceEvenWhenTracked(t *testing.T) {
	cfg := parseCfg(t, `
ca "ref" {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	m := manifest.New()
	m.CAs["ref"] = &manifest.CA{Mode: "reference", Name: "m"}

	ca := cfg.CAs[0]
	p, err := Build(cfg, m, testNow, existsSet(cfg.CACertPathForCA(ca), cfg.CAKeyPathForCA(ca)))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if p.Actions[0].Op != OpReference {
		t.Errorf("op = %q, want reference (plan defers identity check to apply)", p.Actions[0].Op)
	}
}

func TestBuild_ReferenceMissingBothFiles(t *testing.T) {
	cfg := parseCfg(t, `
ca "ref" {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	_, err := Build(cfg, manifest.New(), testNow, existsSet()) // nothing on disk
	if err == nil {
		t.Fatal("Build: want error when referenced files are absent, got nil")
	}
	if !strings.Contains(err.Error(), "referenced CA not found") {
		t.Errorf("error = %q, want it to mention 'referenced CA not found'", err.Error())
	}
}

func TestBuild_ReferenceMissingKeyOnly(t *testing.T) {
	cfg := parseCfg(t, `
ca "ref" {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	ca := cfg.CAs[0]
	_, err := Build(cfg, manifest.New(), testNow, existsSet(cfg.CACertPathForCA(ca)))
	if err == nil {
		t.Fatal("Build: want error when referenced key is absent, got nil")
	}
	if !strings.Contains(err.Error(), "key_file") {
		t.Errorf("error = %q, want it to identify the missing key_file", err.Error())
	}
}

func TestBuild_ReferenceMissingCertOnly(t *testing.T) {
	cfg := parseCfg(t, `
ca "ref" {
  cert_file = "pki/root.crt"
  key_file  = "pki/root.key"
}`)
	ca := cfg.CAs[0]
	_, err := Build(cfg, manifest.New(), testNow, existsSet(cfg.CAKeyPathForCA(ca)))
	if err == nil {
		t.Fatal("Build: want error when referenced cert is absent, got nil")
	}
	if !strings.Contains(err.Error(), "cert_file") {
		t.Errorf("error = %q, want it to identify the missing cert_file", err.Error())
	}
}
