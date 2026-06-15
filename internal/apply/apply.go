// Package apply is the only component in nebula-pki that mutates the
// filesystem. It loads the current manifest, asks internal/plan what must
// change, and — when something must — generates artifacts via internal/pki
// and persists them via internal/fsutil, writing the manifest last.
//
// Everything upstream of apply (config, pki, manifest, plan) is pure and
// side-effect free. Keeping all writes here makes the dangerous part of
// the tool small and auditable, and makes idempotency a property of plan
// rather than of scattered I/O.
//
// v0.0.3 reconciles the CA only. Hosts are parsed and counted but not yet
// signed; they arrive in a later milestone step.
package apply

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/fsutil"
	"github.com/anverse/nebula-pki/internal/manifest"
	"github.com/anverse/nebula-pki/internal/pki"
	"github.com/anverse/nebula-pki/internal/plan"
)

// File modes mandated by spec/adr/002-state-and-artifact-layout.md.
const (
	certMode     fs.FileMode = 0o600
	keyMode      fs.FileMode = 0o600
	manifestMode fs.FileMode = 0o644
)

// Options configures a reconcile run.
type Options struct {
	// Now is the issuance time stamped into generated certificates and the
	// manifest's generated_at. Injected so tests are deterministic.
	Now time.Time
	// GeneratorVersion is recorded as generator.version in the manifest
	// (the caller passes internal/buildinfo.Version; apply does not import
	// it, keeping this package free of build-time globals).
	GeneratorVersion string
}

// Report summarises what a reconcile did, for the CLI to present. Paths
// are logical (as recorded in the manifest and written in HCL), not the
// resolved on-disk paths.
type Report struct {
	// Changed reports whether anything was written. False means the tree
	// was already up to date and not a single byte (including the
	// manifest) was touched.
	Changed bool

	ManifestPath string
	CACertPath   string
	CAKeyPath    string
	CAName       string

	// HostsParsed is the number of host blocks in the config. In v0.0.3
	// they are parsed but not reconciled; the CLI surfaces this so the
	// operator knows they were seen, not silently dropped.
	HostsParsed int
}

// Reconcile brings the output tree in line with cfg and returns a Report.
//
// It loads the manifest, builds a plan, and — if the plan changes nothing
// — returns immediately without writing, so an up-to-date tree stays
// byte-identical across runs (spec/adr/002). Otherwise it generates the CA,
// writes the certificate and key, then writes the manifest last so a crash
// mid-run never records artifacts that were not fully written.
func Reconcile(cfg *config.Config, opts Options) (*Report, error) {
	manifestLogical := cfg.ManifestPath()
	manifestReal := cfg.Resolve(manifestLogical)

	report := &Report{
		ManifestPath: manifestLogical,
		CACertPath:   cfg.CACertPath(),
		CAKeyPath:    cfg.CAKeyPath(),
		HostsParsed:  len(cfg.Hosts),
	}

	current, err := manifest.Load(manifestReal)
	if err != nil {
		return nil, err
	}

	exists := func(logical string) bool {
		return fsutil.Exists(cfg.Resolve(logical))
	}

	p, err := plan.Build(cfg, current, exists)
	if err != nil {
		return nil, err
	}

	if !p.Changes() {
		// Up to date: write nothing, not even the manifest.
		report.Changed = false
		if current.CA != nil {
			report.CAName = current.CA.Name
		}
		return report, nil
	}

	// v0.0.3: the only mutating action plan can emit is CA generation.
	result, err := pki.GenerateCA(cfg.CA, opts.Now)
	if err != nil {
		return nil, err
	}

	if err := fsutil.WriteFile(cfg.Resolve(report.CACertPath), result.CertPEM, certMode); err != nil {
		return nil, fmt.Errorf("write CA certificate: %w", err)
	}
	if err := fsutil.WriteFile(cfg.Resolve(report.CAKeyPath), result.KeyPEM, keyMode); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}

	// Build and persist the manifest last — it is the commit record for the
	// run (spec/adr/002, spec/adr/013).
	next := manifest.New()
	next.GeneratedAt = opts.Now.UTC()
	next.Generator.Version = opts.GeneratorVersion
	next.ConfigPath = manifestRelConfigPath(cfg, manifestReal)
	next.CA = &manifest.CA{
		Mode:        config.CAModeGenerate.String(),
		Name:        result.Name,
		Fingerprint: result.Fingerprint,
		Curve:       result.Curve,
		Version:     result.Version,
		NotBefore:   result.NotBefore.UTC(),
		NotAfter:    result.NotAfter.UTC(),
		CertPath:    report.CACertPath,
		KeyPath:     report.CAKeyPath,
	}

	data, err := manifest.Marshal(next)
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFile(manifestReal, data, manifestMode); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}

	report.Changed = true
	report.CAName = result.Name
	return report, nil
}

// manifestRelConfigPath computes the manifest's config_path field: the
// path to the HCL config relative to the manifest's directory when
// possible, with an absolute path as the fallback (spec/adr/002). Keeping
// it relative makes the committed manifest reproducible regardless of
// where the repository is checked out.
func manifestRelConfigPath(cfg *config.Config, manifestReal string) string {
	absConfig, err := filepath.Abs(cfg.Path)
	if err != nil {
		return cfg.Path
	}
	absManifestDir, err := filepath.Abs(filepath.Dir(manifestReal))
	if err != nil {
		return absConfig
	}
	rel, err := filepath.Rel(absManifestDir, absConfig)
	if err != nil {
		return absConfig
	}
	return rel
}
