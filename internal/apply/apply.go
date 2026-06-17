// Package apply is the only component in nebula-pki that mutates the
// filesystem. It loads the current manifest, asks internal/plan what must
// change, and — when something must — generates or loads the CA via
// internal/pki and persists the manifest via internal/fsutil.
//
// Everything upstream of apply (config, pki, manifest, plan) is pure and
// side-effect free. Keeping all writes here makes the dangerous part of
// the tool small and auditable, and makes idempotency a property of plan
// rather than of scattered I/O.
//
// It reconciles the CA in both modes and signs host certificates under the
// loaded or generated CA. All artifact writes are atomic via fsutil.
package apply

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
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
	// Warn receives non-fatal diagnostics (e.g. an expired reference CA).
	// It is optional; when nil, warnings are discarded. The CLI wires this
	// to stderr. apply never writes progress here itself — only genuine
	// "you should know this" notices.
	Warn io.Writer
}

// SignedArtifact is one destination for a signed host's cert/key pair.
type SignedArtifact struct {
	Dir      string // populated for output_dirs fan-out; empty for default/explicit
	CertPath string
	KeyPath  string
}

// SignedHost is a brief record of one host that was signed this run.
type SignedHost struct {
	Label     string
	Artifacts []SignedArtifact
}

// Report summarises what a reconcile did, for the CLI to present. Paths
// are logical (as recorded in the manifest and written in HCL), not the
// resolved on-disk paths.
type Report struct {
	// Changed reports whether anything was written. False means the tree
	// was already up to date and not a single byte (including the
	// manifest) was touched.
	Changed bool

	// CAMode is the reconciled CA mode ("generate" or "reference"), so the
	// CLI can phrase its summary correctly ("generated" vs "using").
	CAMode string

	ManifestPath string
	CACertPath   string
	CAKeyPath    string
	CAName       string

	// SignedHosts is the set of hosts that were signed this run, in config
	// order. Empty on a noop run.
	SignedHosts []SignedHost
}

// Reconcile brings the output tree in line with cfg and returns a Report.
//
// It loads the manifest, builds a plan, and dispatches on the CA mode.
// In every mode an up-to-date tree stays byte-identical across runs:
// nothing — not even the manifest — is rewritten when the recorded state
// already matches (spec/adr/002).
func Reconcile(cfg *config.Config, opts Options) (*Report, error) {
	manifestLogical := cfg.ManifestPath()
	manifestReal := cfg.Resolve(manifestLogical)

	report := &Report{
		CAMode:       cfg.CA.Mode.String(),
		ManifestPath: manifestLogical,
		CACertPath:   cfg.CACertPath(),
		CAKeyPath:    cfg.CAKeyPath(),
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

	if cfg.CA.Mode == config.CAModeReference {
		return reconcileReference(cfg, opts, report, p, current, manifestReal)
	}
	return reconcileGenerate(cfg, opts, report, p, current, manifestReal)
}

// reconcileGenerate handles generate mode: mint a fresh CA if needed,
// sign any hosts that need signing, then write the manifest last so a
// crash mid-run never records artifacts that were not fully written.
func reconcileGenerate(cfg *config.Config, opts Options, report *Report, p plan.Plan, current *manifest.Manifest, manifestReal string) (*Report, error) {
	if !p.Changes() {
		report.Changed = false
		report.CAName = cfg.CA.Name
		return report, nil
	}

	var caCertPEM, caKeyPEM []byte
	var caResult *pki.CAResult

	if p.CAAction().Op == plan.OpGenerate {
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
		caCertPEM = result.CertPEM
		caKeyPEM = result.KeyPEM
		caResult = result
	} else {
		// CA is up to date; read it from disk so we can sign hosts.
		var err error
		caCertPEM, err = os.ReadFile(cfg.Resolve(report.CACertPath))
		if err != nil {
			return nil, fmt.Errorf("read existing CA certificate for host signing: %w", err)
		}
		caKeyPEM, err = os.ReadFile(cfg.Resolve(report.CAKeyPath))
		if err != nil {
			return nil, fmt.Errorf("read existing CA key for host signing: %w", err)
		}
	}

	next := newManifestFromGenerate(cfg, opts, report, caResult, current)

	signed, err := applyHosts(cfg, opts, p.HostActions(), caCertPEM, caKeyPEM, current, next)
	if err != nil {
		return nil, err
	}

	if err := writeManifest(manifestReal, next); err != nil {
		return nil, err
	}

	report.Changed = true
	if caResult != nil {
		report.CAName = caResult.Name
	} else {
		report.CAName = current.CA.Name
	}
	report.SignedHosts = signed
	return report, nil
}

// reconcileReference handles reference mode: read the operator-supplied CA
// in place, verify it, sign any hosts that need signing, and record
// everything in the manifest. The source CA files are never rewritten
// (spec/adr/002).
//
// Idempotency for the CA record is by rebuild-and-compare: plan cannot
// read the certificate, so apply builds the candidate manifest and writes
// only when it differs from what is already on disk. Host signing follows
// the plan's OpSign/OpNoop verdict. The combined candidate manifest is
// compared to the current one to decide whether to write.
func reconcileReference(cfg *config.Config, opts Options, report *Report, p plan.Plan, current *manifest.Manifest, manifestReal string) (*Report, error) {
	certReal := cfg.Resolve(report.CACertPath)
	keyReal := cfg.Resolve(report.CAKeyPath)

	certPEM, err := os.ReadFile(certReal)
	if err != nil {
		return nil, fmt.Errorf("read referenced CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyReal)
	if err != nil {
		return nil, fmt.Errorf("read referenced CA key: %w", err)
	}

	result, err := pki.LoadReferenceCA(certPEM, keyPEM, opts.Now)
	if errors.Is(err, pki.ErrReferenceCAExpired) {
		fmt.Fprintf(warnWriter(opts.Warn),
			"warning: referenced CA %q is expired (not_after %s); recording it anyway\n",
			result.Name, result.NotAfter.UTC().Format(time.RFC3339),
		)
	} else if err != nil {
		return nil, err
	}

	report.CAName = result.Name

	next := newManifestFromReference(cfg, opts, report, result)

	signed, err := applyHosts(cfg, opts, p.HostActions(), certPEM, keyPEM, current, next)
	if err != nil {
		return nil, err
	}

	// Rebuild-and-compare: if the candidate manifest would be identical to
	// what is already recorded (ignoring the wall-clock generated_at),
	// carry over the previous generated_at and write nothing.
	if unchanged, prev := referenceManifestUnchanged(current, next); unchanged {
		next.GeneratedAt = prev
		report.Changed = false
		return report, nil
	}

	if err := writeManifest(manifestReal, next); err != nil {
		return nil, err
	}
	report.Changed = true
	report.SignedHosts = signed
	return report, nil
}

// newManifestFromGenerate builds the candidate manifest for generate mode.
// When caResult is nil the CA action was a noop and the CA record is
// copied from current.
func newManifestFromGenerate(cfg *config.Config, opts Options, report *Report, caResult *pki.CAResult, current *manifest.Manifest) *manifest.Manifest {
	m := manifest.New()
	m.GeneratedAt = opts.Now.UTC()
	m.Generator.Version = opts.GeneratorVersion
	m.ConfigPath = manifestRelConfigPath(cfg, cfg.Resolve(cfg.ManifestPath()))
	if caResult != nil {
		m.CA = &manifest.CA{
			Mode:        config.CAModeGenerate.String(),
			Name:        caResult.Name,
			Fingerprint: caResult.Fingerprint,
			Curve:       caResult.Curve,
			Version:     caResult.Version,
			NotBefore:   caResult.NotBefore.UTC(),
			NotAfter:    caResult.NotAfter.UTC(),
			CertPath:    report.CACertPath,
			KeyPath:     report.CAKeyPath,
		}
	} else if current != nil && current.CA != nil {
		m.CA = current.CA
	}
	return m
}

// newManifestFromReference builds the candidate manifest for reference mode.
func newManifestFromReference(cfg *config.Config, opts Options, report *Report, result *pki.CAResult) *manifest.Manifest {
	m := manifest.New()
	m.GeneratedAt = opts.Now.UTC()
	m.Generator.Version = opts.GeneratorVersion
	m.ConfigPath = manifestRelConfigPath(cfg, cfg.Resolve(cfg.ManifestPath()))
	m.CA = &manifest.CA{
		Mode:        config.CAModeReference.String(),
		Name:        result.Name,
		Fingerprint: result.Fingerprint,
		Curve:       result.Curve,
		Version:     result.Version,
		NotBefore:   result.NotBefore.UTC(),
		NotAfter:    result.NotAfter.UTC(),
		CertPath:    report.CACertPath,
		KeyPath:     report.CAKeyPath,
	}
	return m
}

// applyHosts executes host actions: signs hosts with OpSign, carries
// forward existing manifest entries for OpNoop. It writes cert and key
// files for each signed host and populates next.Hosts. Returns the list
// of newly signed hosts (in action order).
func applyHosts(cfg *config.Config, opts Options, hostActions []plan.Action, caCertPEM, caKeyPEM []byte, current *manifest.Manifest, next *manifest.Manifest) ([]SignedHost, error) {
	var signed []SignedHost

	// Build a label→Host lookup for quick access.
	hostByLabel := make(map[string]*config.Host, len(cfg.Hosts))
	for i := range cfg.Hosts {
		hostByLabel[cfg.Hosts[i].Label] = &cfg.Hosts[i]
	}

	for _, ha := range hostActions {
		h := hostByLabel[ha.Label]
		if h == nil {
			return nil, fmt.Errorf("host action references unknown label %q", ha.Label)
		}

		if ha.Op == plan.OpNoop {
			if existing, ok := current.Hosts[h.Label]; ok {
				next.Hosts[h.Label] = existing
			}
			continue
		}

		// OpSign: sign the host cert once, then fan out to all destinations.
		result, err := pki.SignHost(caCertPEM, caKeyPEM, *h, opts.Now)
		if err != nil {
			return nil, err
		}

		artifactPaths := cfg.HostArtifactPaths(*h)
		manifestArtifacts := make([]manifest.Artifact, 0, len(artifactPaths))
		signedArtifacts := make([]SignedArtifact, 0, len(artifactPaths))
		for _, a := range artifactPaths {
			if err := fsutil.WriteFile(cfg.Resolve(a.CertPath), result.CertPEM, certMode); err != nil {
				return nil, fmt.Errorf("write host certificate %q: %w", h.Label, err)
			}
			if err := fsutil.WriteFile(cfg.Resolve(a.KeyPath), result.KeyPEM, keyMode); err != nil {
				return nil, fmt.Errorf("write host key %q: %w", h.Label, err)
			}
			manifestArtifacts = append(manifestArtifacts, manifest.Artifact{
				Dir:      a.Dir,
				CertPath: a.CertPath,
				KeyPath:  a.KeyPath,
			})
			signedArtifacts = append(signedArtifacts, SignedArtifact{
				Dir:      a.Dir,
				CertPath: a.CertPath,
				KeyPath:  a.KeyPath,
			})
		}

		durationStr := ""
		if h.HasDuration {
			durationStr = h.Duration.String()
		}

		next.Hosts[h.Label] = manifest.Host{
			Name:           result.Name,
			Fingerprint:    result.Fingerprint,
			Networks:       prefixesToStrings(h.Networks),
			Groups:         h.Groups,
			UnsafeNetworks: prefixesToStrings(h.UnsafeNetworks),
			Duration:       durationStr,
			NotBefore:      result.NotBefore.UTC(),
			NotAfter:       result.NotAfter.UTC(),
			CAFingerprint:  result.CAFingerprint,
			Artifacts:      manifestArtifacts,
		}

		signed = append(signed, SignedHost{Label: h.Label, Artifacts: signedArtifacts})
	}
	return signed, nil
}

// prefixesToStrings converts a slice of netip.Prefix to their string
// representations for manifest storage.
func prefixesToStrings(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	return out
}

// referenceManifestUnchanged reports whether the candidate manifest is, in
// every committed field except generated_at, identical to the current one.
// When true it also returns the current generated_at so the caller can
// preserve it and keep the on-disk bytes stable. A nil or CA-less current
// manifest (first reference run) is always "changed".
func referenceManifestUnchanged(current, candidate *manifest.Manifest) (bool, time.Time) {
	if current == nil || current.CA == nil {
		return false, time.Time{}
	}
	// Compare by marshalling both with a pinned generated_at, so the only
	// remaining differences are the fields we actually care about. This
	// reuses the canonical JSON encoding rather than enumerating fields,
	// so new manifest fields are covered automatically.
	pinned := current.GeneratedAt
	a := withGeneratedAt(current, pinned)
	b := withGeneratedAt(candidate, pinned)
	ab, err1 := manifest.Marshal(a)
	bb, err2 := manifest.Marshal(b)
	if err1 != nil || err2 != nil {
		return false, time.Time{}
	}
	if !bytes.Equal(ab, bb) {
		return false, time.Time{}
	}
	return true, pinned
}

// withGeneratedAt returns a shallow copy of m with GeneratedAt overridden,
// so comparisons can ignore the wall-clock timestamp without mutating the
// originals.
func withGeneratedAt(m *manifest.Manifest, t time.Time) *manifest.Manifest {
	cp := *m
	cp.GeneratedAt = t
	return &cp
}

// writeManifest marshals and atomically writes the manifest. It is the
// commit record for a run (spec/adr/002, spec/adr/013).
func writeManifest(manifestReal string, m *manifest.Manifest) error {
	data, err := manifest.Marshal(m)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFile(manifestReal, data, manifestMode); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

// warnWriter returns w, or io.Discard when w is nil, so callers can write
// diagnostics unconditionally.
func warnWriter(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
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
