// Package apply is the only component in nebula-pki that mutates the
// filesystem. It loads the current manifest, asks internal/plan what must
// change, and — when something must — generates or loads each CA via
// internal/pki and persists the manifest via internal/fsutil.
//
// Everything upstream of apply (config, pki, manifest, plan) is pure and
// side-effect free. Keeping all writes here makes the dangerous part of
// the tool small and auditable, and makes idempotency a property of plan
// rather than of scattered I/O.
//
// It reconciles each CA in both modes and signs host certificates under
// the appropriate CA. All artifact writes are atomic via fsutil.
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
	// DryRun, when true, builds the plan and writes a preview to Out, then
	// returns without modifying the filesystem (including the manifest).
	DryRun bool
	// Out receives the dry-run plan output when DryRun is true.
	// When nil, dry-run output is discarded.
	Out io.Writer
}

// SignedArtifact is the destination for a signed host's cert/key pair.
type SignedArtifact struct {
	Dir      string
	CertPath string
	KeyPath  string
}

// SignedHost is a brief record of one host that was signed this run.
type SignedHost struct {
	Label     string
	Artifacts []SignedArtifact
}

// CAReport summarises the reconciled state of one CA.
type CAReport struct {
	Label    string
	Mode     string
	Name     string
	CertPath string
	KeyPath  string
}

// DeadlineItem is one entry in the deadline report.
type DeadlineItem struct {
	Kind     string    // "host" or "ca"
	Label    string
	Deadline time.Time // when the operator must act (renewal window entry or expiry)
	Desc     string    // e.g. `host "x" enters renewal window` or `CA "y" expires`
}

// DeadlineReport is the post-run advisory: the earliest date the operator
// must act before, plus supplementary soon/overdue detail. Printed after
// every reconcile and --dry-run, including no-op runs.
type DeadlineReport struct {
	// NextDeadline is the single earliest actionable date. Zero when there
	// are no managed certificates yet.
	NextDeadline time.Time
	// NextDeadlineDesc is a short description of what triggers NextDeadline.
	NextDeadlineDesc string
	// SoonItems are additional items whose deadline falls within the next
	// 60 days (excluding the item that set NextDeadline).
	SoonItems []DeadlineItem
	// OverdueItems are items already past their deadline and not re-signed
	// this run (e.g. a reference-mode CA whose cert has lapsed).
	OverdueItems []DeadlineItem
}

// Report summarises what a reconcile did, for the CLI to present. Paths
// are logical (as recorded in the manifest and written in HCL), not the
// resolved on-disk paths.
type Report struct {
	// Changed reports whether anything was written. False means the tree
	// was already up to date and not a single byte (including the
	// manifest) was touched.
	Changed bool

	// CAs holds one entry per reconciled CA, in config order.
	CAs []CAReport

	ManifestPath string

	// TrustBundlePath is the logical path of the trust bundle. Set after a
	// real reconcile; empty on dry-runs, which return before this field is
	// populated.
	TrustBundlePath string

	// TrustBundleWritten is true when the bundle was written (or rewritten)
	// this run. False on a noop run.
	TrustBundleWritten bool

	// SignedHosts is the set of hosts that were signed this run, in config
	// order. Empty on a noop run.
	SignedHosts []SignedHost

	// StaleArtifacts is the list of logical paths from a previous run that
	// are no longer written by the current configuration — for example, the
	// old cert/key under a directory that was renamed via output_dir. The
	// files are never deleted automatically; the operator must clean them up.
	// Populated only when Changed is true and at least one stale file exists.
	StaleArtifacts []string

	// Deadlines is the post-run "run again before" advisory. Always
	// populated (including on no-op runs and --dry-run), unless the mesh has
	// no managed certificates yet.
	Deadlines DeadlineReport
}

// caPEMs holds the PEM bytes for one CA, used to sign hosts.
type caPEMs struct {
	cert []byte
	key  []byte
}

// Reconcile brings the output tree in line with cfg and returns a Report.
//
// It loads the manifest, builds a plan, executes each CA action in order,
// then signs any hosts that need signing. In every mode an up-to-date tree
// stays byte-identical across runs: nothing — not even the manifest — is
// rewritten when the recorded state already matches (spec/adr/002).
func Reconcile(cfg *config.Config, opts Options) (*Report, error) {
	manifestLogical := cfg.ManifestPath()
	manifestReal := cfg.Resolve(manifestLogical)

	report := &Report{ManifestPath: manifestLogical}

	current, err := manifest.Load(manifestReal)
	if err != nil {
		return nil, err
	}

	exists := func(logical string) bool {
		return fsutil.Exists(cfg.Resolve(logical))
	}

	p, err := plan.Build(cfg, current, opts.Now, exists)
	if err != nil {
		return nil, err
	}

	if opts.DryRun {
		writeDryRunPlan(coalesceWriter(opts.Out), cfg, p, exists)
		report.Deadlines = computeDeadlines(cfg, current, opts.Now)
		return report, nil
	}

	// Collect CA PEM bytes while executing CA actions. Reference CAs must
	// always be processed so their fingerprint can be compared to what is
	// already in the manifest — generate-mode CAs that are up-to-date are
	// read from disk.
	caKeys := make(map[string]caPEMs, len(cfg.CAs))
	next := newManifest(cfg, opts)

	hasAnyChange := false
	for _, caAction := range p.CAActions() {
		ca := cfg.CAByLabel(caAction.Label)
		result, pems, err := reconcileOneCA(cfg, ca, caAction, opts, current, next)
		if err != nil {
			return nil, err
		}
		caKeys[ca.Label] = pems
		if caAction.Op != plan.OpNoop {
			hasAnyChange = true
			report.CAs = append(report.CAs, CAReport{
				Label:    ca.Label,
				Mode:     ca.Mode.String(),
				Name:     result.Name,
				CertPath: cfg.CACertPathForCA(*ca),
				KeyPath:  cfg.CAKeyPathForCA(*ca),
			})
		}
	}

	signed, stale, err := applyHosts(cfg, opts, p.HostActions(), caKeys, current, next)
	if err != nil {
		return nil, err
	}
	if len(signed) > 0 {
		hasAnyChange = true
	}

	bundleWritten, err := reconcileTrustBundle(cfg, caKeys, current, next, exists)
	if err != nil {
		return nil, err
	}
	if bundleWritten {
		hasAnyChange = true
	}
	report.TrustBundlePath = cfg.TrustBundlePath()
	report.TrustBundleWritten = bundleWritten

	// Compute deadline advisory from the candidate manifest (already fully
	// populated at this point). This covers no-op runs too: the candidate
	// equals the current manifest in that case, so the report still reflects
	// the current state of the mesh.
	report.Deadlines = computeDeadlines(cfg, next, opts.Now)

	// For all-generate configs without any changes: skip the manifest write.
	// For configs with reference CAs: always compare, since plan cannot
	// check fingerprints.
	if !hasAnyChange && !hasReferenceCA(cfg) {
		return report, nil
	}

	// Rebuild-and-compare: if the candidate manifest is identical to what
	// is already recorded (ignoring generated_at), skip the write so the
	// on-disk bytes stay stable.
	if unchanged, prev := manifestUnchanged(current, next); unchanged {
		next.GeneratedAt = prev
		return report, nil
	}

	if err := writeManifest(manifestReal, next); err != nil {
		return nil, err
	}
	report.Changed = true
	report.SignedHosts = signed
	report.StaleArtifacts = stale
	return report, nil
}

// hasReferenceCA reports whether cfg contains at least one reference-mode CA.
func hasReferenceCA(cfg *config.Config) bool {
	for i := range cfg.CAs {
		if cfg.CAs[i].Mode == config.CAModeReference {
			return true
		}
	}
	return false
}

// reconcileOneCA executes one CA action and returns the CA metadata plus
// the PEM bytes needed to sign hosts. It also populates next.CAs for the
// given CA label.
func reconcileOneCA(cfg *config.Config, ca *config.CA, caAction plan.Action, opts Options, current *manifest.Manifest, next *manifest.Manifest) (*pki.CAResult, caPEMs, error) {
	certPath := cfg.CACertPathForCA(*ca)
	keyPath := cfg.CAKeyPathForCA(*ca)

	switch caAction.Op {
	case plan.OpGenerate:
		result, err := pki.GenerateCA(*ca, opts.Now)
		if err != nil {
			return nil, caPEMs{}, err
		}
		if err := fsutil.WriteFile(cfg.Resolve(certPath), result.CertPEM, certMode); err != nil {
			return nil, caPEMs{}, fmt.Errorf("write CA %q certificate: %w", ca.Label, err)
		}
		if err := fsutil.WriteFile(cfg.Resolve(keyPath), result.KeyPEM, keyMode); err != nil {
			return nil, caPEMs{}, fmt.Errorf("write CA %q key: %w", ca.Label, err)
		}
		next.CAs[ca.Label] = caResultToManifest(ca, result, certPath, keyPath)
		return result, caPEMs{cert: result.CertPEM, key: result.KeyPEM}, nil

	case plan.OpNoop:
		// CA is up to date; read from disk so we can sign hosts.
		certPEM, err := os.ReadFile(cfg.Resolve(certPath))
		if err != nil {
			return nil, caPEMs{}, fmt.Errorf("read CA %q certificate: %w", ca.Label, err)
		}
		keyPEM, err := os.ReadFile(cfg.Resolve(keyPath))
		if err != nil {
			return nil, caPEMs{}, fmt.Errorf("read CA %q key: %w", ca.Label, err)
		}
		// Carry the existing manifest entry forward, but always reflect the
		// current config's Archived and Default flags — these can change
		// (e.g. during rotation) without triggering a CA re-generation.
		if rec := current.CAs[ca.Label]; rec != nil {
			updated := *rec
			updated.Default = ca.Default
			updated.Archived = ca.Archived
			next.CAs[ca.Label] = &updated
		}
		// We need the result for the report's Name field; parse it minimally.
		result, err := pki.LoadReferenceCA(certPEM, keyPEM, opts.Now)
		if err != nil && !errors.Is(err, pki.ErrReferenceCAExpired) {
			return nil, caPEMs{}, fmt.Errorf("read CA %q for host signing: %w", ca.Label, err)
		}
		return result, caPEMs{cert: certPEM, key: keyPEM}, nil

	case plan.OpReference:
		certPEM, err := os.ReadFile(cfg.Resolve(certPath))
		if err != nil {
			return nil, caPEMs{}, fmt.Errorf("read referenced CA %q certificate: %w", ca.Label, err)
		}
		keyPEM, err := os.ReadFile(cfg.Resolve(keyPath))
		if err != nil {
			return nil, caPEMs{}, fmt.Errorf("read referenced CA %q key: %w", ca.Label, err)
		}
		result, err := pki.LoadReferenceCA(certPEM, keyPEM, opts.Now)
		if errors.Is(err, pki.ErrReferenceCAExpired) {
			fmt.Fprintf(coalesceWriter(opts.Warn),
				"warning: referenced CA %q is expired (not_after %s); recording it anyway\n",
				ca.Label, result.NotAfter.UTC().Format(time.RFC3339),
			)
		} else if err != nil {
			return nil, caPEMs{}, err
		}
		next.CAs[ca.Label] = caResultToManifest(ca, result, certPath, keyPath)
		return result, caPEMs{cert: certPEM, key: keyPEM}, nil

	default:
		return nil, caPEMs{}, fmt.Errorf("ca %q: unexpected plan op %q", ca.Label, caAction.Op)
	}
}

func caResultToManifest(ca *config.CA, result *pki.CAResult, certPath, keyPath string) *manifest.CA {
	return &manifest.CA{
		Mode:        ca.Mode.String(),
		Name:        result.Name,
		Fingerprint: result.Fingerprint,
		Curve:       result.Curve,
		Version:     result.Version,
		NotBefore:   result.NotBefore.UTC(),
		NotAfter:    result.NotAfter.UTC(),
		CertPath:    certPath,
		KeyPath:     keyPath,
		Default:     ca.Default,
		Archived:    ca.Archived,
	}
}

// applyHosts executes host actions: signs hosts with OpSign, carries
// forward existing manifest entries for OpNoop. It writes cert and key
// files for each signed host and populates next.Hosts. Returns the list
// of newly signed hosts (in action order) and any logical paths from a
// previous run that are no longer written by the current configuration.
func applyHosts(cfg *config.Config, opts Options, hostActions []plan.Action, caKeys map[string]caPEMs, current *manifest.Manifest, next *manifest.Manifest) ([]SignedHost, []string, error) {
	var signed []SignedHost
	var stale []string

	hostByLabel := make(map[string]*config.Host, len(cfg.Hosts))
	for i := range cfg.Hosts {
		hostByLabel[cfg.Hosts[i].Label] = &cfg.Hosts[i]
	}

	for _, ha := range hostActions {
		h := hostByLabel[ha.Label]
		if h == nil {
			return nil, nil, fmt.Errorf("host action references unknown label %q", ha.Label)
		}

		if ha.Op == plan.OpNoop {
			if existing, ok := current.Hosts[h.Label]; ok {
				next.Hosts[h.Label] = existing
			}
			continue
		}

		// OpSign: check for stale artifact paths before re-signing.
		newArt := cfg.HostArtifactPath(*h)
		if prev, ok := current.Hosts[h.Label]; ok {
			for _, oldArt := range prev.Artifacts {
				if oldArt.CertPath != "" && oldArt.CertPath != newArt.CertPath {
					if fsutil.Exists(cfg.Resolve(oldArt.CertPath)) {
						stale = append(stale, oldArt.CertPath)
					}
				}
				if oldArt.KeyPath != "" && oldArt.KeyPath != newArt.KeyPath {
					if fsutil.Exists(cfg.Resolve(oldArt.KeyPath)) {
						stale = append(stale, oldArt.KeyPath)
					}
				}
			}
		}

		signingCA := cfg.SigningCA(*h)
		if signingCA == nil {
			return nil, nil, fmt.Errorf("host %q: cannot determine signing CA (should have been caught in validation)", h.Label)
		}
		pems, ok := caKeys[signingCA.Label]
		if !ok {
			return nil, nil, fmt.Errorf("host %q: signing CA %q PEM not available", h.Label, signingCA.Label)
		}

		result, err := pki.SignHost(pems.cert, pems.key, *h, opts.Now)
		if err != nil {
			return nil, nil, err
		}

		if err := fsutil.WriteFile(cfg.Resolve(newArt.CertPath), result.CertPEM, certMode); err != nil {
			return nil, nil, fmt.Errorf("write host certificate %q: %w", h.Label, err)
		}
		if err := fsutil.WriteFile(cfg.Resolve(newArt.KeyPath), result.KeyPEM, keyMode); err != nil {
			return nil, nil, fmt.Errorf("write host key %q: %w", h.Label, err)
		}

		durationStr := ""
		if h.HasDuration {
			durationStr = h.Duration.String()
		}

		renewBeforeStr := ""
		if rb := cfg.ResolvedRenewBefore(*h); rb > 0 {
			renewBeforeStr = rb.String()
		}

		next.Hosts[h.Label] = manifest.Host{
			CA:             signingCA.Label,
			Name:           result.Name,
			Fingerprint:    result.Fingerprint,
			Networks:       prefixesToStrings(h.Networks),
			Groups:         h.Groups,
			UnsafeNetworks: prefixesToStrings(h.UnsafeNetworks),
			Duration:       durationStr,
			RenewBefore:    renewBeforeStr,
			NotBefore:      result.NotBefore.UTC(),
			NotAfter:       result.NotAfter.UTC(),
			CAFingerprint:  result.CAFingerprint,
			Artifacts: []manifest.Artifact{{
				Dir:      newArt.Dir,
				CertPath: newArt.CertPath,
				KeyPath:  newArt.KeyPath,
			}},
		}

		signed = append(signed, SignedHost{
			Label: h.Label,
			Artifacts: []SignedArtifact{{
				Dir:      newArt.Dir,
				CertPath: newArt.CertPath,
				KeyPath:  newArt.KeyPath,
			}},
		})
	}
	return signed, stale, nil
}

// reconcileTrustBundle builds the concatenated-PEM trust bundle from every
// active (non-archived) CA in declaration order. It populates next.TrustBundle
// and writes the bundle file when the content has changed. Returns true when
// the file was written.
func reconcileTrustBundle(cfg *config.Config, caKeys map[string]caPEMs, current, next *manifest.Manifest, exists func(string) bool) (bool, error) {
	bundlePath := cfg.TrustBundlePath()

	var bundle []byte
	fps := make([]string, 0, len(cfg.CAs))
	for i := range cfg.CAs {
		ca := &cfg.CAs[i]
		if ca.Archived {
			continue // archived CAs are excluded from the trust bundle (ADR-016)
		}
		bundle = append(bundle, caKeys[ca.Label].cert...)
		if rec := next.CAs[ca.Label]; rec != nil {
			fps = append(fps, rec.Fingerprint)
		}
	}

	next.TrustBundle = &manifest.TrustBundle{
		Path:           bundlePath,
		CAFingerprints: fps,
	}

	// Idempotency: skip the write when the bundle file already exists and
	// the manifest records the same set of CA fingerprints in the same order.
	if current.TrustBundle != nil && exists(bundlePath) {
		if fingerprintsEqual(current.TrustBundle.CAFingerprints, fps) {
			return false, nil
		}
	}

	if err := fsutil.WriteFile(cfg.Resolve(bundlePath), bundle, certMode); err != nil {
		return false, fmt.Errorf("write trust bundle: %w", err)
	}
	return true, nil
}

// fingerprintsEqual reports whether two fingerprint slices are equal.
func fingerprintsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

// newManifest builds an empty candidate manifest with the metadata fields
// filled in. CA and host records are populated by reconcileOneCA /
// applyHosts.
func newManifest(cfg *config.Config, opts Options) *manifest.Manifest {
	m := manifest.New()
	m.GeneratedAt = opts.Now.UTC()
	m.Generator.Version = opts.GeneratorVersion
	m.ConfigPath = manifestRelConfigPath(cfg, cfg.Resolve(cfg.ManifestPath()))
	return m
}

// manifestUnchanged reports whether the candidate manifest is, in every
// committed field except generated_at, identical to the current one. When
// true it also returns the current generated_at so the caller can preserve
// it and keep the on-disk bytes stable.
func manifestUnchanged(current, candidate *manifest.Manifest) (bool, time.Time) {
	if current == nil || len(current.CAs) == 0 {
		return false, time.Time{}
	}
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

// withGeneratedAt returns a shallow copy of m with GeneratedAt overridden.
func withGeneratedAt(m *manifest.Manifest, t time.Time) *manifest.Manifest {
	cp := *m
	cp.GeneratedAt = t
	return &cp
}

// writeManifest marshals and atomically writes the manifest.
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

// writeDryRunPlan writes a human-readable preview of what a real reconcile
// would write. Each file is prefixed with "+ write ". When the plan has no
// mutations (all noops), it prints "up to date; nothing to do".
func writeDryRunPlan(w io.Writer, cfg *config.Config, p plan.Plan, exists func(string) bool) {
	var writes []string

	anyCAGenerate := false
	for _, caAction := range p.CAActions() {
		if caAction.Op == plan.OpGenerate {
			anyCAGenerate = true
			ca := cfg.CAByLabel(caAction.Label)
			if ca != nil {
				writes = append(writes, cfg.CACertPathForCA(*ca), cfg.CAKeyPathForCA(*ca))
			}
		}
	}

	hostByLabel := make(map[string]*config.Host, len(cfg.Hosts))
	for i := range cfg.Hosts {
		hostByLabel[cfg.Hosts[i].Label] = &cfg.Hosts[i]
	}
	for _, ha := range p.HostActions() {
		if ha.Op == plan.OpSign {
			if h, ok := hostByLabel[ha.Label]; ok {
				art := cfg.HostArtifactPath(*h)
				writes = append(writes, art.CertPath, art.KeyPath)
			}
		}
	}

	// Include the trust bundle in the preview when it would be written: any
	// new CA is being generated (new fingerprint), or the bundle file is absent.
	if anyCAGenerate || !exists(cfg.TrustBundlePath()) {
		writes = append(writes, cfg.TrustBundlePath())
	}

	if len(writes) == 0 {
		fmt.Fprintln(w, "up to date; nothing to do")
		return
	}

	for _, path := range writes {
		fmt.Fprintf(w, "+ write %s\n", path)
	}
	fmt.Fprintf(w, "+ write %s\n", cfg.ManifestPath())
}

// deadlineSoonWindow is the look-ahead window for the "also expiring soon"
// section of the deadline report.
const deadlineSoonWindow = 60 * 24 * time.Hour

// computeDeadlines inspects m for every host and non-archived CA, then
// returns the earliest actionable deadline plus supplementary detail.
//
// For a host with renew_before: deadline = not_after − renew_before (the
// moment the host enters its renewal window). For a host without renew_before,
// and for all CAs: deadline = not_after (expiry itself).
//
// The config is used to resolve the current renew_before value (which may
// differ from what was recorded in the manifest when renew_before changed
// between runs without triggering a re-sign).
func computeDeadlines(cfg *config.Config, m *manifest.Manifest, now time.Time) DeadlineReport {
	var rep DeadlineReport

	updateEarliest := func(deadline time.Time, desc string) {
		if rep.NextDeadline.IsZero() || deadline.Before(rep.NextDeadline) {
			rep.NextDeadline = deadline
			rep.NextDeadlineDesc = desc
		}
	}

	// Hosts — iterate in config order for deterministic output.
	for i := range cfg.Hosts {
		h := &cfg.Hosts[i]
		mh, ok := m.Hosts[h.Label]
		if !ok || mh.NotAfter.IsZero() {
			continue
		}
		rb := cfg.ResolvedRenewBefore(*h)
		var deadline time.Time
		var desc string
		if rb > 0 {
			deadline = mh.NotAfter.Add(-rb)
			desc = fmt.Sprintf("host %q enters renewal window", h.Label)
		} else {
			deadline = mh.NotAfter
			desc = fmt.Sprintf("host %q expires", h.Label)
		}

		if !now.Before(deadline) {
			rep.OverdueItems = append(rep.OverdueItems, DeadlineItem{Kind: "host", Label: h.Label, Deadline: deadline, Desc: desc})
		} else if deadline.Before(now.Add(deadlineSoonWindow)) {
			rep.SoonItems = append(rep.SoonItems, DeadlineItem{Kind: "host", Label: h.Label, Deadline: deadline, Desc: desc})
		}
		updateEarliest(deadline, desc)
	}

	// CAs — non-archived only; use config CA order for determinism.
	for i := range cfg.CAs {
		ca := &cfg.CAs[i]
		if ca.Archived {
			continue
		}
		rec, ok := m.CAs[ca.Label]
		if !ok || rec == nil || rec.NotAfter.IsZero() {
			continue
		}
		deadline := rec.NotAfter
		desc := fmt.Sprintf("CA %q expires", ca.Label)

		if !now.Before(deadline) {
			rep.OverdueItems = append(rep.OverdueItems, DeadlineItem{Kind: "ca", Label: ca.Label, Deadline: deadline, Desc: desc})
		} else if deadline.Before(now.Add(deadlineSoonWindow)) {
			rep.SoonItems = append(rep.SoonItems, DeadlineItem{Kind: "ca", Label: ca.Label, Deadline: deadline, Desc: desc})
		}
		updateEarliest(deadline, desc)
	}

	return rep
}

// coalesceWriter returns w, or io.Discard when w is nil.
func coalesceWriter(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// manifestRelConfigPath computes the manifest's config_path field.
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
