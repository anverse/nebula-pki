// Package plan turns the desired configuration plus the current manifest
// and on-disk state into a list of actions. It is the only place that
// decides what should change; it performs no I/O of its own (callers
// supply an existence probe) and never mutates anything.
//
// It plans one action per CA (generate or reference) and one action per
// cert (sign or noop). Cert actions always follow all CA actions. Link,
// trust bundle, and release actions follow the certs.
package plan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/manifest"
)

// Op is what a reconcile action does.
type Op string

const (
	// OpNoop means the target is already up to date.
	OpNoop Op = "noop"
	// OpGenerate means an artifact must be created.
	OpGenerate Op = "generate"
	// OpReference means an operator-supplied CA must be read and recorded
	// (reference mode). It never writes the CA files themselves; apply
	// reads them in place and records their metadata in the manifest.
	OpReference Op = "reference"
	// OpSign means a certificate must be signed and written.
	OpSign Op = "sign"
	// OpCreateSymlink means a symlink must be created (or recreated with the
	// correct target). Used for link_crt entries (ADR-021).
	OpCreateSymlink Op = "create_symlink"
	// OpDeleteSymlink means a managed symlink must be removed because its
	// directory was removed from link_crt. Used for link_crt stale cleanup.
	OpDeleteSymlink Op = "delete_symlink"
	// OpForgetLink means a recorded symlink now belongs to another block
	// that declares the same path. The symlink is left alone; only the old
	// owner's manifest record drops it.
	OpForgetLink Op = "forget_link"
	// OpWrite means a trust bundle file must be (re)written.
	OpWrite Op = "write"
	// OpRelease means files the manifest tracked are no longer managed by
	// the config. They stay on disk; only the manifest record is dropped
	// and a notice is printed (ADR-021, ADR-026).
	OpRelease Op = "release"
)

// Kind is the artifact an action concerns.
type Kind string

const (
	// KindCA is the certificate authority.
	KindCA Kind = "ca"
	// KindCert is a certificate.
	KindCert Kind = "cert"
	// KindLink is a link_crt symlink.
	KindLink Kind = "link"
	// KindTrustBundle is the trust bundle file.
	KindTrustBundle Kind = "trust_bundle"
	// KindRelease is a set of files the config no longer manages (OpRelease).
	KindRelease Kind = "release"
)

// Action is a single planned operation.
type Action struct {
	Op   Op
	Kind Kind
	// Label is the config label for the artifact (CA label for KindCA,
	// cert label for KindCert, the owning block's label for KindLink and
	// for a release, the trust_bundle label for KindTrustBundle).
	Label string
	// Owner is the kind of block that owns a KindLink action (KindCA or
	// KindTrustBundle), so a CA and a trust bundle with the same label never
	// share links. For OpRelease it is the kind of the released block.
	Owner Kind
	// Path is the primary logical artifact path, for display. Empty for
	// no-ops.
	Path string
	// Desc is a human-readable one-line summary.
	Desc string
	// EncryptKey is true when the active storage encryption backend should
	// encrypt the private key artifact for this action. Always false for
	// in_pub certs (no key is written) and for reference-mode CAs (the tool
	// never writes reference CA files).
	EncryptKey bool
	// LinkTarget is the relative symlink target string computed via
	// filepath.Rel. Set for OpCreateSymlink and OpNoop on KindLink actions.
	LinkTarget string
	// LinkDir is the logical directory path for the symlink. Set for
	// OpCreateSymlink (apply calls os.MkdirAll on cfg.Resolve(LinkDir)).
	LinkDir string
	// Paths lists the logical files an OpRelease action stops managing.
	Paths []string
}

// Plan is the ordered set of actions a reconcile would perform.
// CA actions appear before cert actions.
type Plan struct {
	Actions []Action
}

// Changes reports whether the plan would mutate anything. A plan with
// only no-ops returns false, which the apply layer uses to skip all
// writes (including the manifest) so an up-to-date tree stays
// byte-identical.
func (p Plan) Changes() bool {
	for _, a := range p.Actions {
		if a.Op != OpNoop {
			return true
		}
	}
	return false
}

// CAActions returns all CA actions from the plan, in config order.
func (p Plan) CAActions() []Action {
	var cas []Action
	for _, a := range p.Actions {
		if a.Kind == KindCA {
			cas = append(cas, a)
		}
	}
	return cas
}

// CertActions returns all cert actions from the plan, in config order.
func (p Plan) CertActions() []Action {
	var certs []Action
	for _, a := range p.Actions {
		if a.Kind == KindCert {
			certs = append(certs, a)
		}
	}
	return certs
}

// TrustBundleActions returns one action per declared trust_bundle block, in
// config order.
func (p Plan) TrustBundleActions() []Action {
	var tbs []Action
	for _, a := range p.Actions {
		if a.Kind == KindTrustBundle {
			tbs = append(tbs, a)
		}
	}
	return tbs
}

// ReleaseActions returns the actions for artifacts that are no longer
// managed: removed ca blocks and a removed or moved trust bundle.
func (p Plan) ReleaseActions() []Action {
	var rel []Action
	for _, a := range p.Actions {
		if a.Op == OpRelease {
			rel = append(rel, a)
		}
	}
	return rel
}

// LinkActions returns all link_crt symlink actions from the plan.
func (p Plan) LinkActions() []Action {
	var links []Action
	for _, a := range p.Actions {
		if a.Kind == KindLink {
			links = append(links, a)
		}
	}
	return links
}

// Options configures how Build constructs the reconcile plan.
type Options struct {
	// NoRenewal, when true, skips the certInRenewalWindow check for every
	// cert. A cert that is within its renew_before window is treated
	// as up-to-date for this run. All other re-sign triggers (new cert,
	// missing artifact, CA label mismatch) are unaffected.
	// The zero value (false) preserves the existing behaviour.
	NoRenewal bool

	// Lstat returns the mode bits for the absolute filesystem path.
	// Returns (0, fs.ErrNotExist) when the path does not exist; (0, err)
	// for other I/O errors. Used by planLinks to inspect symlink state.
	// When nil, all link_crt paths are treated as absent.
	Lstat func(realPath string) (os.FileMode, error)

	// Readlink returns the stored target string for a symlink. Only called
	// when Lstat reports os.ModeSymlink set on the same path.
	Readlink func(realPath string) (string, error)

	// Fingerprint returns the fingerprint of the certificate at the absolute
	// filesystem path. Used read-only to check that a reference-mode CA is
	// still the CA the manifest recorded under its label. When nil, the check
	// is skipped.
	Fingerprint func(realPath string) (string, error)
}

// Build computes the reconcile plan for cfg given the current manifest m,
// the current wall-clock time now (used for renewal-window checks), and an
// exists probe that reports whether a logical artifact path is present on
// disk. The caller is responsible for resolving logical paths to real ones
// inside exists.
func Build(cfg *config.Config, m *manifest.Manifest, now time.Time, exists func(logicalPath string) bool, opts Options) (Plan, error) {
	var actions []Action

	for i := range cfg.CAs {
		ca := &cfg.CAs[i]
		var a Action
		var err error
		if ca.Mode == config.CAModeReference {
			a, err = planReferenceCA(cfg, ca, m, exists, opts)
		} else {
			a, err = planCA(cfg, ca, m, exists, opts)
		}
		if err != nil {
			return Plan{}, err
		}
		actions = append(actions, a)
	}

	for i := range cfg.Certs {
		ha := planCert(cfg, m, &cfg.Certs[i], now, exists, opts.NoRenewal)
		actions = append(actions, ha)
	}

	// Stale links are removed before any link is created: a link renamed only
	// in case is one file on a case-insensitive filesystem, so deleting the
	// old spelling afterwards would remove the new link.
	srcs := linkSources(cfg, m)
	declared := declaredLinkPaths(srcs)
	removed := removedLinkPaths(srcs, declared)
	var removals, links []Action
	for _, src := range srcs {
		r, l, err := planLinks(cfg, src, declared, removed, opts)
		if err != nil {
			return Plan{}, err
		}
		removals = append(removals, r...)
		links = append(links, l...)
	}
	actions = append(actions, removals...)
	actions = append(actions, links...)

	actions = append(actions, planTrustBundles(cfg, m, actions, exists)...)
	actions = append(actions, planReleases(cfg, m, exists)...)

	return Plan{Actions: actions}, nil
}

// certInRenewalWindow reports whether a cert is within its renew_before
// window as of now: true when now >= not_after - renewBefore. Returns false
// when renewBefore is zero (no time-based renewal configured).
func certInRenewalWindow(renewBefore time.Duration, notAfter, now time.Time) bool {
	if renewBefore <= 0 {
		return false
	}
	return !now.Before(notAfter.Add(-renewBefore))
}

// planCert decides the action for a single cert. Certs are not as
// precious as CAs (they can always be re-signed), so partial pairs and
// untracked files are resolved by re-signing rather than erroring.
//
// A cert is a noop when ALL of the following hold (ADR-002 + ADR-017 + ADR-018):
//  1. tracked in manifest
//  2. signing CA label matches the manifest record
//  3. provenance matches: both config and manifest agree on in_pub vs regular
//  4. cert artifact is present on disk
//  5. key artifact is present on disk (skipped for in_pub certs; no key is written)
//  6. the cert is NOT within its renew_before window, OR noRenewal is true
//
// Any failing condition → sign.
//
// Note on in_pub idempotency (ADR-018): if the content of the in_pub file
// changes at the same path (same filename, different key bytes), this check
// does NOT detect it; only cert presence and provenance are compared. For
// hardware-bound keys this is correct (key never changes). For other cases
// the operator must delete the cert file to force a re-sign.
func planCert(cfg *config.Config, m *manifest.Manifest, h *config.Cert, now time.Time, exists func(string) bool, noRenewal bool) Action {
	artifact := cfg.CertArtifactPath(*h)
	signingCA := cfg.SigningCA(*h)

	isInPub := h.InPub != ""

	tracked := m != nil && m.Certs[h.Label].Name != ""
	caMatch := tracked && signingCA != nil && m.Certs[h.Label].CA == signingCA.Label
	// Provenance must match: a cert switching between regular signing and
	// in_pub (or back) must be re-signed so the cert reflects the correct
	// public key source and the manifest records the right shape.
	provenanceMatch := tracked && m.Certs[h.Label].InPub == isInPub

	// in_pub certs never write a key file; encryption does not apply to them.
	suffix := ""
	if !isInPub {
		suffix = cfg.Storage.Encryption.KeySuffix()
	}
	encKeyPath := artifact.KeyPath + suffix // equals artifact.KeyPath when suffix is ""

	certOK := exists(artifact.CertPath)
	// in_pub certs never write a key file; skip the key-existence check for them.
	keyOK := isInPub || exists(encKeyPath)

	encryptKey := !isInPub && !cfg.Storage.Encryption.IsNone()

	if tracked && caMatch && provenanceMatch && certOK && keyOK {
		rb := cfg.ResolvedRenewBefore(*h)
		mh := m.Certs[h.Label]
		if noRenewal || !certInRenewalWindow(rb, mh.NotAfter, now) {
			return Action{Op: OpNoop, Kind: KindCert, Label: h.Label, EncryptKey: encryptKey, Desc: fmt.Sprintf("cert %q up to date", h.Label)}
		}
		// Inside renewal window and renewal is not suppressed; fall through to sign.
	}
	return Action{
		Op:         OpSign,
		Kind:       KindCert,
		Label:      h.Label,
		Path:       artifact.CertPath,
		Desc:       fmt.Sprintf("sign cert %q", h.Label),
		EncryptKey: encryptKey,
	}
}

// planReferenceCA decides the action for an operator-supplied existing CA.
// The tool never writes the reference files, so the rules are simpler than
// generate mode:
//
//   - either file missing -> error (the operator named a path that is not
//     there; fail loudly rather than silently ignoring it);
//   - both files present -> reference;
//   - the certificate's fingerprint differs from the one the manifest
//     recorded under this label -> error. A different CA under the same
//     label would leave the certs it signed, and the trust bundles, out of
//     step without notice; switching CAs takes a new label. Moving the same
//     CA to another path keeps its fingerprint and is fine.
//
// plan is pure and cannot read the certificate, so it always emits a
// reference action when the files are present and defers the real
// idempotency decision to apply. apply reads the CA, rebuilds the
// candidate manifest, and writes only when it differs from what is already
// recorded; so a reference run whose inputs are unchanged still produces
// a byte-identical tree, while a swapped reference file is detected via
// its changed fingerprint. Keeping plan pure (no cert parsing) is the
// reason the OpReference action is not collapsed to a noop here.
func planReferenceCA(cfg *config.Config, ca *config.CA, m *manifest.Manifest, exists func(string) bool, opts Options) (Action, error) {
	certPath := cfg.CACertPathForCA(*ca)
	keyPath := cfg.CAKeyPathForCA(*ca)
	haveCert := exists(certPath)
	haveKey := exists(keyPath)

	if !haveCert || !haveKey {
		return Action{}, referenceMissingError(ca.Label, haveCert, haveKey, certPath, keyPath)
	}

	if err := checkRecordedFingerprint(cfg, ca, recordedCA(m, ca.Label), "cert_file "+certPath, opts, "referenced CA changed"); err != nil {
		return Action{}, err
	}

	return Action{
		Op:    OpReference,
		Kind:  KindCA,
		Label: ca.Label,
		Path:  certPath,
		Desc:  fmt.Sprintf("use referenced CA %q (%s)", ca.Label, certPath),
	}, nil
}

// newLabelHint ends the errors for a CA that changed under its label.
const newLabelHint = "declare the new CA under a new label (move default = true and update ca_refs) to switch to it"

// checkRecordedFingerprint compares the certificate at certPath with the
// fingerprint rec records for ca's label (ADR-027). what names the file in
// the error and problem leads it. Without a recorded fingerprint or a
// Fingerprint probe there is nothing to compare.
func checkRecordedFingerprint(cfg *config.Config, ca *config.CA, rec *manifest.CA, what string, opts Options, problem string) error {
	if rec == nil || rec.Fingerprint == "" || opts.Fingerprint == nil {
		return nil
	}
	fp, err := opts.Fingerprint(cfg.Resolve(cfg.CACertPathForCA(*ca)))
	if err != nil {
		return fmt.Errorf("ca %q: read %s: %w", ca.Label, what, err)
	}
	if fp != rec.Fingerprint {
		return fmt.Errorf("ca %q: %s: %s has fingerprint %s, but the manifest records %s for this label; restore the recorded CA, or %s",
			ca.Label, problem, what, fp, rec.Fingerprint, newLabelHint)
	}
	return nil
}

// recordedCA returns the manifest record for label, or nil.
func recordedCA(m *manifest.Manifest, label string) *manifest.CA {
	if m == nil {
		return nil
	}
	return m.CAs[label]
}

func referenceMissingError(label string, haveCert, haveKey bool, certPath, keyPath string) error {
	switch {
	case !haveCert && !haveKey:
		return fmt.Errorf(
			"ca %q: referenced CA not found: neither cert_file %s nor key_file %s exists",
			label, certPath, keyPath,
		)
	case !haveCert:
		return fmt.Errorf("ca %q: referenced CA cert_file %s does not exist", label, certPath)
	default:
		return fmt.Errorf("ca %q: referenced CA key_file %s does not exist", label, keyPath)
	}
}

// planCA decides the CA action for a generate-mode CA. The rule
// (spec/adr/002 idempotency, and the "noop, never auto-overwrite"
// decision):
//
//   - tracked in the manifest AND both files present  -> noop
//   - untracked AND neither file present              -> generate
//   - anything else (files present but untracked, or
//     only one of the pair present)                   -> error
//
// A CA is pinned to its label (ADR-027): certs re-sign only when their
// signing CA label changes, so a different CA under a tracked label would
// leave them and the trust bundles out of step. Hence a tracked CA whose
// files are both gone is an error, not a fresh generate, and a tracked CA
// whose certificate fingerprint differs from the recorded one is an error.
// Switching CAs takes a new label.
//
// The key file path used for existence checks includes the active
// encryption suffix (e.g. ".enc") so that idempotency works correctly
// after the first encrypted write.
//
// The tool never silently overwrites an existing CA, matching upstream
// nebula-cert's refuse-to-overwrite behaviour.
func planCA(cfg *config.Config, ca *config.CA, m *manifest.Manifest, exists func(string) bool, opts Options) (Action, error) {
	certPath := cfg.CACertPathForCA(*ca)
	keyPath := cfg.CAKeyPathForCA(*ca)
	suffix := cfg.Storage.Encryption.KeySuffix()
	encKeyPath := keyPath + suffix // equals keyPath when suffix is ""

	haveCert := exists(certPath)
	haveKey := exists(encKeyPath)
	tracked := m != nil && m.CAs[ca.Label] != nil
	encryptKey := !cfg.Storage.Encryption.IsNone()

	switch {
	case tracked && haveCert && haveKey:
		if err := checkRecordedFingerprint(cfg, ca, m.CAs[ca.Label], certPath, opts, "CA certificate changed"); err != nil {
			return Action{}, err
		}
		return Action{Op: OpNoop, Kind: KindCA, Label: ca.Label, EncryptKey: encryptKey, Desc: fmt.Sprintf("CA %q up to date", ca.Label)}, nil
	case tracked && !haveCert && !haveKey:
		return Action{}, fmt.Errorf(
			"ca %q: CA files missing: neither %s nor %s exists, but the manifest records CA %s for this label; restore them, or %s",
			ca.Label, certPath, encKeyPath, m.CAs[ca.Label].Fingerprint, newLabelHint,
		)
	case !haveCert && !haveKey:
		return Action{
			Op:         OpGenerate,
			Kind:       KindCA,
			Label:      ca.Label,
			Path:       certPath,
			Desc:       fmt.Sprintf("generate CA %q (%s)", ca.Label, ca.Name),
			EncryptKey: encryptKey,
		}, nil
	case tracked && haveCert && !haveKey:
		// Before emitting a generic caStateError, check whether the key exists
		// at the manifest-recorded path. If it does, the encryption config changed
		// between runs (e.g. sops enabled/disabled or output_suffix renamed) rather
		// than the key being genuinely missing.
		if rec := m.CAs[ca.Label]; rec != nil && rec.KeyPath != "" && !cfg.SamePath(rec.KeyPath, encKeyPath) && exists(rec.KeyPath) {
			return Action{}, fmt.Errorf(
				"ca %q: encryption configuration changed: CA key exists at %s "+
					"(recorded in manifest) but current config expects it at %s; "+
					"use `nebula-pki rekey` to migrate between encryption configs, "+
					"or manually move/rename the key file to the expected path",
				ca.Label, rec.KeyPath, encKeyPath,
			)
		}
		return Action{}, caStateError(ca.Label, tracked, haveCert, haveKey, certPath, encKeyPath)
	default:
		return Action{}, caStateError(ca.Label, tracked, haveCert, haveKey, certPath, encKeyPath)
	}
}

func caStateError(label string, tracked, haveCert, haveKey bool, certPath, keyPath string) error {
	switch {
	case haveCert && haveKey && !tracked:
		return fmt.Errorf(
			"ca %q: refusing to overwrite an untracked CA: %s and %s exist on disk but the manifest has no CA record; remove them to regenerate, or restore the manifest that produced them",
			label, certPath, keyPath,
		)
	case haveCert && !haveKey:
		return fmt.Errorf(
			"ca %q: inconsistent CA state: certificate %s exists but key %s is missing; remove the certificate to regenerate the pair",
			label, certPath, keyPath,
		)
	case haveKey && !haveCert:
		return fmt.Errorf(
			"ca %q: inconsistent CA state: key %s exists but certificate %s is missing; remove the key to regenerate the pair",
			label, keyPath, certPath,
		)
	default:
		return fmt.Errorf(
			"ca %q: inconsistent CA state for %s / %s; remove any remaining CA files to regenerate",
			label, certPath, keyPath,
		)
	}
}

// linkSource is one owner of link_crt symlinks: a ca block, a trust_bundle
// block, or a block removed from the config whose recorded links must be
// cleaned up.
type linkSource struct {
	owner Kind
	label string
	// dirs is the declared link_crt list; nil for a removed block.
	dirs []string
	// filename is the symlink name; target is the logical path it points at.
	filename string
	target   string
	// recorded is the manifest's links for this owner.
	recorded []manifest.CertLink
}

// desc names the owner in messages, e.g. `ca "mesh"`.
func (s linkSource) desc() string {
	if s.owner == KindTrustBundle {
		return fmt.Sprintf("trust_bundle %q", s.label)
	}
	return fmt.Sprintf("ca %q", s.label)
}

// linkSources lists every link owner: the declared CAs in config order, CAs
// recorded in the manifest but no longer declared (sorted by label, so their
// stale links are deleted, ADR-021 amendment), the declared trust bundles,
// and trust bundles only recorded in the manifest.
func linkSources(cfg *config.Config, m *manifest.Manifest) []linkSource {
	var srcs []linkSource
	for i := range cfg.CAs {
		ca := cfg.CAs[i]
		src := linkSource{
			owner:    KindCA,
			label:    ca.Label,
			dirs:     ca.LinkCrt,
			filename: cfg.CACertFilename(ca),
			target:   cfg.CACertPathForCA(ca),
		}
		if m != nil && m.CAs[ca.Label] != nil {
			src.recorded = m.CAs[ca.Label].Links
		}
		srcs = append(srcs, src)
	}
	for _, label := range removedCALabels(cfg, m) {
		srcs = append(srcs, linkSource{owner: KindCA, label: label, recorded: m.CAs[label].Links})
	}

	for i := range cfg.TrustBundles {
		tb := cfg.TrustBundles[i]
		src := linkSource{
			owner:    KindTrustBundle,
			label:    tb.Label,
			dirs:     tb.LinkCrt,
			filename: cfg.TrustBundleFilename(tb),
			target:   cfg.TrustBundlePath(tb),
		}
		if m != nil && m.TrustBundles[tb.Label] != nil {
			src.recorded = m.TrustBundles[tb.Label].Links
		}
		srcs = append(srcs, src)
	}
	for _, label := range removedBundleLabels(cfg, m) {
		srcs = append(srcs, linkSource{owner: KindTrustBundle, label: label, recorded: m.TrustBundles[label].Links})
	}
	return srcs
}

// declaredLinkPaths returns every symlink path some current block declares.
// A stale link at such a path belongs to its new owner now (e.g. after a
// label rename) and must not be deleted.
func declaredLinkPaths(srcs []linkSource) map[string]bool {
	declared := make(map[string]bool)
	for _, src := range srcs {
		for _, dir := range src.dirs {
			declared[filepath.Join(dir, src.filename)] = true
		}
	}
	return declared
}

// removedLinkPaths returns the recorded symlinks that planLinks deletes
// (those no current block declares), keyed by config.FoldPath. A declared
// link whose path matches one of them ignoring case shares its file on a
// case-insensitive filesystem and is created again after the delete.
func removedLinkPaths(srcs []linkSource, declared map[string]bool) map[string]bool {
	removed := make(map[string]bool)
	for _, src := range srcs {
		for _, link := range src.recorded {
			if !declared[link.Path] {
				removed[config.FoldPath(link.Path)] = true
			}
		}
	}
	return removed
}

// removedBundleLabels returns the labels of trust bundles recorded in the
// manifest but no longer declared, sorted for deterministic output.
func removedBundleLabels(cfg *config.Config, m *manifest.Manifest) []string {
	if m == nil {
		return nil
	}
	var labels []string
	for label := range m.TrustBundles {
		if cfg.TrustBundleByLabel(label) == nil {
			labels = append(labels, label)
		}
	}
	sort.Strings(labels)
	return labels
}

// removedCALabels returns the labels of CAs recorded in the manifest but no
// longer declared in the config, sorted for deterministic output.
func removedCALabels(cfg *config.Config, m *manifest.Manifest) []string {
	if m == nil {
		return nil
	}
	var labels []string
	for label := range m.CAs {
		if cfg.CAByLabel(label) == nil {
			labels = append(labels, label)
		}
	}
	sort.Strings(labels)
	return labels
}

// planLinks computes the symlink actions for one link owner. For each
// declared directory it checks the current symlink state via opts.Lstat /
// opts.Readlink and emits CreateSymlink, Noop, or an error; a link whose
// path matches a removed one ignoring case (removed, keyed by
// config.FoldPath) is always created, since deleting the old spelling may
// remove it. Symlinks recorded in the manifest but no longer declared by
// this owner emit DeleteSymlink for stale-link cleanup, unless another
// current block now declares the same path (declared): that block manages
// the symlink from now on, and this owner only forgets it (OpForgetLink).
// Deletes and hand-overs are returned as removals, which Build orders before
// every other link action.
func planLinks(cfg *config.Config, src linkSource, declared, removed map[string]bool, opts Options) (removals, actions []Action, err error) {
	absTarget := cfg.Resolve(src.target)

	// expectedPaths tracks which logical link paths are currently declared,
	// so we can diff against the manifest for stale detection.
	expectedPaths := make(map[string]struct{}, len(src.dirs))

	for _, dir := range src.dirs {
		linkPath := filepath.Join(dir, src.filename) // logical
		absLinkDir := cfg.Resolve(dir)
		absLinkPath := cfg.Resolve(linkPath)

		target, err := filepath.Rel(absLinkDir, absTarget)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: link_crt %q: cannot compute relative path to %s: %w", src.desc(), dir, src.target, err)
		}

		expectedPaths[linkPath] = struct{}{}

		create := Action{
			Op:         OpCreateSymlink,
			Kind:       KindLink,
			Owner:      src.owner,
			Label:      src.label,
			Path:       linkPath,
			LinkTarget: target,
			LinkDir:    dir,
			Desc:       fmt.Sprintf("create link %s → %s", linkPath, target),
		}

		if opts.Lstat == nil {
			actions = append(actions, create)
			continue
		}

		mode, err := opts.Lstat(absLinkPath)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			actions = append(actions, create)
		case err != nil:
			return nil, nil, fmt.Errorf("%s: link_crt %q: lstat %s: %w", src.desc(), dir, linkPath, err)
		case mode&os.ModeSymlink != 0:
			currentTarget, err := opts.Readlink(absLinkPath)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: link_crt %q: readlink %s: %w", src.desc(), dir, linkPath, err)
			}
			switch {
			case removed[config.FoldPath(linkPath)]:
				// The symlink found is the removed spelling of this path; it
				// is deleted first, so this one is created again.
				if currentTarget != target {
					create.Desc = fmt.Sprintf("update link %s → %s (was %s)", linkPath, target, currentTarget)
				}
				actions = append(actions, create)
			case currentTarget == target:
				actions = append(actions, Action{
					Op:         OpNoop,
					Kind:       KindLink,
					Owner:      src.owner,
					Label:      src.label,
					Path:       linkPath,
					LinkTarget: target,
					Desc:       fmt.Sprintf("link %s up to date", linkPath),
				})
			default:
				create.Desc = fmt.Sprintf("update link %s → %s (was %s)", linkPath, target, currentTarget)
				actions = append(actions, create)
			}
		default:
			return nil, nil, fmt.Errorf(
				"%s: link_crt %q: %s is not a symlink; remove it manually to let nebula-pki manage this path",
				src.desc(), dir, linkPath,
			)
		}
	}

	for _, link := range src.recorded {
		if _, ok := expectedPaths[link.Path]; ok {
			continue
		}
		if declared[link.Path] {
			removals = append(removals, Action{
				Op:    OpForgetLink,
				Kind:  KindLink,
				Owner: src.owner,
				Label: src.label,
				Path:  link.Path,
				Desc:  fmt.Sprintf("hand over link %s from %s", link.Path, src.desc()),
			})
			continue
		}
		removals = append(removals, Action{
			Op:    OpDeleteSymlink,
			Kind:  KindLink,
			Owner: src.owner,
			Label: src.label,
			Path:  link.Path,
			Desc:  fmt.Sprintf("delete stale link %s", link.Path),
		})
	}
	return removals, actions, nil
}

// planTrustBundles decides one action per declared trust_bundle block
// (ADR-026 "Detailed rules"). This is the only place that decides whether a
// bundle is written; apply carries the decision out. A bundle is written when
// its label is not recorded yet, its path changed, the file is missing, a
// member CA is generated in this run, or the members' fingerprints (in
// ca_refs order) differ from the recorded ones. A reference-mode member
// whose file was swapped never gets here: planReferenceCA rejects it.
func planTrustBundles(cfg *config.Config, m *manifest.Manifest, caActions []Action, exists func(string) bool) []Action {
	generated := make(map[string]bool)
	for _, a := range caActions {
		if a.Kind == KindCA && a.Op == OpGenerate {
			generated[a.Label] = true
		}
	}
	var actions []Action
	for i := range cfg.TrustBundles {
		tb := cfg.TrustBundles[i]
		write := bundleNeedsWrite(cfg, m, tb, generated, exists)
		path := cfg.TrustBundlePath(tb)
		a := Action{Op: OpNoop, Kind: KindTrustBundle, Label: tb.Label, Path: path, Desc: fmt.Sprintf("trust bundle %q up to date", tb.Label)}
		if write {
			a.Op = OpWrite
			a.Desc = fmt.Sprintf("write trust bundle %q %s", tb.Label, path)
		}
		actions = append(actions, a)
	}
	return actions
}

func bundleNeedsWrite(cfg *config.Config, m *manifest.Manifest, tb config.TrustBundle, generated map[string]bool, exists func(string) bool) bool {
	path := cfg.TrustBundlePath(tb)
	if m == nil || m.TrustBundles[tb.Label] == nil {
		return true
	}
	rec := m.TrustBundles[tb.Label]
	if !cfg.SamePath(rec.Path, path) || !exists(path) {
		return true
	}
	fps := make([]string, 0, len(tb.CARefs))
	for _, label := range tb.CARefs {
		caRec := m.CAs[label]
		if generated[label] || caRec == nil {
			return true
		}
		fps = append(fps, caRec.Fingerprint)
	}
	return !slices.Equal(fps, rec.CAFingerprints)
}

// planReleases emits OpRelease actions for files the manifest tracked that
// the config no longer manages: the cert and key of every removed
// generate-mode ca block, and the file of every trust bundle whose label was
// removed or renamed or whose path changed. The files stay on disk (ADR-021
// amendment, ADR-026). A removed reference-mode CA releases no paths: its
// files were never managed. A path still managed by the current config is
// never reported, and neither is a file that is already gone: the notice says
// the files stay on disk. The action is emitted even without paths, so the
// manifest drops the record.
func planReleases(cfg *config.Config, m *manifest.Manifest, exists func(string) bool) []Action {
	if m == nil {
		return nil
	}
	// Keyed by resolved path under config.FoldPath: a manifest may spell a
	// managed file differently from the config (see config.SamePath), and a
	// path renamed only in case is the same file on a case-insensitive
	// filesystem, as every written path counts (D-23).
	managedSet := make(map[string]bool)
	key := func(p string) string { return config.FoldPath(cfg.Resolve(p)) }
	suffix := cfg.Storage.Encryption.KeySuffix()
	for i := range cfg.CAs {
		managedSet[key(cfg.CACertPathForCA(cfg.CAs[i]))] = true
		managedSet[key(cfg.CAKeyPathForCA(cfg.CAs[i]))] = true
		managedSet[key(cfg.CAKeyPathForCA(cfg.CAs[i])+suffix)] = true
	}
	for i := range cfg.TrustBundles {
		managedSet[key(cfg.TrustBundlePath(cfg.TrustBundles[i]))] = true
	}
	managed := func(p string) bool { return managedSet[key(p)] }

	keep := func(paths ...string) []string {
		var kept []string
		for _, p := range paths {
			if p != "" && !managed(p) && exists(p) {
				kept = append(kept, p)
			}
		}
		return kept
	}

	var actions []Action
	for _, label := range removedCALabels(cfg, m) {
		rec := m.CAs[label]
		var paths []string
		if rec.Mode != "reference" {
			paths = keep(rec.CertPath, rec.KeyPath)
		}
		// Emitted even without paths: the manifest drops the record.
		actions = append(actions, Action{
			Op: OpRelease, Kind: KindRelease, Owner: KindCA, Label: label, Paths: paths,
			Desc: fmt.Sprintf("release ca %q", label),
		})
	}
	labels := make([]string, 0, len(m.TrustBundles))
	for label := range m.TrustBundles {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		path := m.TrustBundles[label].Path
		// Still managed: the bundle (or a renamed one) keeps writing it.
		if managed(path) {
			continue
		}
		paths := keep(path)
		actions = append(actions, Action{
			Op: OpRelease, Kind: KindRelease, Owner: KindTrustBundle, Label: label, Paths: paths,
			Desc: fmt.Sprintf("release trust bundle %q", label),
		})
	}
	return actions
}
