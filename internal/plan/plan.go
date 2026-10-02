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
	// OpWrite means the trust bundle file must be (re)written.
	OpWrite Op = "write"
	// OpRelabel means only the trust bundle's recorded label changed; the
	// manifest is rewritten, no file or symlink is touched (ADR-026).
	OpRelabel Op = "relabel"
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

// TrustBundleAction returns the trust bundle action, if a trust_bundle block
// is declared.
func (p Plan) TrustBundleAction() (Action, bool) {
	for _, a := range p.Actions {
		if a.Kind == KindTrustBundle {
			return a, true
		}
	}
	return Action{}, false
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
			a, err = planReferenceCA(cfg, ca, exists)
		} else {
			a, err = planCA(cfg, ca, m, exists)
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

	for _, src := range linkSources(cfg, m) {
		linkActions, err := planLinks(cfg, src, opts)
		if err != nil {
			return Plan{}, err
		}
		actions = append(actions, linkActions...)
	}

	if a, ok := planTrustBundle(cfg, m, actions, exists); ok {
		actions = append(actions, a)
	}
	actions = append(actions, planReleases(cfg, m)...)

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
//   - both files present -> reference.
//
// plan is pure and cannot read the certificate, so it always emits a
// reference action when the files are present and defers the real
// idempotency decision to apply. apply reads the CA, rebuilds the
// candidate manifest, and writes only when it differs from what is already
// recorded; so a reference run whose inputs are unchanged still produces
// a byte-identical tree, while a swapped reference file is detected via
// its changed fingerprint. Keeping plan pure (no cert parsing) is the
// reason the OpReference action is not collapsed to a noop here.
func planReferenceCA(cfg *config.Config, ca *config.CA, exists func(string) bool) (Action, error) {
	certPath := cfg.CACertPathForCA(*ca)
	keyPath := cfg.CAKeyPathForCA(*ca)
	haveCert := exists(certPath)
	haveKey := exists(keyPath)

	if !haveCert || !haveKey {
		return Action{}, referenceMissingError(ca.Label, haveCert, haveKey, certPath, keyPath)
	}

	return Action{
		Op:    OpReference,
		Kind:  KindCA,
		Label: ca.Label,
		Path:  certPath,
		Desc:  fmt.Sprintf("use referenced CA %q (%s)", ca.Label, certPath),
	}, nil
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
//   - neither file present                            -> generate
//   - anything else (files present but untracked, or
//     only one of the pair present)                   -> error
//
// The key file path used for existence checks includes the active
// encryption suffix (e.g. ".enc") so that idempotency works correctly
// after the first encrypted write.
//
// The tool never silently overwrites an existing CA, matching upstream
// nebula-cert's refuse-to-overwrite behaviour.
func planCA(cfg *config.Config, ca *config.CA, m *manifest.Manifest, exists func(string) bool) (Action, error) {
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
		return Action{Op: OpNoop, Kind: KindCA, Label: ca.Label, EncryptKey: encryptKey, Desc: fmt.Sprintf("CA %q up to date", ca.Label)}, nil
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
		if rec := m.CAs[ca.Label]; rec != nil && rec.KeyPath != "" && rec.KeyPath != encKeyPath && exists(rec.KeyPath) {
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

// linkSource is one owner of link_crt symlinks: a ca block, the trust
// bundle, or a block removed from the config whose recorded links must be
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
// stale links are deleted, ADR-021 amendment), and the trust bundle, whether
// declared or only recorded.
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

	var recorded []manifest.CertLink
	if m != nil && m.TrustBundle != nil {
		recorded = m.TrustBundle.Links
	}
	if tb := cfg.TrustBundle; tb != nil {
		srcs = append(srcs, linkSource{
			owner:    KindTrustBundle,
			label:    tb.Label,
			dirs:     tb.LinkCrt,
			filename: cfg.TrustBundleFilename(),
			target:   cfg.TrustBundlePath(),
			recorded: recorded,
		})
	} else if m != nil && m.TrustBundle != nil {
		srcs = append(srcs, linkSource{owner: KindTrustBundle, label: m.TrustBundle.Label, recorded: recorded})
	}
	return srcs
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
// opts.Readlink and emits CreateSymlink, Noop, or an error. Symlinks
// recorded in the manifest but no longer declared emit DeleteSymlink for
// stale-link cleanup.
func planLinks(cfg *config.Config, src linkSource, opts Options) ([]Action, error) {
	absTarget := cfg.Resolve(src.target)

	// expectedPaths tracks which logical link paths are currently declared,
	// so we can diff against the manifest for stale detection.
	expectedPaths := make(map[string]struct{}, len(src.dirs))
	var actions []Action

	for _, dir := range src.dirs {
		linkPath := filepath.Join(dir, src.filename) // logical
		absLinkDir := cfg.Resolve(dir)
		absLinkPath := cfg.Resolve(linkPath)

		target, err := filepath.Rel(absLinkDir, absTarget)
		if err != nil {
			return nil, fmt.Errorf("%s: link_crt %q: cannot compute relative path to %s: %w", src.desc(), dir, src.target, err)
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
			return nil, fmt.Errorf("%s: link_crt %q: lstat %s: %w", src.desc(), dir, linkPath, err)
		case mode&os.ModeSymlink != 0:
			currentTarget, err := opts.Readlink(absLinkPath)
			if err != nil {
				return nil, fmt.Errorf("%s: link_crt %q: readlink %s: %w", src.desc(), dir, linkPath, err)
			}
			if currentTarget == target {
				actions = append(actions, Action{
					Op:         OpNoop,
					Kind:       KindLink,
					Owner:      src.owner,
					Label:      src.label,
					Path:       linkPath,
					LinkTarget: target,
					Desc:       fmt.Sprintf("link %s up to date", linkPath),
				})
			} else {
				create.Desc = fmt.Sprintf("update link %s → %s (was %s)", linkPath, target, currentTarget)
				actions = append(actions, create)
			}
		default:
			return nil, fmt.Errorf(
				"%s: link_crt %q: %s is not a symlink; remove it manually to let nebula-pki manage this path",
				src.desc(), dir, linkPath,
			)
		}
	}

	for _, link := range src.recorded {
		if _, ok := expectedPaths[link.Path]; ok {
			continue
		}
		actions = append(actions, Action{
			Op:    OpDeleteSymlink,
			Kind:  KindLink,
			Owner: src.owner,
			Label: src.label,
			Path:  link.Path,
			Desc:  fmt.Sprintf("delete stale link %s", link.Path),
		})
	}
	return actions, nil
}

// planTrustBundle decides the trust bundle action when a trust_bundle block
// is declared (ADR-026 "Detailed rules"). The bundle is written when it is
// not recorded yet, its path changed, the file is missing, a member CA is
// generated in this run, or the members' recorded fingerprints (in ca_refs
// order) differ from the bundle's. A changed label alone only rewrites the
// manifest. Reference-mode CAs are re-read on every run, so apply re-checks
// the actual fingerprints before deciding not to write.
func planTrustBundle(cfg *config.Config, m *manifest.Manifest, caActions []Action, exists func(string) bool) (Action, bool) {
	tb := cfg.TrustBundle
	if tb == nil {
		return Action{}, false
	}
	path := cfg.TrustBundlePath()
	write := Action{Op: OpWrite, Kind: KindTrustBundle, Label: tb.Label, Path: path, Desc: fmt.Sprintf("write trust bundle %s", path)}

	if m == nil || m.TrustBundle == nil || m.TrustBundle.Path != path || !exists(path) {
		return write, true
	}
	generated := make(map[string]bool)
	for _, a := range caActions {
		if a.Kind == KindCA && a.Op == OpGenerate {
			generated[a.Label] = true
		}
	}
	fps := make([]string, 0, len(tb.CARefs))
	for _, label := range tb.CARefs {
		rec := m.CAs[label]
		if generated[label] || rec == nil {
			return write, true
		}
		fps = append(fps, rec.Fingerprint)
	}
	if !slices.Equal(fps, m.TrustBundle.CAFingerprints) {
		return write, true
	}
	if m.TrustBundle.Label != tb.Label {
		return Action{Op: OpRelabel, Kind: KindTrustBundle, Label: tb.Label, Path: path,
			Desc: fmt.Sprintf("relabel trust bundle %q → %q", m.TrustBundle.Label, tb.Label)}, true
	}
	return Action{Op: OpNoop, Kind: KindTrustBundle, Label: tb.Label, Path: path, Desc: "trust bundle up to date"}, true
}

// planReleases emits OpRelease actions for files the manifest tracked that
// the config no longer manages: the cert and key of every removed ca block,
// and the bundle file when the trust_bundle block was removed or its path
// changed. The files stay on disk (ADR-021 amendment, ADR-026). A path that
// is still managed by the current config is never reported.
func planReleases(cfg *config.Config, m *manifest.Manifest) []Action {
	if m == nil {
		return nil
	}
	managed := make(map[string]bool)
	suffix := cfg.Storage.Encryption.KeySuffix()
	for i := range cfg.CAs {
		managed[cfg.CACertPathForCA(cfg.CAs[i])] = true
		managed[cfg.CAKeyPathForCA(cfg.CAs[i])] = true
		managed[cfg.CAKeyPathForCA(cfg.CAs[i])+suffix] = true
	}
	if cfg.TrustBundle != nil {
		managed[cfg.TrustBundlePath()] = true
	}

	var actions []Action
	release := func(owner Kind, label string, paths ...string) {
		var kept []string
		for _, p := range paths {
			if p != "" && !managed[p] {
				kept = append(kept, p)
			}
		}
		if len(kept) == 0 && owner == KindTrustBundle {
			return
		}
		actions = append(actions, Action{
			Op:    OpRelease,
			Kind:  KindRelease,
			Owner: owner,
			Label: label,
			Paths: kept,
			Desc:  fmt.Sprintf("release %s %q", owner, label),
		})
	}
	for _, label := range removedCALabels(cfg, m) {
		rec := m.CAs[label]
		release(KindCA, label, rec.CertPath, rec.KeyPath)
	}
	if m.TrustBundle != nil {
		release(KindTrustBundle, m.TrustBundle.Label, m.TrustBundle.Path)
	}
	return actions
}
