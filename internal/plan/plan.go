// Package plan turns the desired configuration plus the current manifest
// and on-disk state into a list of actions. It is the only place that
// decides what should change; it performs no I/O of its own (callers
// supply an existence probe) and never mutates anything.
//
// It plans one action per CA (generate or reference) and one action per
// host (sign or noop). Host actions always follow all CA actions.
package plan

import (
	"fmt"
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
	// OpSign means a host certificate must be signed and written.
	OpSign Op = "sign"
)

// Kind is the artifact an action concerns.
type Kind string

const (
	// KindCA is the certificate authority.
	KindCA Kind = "ca"
	// KindHost is a host certificate.
	KindHost Kind = "host"
)

// Action is a single planned operation.
type Action struct {
	Op   Op
	Kind Kind
	// Label is the config label for the artifact (CA label for KindCA,
	// host label for KindHost).
	Label string
	// Path is the primary logical artifact path, for display. Empty for
	// no-ops.
	Path string
	// Desc is a human-readable one-line summary.
	Desc string
	// EncryptKey is true when the active storage encryption backend should
	// encrypt the private key artifact for this action. Always false for
	// in_pub hosts (no key is written) and for reference-mode CAs (the tool
	// never writes reference CA files).
	EncryptKey bool
}

// Plan is the ordered set of actions a reconcile would perform.
// CA actions appear before host actions.
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

// HostActions returns all host actions from the plan, in config order.
func (p Plan) HostActions() []Action {
	var hosts []Action
	for _, a := range p.Actions {
		if a.Kind == KindHost {
			hosts = append(hosts, a)
		}
	}
	return hosts
}

// Options configures how Build constructs the reconcile plan.
type Options struct {
	// NoRenewal, when true, skips the hostInRenewalWindow check for every
	// host. A host whose cert is within its renew_before window is treated
	// as up-to-date for this run. All other re-sign triggers (new host,
	// missing artifact, CA label mismatch) are unaffected.
	// The zero value (false) preserves the existing behaviour.
	NoRenewal bool
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

	for i := range cfg.Hosts {
		ha := planHost(cfg, m, &cfg.Hosts[i], now, exists, opts.NoRenewal)
		actions = append(actions, ha)
	}
	return Plan{Actions: actions}, nil
}

// hostInRenewalWindow reports whether a host cert is within its renew_before
// window as of now: true when now >= not_after - renewBefore. Returns false
// when renewBefore is zero (no time-based renewal configured).
func hostInRenewalWindow(renewBefore time.Duration, notAfter, now time.Time) bool {
	if renewBefore <= 0 {
		return false
	}
	return !now.Before(notAfter.Add(-renewBefore))
}

// planHost decides the action for a single host. Host certs are not as
// precious as CAs (they can always be re-signed), so partial pairs and
// untracked files are resolved by re-signing rather than erroring.
//
// A host is a noop when ALL of the following hold (ADR-002 + ADR-017 + ADR-018):
//  1. tracked in manifest
//  2. signing CA label matches the manifest record
//  3. provenance matches: both config and manifest agree on in_pub vs regular
//  4. cert artifact is present on disk
//  5. key artifact is present on disk (skipped for in_pub hosts; no key is written)
//  6. the cert is NOT within its renew_before window, OR noRenewal is true
//
// Any failing condition → sign.
//
// Note on in_pub idempotency (ADR-018): if the content of the in_pub file
// changes at the same path (same filename, different key bytes), this check
// does NOT detect it; only cert presence and provenance are compared. For
// hardware-bound keys this is correct (key never changes). For other cases
// the operator must delete the cert file to force a re-sign.
func planHost(cfg *config.Config, m *manifest.Manifest, h *config.Host, now time.Time, exists func(string) bool, noRenewal bool) Action {
	artifact := cfg.HostArtifactPath(*h)
	signingCA := cfg.SigningCA(*h)

	isInPub := h.InPub != ""

	tracked := m != nil && m.Hosts[h.Label].Name != ""
	caMatch := tracked && signingCA != nil && m.Hosts[h.Label].CA == signingCA.Label
	// Provenance must match: a host switching between regular signing and
	// in_pub (or back) must be re-signed so the cert reflects the correct
	// public key source and the manifest records the right shape.
	provenanceMatch := tracked && m.Hosts[h.Label].InPub == isInPub

	// in_pub hosts never write a key file; encryption does not apply to them.
	suffix := ""
	if !isInPub {
		suffix = cfg.Storage.Encryption.KeySuffix()
	}
	encKeyPath := artifact.KeyPath + suffix // equals artifact.KeyPath when suffix is ""

	certOK := exists(artifact.CertPath)
	// in_pub hosts never write a key file; skip the key-existence check for them.
	keyOK := isInPub || exists(encKeyPath)

	encryptKey := !isInPub && !cfg.Storage.Encryption.IsNone()

	if tracked && caMatch && provenanceMatch && certOK && keyOK {
		rb := cfg.ResolvedRenewBefore(*h)
		mh := m.Hosts[h.Label]
		if noRenewal || !hostInRenewalWindow(rb, mh.NotAfter, now) {
			return Action{Op: OpNoop, Kind: KindHost, Label: h.Label, EncryptKey: encryptKey, Desc: fmt.Sprintf("host %q up to date", h.Label)}
		}
		// Inside renewal window and renewal is not suppressed; fall through to sign.
	}
	return Action{
		Op:         OpSign,
		Kind:       KindHost,
		Label:      h.Label,
		Path:       artifact.CertPath,
		Desc:       fmt.Sprintf("sign host %q", h.Label),
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
