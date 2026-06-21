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

// Build computes the reconcile plan for cfg given the current manifest m
// and an exists probe that reports whether a logical artifact path is
// present on disk. The caller is responsible for resolving logical paths
// to real ones inside exists.
func Build(cfg *config.Config, m *manifest.Manifest, exists func(logicalPath string) bool) (Plan, error) {
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
		ha := planHost(cfg, m, &cfg.Hosts[i], exists)
		actions = append(actions, ha)
	}
	return Plan{Actions: actions}, nil
}

// planHost decides the action for a single host. Host certs are not as
// precious as CAs (they can always be re-signed), so partial pairs and
// untracked files are resolved by re-signing rather than erroring:
//
//   - tracked in manifest AND signing CA matches AND every artifact file present → noop
//   - anything else (untracked, files absent, partial pair, new dir, CA changed) → sign
func planHost(cfg *config.Config, m *manifest.Manifest, h *config.Host, exists func(string) bool) Action {
	artifact := cfg.HostArtifactPath(*h)
	signingCA := cfg.SigningCA(*h)

	tracked := m != nil && m.Hosts[h.Label].Name != ""
	caMatch := tracked && signingCA != nil && m.Hosts[h.Label].CA == signingCA.Label

	if tracked && caMatch && exists(artifact.CertPath) && exists(artifact.KeyPath) {
		return Action{Op: OpNoop, Kind: KindHost, Label: h.Label, Desc: fmt.Sprintf("host %q up to date", h.Label)}
	}
	return Action{
		Op:    OpSign,
		Kind:  KindHost,
		Label: h.Label,
		Path:  artifact.CertPath,
		Desc:  fmt.Sprintf("sign host %q", h.Label),
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
// recorded — so a reference run whose inputs are unchanged still produces
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
// The tool never silently overwrites an existing CA, matching upstream
// nebula-cert's refuse-to-overwrite behaviour.
func planCA(cfg *config.Config, ca *config.CA, m *manifest.Manifest, exists func(string) bool) (Action, error) {
	certPath := cfg.CACertPathForCA(*ca)
	keyPath := cfg.CAKeyPathForCA(*ca)
	haveCert := exists(certPath)
	haveKey := exists(keyPath)
	tracked := m != nil && m.CAs[ca.Label] != nil

	switch {
	case tracked && haveCert && haveKey:
		return Action{Op: OpNoop, Kind: KindCA, Label: ca.Label, Desc: fmt.Sprintf("CA %q up to date", ca.Label)}, nil
	case !haveCert && !haveKey:
		return Action{
			Op:    OpGenerate,
			Kind:  KindCA,
			Label: ca.Label,
			Path:  certPath,
			Desc:  fmt.Sprintf("generate CA %q (%s)", ca.Label, ca.Name),
		}, nil
	default:
		return Action{}, caStateError(ca.Label, tracked, haveCert, haveKey, certPath, keyPath)
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
