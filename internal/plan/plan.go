// Package plan turns the desired configuration plus the current manifest
// and on-disk state into a list of actions. It is the only place that
// decides what should change; it performs no I/O of its own (callers
// supply an existence probe) and never mutates anything.
//
// It plans both CA modes: generate (mint a fresh CA) and reference (use
// an operator-supplied existing CA). Hosts are parsed but not yet
// reconciled.
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
)

// Kind is the artifact an action concerns.
type Kind string

const (
	// KindCA is the certificate authority.
	KindCA Kind = "ca"
)

// Action is a single planned operation.
type Action struct {
	Op   Op
	Kind Kind
	// Path is the primary logical artifact path, for display. Empty for
	// no-ops.
	Path string
	// Desc is a human-readable one-line summary.
	Desc string
}

// Plan is the ordered set of actions a reconcile would perform.
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

// Build computes the reconcile plan for cfg given the current manifest m
// and an exists probe that reports whether a logical artifact path is
// present on disk. The caller is responsible for resolving logical paths
// to real ones inside exists.
func Build(cfg *config.Config, m *manifest.Manifest, exists func(logicalPath string) bool) (Plan, error) {
	if cfg.CA.Mode == config.CAModeReference {
		refAction, err := planReferenceCA(cfg, m, exists)
		if err != nil {
			return Plan{}, err
		}
		return Plan{Actions: []Action{refAction}}, nil
	}

	caAction, err := planCA(cfg, m, exists)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Actions: []Action{caAction}}, nil
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
func planReferenceCA(cfg *config.Config, _ *manifest.Manifest, exists func(string) bool) (Action, error) {
	certPath := cfg.CACertPath()
	keyPath := cfg.CAKeyPath()
	haveCert := exists(certPath)
	haveKey := exists(keyPath)

	if !haveCert || !haveKey {
		return Action{}, referenceMissingError(haveCert, haveKey, certPath, keyPath)
	}

	return Action{
		Op:   OpReference,
		Kind: KindCA,
		Path: certPath,
		Desc: fmt.Sprintf("use referenced CA %s", certPath),
	}, nil
}

func referenceMissingError(haveCert, haveKey bool, certPath, keyPath string) error {
	switch {
	case !haveCert && !haveKey:
		return fmt.Errorf(
			"referenced CA not found: neither cert_file %s nor key_file %s exists",
			certPath, keyPath,
		)
	case !haveCert:
		return fmt.Errorf("referenced CA cert_file %s does not exist", certPath)
	default:
		return fmt.Errorf("referenced CA key_file %s does not exist", keyPath)
	}
}

// planCA decides the CA action. The rule (spec/adr/002 idempotency, and
// the "noop, never auto-overwrite" decision):
//
//   - tracked in the manifest AND both files present  -> noop
//   - neither file present                            -> generate
//   - anything else (files present but untracked, or
//     only one of the pair present)                   -> error
//
// The tool never silently overwrites an existing CA, matching upstream
// nebula-cert's refuse-to-overwrite behaviour.
func planCA(cfg *config.Config, m *manifest.Manifest, exists func(string) bool) (Action, error) {
	certPath := cfg.CACertPath()
	keyPath := cfg.CAKeyPath()
	haveCert := exists(certPath)
	haveKey := exists(keyPath)
	tracked := m != nil && m.CA != nil

	switch {
	case tracked && haveCert && haveKey:
		return Action{Op: OpNoop, Kind: KindCA, Desc: "CA up to date"}, nil
	case !haveCert && !haveKey:
		return Action{
			Op:   OpGenerate,
			Kind: KindCA,
			Path: certPath,
			Desc: fmt.Sprintf("generate CA %q", cfg.CA.Name),
		}, nil
	default:
		return Action{}, caStateError(tracked, haveCert, haveKey, certPath, keyPath)
	}
}

func caStateError(tracked, haveCert, haveKey bool, certPath, keyPath string) error {
	switch {
	case haveCert && haveKey && !tracked:
		return fmt.Errorf(
			"refusing to overwrite an untracked CA: %s and %s exist on disk but the manifest has no CA record; remove them to regenerate, or restore the manifest that produced them",
			certPath, keyPath,
		)
	case haveCert && !haveKey:
		return fmt.Errorf(
			"inconsistent CA state: certificate %s exists but key %s is missing; remove the certificate to regenerate the pair",
			certPath, keyPath,
		)
	case haveKey && !haveCert:
		return fmt.Errorf(
			"inconsistent CA state: key %s exists but certificate %s is missing; remove the key to regenerate the pair",
			keyPath, certPath,
		)
	default:
		// Defensive: planCA's switch routes (haveCert==haveKey==true)
		// and (haveCert==haveKey==false) elsewhere, and the three
		// non-default cases above cover every remaining shape (cert
		// only, key only, untracked-both). This arm is therefore
		// unreachable today; it exists so a future change to planCA
		// that introduces a new shape produces a usable error rather
		// than a zero-value Action with a nil error.
		return fmt.Errorf(
			"inconsistent CA state for %s / %s; remove any remaining CA files to regenerate",
			certPath, keyPath,
		)
	}
}
