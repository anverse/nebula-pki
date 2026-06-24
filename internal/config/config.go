// Package config parses and validates nebula-pki HCL configuration.
//
// The package is pure: bytes (or a path) in, a validated *Config out, or
// a structured error. No filesystem mutation, no signing, no manifest
// I/O.
//
// The HCL surface is described in spec/hcl-schema.md and the formal
// JSON Schema at spec/hcl-schema.formal.json. Field names match 1:1.
//
// Signing-relevant fields reuse upstream types from
// github.com/slackhq/nebula/cert (Curve, Version, Argon2Parameters) so
// we never duplicate the wire-level vocabulary; the HCL surface only
// adds the translation layer needed to express those types declaratively.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/slackhq/nebula/cert"
)

// Config is the parsed, validated configuration.
type Config struct {
	// Path is the on-disk path the configuration was loaded from, when
	// known. Empty for in-memory loads via Parse.
	Path string

	// CAs holds all certificate authorities, in declaration order. Always
	// at least one element. Single-CA configs have exactly one element.
	CAs     []CA
	Storage Storage
	Hosts   []Host
}

// IsMultiCA reports whether the config declares more than one CA.
func (c *Config) IsMultiCA() bool { return len(c.CAs) > 1 }

// CAByLabel returns a pointer to the CA with the given label, or nil if
// no such CA exists.
func (c *Config) CAByLabel(label string) *CA {
	for i := range c.CAs {
		if c.CAs[i].Label == label {
			return &c.CAs[i]
		}
	}
	return nil
}

// DefaultCA returns the CA marked default = true, or the sole CA when
// there is exactly one. Returns nil only if there are multiple CAs and
// none is marked default — callers should ensure validate() has passed
// before relying on non-nil semantics.
func (c *Config) DefaultCA() *CA {
	for i := range c.CAs {
		if c.CAs[i].Default {
			return &c.CAs[i]
		}
	}
	if len(c.CAs) == 1 {
		return &c.CAs[0]
	}
	return nil
}

// SigningCA returns the CA that should sign the given host. Returns nil
// only when the signing CA is ambiguous — validate() rejects such configs,
// so a nil return here indicates a bug in the caller.
func (c *Config) SigningCA(h Host) *CA {
	if h.CARef != "" {
		return c.CAByLabel(h.CARef)
	}
	return c.DefaultCA()
}

// ResolvedRenewBefore returns the effective renewal threshold for h:
// host.renew_before if set, else the signing CA's ca.renew_before if set,
// else zero (no time-based renewal — pure ADR-002 idempotency only).
func (c *Config) ResolvedRenewBefore(h Host) time.Duration {
	if h.HasRenewBefore {
		return h.RenewBefore
	}
	ca := c.SigningCA(h)
	if ca != nil && ca.HasRenewBefore {
		return ca.RenewBefore
	}
	return 0
}

// CAMode enumerates the two modes of the `ca` block.
type CAMode int

const (
	// CAModeGenerate means the CLI will create a new CA.
	CAModeGenerate CAMode = iota
	// CAModeReference means an existing CA on disk is reused.
	CAModeReference
)

func (m CAMode) String() string {
	switch m {
	case CAModeGenerate:
		return "generate"
	case CAModeReference:
		return "reference"
	}
	return "unknown"
}

// CA is the certificate authority configuration.
//
// In generate mode, the fields populated here feed directly into a
// cert.TBSCertificate when the CA is later signed: Name, Networks,
// UnsafeNetworks, Groups, Curve and Version are passed through
// unchanged. In reference mode only CertFile/KeyFile are meaningful.
type CA struct {
	// Label is the HCL block label (e.g. ca "mesh" → "mesh"). Always set.
	Label string
	// Default marks this CA as the default signing CA in multi-CA configs.
	Default bool

	Mode CAMode

	// Generate-mode fields.
	Name           string
	Duration       time.Duration
	HasDuration    bool
	Version        cert.Version
	HasVersion     bool
	Curve          cert.Curve
	HasCurve       bool
	Groups         []string
	Networks       []netip.Prefix
	UnsafeNetworks []netip.Prefix
	Encrypt        bool
	Argon          *cert.Argon2Parameters
	OutCRT         string
	OutKey         string
	OutQR          string

	// RenewBefore is the default renewal threshold for hosts signed by this
	// CA. Hosts inherit this value when they do not set their own
	// renew_before. A host cert is re-signed when it is within this window
	// of its not_after. See ADR-017.
	RenewBefore    time.Duration
	HasRenewBefore bool

	// Archived, when true, excludes this CA's certificate from the emitted
	// trust bundle and prevents it from signing hosts. The manifest record
	// is kept for audit. Used to stage the final step of a CA rotation.
	// See ADR-016.
	Archived bool

	// Reference-mode fields.
	CertFile string
	KeyFile  string
}

// Storage holds the storage block.
//
// The encryption sub-block is parsed only well enough to reject it with
// a clear error message; no encryption state is retained.
type Storage struct {
	OutDir          string
	ManifestFile    string
	TrustBundleFile string
}

// Host is a host certificate to sign. Networks, UnsafeNetworks, Groups
// and Name flow directly into cert.TBSCertificate at signing time.
type Host struct {
	// Label is the HCL identifier (manifest key).
	Label string
	// Name is the certificate CN. Defaults to Label.
	Name string

	// CARef is the value of the `ca` field on the host block — the label
	// of the signing CA. Empty means "use the default (or sole) CA".
	CARef string

	Networks       []netip.Prefix
	Groups         []string
	UnsafeNetworks []netip.Prefix
	Duration       time.Duration
	HasDuration    bool
	OutCRT         string
	OutKey         string
	OutQR          string
	InPub          string
	OutputDir      string

	// RenewBefore overrides the signing CA's renew_before for this host.
	// When set, the host is re-signed within this window of its not_after.
	RenewBefore    time.Duration
	HasRenewBefore bool
}

// Defaults applied when fields are omitted.
const (
	defaultOutDir       = "out"
	defaultManifestName = "nebula-pki.json"
)

// caLabelRe is the identifier rule from spec/hcl-schema.md and ADR-015.
var caLabelRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// hclCurveAliases maps the user-facing HCL curve strings to upstream
// cert.Curve values. The schema documents "25519" and "P256"; upstream
// uses "CURVE25519" and "P256" internally. We accept the documented
// spellings and translate.
var hclCurveAliases = map[string]cert.Curve{
	"25519": cert.Curve_CURVE25519,
	"P256":  cert.Curve_P256,
}

// hclVersions enumerates the certificate format versions the HCL
// surface accepts. Values mirror upstream cert.Version.
var hclVersions = map[int]cert.Version{
	1: cert.Version1,
	2: cert.Version2,
}

// Load reads and parses an HCL file at path, then validates the result.
func Load(path string) (*Config, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(path, src)
}

// Parse parses the supplied HCL source under the given filename (used
// only for diagnostics) and returns the validated Config.
func Parse(filename string, src []byte) (*Config, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, diagsError(diags)
	}

	var raw rawConfig
	if diags := gohcl.DecodeBody(file.Body, nil, &raw); diags.HasErrors() {
		return nil, diagsError(diags)
	}

	cfg, err := decode(filename, &raw)
	if err != nil {
		return nil, err
	}
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func diagsError(diags hcl.Diagnostics) error {
	parts := make([]string, 0, len(diags))
	for _, d := range diags {
		if d.Subject != nil {
			parts = append(parts, fmt.Sprintf("%s: %s: %s", d.Subject, d.Summary, d.Detail))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", d.Summary, d.Detail))
		}
	}
	return errors.New(strings.Join(parts, "\n"))
}

// ---------------------------------------------------------------------------
// Raw HCL schema (decode-only). Field shapes mirror spec/hcl-schema.md
// 1:1; cross-field invariants are enforced after decode.
// ---------------------------------------------------------------------------

type rawConfig struct {
	CAs     []rawCA     `hcl:"ca,block"`
	Storage *rawStorage `hcl:"storage,block"`
	Hosts   []rawHost   `hcl:"host,block"`
}

type rawCA struct {
	Label string `hcl:"label,label"`

	Default          *bool    `hcl:"default,optional"`
	Name             *string  `hcl:"name,optional"`
	Duration         *string  `hcl:"duration,optional"`
	Version          *int     `hcl:"version,optional"`
	Curve            *string  `hcl:"curve,optional"`
	Groups           []string `hcl:"groups,optional"`
	Networks         []string `hcl:"networks,optional"`
	UnsafeNetworks   []string `hcl:"unsafe_networks,optional"`
	Encrypt          *bool    `hcl:"encrypt,optional"`
	ArgonMemory      *int     `hcl:"argon_memory,optional"`
	ArgonIterations  *int     `hcl:"argon_iterations,optional"`
	ArgonParallelism *int     `hcl:"argon_parallelism,optional"`
	OutCRT           *string  `hcl:"out_crt,optional"`
	OutKey           *string  `hcl:"out_key,optional"`
	OutQR            *string  `hcl:"out_qr,optional"`
	CertFile         *string  `hcl:"cert_file,optional"`
	KeyFile          *string  `hcl:"key_file,optional"`
	RenewBefore      *string  `hcl:"renew_before,optional"`
	Archived         *bool    `hcl:"archived,optional"`

	Range hcl.Range `hcl:",def_range"`
}

type rawStorage struct {
	OutDir          *string            `hcl:"out_dir,optional"`
	ManifestFile    *string            `hcl:"manifest_file,optional"`
	TrustBundleFile *string            `hcl:"trust_bundle_file,optional"`
	Encryption      []rawEncryptionRaw `hcl:"encryption,block"`

	Range hcl.Range `hcl:",def_range"`
}

// rawEncryptionRaw captures the encryption block label and ignores its
// body. The CLI rejects any non-"none" backend with a clear error, so
// staying tolerant of unknown attributes inside the block keeps the
// failure mode about the feature, not about the HCL.
type rawEncryptionRaw struct {
	Label string   `hcl:"label,label"`
	Body  hcl.Body `hcl:",remain"`

	Range hcl.Range `hcl:",def_range"`
}

type rawHost struct {
	Label string `hcl:"label,label"`

	CARef          *string  `hcl:"ca,optional"`
	Name           *string  `hcl:"name,optional"`
	Networks       []string `hcl:"networks,optional"`
	Groups         []string `hcl:"groups,optional"`
	UnsafeNetworks []string `hcl:"unsafe_networks,optional"`
	Duration       *string  `hcl:"duration,optional"`
	OutCRT         *string  `hcl:"out_crt,optional"`
	OutKey         *string  `hcl:"out_key,optional"`
	OutQR          *string  `hcl:"out_qr,optional"`
	InPub          *string  `hcl:"in_pub,optional"`
	OutputDir      *string  `hcl:"output_dir,optional"`
	RenewBefore    *string  `hcl:"renew_before,optional"`

	Range hcl.Range `hcl:",def_range"`
}

// ---------------------------------------------------------------------------
// Decode: raw -> Config. Performs per-field type conversion (durations,
// CIDR prefixes, curve/version enums) and applies defaults.
// ---------------------------------------------------------------------------

func decode(filename string, raw *rawConfig) (*Config, error) {
	if len(raw.CAs) == 0 {
		return nil, fmt.Errorf("%s: missing required `ca` block", filename)
	}

	cfg := &Config{Path: filename}

	cas := make([]CA, 0, len(raw.CAs))
	for i := range raw.CAs {
		ca, err := decodeCA(filename, &raw.CAs[i])
		if err != nil {
			return nil, err
		}
		cas = append(cas, *ca)
	}
	cfg.CAs = cas

	storage, err := decodeStorage(filename, raw.Storage)
	if err != nil {
		return nil, err
	}
	cfg.Storage = *storage

	hosts := make([]Host, 0, len(raw.Hosts))
	for _, rh := range raw.Hosts {
		h, err := decodeHost(filename, &rh)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, *h)
	}
	cfg.Hosts = hosts

	return cfg, nil
}

func decodeCA(filename string, r *rawCA) (*CA, error) {
	ca := &CA{Label: r.Label}

	if r.Default != nil {
		ca.Default = *r.Default
	}

	hasCert := r.CertFile != nil && *r.CertFile != ""
	hasKey := r.KeyFile != nil && *r.KeyFile != ""

	switch {
	case hasCert && hasKey:
		ca.Mode = CAModeReference
	case hasCert || hasKey:
		// Half-set. Reported in validate for a richer message.
		ca.Mode = CAModeReference
	default:
		ca.Mode = CAModeGenerate
	}

	if r.CertFile != nil {
		ca.CertFile = *r.CertFile
	}
	if r.KeyFile != nil {
		ca.KeyFile = *r.KeyFile
	}

	if r.Name != nil {
		ca.Name = *r.Name
	}
	if r.Duration != nil {
		d, err := time.ParseDuration(*r.Duration)
		if err != nil {
			return nil, fmt.Errorf("%s: ca %q.duration: %w", filename, r.Label, err)
		}
		ca.Duration = d
		ca.HasDuration = true
	}
	if r.Version != nil {
		v, ok := hclVersions[*r.Version]
		if !ok {
			return nil, fmt.Errorf("%s: ca %q.version must be 1 or 2, got %d", filename, r.Label, *r.Version)
		}
		ca.Version = v
		ca.HasVersion = true
	}
	if r.Curve != nil {
		c, ok := hclCurveAliases[*r.Curve]
		if !ok {
			return nil, fmt.Errorf("%s: ca %q.curve must be \"25519\" or \"P256\", got %q", filename, r.Label, *r.Curve)
		}
		ca.Curve = c
		ca.HasCurve = true
	}
	ca.Groups = append(ca.Groups, r.Groups...)

	nets, err := parsePrefixes(filename, fmt.Sprintf("ca %q.networks", r.Label), r.Networks)
	if err != nil {
		return nil, err
	}
	ca.Networks = nets

	unets, err := parsePrefixes(filename, fmt.Sprintf("ca %q.unsafe_networks", r.Label), r.UnsafeNetworks)
	if err != nil {
		return nil, err
	}
	ca.UnsafeNetworks = unets

	if r.Encrypt != nil {
		ca.Encrypt = *r.Encrypt
	}
	if argon, err := decodeArgon(filename, r); err != nil {
		return nil, err
	} else if argon != nil {
		ca.Argon = argon
	}
	if r.OutCRT != nil {
		ca.OutCRT = *r.OutCRT
	}
	if r.OutKey != nil {
		ca.OutKey = *r.OutKey
	}
	if r.OutQR != nil {
		ca.OutQR = *r.OutQR
	}
	if r.RenewBefore != nil {
		d, err := time.ParseDuration(*r.RenewBefore)
		if err != nil {
			return nil, fmt.Errorf("%s: ca %q.renew_before: %w", filename, r.Label, err)
		}
		ca.RenewBefore = d
		ca.HasRenewBefore = true
	}
	if r.Archived != nil {
		ca.Archived = *r.Archived
	}

	return ca, nil
}

// decodeArgon returns a *cert.Argon2Parameters when at least one of the
// argon_* fields was set, otherwise nil. Range-checks the integers so
// they fit the upstream type (uint32 memory/iterations, uint8 parallelism).
func decodeArgon(filename string, r *rawCA) (*cert.Argon2Parameters, error) {
	if r.ArgonMemory == nil && r.ArgonIterations == nil && r.ArgonParallelism == nil {
		return nil, nil
	}

	var (
		memory      uint32 = 2 * 1024 * 1024 // upstream default: 2 GiB
		iterations  uint32 = 1
		parallelism uint8  = 4
	)
	if r.ArgonMemory != nil {
		if *r.ArgonMemory <= 0 {
			return nil, fmt.Errorf("%s: ca %q.argon_memory must be positive", filename, r.Label)
		}
		memory = uint32(*r.ArgonMemory)
	}
	if r.ArgonIterations != nil {
		if *r.ArgonIterations <= 0 {
			return nil, fmt.Errorf("%s: ca %q.argon_iterations must be positive", filename, r.Label)
		}
		iterations = uint32(*r.ArgonIterations)
	}
	if r.ArgonParallelism != nil {
		if *r.ArgonParallelism <= 0 || *r.ArgonParallelism > 255 {
			return nil, fmt.Errorf("%s: ca %q.argon_parallelism must be between 1 and 255", filename, r.Label)
		}
		parallelism = uint8(*r.ArgonParallelism)
	}
	return cert.NewArgon2Parameters(memory, parallelism, iterations), nil
}

func decodeStorage(filename string, r *rawStorage) (*Storage, error) {
	s := &Storage{
		OutDir: defaultOutDir,
	}
	if r != nil {
		if r.OutDir != nil && *r.OutDir != "" {
			s.OutDir = *r.OutDir
		}
		if r.ManifestFile != nil && *r.ManifestFile != "" {
			s.ManifestFile = *r.ManifestFile
		}
		if r.TrustBundleFile != nil && *r.TrustBundleFile != "" {
			s.TrustBundleFile = *r.TrustBundleFile
		}
		if len(r.Encryption) > 1 {
			return nil, fmt.Errorf("%s: storage: multiple `encryption` blocks are not allowed", filename)
		}
		if len(r.Encryption) == 1 {
			enc := r.Encryption[0]
			if enc.Label != "none" {
				return nil, fmt.Errorf(
					"%s: storage: encryption %q is not implemented in this release; encryption ships in a later release (v0.2). For now, remove the `encryption` block or use `encryption \"none\" {}`.",
					filename, enc.Label,
				)
			}
		}
	}
	if s.ManifestFile == "" {
		s.ManifestFile = filepath.Join(s.OutDir, defaultManifestName)
	}
	return s, nil
}

func decodeHost(filename string, r *rawHost) (*Host, error) {
	h := &Host{Label: r.Label}
	if r.Name != nil && *r.Name != "" {
		h.Name = *r.Name
	} else {
		h.Name = r.Label
	}

	if r.CARef != nil {
		h.CARef = *r.CARef
	}

	nets, err := parsePrefixes(filename, fmt.Sprintf("host %q.networks", r.Label), r.Networks)
	if err != nil {
		return nil, err
	}
	h.Networks = nets

	h.Groups = append(h.Groups, r.Groups...)

	unets, err := parsePrefixes(filename, fmt.Sprintf("host %q.unsafe_networks", r.Label), r.UnsafeNetworks)
	if err != nil {
		return nil, err
	}
	h.UnsafeNetworks = unets

	if r.Duration != nil {
		d, err := time.ParseDuration(*r.Duration)
		if err != nil {
			return nil, fmt.Errorf("%s: host %q.duration: %w", filename, r.Label, err)
		}
		h.Duration = d
		h.HasDuration = true
	}
	if r.OutCRT != nil {
		h.OutCRT = *r.OutCRT
	}
	if r.OutKey != nil {
		h.OutKey = *r.OutKey
	}
	if r.OutQR != nil {
		h.OutQR = *r.OutQR
	}
	if r.InPub != nil {
		h.InPub = *r.InPub
	}
	if r.OutputDir != nil {
		h.OutputDir = *r.OutputDir
	}
	if r.RenewBefore != nil {
		d, err := time.ParseDuration(*r.RenewBefore)
		if err != nil {
			return nil, fmt.Errorf("%s: host %q.renew_before: %w", filename, r.Label, err)
		}
		h.RenewBefore = d
		h.HasRenewBefore = true
	}

	return h, nil
}

func parsePrefixes(filename, field string, raw []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raw))
	for i, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %s[%d]: invalid CIDR %q: %w", filename, field, i, s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Cross-field validation. Each rule from spec/hcl-schema.md is enforced
// here and named in the error message so users can find it in the docs.
// ---------------------------------------------------------------------------

func validate(cfg *Config) error {
	if err := validateCAs(cfg); err != nil {
		return err
	}
	return validateHosts(cfg)
}

func validateCAs(cfg *Config) error {
	seenLabels := make(map[string]struct{}, len(cfg.CAs))
	defaultCount := 0

	for i := range cfg.CAs {
		ca := &cfg.CAs[i]

		if !caLabelRe.MatchString(ca.Label) {
			return fmt.Errorf("ca %q: label must match ^[A-Za-z_][A-Za-z0-9_-]*$", ca.Label)
		}
		if _, dup := seenLabels[ca.Label]; dup {
			return fmt.Errorf("ca %q: duplicate label", ca.Label)
		}
		seenLabels[ca.Label] = struct{}{}

		if ca.Default {
			defaultCount++
		}

		if err := validateOneCA(cfg.Path, ca); err != nil {
			return err
		}
	}

	if defaultCount > 1 {
		return fmt.Errorf("at most one ca block may have default = true")
	}

	return nil
}

func validateOneCA(filename string, ca *CA) error {
	switch ca.Mode {
	case CAModeReference:
		if ca.CertFile == "" || ca.KeyFile == "" {
			return fmt.Errorf("ca %q: reference mode requires both `cert_file` and `key_file`", ca.Label)
		}
		var bad []string
		if ca.Name != "" {
			bad = append(bad, "name")
		}
		if ca.HasDuration {
			bad = append(bad, "duration")
		}
		if ca.HasVersion {
			bad = append(bad, "version")
		}
		if ca.HasCurve {
			bad = append(bad, "curve")
		}
		if ca.Encrypt {
			bad = append(bad, "encrypt")
		}
		if ca.Argon != nil {
			bad = append(bad, "argon_*")
		}
		if ca.OutCRT != "" {
			bad = append(bad, "out_crt")
		}
		if ca.OutKey != "" {
			bad = append(bad, "out_key")
		}
		if ca.OutQR != "" {
			bad = append(bad, "out_qr")
		}
		if len(bad) > 0 {
			return fmt.Errorf("ca %q: reference mode does not allow generate-only fields: %s", ca.Label, strings.Join(bad, ", "))
		}

	case CAModeGenerate:
		if ca.Name == "" {
			return fmt.Errorf("ca %q: `name` is required in generate mode", ca.Label)
		}
		if err := validateGroupStrings(fmt.Sprintf("ca %q.groups", ca.Label), ca.Groups); err != nil {
			return err
		}
		// Validate that ca.renew_before < ca.duration so it is sane as a host
		// default. An infinite-churn scenario arises when renew_before ≥ validity.
		if ca.HasRenewBefore && ca.HasDuration && ca.RenewBefore >= ca.Duration {
			return fmt.Errorf("ca %q: renew_before %s must be less than duration %s",
				ca.Label, ca.RenewBefore, ca.Duration)
		}
	}

	// An archived CA cannot also be the default: all hosts that lack an
	// explicit host.ca would resolve to an archived (non-signing) CA,
	// making the configuration immediately invalid.
	if ca.Archived && ca.Default {
		return fmt.Errorf("ca %q: an archived CA cannot be marked default = true", ca.Label)
	}

	return nil
}

func validateHosts(cfg *Config) error {
	seenLabels := make(map[string]struct{}, len(cfg.Hosts))
	seenNames := make(map[string]string, len(cfg.Hosts)) // name -> label
	seenAddrs := make(map[string]string, len(cfg.Hosts)) // addr -> label
	for i := range cfg.Hosts {
		h := &cfg.Hosts[i]
		if _, dup := seenLabels[h.Label]; dup {
			return fmt.Errorf("host %q: duplicate label", h.Label)
		}
		seenLabels[h.Label] = struct{}{}

		if other, dup := seenNames[h.Name]; dup {
			return fmt.Errorf("host %q: certificate name %q already used by host %q", h.Label, h.Name, other)
		}
		seenNames[h.Name] = h.Label

		if len(h.Networks) == 0 {
			return fmt.Errorf("host %q: `networks` is required and must contain at least one CIDR", h.Label)
		}

		addr := h.Networks[0].Addr().String()
		if other, dup := seenAddrs[addr]; dup {
			return fmt.Errorf("host %q: overlay address %s already used by host %q", h.Label, addr, other)
		}
		seenAddrs[addr] = h.Label

		if err := validateGroupStrings(fmt.Sprintf("host %q.groups", h.Label), h.Groups); err != nil {
			return err
		}

		// Resolve the signing CA for this host.
		signingCA, err := resolveSigningCA(cfg, h)
		if err != nil {
			return err
		}

		// Per-CA restriction scoping: validate host fields against the
		// signing CA's restrictions, not against some other CA.
		if signingCA.Mode == CAModeGenerate {
			if len(signingCA.Groups) > 0 {
				if extra := groupsNotIn(h.Groups, signingCA.Groups); len(extra) > 0 {
					return fmt.Errorf("host %q: groups %v not permitted by ca %q.groups", h.Label, extra, signingCA.Label)
				}
			}
			if len(signingCA.Networks) > 0 {
				if bad := prefixesNotContained(h.Networks, signingCA.Networks); bad != "" {
					return fmt.Errorf("host %q: network %s not contained by any ca %q.networks prefix", h.Label, bad, signingCA.Label)
				}
			}
			if len(signingCA.UnsafeNetworks) > 0 {
				if bad := prefixesNotContained(h.UnsafeNetworks, signingCA.UnsafeNetworks); bad != "" {
					return fmt.Errorf("host %q: unsafe_network %s not contained by any ca %q.unsafe_networks prefix", h.Label, bad, signingCA.Label)
				}
			}
			if signingCA.HasDuration && h.HasDuration && h.Duration > signingCA.Duration {
				return fmt.Errorf("host %q: duration %s exceeds ca %q.duration %s", h.Label, h.Duration, signingCA.Label, signingCA.Duration)
			}
		}

		// Validate renew_before < effective host validity so that issuing a
		// cert never leaves the host immediately inside its renewal window
		// (which would cause re-sign on every run).
		if err := validateHostRenewBefore(h, signingCA); err != nil {
			return err
		}
	}
	return nil
}

// validateHostRenewBefore ensures the effective renew_before for a host is
// strictly less than the host's effective validity window.
func validateHostRenewBefore(h *Host, signingCA *CA) error {
	// Resolve which renew_before applies.
	var rb time.Duration
	var rbSource string
	switch {
	case h.HasRenewBefore:
		rb = h.RenewBefore
		rbSource = fmt.Sprintf("host %q.renew_before", h.Label)
	case signingCA.HasRenewBefore:
		rb = signingCA.RenewBefore
		rbSource = fmt.Sprintf("ca %q.renew_before (inherited by host %q)", signingCA.Label, h.Label)
	default:
		return nil // no renew_before configured; nothing to validate
	}

	// Resolve the effective validity: host.duration if set, else ca.duration
	// if the CA is generate-mode (reference-mode CA expiry is not known at
	// parse time and is checked at run time instead).
	switch {
	case h.HasDuration:
		if rb >= h.Duration {
			return fmt.Errorf("host %q: %s %s must be less than duration %s",
				h.Label, rbSource, rb, h.Duration)
		}
	case signingCA.Mode == CAModeGenerate && signingCA.HasDuration:
		if rb >= signingCA.Duration {
			return fmt.Errorf("host %q: %s %s must be less than signing ca %q duration %s",
				h.Label, rbSource, rb, signingCA.Label, signingCA.Duration)
		}
	}
	return nil
}

// resolveSigningCA returns the CA that signs h, or an error if the
// signing CA is ambiguous, undeclared, or archived. This is the single
// point of CA-selection logic shared by validate and the callers in
// plan/apply.
func resolveSigningCA(cfg *Config, h *Host) (*CA, error) {
	var ca *CA
	if h.CARef != "" {
		ca = cfg.CAByLabel(h.CARef)
		if ca == nil {
			return nil, fmt.Errorf("host %q: ca %q is not declared", h.Label, h.CARef)
		}
	} else if len(cfg.CAs) == 1 {
		ca = &cfg.CAs[0]
	} else {
		for i := range cfg.CAs {
			if cfg.CAs[i].Default {
				ca = &cfg.CAs[i]
				break
			}
		}
		if ca == nil {
			return nil, fmt.Errorf(
				"host %q: ambiguous signing ca (the config has %d CAs and none is marked default = true; set host.ca or add default = true to one ca block)",
				h.Label, len(cfg.CAs),
			)
		}
	}
	if ca.Archived {
		return nil, fmt.Errorf("host %q: ca %q is archived and may not sign hosts", h.Label, ca.Label)
	}
	return ca, nil
}

func validateGroupStrings(field string, groups []string) error {
	for _, g := range groups {
		if g == "" {
			return fmt.Errorf("%s: group entries must be non-empty", field)
		}
		if strings.Contains(g, ",") {
			return fmt.Errorf("%s: group %q contains a comma (forbidden — nebula-cert uses comma-separated groups)", field, g)
		}
		if g != strings.TrimSpace(g) {
			return fmt.Errorf("%s: group %q has leading or trailing whitespace", field, g)
		}
	}
	return nil
}

func groupsNotIn(have, allowed []string) []string {
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	var extra []string
	for _, g := range have {
		if _, ok := set[g]; !ok {
			extra = append(extra, g)
		}
	}
	sort.Strings(extra)
	return extra
}

// prefixesNotContained returns the first prefix in `have` that is not
// fully contained by any prefix in `allowed`, or "" if all fit.
func prefixesNotContained(have, allowed []netip.Prefix) string {
	for _, p := range have {
		ok := false
		for _, a := range allowed {
			if prefixContains(a, p) {
				ok = true
				break
			}
		}
		if !ok {
			return p.String()
		}
	}
	return ""
}

// prefixContains reports whether outer fully contains inner: same
// address family, outer's prefix length is <= inner's, and inner's
// network address falls inside outer.
func prefixContains(outer, inner netip.Prefix) bool {
	if outer.Addr().Is4() != inner.Addr().Is4() {
		return false
	}
	if outer.Bits() > inner.Bits() {
		return false
	}
	return outer.Contains(inner.Addr())
}
