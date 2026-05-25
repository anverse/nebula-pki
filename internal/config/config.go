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
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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

	CA      CA
	Storage Storage
	Hosts   []Host
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

	// Reference-mode fields.
	CertFile string
	KeyFile  string
}

// Storage holds the storage block.
//
// The encryption sub-block is parsed only well enough to reject it with
// a clear error message; no encryption state is retained.
type Storage struct {
	OutDir       string
	ManifestFile string
}

// Host is a host certificate to sign. Networks, UnsafeNetworks, Groups
// and Name flow directly into cert.TBSCertificate at signing time.
type Host struct {
	// Label is the HCL identifier (manifest key).
	Label string
	// Name is the certificate CN. Defaults to Label.
	Name string

	Networks       []netip.Prefix
	Groups         []string
	UnsafeNetworks []netip.Prefix
	Duration       time.Duration
	HasDuration    bool
	OutCRT         string
	OutKey         string
	OutQR          string
	InPub          string
	OutputDirs     []string
}

// Defaults applied when fields are omitted.
const (
	defaultOutDir       = "out"
	defaultManifestName = "nebula-pki.json"
)

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
	return fmt.Errorf("%s", strings.Join(parts, "\n"))
}

// ---------------------------------------------------------------------------
// Raw HCL schema (decode-only). Field shapes mirror spec/hcl-schema.md
// 1:1; cross-field invariants are enforced after decode.
// ---------------------------------------------------------------------------

type rawConfig struct {
	CA      *rawCA      `hcl:"ca,block"`
	Storage *rawStorage `hcl:"storage,block"`
	Hosts   []rawHost   `hcl:"host,block"`
}

type rawCA struct {
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

	Range hcl.Range `hcl:",def_range"`
}

type rawStorage struct {
	OutDir       *string            `hcl:"out_dir,optional"`
	ManifestFile *string            `hcl:"manifest_file,optional"`
	Encryption   []rawEncryptionRaw `hcl:"encryption,block"`

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

	Name           *string  `hcl:"name,optional"`
	Networks       []string `hcl:"networks,optional"`
	Groups         []string `hcl:"groups,optional"`
	UnsafeNetworks []string `hcl:"unsafe_networks,optional"`
	Duration       *string  `hcl:"duration,optional"`
	OutCRT         *string  `hcl:"out_crt,optional"`
	OutKey         *string  `hcl:"out_key,optional"`
	OutQR          *string  `hcl:"out_qr,optional"`
	InPub          *string  `hcl:"in_pub,optional"`
	OutputDirs     []string `hcl:"output_dirs,optional"`

	Range hcl.Range `hcl:",def_range"`
}

// ---------------------------------------------------------------------------
// Decode: raw -> Config. Performs per-field type conversion (durations,
// CIDR prefixes, curve/version enums) and applies defaults.
// ---------------------------------------------------------------------------

func decode(filename string, raw *rawConfig) (*Config, error) {
	if raw.CA == nil {
		return nil, fmt.Errorf("%s: missing required `ca` block", filename)
	}

	cfg := &Config{Path: filename}

	ca, err := decodeCA(filename, raw.CA)
	if err != nil {
		return nil, err
	}
	cfg.CA = *ca

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
	ca := &CA{}

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
			return nil, fmt.Errorf("%s: ca.duration: %w", filename, err)
		}
		ca.Duration = d
		ca.HasDuration = true
	}
	if r.Version != nil {
		v, ok := hclVersions[*r.Version]
		if !ok {
			return nil, fmt.Errorf("%s: ca.version must be 1 or 2, got %d", filename, *r.Version)
		}
		ca.Version = v
		ca.HasVersion = true
	}
	if r.Curve != nil {
		c, ok := hclCurveAliases[*r.Curve]
		if !ok {
			return nil, fmt.Errorf("%s: ca.curve must be \"25519\" or \"P256\", got %q", filename, *r.Curve)
		}
		ca.Curve = c
		ca.HasCurve = true
	}
	ca.Groups = append(ca.Groups, r.Groups...)

	nets, err := parsePrefixes(filename, "ca.networks", r.Networks)
	if err != nil {
		return nil, err
	}
	ca.Networks = nets

	unets, err := parsePrefixes(filename, "ca.unsafe_networks", r.UnsafeNetworks)
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
			return nil, fmt.Errorf("%s: ca.argon_memory must be positive", filename)
		}
		memory = uint32(*r.ArgonMemory)
	}
	if r.ArgonIterations != nil {
		if *r.ArgonIterations <= 0 {
			return nil, fmt.Errorf("%s: ca.argon_iterations must be positive", filename)
		}
		iterations = uint32(*r.ArgonIterations)
	}
	if r.ArgonParallelism != nil {
		if *r.ArgonParallelism <= 0 || *r.ArgonParallelism > 255 {
			return nil, fmt.Errorf("%s: ca.argon_parallelism must be between 1 and 255", filename)
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
	h.OutputDirs = append(h.OutputDirs, r.OutputDirs...)

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
	if err := validateCA(cfg); err != nil {
		return err
	}
	return validateHosts(cfg)
}

func validateCA(cfg *Config) error {
	ca := &cfg.CA

	switch ca.Mode {
	case CAModeReference:
		if ca.CertFile == "" || ca.KeyFile == "" {
			return fmt.Errorf("ca: reference mode requires both `cert_file` and `key_file`")
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
			return fmt.Errorf("ca: reference mode does not allow generate-only fields: %s", strings.Join(bad, ", "))
		}

	case CAModeGenerate:
		if ca.Name == "" {
			return fmt.Errorf("ca: `name` is required in generate mode")
		}
		if err := validateGroupStrings("ca.groups", ca.Groups); err != nil {
			return err
		}
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

		hasExplicit := h.OutCRT != "" || h.OutKey != ""
		if hasExplicit && len(h.OutputDirs) > 0 {
			return fmt.Errorf("host %q: `out_crt`/`out_key` and `output_dirs` are mutually exclusive", h.Label)
		}

		if dup := firstDuplicateDir(h.OutputDirs); dup != "" {
			return fmt.Errorf("host %q: `output_dirs` lists %q more than once", h.Label, dup)
		}

		if cfg.CA.Mode == CAModeGenerate {
			if len(cfg.CA.Groups) > 0 {
				if extra := groupsNotIn(h.Groups, cfg.CA.Groups); len(extra) > 0 {
					return fmt.Errorf("host %q: groups %v not permitted by ca.groups", h.Label, extra)
				}
			}
			if len(cfg.CA.Networks) > 0 {
				if bad := prefixesNotContained(h.Networks, cfg.CA.Networks); bad != "" {
					return fmt.Errorf("host %q: network %s not contained by any ca.networks prefix", h.Label, bad)
				}
			}
			if len(cfg.CA.UnsafeNetworks) > 0 {
				if bad := prefixesNotContained(h.UnsafeNetworks, cfg.CA.UnsafeNetworks); bad != "" {
					return fmt.Errorf("host %q: unsafe_network %s not contained by any ca.unsafe_networks prefix", h.Label, bad)
				}
			}
			if cfg.CA.HasDuration && h.HasDuration && h.Duration > cfg.CA.Duration {
				return fmt.Errorf("host %q: duration %s exceeds ca.duration %s", h.Label, h.Duration, cfg.CA.Duration)
			}
		}
	}
	return nil
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

func firstDuplicateDir(dirs []string) string {
	seen := make(map[string]string, len(dirs))
	for _, d := range dirs {
		n := filepath.Clean(d)
		if orig, ok := seen[n]; ok {
			return orig
		}
		seen[n] = d
	}
	return ""
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
