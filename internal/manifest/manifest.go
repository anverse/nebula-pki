// Package manifest is the typed representation of nebula-pki.json, the
// git-committable record of what the tool last produced. It is the source
// of truth for idempotency (see spec/adr/002-state-and-artifact-layout.md).
//
// This package is pure on the data side: it marshals and unmarshals JSON
// and never decides what should change. It also never *writes* the file —
// that mutation belongs to internal/apply via internal/fsutil. Reading is
// allowed here because a read is not a mutation.
//
// The manifest contains no secret material. Fingerprints are SHA256 sums
// of the public certificates; paths are strings, never file contents.
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// SchemaVersion is the current manifest format version. It is bumped only
// on an incompatible change to this structure.
const SchemaVersion = 1

// GeneratorName is the fixed generator identifier recorded in every
// manifest.
const GeneratorName = "nebula-pki"

// Manifest is the top-level nebula-pki.json document.
type Manifest struct {
	SchemaVersion int             `json:"schema_version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Generator     Generator       `json:"generator"`
	ConfigPath    string          `json:"config_path"`
	TrustBundle   *TrustBundle    `json:"trust_bundle,omitempty"`
	CAs           map[string]*CA  `json:"cas"`
	Hosts         map[string]Host `json:"hosts"`
}

// TrustBundle records the emitted CA trust bundle artifact.
// Path is where bundle.crt was written (logical, relative to manifest dir when
// possible). CAFingerprints lists, in bundle order, the SHA-256 fingerprint of
// every active CA cert included — lets downstream tooling verify mesh trust
// without parsing PEM.
type TrustBundle struct {
	Path           string   `json:"path"`
	CAFingerprints []string `json:"ca_fingerprints"`
}

// Generator identifies the tool (and, later, the pinned upstream library)
// that produced the manifest.
type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CA is the certificate-authority record. Mode is "generate" or
// "reference".
type CA struct {
	Mode        string    `json:"mode"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	Curve       string    `json:"curve"`
	Version     int       `json:"version"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	CertPath    string    `json:"cert_path"`
	KeyPath     string    `json:"key_path"`
	Default     bool      `json:"default,omitempty"`
}

// Host is a signed host record.
type Host struct {
	CA             string     `json:"ca"`
	Name           string     `json:"name"`
	Fingerprint    string     `json:"fingerprint"`
	Networks       []string   `json:"networks"`
	Groups         []string   `json:"groups,omitempty"`
	UnsafeNetworks []string   `json:"unsafe_networks,omitempty"`
	Duration       string     `json:"duration,omitempty"`
	NotBefore      time.Time  `json:"not_before"`
	NotAfter       time.Time  `json:"not_after"`
	CAFingerprint  string     `json:"ca_fingerprint"`
	Artifacts      []Artifact `json:"artifacts"`
}

// Artifact is one resolved destination for a host's cert/key pair.
// KeyPath is omitted for in_pub hosts (air-gapped signing: cert only, no
// key is ever written by the tool).
type Artifact struct {
	Dir      string `json:"dir,omitempty"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path,omitempty"`
}

// New returns an empty manifest with the current schema version and
// initialised (non-nil) maps, so they marshal as {} rather than null.
func New() *Manifest {
	return &Manifest{
		SchemaVersion: SchemaVersion,
		Generator:     Generator{Name: GeneratorName},
		CAs:           map[string]*CA{},
		Hosts:         map[string]Host{},
	}
}

// Load reads and parses the manifest at path. A missing file is not an
// error: it returns a fresh empty manifest, which callers treat as
// "nothing has been produced yet". A present file with an unsupported
// schema_version is an error.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if m.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf(
			"manifest %s has schema_version %d, but this build of nebula-pki supports %d",
			path, m.SchemaVersion, SchemaVersion,
		)
	}
	if m.CAs == nil {
		m.CAs = map[string]*CA{}
	}
	if m.Hosts == nil {
		m.Hosts = map[string]Host{}
	}
	return &m, nil
}

// Marshal renders the manifest as indented JSON with a trailing newline.
// It is pure: callers persist the bytes (atomically) themselves.
func Marshal(m *Manifest) ([]byte, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	return append(data, '\n'), nil
}
