package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if m.CA != nil {
		t.Error("CA = non-nil for missing manifest, want nil")
	}
	if m.Hosts == nil {
		t.Error("Hosts = nil, want initialised empty map")
	}
}

func TestMarshalLoadRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	orig := New()
	orig.GeneratedAt = t0
	orig.Generator.Version = "v0.0.3"
	orig.ConfigPath = "../nebula.hcl"
	orig.CA = &CA{
		Mode:        "generate",
		Name:        "test-mesh",
		Fingerprint: "f2a1c9deadbeef",
		Curve:       "25519",
		Version:     2,
		NotBefore:   t0,
		NotAfter:    t0.Add(8760 * time.Hour),
		CertPath:    filepath.Join("out", "ca", "ca.crt"),
		KeyPath:     filepath.Join("out", "ca", "ca.key"),
	}

	data, err := Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if data[len(data)-1] != '\n' {
		t.Error("marshalled manifest does not end with a newline")
	}

	path := filepath.Join(t.TempDir(), "nebula-pki.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, SchemaVersion)
	}
	if got.CA == nil || got.CA.Name != "test-mesh" || got.CA.Fingerprint != "f2a1c9deadbeef" {
		t.Errorf("CA round-trip mismatch: %+v", got.CA)
	}
	if !got.CA.NotAfter.Equal(orig.CA.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", got.CA.NotAfter, orig.CA.NotAfter)
	}
}

// TestHostsSerialiseAsObject guards against the empty hosts map encoding
// as null, which would break downstream `jq`-style consumers.
func TestHostsSerialiseAsObject(t *testing.T) {
	data, err := Marshal(New())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(raw["hosts"]) != "{}" {
		t.Errorf("hosts = %s, want {}", raw["hosts"])
	}
	// CA is omitempty, so an empty manifest must not carry a ca key.
	if _, ok := raw["ca"]; ok {
		t.Error("empty manifest unexpectedly contains a ca key")
	}
}

func TestLoadRejectsUnsupportedSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nebula-pki.json")
	if err := os.WriteFile(path, []byte(`{"schema_version": 999, "hosts": {}}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load: want error for schema_version 999, got nil")
	}
}

// TestLoadRejectsZeroSchema covers a manifest written by a tool that
// forgot to set the field at all (or by an attacker stripping it). Zero
// is the JSON default for missing integers; treating it as "no schema"
// instead of an explicit rejection would let callers silently misread a
// future-format file as v1.
func TestLoadRejectsZeroSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nebula-pki.json")
	if err := os.WriteFile(path, []byte(`{"hosts": {}}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: want error for missing schema_version (decoded as 0), got nil")
	}
	if !strings.Contains(err.Error(), "schema_version 0") {
		t.Errorf("error = %q, want it to mention 'schema_version 0'", err.Error())
	}
}

// TestLoadRejectsCorruptJSON covers the ReadFile-succeeds /
// Unmarshal-fails branch. A truncated or hand-edited manifest must not
// crash and must not be silently treated as an empty manifest (which
// would erase the next reconcile's planning input).
func TestLoadRejectsCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nebula-pki.json")
	if err := os.WriteFile(path, []byte(`{"schema_version": 1, "hosts": {`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: want error for truncated JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse manifest") {
		t.Errorf("error = %q, want it to wrap 'parse manifest'", err.Error())
	}
}

// TestHostsAndArtifactsRoundTrip pins the JSON shape of the host /
// artifact records. v0.0.3 doesn't write hosts yet, but the schema is
// frozen from day one (see spec/milestones/v0.1.md): a v0.0.5 release
// that decides to rename `cert_path` to `crt_path` would silently
// invalidate every committed manifest. This test fails loudly the moment
// any of those tags drift.
func TestHostsAndArtifactsRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	orig := New()
	orig.GeneratedAt = t0
	orig.Generator.Version = "v0.0.3"
	orig.Hosts = map[string]Host{
		"alpha": {
			Name:           "alpha.mesh",
			Fingerprint:    "abc123",
			Networks:       []string{"10.0.0.1/16"},
			Groups:         []string{"app", "edge"},
			UnsafeNetworks: []string{"192.168.1.0/24"},
			Duration:       "8760h",
			NotBefore:      t0,
			NotAfter:       t0.Add(8760 * time.Hour),
			CAFingerprint:  "ca-fp",
			Artifacts: []Artifact{
				{Dir: "out/hosts", CertPath: "out/hosts/alpha.mesh.crt", KeyPath: "out/hosts/alpha.mesh.key"},
				{Dir: "out/shared", CertPath: "out/shared/alpha.mesh.crt", KeyPath: "out/shared/alpha.mesh.key"},
			},
		},
	}

	data, err := Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Decode into a generic map and assert the JSON tag names rather
	// than just the round-tripped struct, so a tag rename is caught
	// even if the Go struct still works.
	var raw struct {
		Hosts map[string]struct {
			Name           string   `json:"name"`
			Fingerprint    string   `json:"fingerprint"`
			Networks       []string `json:"networks"`
			Groups         []string `json:"groups"`
			UnsafeNetworks []string `json:"unsafe_networks"`
			Duration       string   `json:"duration"`
			CAFingerprint  string   `json:"ca_fingerprint"`
			Artifacts      []struct {
				Dir      string `json:"dir"`
				CertPath string `json:"cert_path"`
				KeyPath  string `json:"key_path"`
			} `json:"artifacts"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	alpha, ok := raw.Hosts["alpha"]
	if !ok {
		t.Fatal("hosts.alpha missing from JSON")
	}
	if alpha.Name != "alpha.mesh" {
		t.Errorf("hosts.alpha.name = %q, want alpha.mesh", alpha.Name)
	}
	if alpha.UnsafeNetworks[0] != "192.168.1.0/24" {
		t.Errorf("hosts.alpha.unsafe_networks[0] = %q", alpha.UnsafeNetworks[0])
	}
	if alpha.CAFingerprint != "ca-fp" {
		t.Errorf("hosts.alpha.ca_fingerprint = %q", alpha.CAFingerprint)
	}
	if len(alpha.Artifacts) != 2 {
		t.Fatalf("artifacts: got %d, want 2", len(alpha.Artifacts))
	}
	if alpha.Artifacts[0].Dir != "out/hosts" || alpha.Artifacts[0].CertPath != "out/hosts/alpha.mesh.crt" {
		t.Errorf("artifact[0] = %+v", alpha.Artifacts[0])
	}

	// And: full struct round-trip via Load.
	path := filepath.Join(t.TempDir(), "nebula-pki.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	gotHost, ok := got.Hosts["alpha"]
	if !ok {
		t.Fatal("Load: hosts.alpha missing")
	}
	if len(gotHost.Artifacts) != 2 {
		t.Errorf("artifacts after load: got %d, want 2", len(gotHost.Artifacts))
	}
	if gotHost.Duration != "8760h" {
		t.Errorf("duration after load = %q, want 8760h", gotHost.Duration)
	}
}

// TestArtifactDirOmitEmpty pins the `omitempty` tag on Artifact.Dir.
// Single-destination hosts (the common case: no host.output_dirs set)
// produce one artifact with an empty Dir; emitting `"dir": ""` would
// be noise. Cert/key paths are always present and must NOT be omitted
// even when empty (so a malformed input is visible).
func TestArtifactDirOmitEmpty(t *testing.T) {
	a := Artifact{CertPath: "x.crt", KeyPath: "x.key"}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), `"dir"`) {
		t.Errorf("artifact JSON = %s, must not contain dir key when empty", data)
	}
	if !strings.Contains(string(data), `"cert_path":"x.crt"`) {
		t.Errorf("artifact JSON = %s, must contain cert_path", data)
	}
}

// TestRoundTripNormalisesNonUTCTime documents what currently happens to
// a time loaded from JSON: encoding/json renders time.Time as RFC3339,
// which preserves the instant but expresses it in UTC on the way back.
// internal/apply normalises to UTC explicitly before marshalling, so
// callers should rely on `.Equal()` rather than struct equality. This
// test pins that rule so a future refactor that switches to
// reflect.DeepEqual on Manifest (which would silently fail on tz drift)
// is caught immediately.
func TestRoundTripNormalisesNonUTCTime(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	t0 := time.Date(2026, 6, 14, 12, 0, 0, 0, loc)

	orig := New()
	orig.GeneratedAt = t0
	orig.CA = &CA{
		Mode:      "generate",
		Name:      "tz-test",
		NotBefore: t0,
		NotAfter:  t0.Add(time.Hour),
	}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "nebula-pki.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The instant survives — Equal compares wall-clock instants, not
	// monotonic / location identity.
	if !got.GeneratedAt.Equal(t0) {
		t.Errorf("GeneratedAt instant changed: got %v, want %v", got.GeneratedAt, t0)
	}
	if !got.CA.NotBefore.Equal(t0) {
		t.Errorf("NotBefore instant changed: got %v, want %v", got.CA.NotBefore, t0)
	}
}
