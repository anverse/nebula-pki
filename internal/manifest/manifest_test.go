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
	if len(m.CAs) != 0 {
		t.Error("CAs = non-empty for missing manifest, want empty map")
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
	orig.CAs["mesh"] = &CA{
		Mode:        "generate",
		Name:        "test-mesh",
		Fingerprint: "f2a1c9deadbeef",
		Curve:       "25519",
		Version:     2,
		NotBefore:   t0,
		NotAfter:    t0.Add(8760 * time.Hour),
		CertPath:    filepath.Join("out", "ca", "mesh.crt"),
		KeyPath:     filepath.Join("out", "ca", "mesh.key"),
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
	ca := got.CAs["mesh"]
	if ca == nil || ca.Name != "test-mesh" || ca.Fingerprint != "f2a1c9deadbeef" {
		t.Errorf("CAs[mesh] round-trip mismatch: %+v", ca)
	}
	if !ca.NotAfter.Equal(orig.CAs["mesh"].NotAfter) {
		t.Errorf("NotAfter = %v, want %v", ca.NotAfter, orig.CAs["mesh"].NotAfter)
	}
}

// TestCAsSerialiseAsObject guards against the empty CAs map encoding as null.
func TestCAsSerialiseAsObject(t *testing.T) {
	data, err := Marshal(New())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(raw["cas"]) != "{}" {
		t.Errorf("cas = %s, want {}", raw["cas"])
	}
	if string(raw["hosts"]) != "{}" {
		t.Errorf("hosts = %s, want {}", raw["hosts"])
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
// Unmarshal-fails branch.
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
// artifact records.
func TestHostsAndArtifactsRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	orig := New()
	orig.GeneratedAt = t0
	orig.Generator.Version = "v0.0.3"
	orig.Hosts = map[string]Host{
		"alpha": {
			CA:             "mesh",
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

	var raw struct {
		Hosts map[string]struct {
			CA             string   `json:"ca"`
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
	if alpha.CA != "mesh" {
		t.Errorf("hosts.alpha.ca = %q, want mesh", alpha.CA)
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
	if gotHost.CA != "mesh" {
		t.Errorf("ca after load = %q, want mesh", gotHost.CA)
	}
}

// TestHostOptionalFieldsOmitEmpty pins the omitempty behaviour for
// optional host fields (Groups, UnsafeNetworks).
func TestHostOptionalFieldsOmitEmpty(t *testing.T) {
	t0 := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
	m := New()
	m.Hosts["bare"] = Host{
		CA:          "mesh",
		Name:        "bare",
		Fingerprint: "fp",
		Networks:    []string{"10.0.0.1/16"},
		// Groups and UnsafeNetworks deliberately omitted
		NotBefore:     t0,
		NotAfter:      t0.Add(8760 * time.Hour),
		CAFingerprint: "ca-fp",
		Artifacts:     []Artifact{{CertPath: "out/hosts/bare.crt", KeyPath: "out/hosts/bare.key"}},
	}

	data, err := Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)

	if strings.Contains(s, `"groups"`) {
		t.Errorf("JSON must not contain groups key when empty:\n%s", s)
	}
	if strings.Contains(s, `"unsafe_networks"`) {
		t.Errorf("JSON must not contain unsafe_networks key when empty:\n%s", s)
	}
	if !strings.Contains(s, `"networks"`) {
		t.Errorf("JSON must contain networks key:\n%s", s)
	}
	if !strings.Contains(s, `"artifacts"`) {
		t.Errorf("JSON must contain artifacts key:\n%s", s)
	}
	if !strings.Contains(s, `"ca_fingerprint"`) {
		t.Errorf("JSON must contain ca_fingerprint key:\n%s", s)
	}
}

// TestArtifactDirOmitEmpty pins the omitempty behaviour for Artifact fields.
func TestArtifactDirOmitEmpty(t *testing.T) {
	normal := Artifact{Dir: "out/hosts", CertPath: "x.crt", KeyPath: "x.key"}
	data, err := json.Marshal(normal)
	if err != nil {
		t.Fatalf("Marshal normal: %v", err)
	}
	if !strings.Contains(string(data), `"dir"`) {
		t.Errorf("normal artifact must contain dir: %s", data)
	}
	if !strings.Contains(string(data), `"key_path":"x.key"`) {
		t.Errorf("normal artifact must contain key_path: %s", data)
	}

	noDir := Artifact{CertPath: "x.crt", KeyPath: "x.key"}
	data, err = json.Marshal(noDir)
	if err != nil {
		t.Fatalf("Marshal no-dir: %v", err)
	}
	if strings.Contains(string(data), `"dir"`) {
		t.Errorf("no-dir artifact must not contain dir: %s", data)
	}
	if !strings.Contains(string(data), `"cert_path":"x.crt"`) {
		t.Errorf("no-dir artifact must contain cert_path: %s", data)
	}
	if !strings.Contains(string(data), `"key_path":"x.key"`) {
		t.Errorf("no-dir artifact must contain key_path: %s", data)
	}

	inPub := Artifact{Dir: "out/hosts", CertPath: "x.crt"}
	data, err = json.Marshal(inPub)
	if err != nil {
		t.Fatalf("Marshal in_pub: %v", err)
	}
	if strings.Contains(string(data), `"key_path"`) {
		t.Errorf("in_pub artifact must not contain key_path: %s", data)
	}
	if !strings.Contains(string(data), `"cert_path":"x.crt"`) {
		t.Errorf("in_pub artifact must contain cert_path: %s", data)
	}
}

// TestRoundTripNormalisesNonUTCTime documents that encoding/json renders
// time.Time as RFC3339; internal/apply normalises to UTC before marshalling.
func TestRoundTripNormalisesNonUTCTime(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	t0 := time.Date(2026, 6, 14, 12, 0, 0, 0, loc)

	orig := New()
	orig.GeneratedAt = t0
	orig.CAs["tz"] = &CA{
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

	if !got.GeneratedAt.Equal(t0) {
		t.Errorf("GeneratedAt instant changed: got %v, want %v", got.GeneratedAt, t0)
	}
	tzCA := got.CAs["tz"]
	if tzCA == nil {
		t.Fatal("CAs[tz] missing after round-trip")
	}
	if !tzCA.NotBefore.Equal(t0) {
		t.Errorf("NotBefore instant changed: got %v, want %v", tzCA.NotBefore, t0)
	}
}
