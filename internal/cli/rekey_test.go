package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/crypto"
	"github.com/anverse/nebula-pki/internal/manifest"
)

// -- CLI wiring ---------------------------------------------------------------

func TestRekeyCmd_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"rekey", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"rekey", "dry-run", "force", "storage backend config"} {
		if !containsStr(out, want) {
			t.Errorf("help output missing %q:\n%s", want, out)
		}
	}
}

func TestRekeyCmd_UnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"rekey", "--does-not-exist"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for unknown flag, got nil")
	}
}

func TestRekeyCmd_MissingConfig(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	cmd := New(&stdout, &stderr)
	cmd.SetArgs([]string{"rekey", "-c", filepath.Join(dir, "nonexistent.hcl")})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing config, got nil")
	}
}

// -- needsRekey ---------------------------------------------------------------

func TestNeedsRekey(t *testing.T) {
	sopsEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "sops", Sops: &config.SopsConfig{
		Age: []string{"age1rtertzj2zyt36nl3lp8cqlcjgq3e584lhfurv7rf7fmyld4ldcese49nj9"},
	}})
	sopsEnc2 := mustNewEnc(t, config.EncryptionConfig{Backend: "sops", Sops: &config.SopsConfig{
		Age: []string{"age1ylsajqmdg4kd7u7s6mn6vxt35llrrpwj7nj578qcsx78g72w8uhqdzstdt"},
	}})
	sopsNilEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "sops"})
	sopsGpgEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "sops", Sops: &config.SopsConfig{
		Age:          []string{"age1rtertzj2zyt36nl3lp8cqlcjgq3e584lhfurv7rf7fmyld4ldcese49nj9"},
		OutputSuffix: ".gpg",
	}})
	noneEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "none"})
	extEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "external", External: &config.ExternalConfig{
		EncryptCommand: []string{"age", "--encrypt"},
		DecryptCommand: []string{"age", "--decrypt"},
	}})

	sopsRec := func(hash, suffix string) *manifest.EncryptionRecord {
		return &manifest.EncryptionRecord{Backend: "sops", RecipientsHash: hash, Suffix: suffix}
	}
	extRec := func(suffix string) *manifest.EncryptionRecord {
		return &manifest.EncryptionRecord{Backend: "external", Suffix: suffix}
	}

	cases := []struct {
		name string
		rec  *manifest.EncryptionRecord
		enc  crypto.Encryptor
		want bool
	}{
		{"plaintext stays none", nil, noneEnc, false},
		{"plaintext needs sops", nil, sopsEnc, true},
		{"plaintext needs external", nil, extEnc, true},
		{"sops stays same recipients", sopsRec(sopsEnc.RecipientsHash(), ".enc"), sopsEnc, false},
		{"sops recipients changed", sopsRec(sopsEnc.RecipientsHash(), ".enc"), sopsEnc2, true},
		{"sops yaml-only stays (no hash)", sopsRec("", ".enc"), sopsNilEnc, false},
		{"sops suffix changed", sopsRec(sopsEnc.RecipientsHash(), ".enc"), sopsGpgEnc, true},
		{"sops to none", sopsRec(sopsEnc.RecipientsHash(), ".enc"), noneEnc, true},
		{"sops to external", sopsRec(sopsEnc.RecipientsHash(), ".enc"), extEnc, true},
		{"external to none", extRec(".enc"), noneEnc, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := needsRekey(tc.rec, tc.enc)
			if got != tc.want {
				t.Errorf("needsRekey(%+v, %s) = %v, want %v", tc.rec, tc.enc.BackendName(), got, tc.want)
			}
		})
	}
}

// -- keyBasePath --------------------------------------------------------------

func TestKeyBasePath(t *testing.T) {
	cases := []struct {
		logPath string
		enc     *manifest.EncryptionRecord
		want    string
	}{
		{"out/ca/mesh.key.enc", &manifest.EncryptionRecord{Suffix: ".enc"}, "out/ca/mesh.key"},
		{"out/ca/mesh.key", nil, "out/ca/mesh.key"},
		{"out/ca/mesh.key", &manifest.EncryptionRecord{Suffix: ""}, "out/ca/mesh.key"},
		{"out/ca/mesh.key.gpg", &manifest.EncryptionRecord{Suffix: ".gpg"}, "out/ca/mesh.key"},
	}
	for _, tc := range cases {
		got := keyBasePath(tc.logPath, tc.enc)
		if got != tc.want {
			t.Errorf("keyBasePath(%q, %v) = %q, want %q", tc.logPath, tc.enc, got, tc.want)
		}
	}
}

// -- rekeyAction --------------------------------------------------------------

func TestRekeyAction(t *testing.T) {
	sopsEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "sops", Sops: &config.SopsConfig{
		Age: []string{"age1rtertzj2zyt36nl3lp8cqlcjgq3e584lhfurv7rf7fmyld4ldcese49nj9"},
	}})
	sopsGpgEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "sops", Sops: &config.SopsConfig{
		Age:          []string{"age1rtertzj2zyt36nl3lp8cqlcjgq3e584lhfurv7rf7fmyld4ldcese49nj9"},
		OutputSuffix: ".gpg",
	}})
	noneEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "none"})
	extEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "external", External: &config.ExternalConfig{
		EncryptCommand: []string{"e"},
		DecryptCommand: []string{"d"},
	}})

	cases := []struct {
		name       string
		rec        *manifest.EncryptionRecord
		enc        crypto.Encryptor
		wantAction string
		wantDetail string
	}{
		{
			"plaintext to sops",
			nil, sopsEnc,
			"encrypt", "sops",
		},
		{
			"sops to none",
			&manifest.EncryptionRecord{Backend: "sops", RecipientsHash: sopsEnc.RecipientsHash(), Suffix: ".enc"},
			noneEnc,
			"decrypt", "plaintext",
		},
		{
			"sops to external",
			&manifest.EncryptionRecord{Backend: "sops", RecipientsHash: sopsEnc.RecipientsHash(), Suffix: ".enc"},
			extEnc,
			"re-encrypt", "sops to external",
		},
		{
			"sops new recipients",
			&manifest.EncryptionRecord{Backend: "sops", RecipientsHash: "oldhash", Suffix: ".enc"},
			sopsEnc,
			"re-encrypt", "sops, new recipients",
		},
		{
			"sops new suffix",
			&manifest.EncryptionRecord{Backend: "sops", RecipientsHash: sopsEnc.RecipientsHash(), Suffix: ".enc"},
			sopsGpgEnc,
			"re-encrypt", "sops, new suffix",
		},
		{
			"sops forced (same recipients)",
			&manifest.EncryptionRecord{Backend: "sops", RecipientsHash: sopsEnc.RecipientsHash(), Suffix: ".enc"},
			sopsEnc,
			"re-encrypt", "sops, forced",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAction, gotDetail := rekeyAction(tc.rec, tc.enc)
			if gotAction != tc.wantAction {
				t.Errorf("action = %q, want %q", gotAction, tc.wantAction)
			}
			if gotDetail != tc.wantDetail {
				t.Errorf("detail = %q, want %q", gotDetail, tc.wantDetail)
			}
		})
	}
}

// -- collectRekeyEntries ------------------------------------------------------

func TestCollectRekeyEntries_SkipsReferenceCA(t *testing.T) {
	m := manifest.New()
	m.CAs["ref"] = &manifest.CA{Mode: "reference", KeyPath: "out/ca/ref.key"}

	noneEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "none"})
	sopsEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "sops"})

	if got := collectRekeyEntries(m, noneEnc, true); len(got) != 0 {
		t.Errorf("expected 0 entries for reference CA with none, got %d", len(got))
	}
	if got := collectRekeyEntries(m, sopsEnc, true); len(got) != 0 {
		t.Errorf("expected 0 entries for reference CA with sops, got %d", len(got))
	}
}

func TestCollectRekeyEntries_SkipsInPubHost(t *testing.T) {
	m := manifest.New()
	m.Hosts["inpub"] = manifest.Host{InPub: true, Artifacts: []manifest.Artifact{{CertPath: "out/hosts/inpub.crt"}}}

	sopsEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "sops", Sops: &config.SopsConfig{
		Age: []string{"age1rtertzj2zyt36nl3lp8cqlcjgq3e584lhfurv7rf7fmyld4ldcese49nj9"},
	}})

	if got := collectRekeyEntries(m, sopsEnc, true); len(got) != 0 {
		t.Errorf("expected 0 entries for in_pub host, got %d", len(got))
	}
}

func TestCollectRekeyEntries_PlaintextToEncrypted(t *testing.T) {
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", KeyPath: "out/ca/mesh.key", Encryption: nil}

	sopsEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "sops", Sops: &config.SopsConfig{
		Age: []string{"age1rtertzj2zyt36nl3lp8cqlcjgq3e584lhfurv7rf7fmyld4ldcese49nj9"},
	}})

	entries := collectRekeyEntries(m, sopsEnc, false)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].label != "mesh" || entries[0].kind != "CA" {
		t.Errorf("unexpected entry: %+v", entries[0])
	}
}

func TestCollectRekeyEntries_NoOpWithForce_BothNone(t *testing.T) {
	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{Mode: "generate", KeyPath: "out/ca/mesh.key", Encryption: nil}

	noneEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "none"})
	entries := collectRekeyEntries(m, noneEnc, true)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries when both sides are none, got %d", len(entries))
	}
}

func TestCollectRekeyEntries_EncryptedToReencrypted(t *testing.T) {
	sopsEnc := mustNewEnc(t, config.EncryptionConfig{Backend: "sops", Sops: &config.SopsConfig{
		Age: []string{"age1rtertzj2zyt36nl3lp8cqlcjgq3e584lhfurv7rf7fmyld4ldcese49nj9"},
	}})
	sopsEnc2 := mustNewEnc(t, config.EncryptionConfig{Backend: "sops", Sops: &config.SopsConfig{
		Age: []string{"age1ylsajqmdg4kd7u7s6mn6vxt35llrrpwj7nj578qcsx78g72w8uhqdzstdt"},
	}})

	m := manifest.New()
	m.CAs["mesh"] = &manifest.CA{
		Mode:    "generate",
		KeyPath: "out/ca/mesh.key.enc",
		Encryption: &manifest.EncryptionRecord{
			Backend:        "sops",
			RecipientsHash: sopsEnc.RecipientsHash(),
			Suffix:         ".enc",
		},
	}

	// Hash mismatch without --force → entry collected.
	entries := collectRekeyEntries(m, sopsEnc2, false)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry for hash mismatch, got %d", len(entries))
	}
	if entries[0].label != "mesh" || entries[0].kind != "CA" {
		t.Errorf("unexpected entry: %+v", entries[0])
	}

	// Same encryptor → no mismatch → no entry.
	entries = collectRekeyEntries(m, sopsEnc, false)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries when hash matches, got %d", len(entries))
	}
}

// -- helpers ------------------------------------------------------------------

func mustNewEnc(t *testing.T, enc config.EncryptionConfig) crypto.Encryptor {
	t.Helper()
	b, err := crypto.New(enc)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	return b
}

func containsStr(s, sub string) bool { return strings.Contains(s, sub) }
