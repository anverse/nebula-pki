package config

import (
	"strings"
	"testing"
)

// TestPathSpelling_Cleaned checks that every configured path is stored in
// its one cleaned spelling, so plan, apply and the manifest never compare
// two spellings of one file.
func TestPathSpelling_Cleaned(t *testing.T) {
	src := `
ca "g" {
  name     = "g"
  default  = true
  out_crt  = "./out//ca/g.crt"
  out_key  = "out/ca/../ca/g.key"
  out_qr   = "./out/ca/g.png"
  link_crt = ["./links/", "out//shared"]
}
ca "r" {
  cert_file = "./ref/ca.crt"
  key_file  = "ref//ca.key"
}
trust_bundle "main" {
  ca_refs  = [ca.g]
  path     = "./out/b.crt"
  link_crt = ["./links/bundle/"]
}
cert "c" {
  networks   = ["10.0.0.1/16"]
  output_dir = "./out/c/"
  out_crt    = "./c.crt"
  out_key    = "sub/../c.key"
  out_qr     = "./c.png"
}
cert "p" {
  networks = ["10.0.0.2/16"]
  in_pub   = "./pub//p.pub"
}
storage {
  out_dir       = "./out/"
  manifest_file = "./out/m.json"
}
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	g, r := cfg.CAs[0], cfg.CAs[1]
	tb := cfg.TrustBundles[0]
	c, p := cfg.Certs[0], cfg.Certs[1]
	checks := []struct{ field, got, want string }{
		{"ca.out_crt", g.OutCRT, "out/ca/g.crt"},
		{"ca.out_key", g.OutKey, "out/ca/g.key"},
		{"ca.out_qr", g.OutQR, "out/ca/g.png"},
		{"ca.link_crt[0]", g.LinkCrt[0], "links"},
		{"ca.link_crt[1]", g.LinkCrt[1], "out/shared"},
		{"ca.cert_file", r.CertFile, "ref/ca.crt"},
		{"ca.key_file", r.KeyFile, "ref/ca.key"},
		{"trust_bundle.path", tb.Path, "out/b.crt"},
		{"trust_bundle.link_crt[0]", tb.LinkCrt[0], "links/bundle"},
		{"cert.output_dir", c.OutputDir, "out/c"},
		{"cert.out_crt", c.OutCRT, "c.crt"},
		{"cert.out_key", c.OutKey, "c.key"},
		{"cert.out_qr", c.OutQR, "c.png"},
		{"cert.in_pub", p.InPub, "pub/p.pub"},
		{"storage.out_dir", cfg.Storage.OutDir, "out"},
		{"storage.manifest_file", cfg.Storage.ManifestFile, "out/m.json"},
	}
	for _, ck := range checks {
		if ck.got != ck.want {
			t.Errorf("%s = %q, want %q", ck.field, ck.got, ck.want)
		}
	}
}

// TestPathSpelling_AbsoluteStaysAbsolute checks that cleaning keeps an
// absolute path absolute.
func TestPathSpelling_AbsoluteStaysAbsolute(t *testing.T) {
	cfg, err := Parse("t.hcl", []byte(`
ca "a" { name = "a" }
trust_bundle "main" {
  ca_refs = [ca.a]
  path    = "/srv//pki/./main.crt"
}
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.TrustBundles[0].Path; got != "/srv/pki/main.crt" {
		t.Errorf("path = %q, want /srv/pki/main.crt", got)
	}
}

// TestPathSpelling_Collisions checks that two spellings of one path clash
// like identical spellings do.
func TestPathSpelling_Collisions(t *testing.T) {
	tests := []struct{ name, src, want string }{
		{
			name: "bundle paths spelled differently",
			src: `
ca "a" { name = "a" }
trust_bundle "x" {
  ca_refs = [ca.a]
  path    = "./out/t.crt"
}
trust_bundle "y" {
  ca_refs = [ca.a]
  path    = "out/t.crt"
}
`,
			want: `path out/t.crt is used by trust_bundle "x" (path) and trust_bundle "y" (path)`,
		},
		{
			name: "link_crt directories spelled differently",
			src: `
ca "a" {
  name     = "a"
  link_crt = ["l", "./l/"]
}
`,
			want: `ca "a": link_crt[1]: duplicate directory "l"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("t.hcl", []byte(tt.src))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.want)
			}
		})
	}
}

// TestFilePath_MustNameAFile checks that every file field rejects a value
// that names a directory, and that directory fields accept a trailing
// separator.
func TestFilePath_MustNameAFile(t *testing.T) {
	type field struct {
		name  string
		owner string
		hcl   func(v string) string
	}
	// block renders one multi-line HCL block; single-line blocks allow only
	// one attribute.
	block := func(header string, attrs ...string) string {
		return header + " {\n" + strings.Join(attrs, "\n") + "\n}\n"
	}
	ca := `ca "a" {}` + "\n"
	net := `networks = ["10.0.0.1/16"]`
	fields := []field{
		{"out_crt", `ca "a"`, func(v string) string { return block(`ca "a"`, `out_crt = "`+v+`"`) }},
		{"out_key", `ca "a"`, func(v string) string { return block(`ca "a"`, `out_key = "`+v+`"`) }},
		{"out_qr", `ca "a"`, func(v string) string { return block(`ca "a"`, `out_qr = "`+v+`"`) }},
		{"cert_file", `ca "a"`, func(v string) string { return block(`ca "a"`, `cert_file = "`+v+`"`, `key_file = "k.key"`) }},
		{"key_file", `ca "a"`, func(v string) string { return block(`ca "a"`, `cert_file = "c.crt"`, `key_file = "`+v+`"`) }},
		{"path", `trust_bundle "main"`, func(v string) string {
			return ca + block(`trust_bundle "main"`, `ca_refs = [ca.a]`, `path = "`+v+`"`)
		}},
		{"out_crt", `cert "c"`, func(v string) string { return ca + block(`cert "c"`, net, `out_crt = "`+v+`"`) }},
		{"out_key", `cert "c"`, func(v string) string { return ca + block(`cert "c"`, net, `out_key = "`+v+`"`) }},
		{"out_qr", `cert "c"`, func(v string) string { return ca + block(`cert "c"`, net, `out_qr = "`+v+`"`) }},
		{"in_pub", `cert "c"`, func(v string) string { return ca + block(`cert "c"`, net, `in_pub = "`+v+`"`) }},
		{"manifest_file", `storage`, func(v string) string { return ca + block(`storage`, `manifest_file = "`+v+`"`) }},
	}
	for _, f := range fields {
		for _, v := range []string{"out/x/", ".", "./", "out/..", "/"} {
			t.Run(f.owner+"."+f.name+"="+v, func(t *testing.T) {
				_, err := Parse("t.hcl", []byte(f.hcl(v)))
				want := `t.hcl: ` + f.owner + `.` + f.name + `: "` + v + `" must name a file, not a directory`
				if err == nil {
					t.Fatalf("Parse succeeded, want error %q", want)
				}
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err.Error(), want)
				}
			})
		}
	}
}

func TestDirPath_TrailingSeparatorAccepted(t *testing.T) {
	cfg, err := Parse("t.hcl", []byte(`
ca "a" {
  name     = "a"
  link_crt = ["l/"]
}
trust_bundle "main" {
  ca_refs  = [ca.a]
  link_crt = ["lb/"]
}
cert "c" {
  networks   = ["10.0.0.1/16"]
  output_dir = "out/x/"
}
storage { out_dir = "o/" }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.CertArtifactPath(cfg.Certs[0]).CertPath; got != "out/x/c.crt" {
		t.Errorf("cert path = %q, want out/x/c.crt", got)
	}
	if got := cfg.TrustBundlePath(cfg.TrustBundles[0]); got != "o/bundles/main.crt" {
		t.Errorf("bundle path = %q, want o/bundles/main.crt", got)
	}
}
