package config

import "path/filepath"

// Path resolution lives here, next to the parsed configuration that owns
// the relevant inputs (the config file location and the storage block).
// These helpers are pure string manipulation — no filesystem access — so
// they stay in `config` rather than in `fsutil`.
//
// "Logical" paths are the paths as they appear in (or default from) the
// HCL and as they are recorded in the manifest: relative to the config
// file's directory unless absolute. Resolve turns a logical path into an
// absolute-or-cwd-relative path suitable for actual I/O.

// CA artifact sub-directory under storage.out_dir.
const caSubdir = "ca"

// bundleFile is the default trust bundle filename under the CA sub-directory.
const bundleFile = "bundle.crt"

// Host artifact defaults.
const (
	hostsSubdir        = "hosts"
	defaultHostCertExt = ".crt"
	defaultHostKeyExt  = ".key"
)

// baseDir is the directory the configuration was loaded from. Relative
// logical paths resolve against it (see spec/adr/002). For in-memory
// loads (Parse with a bare filename) this is ".".
func (c *Config) baseDir() string {
	return filepath.Dir(c.Path)
}

// Resolve turns a logical path into one usable for filesystem I/O.
// Absolute paths are returned unchanged; relative paths are joined onto
// the config file's directory.
func (c *Config) Resolve(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.baseDir(), p)
}

// CACertPathForCA returns the logical path of the CA certificate for ca.
// In reference mode it is the operator-supplied cert_file (read in place,
// never rewritten). In generate mode it is the explicit out_crt when set,
// otherwise <out_dir>/ca/<label>.crt.
func (c *Config) CACertPathForCA(ca CA) string {
	if ca.Mode == CAModeReference {
		return ca.CertFile
	}
	if ca.OutCRT != "" {
		return ca.OutCRT
	}
	return filepath.Join(c.Storage.OutDir, caSubdir, ca.Label+".crt")
}

// CAKeyPathForCA returns the logical path of the CA private key for ca.
// In reference mode it is the operator-supplied key_file (read in place,
// never rewritten). In generate mode it is the explicit out_key when set,
// otherwise <out_dir>/ca/<label>.key.
func (c *Config) CAKeyPathForCA(ca CA) string {
	if ca.Mode == CAModeReference {
		return ca.KeyFile
	}
	if ca.OutKey != "" {
		return ca.OutKey
	}
	return filepath.Join(c.Storage.OutDir, caSubdir, ca.Label+".key")
}

// ManifestPath returns the logical path of the manifest. Storage decoding
// always populates Storage.ManifestFile (defaulting to
// <out_dir>/nebula-pki.json), so this is a simple accessor.
func (c *Config) ManifestPath() string {
	return c.Storage.ManifestFile
}

// TrustBundlePath returns the logical path of the emitted trust bundle.
// When storage.trust_bundle_file is set it is returned unchanged; otherwise
// the default <out_dir>/ca/bundle.crt is used.
func (c *Config) TrustBundlePath() string {
	if c.Storage.TrustBundleFile != "" {
		return c.Storage.TrustBundleFile
	}
	return filepath.Join(c.Storage.OutDir, caSubdir, bundleFile)
}

// ArtifactPath is the single (cert, key) destination for a host.
// Dir is populated when host.output_dir is explicitly set; it is empty
// when the default placement or out_crt/out_key-only paths are used.
type ArtifactPath struct {
	Dir      string
	CertPath string
	KeyPath  string
}

// HostArtifactPath returns the single destination a host's cert and key
// should be written to. This is the single source of truth used by both
// plan and apply.
//
// Path resolution (per ADR-020):
//
//	base = output_dir when set, else <storage.out_dir>/hosts
//	cert = filepath.Join(base, out_crt)  when out_crt is set
//	     = filepath.Join(base, <name>.crt) otherwise
//	key  = filepath.Join(base, out_key)  when out_key is set
//	     = filepath.Join(base, <name>.key) otherwise
func (c *Config) HostArtifactPath(h Host) ArtifactPath {
	var base, dir string
	if h.OutputDir != "" {
		base = h.OutputDir
		dir = h.OutputDir
	} else {
		base = filepath.Join(c.Storage.OutDir, hostsSubdir)
	}

	certCmp := h.Name + defaultHostCertExt
	if h.OutCRT != "" {
		certCmp = h.OutCRT
	}
	keyCmp := h.Name + defaultHostKeyExt
	if h.OutKey != "" {
		keyCmp = h.OutKey
	}

	return ArtifactPath{
		Dir:      dir,
		CertPath: filepath.Join(base, certCmp),
		KeyPath:  filepath.Join(base, keyCmp),
	}
}
