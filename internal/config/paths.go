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

// CA artifact default sub-paths under storage.out_dir.
const (
	defaultCACertName = "ca.crt"
	defaultCAKeyName  = "ca.key"
	caSubdir          = "ca"
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

// CACertPath returns the logical path of the CA certificate: the explicit
// ca.out_crt when set, otherwise <out_dir>/ca/ca.crt.
func (c *Config) CACertPath() string {
	if c.CA.OutCRT != "" {
		return c.CA.OutCRT
	}
	return filepath.Join(c.Storage.OutDir, caSubdir, defaultCACertName)
}

// CAKeyPath returns the logical path of the CA private key: the explicit
// ca.out_key when set, otherwise <out_dir>/ca/ca.key.
func (c *Config) CAKeyPath() string {
	if c.CA.OutKey != "" {
		return c.CA.OutKey
	}
	return filepath.Join(c.Storage.OutDir, caSubdir, defaultCAKeyName)
}

// ManifestPath returns the logical path of the manifest. Storage decoding
// always populates Storage.ManifestFile (defaulting to
// <out_dir>/nebula-pki.json), so this is a simple accessor.
func (c *Config) ManifestPath() string {
	return c.Storage.ManifestFile
}
