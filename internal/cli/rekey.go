package cli

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/crypto"
	"github.com/anverse/nebula-pki/internal/fsutil"
	"github.com/anverse/nebula-pki/internal/manifest"
	"github.com/spf13/cobra"
)

const (
	rekeyKeyMode      fs.FileMode = 0o600
	rekeyManifestMode fs.FileMode = 0o644
)

func newRekeyCmd(configPath *string) *cobra.Command {
	var dryRun, force bool
	cmd := &cobra.Command{
		Use:   "rekey",
		Short: "synchronize encryption of managed private key files with the current storage config",
		Long: `rekey synchronizes the encryption of all managed private key files with the
current storage backend config. This operates on key files at rest — it has
nothing to do with Nebula network certificates or tunnel encryption.

It handles three cases in one pass:

  plaintext to encrypted   storage encryption added to config
  encrypted to re-encrypted  recipients or backend changed
  encrypted to plaintext   encryption block removed from config

Without --force, only files with a detectable mismatch are processed.
Files encrypted using .sops.yaml-only mode (no inline recipients) store no
recipients hash; use --force after rotating .sops.yaml keys.

The manifest is updated only when all files succeed. On partial failure,
re-running rekey is safe — already-matching files are skipped.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRekey(cmd, *configPath, dryRun, force)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would change; no writes")
	cmd.Flags().BoolVar(&force, "force", false, "process all managed key files regardless of detected mismatch")
	return cmd
}

func runRekey(cmd *cobra.Command, configPath string, dryRun, force bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	newEnc, err := crypto.New(cfg.Storage.Encryption)
	if err != nil {
		return err
	}

	manifestReal := cfg.Resolve(cfg.ManifestPath())
	m, err := manifest.Load(manifestReal)
	if err != nil {
		return err
	}

	entries := collectRekeyEntries(m, newEnc, force)
	if len(entries) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "nothing to rekey")
		return nil
	}

	if dryRun {
		printRekeyPlan(cmd.OutOrStdout(), entries, newEnc)
		return nil
	}

	for _, e := range entries {
		if err := rekeyOne(cfg, e, newEnc, m); err != nil {
			return err
		}
	}

	data, err := manifest.Marshal(m)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFile(manifestReal, data, rekeyManifestMode); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	n := len(entries)
	noun := "key file"
	if n != 1 {
		noun = "key files"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%d %s rekeyed\n", n, noun)
	return nil
}

// rekeyEntry is one key file candidate for rekeying.
type rekeyEntry struct {
	label      string
	kind       string // "CA" or "host"
	artIdx     int    // artifact index within host (-1 for CA)
	logPath    string // manifest-recorded logical path
	encryption *manifest.EncryptionRecord
}

// collectRekeyEntries gathers entries to process. Without force, only entries
// with a detectable mismatch against newEnc are included.
func collectRekeyEntries(m *manifest.Manifest, newEnc crypto.Encryptor, force bool) []rekeyEntry {
	var entries []rekeyEntry

	caLabels := sortedKeys(m.CAs)
	for _, label := range caLabels {
		ca := m.CAs[label]
		if ca == nil || ca.Mode == "reference" || ca.KeyPath == "" {
			continue
		}
		if !force && !needsRekey(ca.Encryption, newEnc) {
			continue
		}
		if force && ca.Encryption == nil && newEnc.BackendName() == "none" {
			continue
		}
		entries = append(entries, rekeyEntry{
			label:      label,
			kind:       "CA",
			artIdx:     -1,
			logPath:    ca.KeyPath,
			encryption: ca.Encryption,
		})
	}

	hostLabels := sortedKeys(m.Hosts)
	for _, label := range hostLabels {
		h := m.Hosts[label]
		if h.InPub {
			continue
		}
		for i, art := range h.Artifacts {
			if art.KeyPath == "" {
				continue
			}
			if !force && !needsRekey(art.Encryption, newEnc) {
				continue
			}
			if force && art.Encryption == nil && newEnc.BackendName() == "none" {
				continue
			}
			entries = append(entries, rekeyEntry{
				label:      label,
				kind:       "host",
				artIdx:     i,
				logPath:    art.KeyPath,
				encryption: art.Encryption,
			})
		}
	}

	return entries
}

func needsRekey(rec *manifest.EncryptionRecord, enc crypto.Encryptor) bool {
	if rec == nil {
		return enc.Suffix() != ""
	}
	if enc.BackendName() == "none" {
		return true
	}
	if rec.Backend != enc.BackendName() {
		return true
	}
	if rec.Suffix != enc.Suffix() {
		return true
	}
	if rec.RecipientsHash != "" && enc.RecipientsHash() != "" && rec.RecipientsHash != enc.RecipientsHash() {
		return true
	}
	return false
}

func rekeyOne(cfg *config.Config, e rekeyEntry, newEnc crypto.Encryptor, m *manifest.Manifest) error {
	diskPath := cfg.Resolve(e.logPath)
	data, err := os.ReadFile(diskPath)
	if err != nil {
		return fmt.Errorf("rekey %s %q: read %s: %w", e.kind, e.label, e.logPath, err)
	}

	plaintext := data
	if e.encryption != nil {
		dec, err := crypto.NewDecryptorForRecord(e.encryption.Backend, cfg.Storage.Encryption)
		if err != nil {
			return fmt.Errorf("rekey %s %q: %w", e.kind, e.label, err)
		}
		plaintext, err = dec.Decrypt(data)
		if err != nil {
			return fmt.Errorf("rekey %s %q: decrypt: %w", e.kind, e.label, err)
		}
	}

	base := keyBasePath(e.logPath, e.encryption)
	newLogPath := base + newEnc.Suffix()

	if newEnc.BackendName() == "none" {
		if err := fsutil.WriteFile(cfg.Resolve(newLogPath), plaintext, rekeyKeyMode); err != nil {
			return fmt.Errorf("rekey %s %q: write: %w", e.kind, e.label, err)
		}
	} else {
		ciphertext, err := newEnc.Encrypt(plaintext, cfg.Resolve(newLogPath))
		if err != nil {
			return fmt.Errorf("rekey %s %q: encrypt: %w", e.kind, e.label, err)
		}
		if err := fsutil.WriteFile(cfg.Resolve(newLogPath), ciphertext, rekeyKeyMode); err != nil {
			return fmt.Errorf("rekey %s %q: write: %w", e.kind, e.label, err)
		}
	}

	if newLogPath != e.logPath {
		if rmErr := os.Remove(diskPath); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("rekey %s %q: remove old key %s: %w", e.kind, e.label, e.logPath, rmErr)
		}
	}

	var newEncRec *manifest.EncryptionRecord
	if newEnc.BackendName() != "none" {
		newEncRec = &manifest.EncryptionRecord{
			Backend:        newEnc.BackendName(),
			RecipientsHash: newEnc.RecipientsHash(),
			Suffix:         newEnc.Suffix(),
		}
	}
	updateRekeyManifest(m, e, newLogPath, newEncRec)
	return nil
}

func updateRekeyManifest(m *manifest.Manifest, e rekeyEntry, newLogPath string, newEncRec *manifest.EncryptionRecord) {
	if e.kind == "CA" {
		ca := m.CAs[e.label]
		ca.KeyPath = newLogPath
		ca.Encryption = newEncRec
		return
	}
	h := m.Hosts[e.label]
	h.Artifacts[e.artIdx].KeyPath = newLogPath
	h.Artifacts[e.artIdx].Encryption = newEncRec
	m.Hosts[e.label] = h
}

func keyBasePath(logPath string, enc *manifest.EncryptionRecord) string {
	if enc != nil && enc.Suffix != "" {
		return strings.TrimSuffix(logPath, enc.Suffix)
	}
	return logPath
}

func printRekeyPlan(w io.Writer, entries []rekeyEntry, newEnc crypto.Encryptor) {
	for _, e := range entries {
		base := keyBasePath(e.logPath, e.encryption)
		newLogPath := base + newEnc.Suffix()
		action, detail := rekeyAction(e.encryption, newEnc)
		if e.logPath == newLogPath {
			fmt.Fprintf(w, "would %s %s %q key: %s (%s)\n", action, e.kind, e.label, e.logPath, detail)
		} else {
			fmt.Fprintf(w, "would %s %s %q key: %s to %s (%s)\n", action, e.kind, e.label, e.logPath, newLogPath, detail)
		}
	}
	n := len(entries)
	noun := "key file"
	if n != 1 {
		noun = "key files"
	}
	fmt.Fprintf(w, "%d %s would be rekeyed\n", n, noun)
}

func rekeyAction(oldRec *manifest.EncryptionRecord, newEnc crypto.Encryptor) (action, detail string) {
	switch {
	case oldRec == nil:
		return "encrypt", newEnc.BackendName()
	case newEnc.BackendName() == "none":
		return "decrypt", "plaintext"
	case oldRec.Backend != newEnc.BackendName():
		return "re-encrypt", oldRec.Backend + " to " + newEnc.BackendName()
	case oldRec.RecipientsHash != "" && oldRec.RecipientsHash != newEnc.RecipientsHash():
		return "re-encrypt", newEnc.BackendName() + ", new recipients"
	default:
		return "re-encrypt", newEnc.BackendName() + ", forced"
	}
}

// sortedKeys returns the sorted keys of a map. It works for map[string]*T and
// map[string]T through two separate type-constrained helpers below.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
