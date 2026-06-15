// Package fsutil holds the low-level filesystem primitives nebula-pki
// uses to persist artifacts. It is deliberately tiny: an atomic
// WriteFile and an existence check.
//
// The single reason this package exists rather than calling os.WriteFile
// directly is durability. os.WriteFile truncates and streams bytes into
// the target in place, so an interrupted write (Ctrl-C, OOM, full disk,
// power loss) leaves a torn file at the real path — an unrecoverable
// ca.key or a corrupt manifest. WriteFile here writes to a temp file in
// the same directory and renames it over the target; rename(2) is atomic
// within a filesystem, so a reader or a crash-recovery run sees either
// the old contents or the complete new contents, never a stump.
//
// See spec/adr/013-atomic-artifact-writes.md for the full rationale and
// the boundaries of this guarantee (it is per-file, not a cross-file
// transaction).
package fsutil

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Directory mode for parent directories created on demand. Matches the
// 0755 mandated by spec/adr/002-state-and-artifact-layout.md.
const dirMode fs.FileMode = 0o755

// WriteFile atomically writes data to path with the given mode, creating
// parent directories as needed.
//
// The write is performed to a temporary file in the same directory as
// path (so the final rename stays within one filesystem and is therefore
// atomic) created with the final mode, then fsync'd and renamed over the
// target. On any error the temporary file is removed and the existing
// target, if any, is left untouched.
func WriteFile(path string, data []byte, mode fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, dirMode); mkErr != nil {
		return fmt.Errorf("create directory %s: %w", dir, mkErr)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	// Ensure the temp file is cleaned up on any failure path. After a
	// successful rename tmpName no longer exists, so the Remove is a
	// harmless no-op.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	// Set the final mode explicitly: CreateTemp makes 0600 files, which
	// is fine for keys but wrong for 0644 artifacts like the manifest.
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}

	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}

	// Flush to stable storage before the rename so the bytes are durable,
	// not just the directory entry.
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}

	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file over %s: %w", path, err)
	}
	return nil
}

// Exists reports whether a file or directory exists at path. Any error
// other than fs.ErrNotExist (for example a permission problem) is treated
// as "does not exist" for planning purposes; the subsequent write or read
// surfaces the real error with context.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
