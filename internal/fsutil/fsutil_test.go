package fsutil

import (
	"bytes"
	"crypto/rand"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestWriteFileCreatesParentsAndContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a", "b", "c", "ca.key")

	want := []byte("secret-key-bytes")
	if err := WriteFile(target, want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestWriteFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes not meaningful on windows")
	}
	dir := t.TempDir()

	cases := []struct {
		name string
		mode fs.FileMode
	}{
		{"key.enc", 0o600},
		{"manifest.json", 0o644},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(dir, tc.name)
			if err := WriteFile(target, []byte("x"), tc.mode); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			if info.Mode().Perm() != tc.mode {
				t.Errorf("mode = %o, want %o", info.Mode().Perm(), tc.mode)
			}
		})
	}
}

// TestWriteFileOverwriteIsAtomic verifies an existing file is replaced
// and that no temporary files are left behind in the directory.
func TestWriteFileOverwrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ca.crt")

	if err := WriteFile(target, []byte("v1"), 0o600); err != nil {
		t.Fatalf("WriteFile v1: %v", err)
	}
	if err := WriteFile(target, []byte("v2-longer"), 0o600); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "v2-longer" {
		t.Errorf("content = %q, want %q", got, "v2-longer")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "ca.crt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory entries = %v, want exactly [ca.crt] (no temp files left behind)", names)
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")

	if Exists(target) {
		t.Error("Exists = true before write, want false")
	}
	if err := WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !Exists(target) {
		t.Error("Exists = false after write, want true")
	}
}

// TestWriteFile_FailedWriteLeavesPreviousIntact is the central
// durability claim from spec/adr/013-atomic-artifact-writes.md: an
// interrupted or failing write must never leave a torn target. We force
// a CreateTemp failure (the parent directory is read-only at the moment
// of the second write) and then assert that (a) the call errored, (b)
// the previous content is still on disk byte-for-byte, and (c) no
// leftover temp files litter the directory.
func TestWriteFile_FailedWriteLeavesPreviousIntact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: 0500 dirs are still writable")
	}
	dir := t.TempDir()
	parent := filepath.Join(dir, "ro")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}

	target := filepath.Join(parent, "ca.key")
	original := []byte("original-secret-bytes")
	if err := WriteFile(target, original, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Make the directory unwritable so the next CreateTemp fails. The
	// pre-existing target file must survive untouched.
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("chmod ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	err := WriteFile(target, []byte("new-bytes-that-must-not-land"), 0o600)
	if err == nil {
		t.Fatal("WriteFile: want error when parent dir is read-only, got nil")
	}

	// Restore write permission so we can read back and inspect.
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatalf("chmod restore: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("target after failed write = %q, want previous content %q", got, original)
	}

	// No stray temp files alongside the target.
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "ca.key" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory entries = %v, want exactly [ca.key]", names)
	}
}

// TestWriteFile_PermissionDeniedOnFreshTarget covers the
// no-pre-existing-target arm of the durability story: a failed write
// into a read-only directory yields a clear error and leaves nothing
// behind.
func TestWriteFile_PermissionDeniedOnFreshTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits not meaningful on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: 0500 dirs are still writable")
	}
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatalf("mkdir ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })

	target := filepath.Join(ro, "ca.key")
	err := WriteFile(target, []byte("x"), 0o600)
	if err == nil {
		t.Fatal("WriteFile: want error for read-only parent, got nil")
	}
	if !strings.Contains(err.Error(), "create temp file") {
		t.Errorf("error = %q, want it to wrap 'create temp file'", err.Error())
	}

	// Restore so ReadDir works and check no temp file was left behind.
	if err := os.Chmod(ro, 0o755); err != nil {
		t.Fatalf("chmod restore: %v", err)
	}
	entries, err := os.ReadDir(ro)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory entries after failed write = %v, want empty", names)
	}
}

// TestWriteFile_UpdatesModeOnExistingTarget exercises the Chmod step:
// the comment in fsutil.go calls out that CreateTemp produces 0600 and
// we explicitly Chmod to the requested mode. Verify a 0644 manifest
// overwriting a 0600 file ends up at 0644 (not 0600 inherited from
// either the temp file or the previous target).
func TestWriteFile_UpdatesModeOnExistingTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes not meaningful on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "manifest.json")

	if err := WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile v1: %v", err)
	}
	if err := WriteFile(target, []byte("{}"), 0o644); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("mode = %o, want 0o644", got)
	}
}

// TestWriteFile_LargePayload guards against any silent buffering or
// short-write bug in the temp-file path.
func TestWriteFile_LargePayload(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "blob")

	// 1 MiB of random bytes — fits comfortably in a unit test, large
	// enough to expose a partial-write bug.
	want := make([]byte, 1<<20)
	if _, err := rand.Read(want); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if err := WriteFile(target, want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read-back differs from written bytes (len got=%d want=%d)", len(got), len(want))
	}
}

// TestWriteFile_ConcurrentWritesPickOneWinner pins the rename(2)
// atomicity contract: two writers racing on the same target must each
// see a clean success (no partial files, no leftover temp files), and
// the final content must be exactly one of the two payloads.
func TestWriteFile_ConcurrentWritesPickOneWinner(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "race")

	a := bytes.Repeat([]byte("A"), 4096)
	b := bytes.Repeat([]byte("B"), 4096)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, payload := range [][]byte{a, b} {
		payload := payload
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- WriteFile(target, payload, 0o600)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent WriteFile: %v", err)
		}
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, a) && !bytes.Equal(got, b) {
		t.Errorf("final content is neither winner; got %q...", got[:32])
	}

	// No stray temp files survived the race.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "race" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory entries after race = %v, want exactly [race]", names)
	}
}

// TestWriteFile_RenameFailsCleansUpTemp covers the last error branch in
// WriteFile: the rename step. We arrange for rename(2) to fail by
// pointing the target at an existing non-empty directory of the same
// name; on POSIX this returns ENOTDIR / EISDIR. The deferred cleanup
// must then remove the temp file so the parent directory is left with
// only the trap directory and no stray dotfiles.
func TestWriteFile_RenameFailsCleansUpTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rename-over-non-empty-directory semantics differ on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "ca.key")

	// Trap: a non-empty directory at the target path. rename(tmp,target)
	// fails because tmp is a regular file and target is a populated dir.
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir trap: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "block"), []byte("x"), 0o600); err != nil {
		t.Fatalf("populate trap: %v", err)
	}

	err := WriteFile(target, []byte("payload"), 0o600)
	if err == nil {
		t.Fatal("WriteFile: want error renaming over a non-empty directory, got nil")
	}
	if !strings.Contains(err.Error(), "rename temp file over") {
		t.Errorf("error = %q, want it to wrap 'rename temp file over'", err.Error())
	}

	// Walk the parent directory and assert no leftover ".ca.key.tmp-*"
	// dotfile survived. The trap directory itself is fine to find.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == "ca.key" {
			continue
		}
		t.Errorf("unexpected leftover %q in %s after rename failure", e.Name(), dir)
	}
}
