//go:build linux

package output

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSpoolUsesRequestedFilesystemWithoutDirectoryEntries(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := newSpoolInDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	parent, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*os.File{s.findings, s.errors} {
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Dev != parent.Sys().(*syscall.Stat_t).Dev {
			t.Fatal("spool uses a different filesystem")
		}
		if stat.Nlink != 0 {
			t.Fatalf("spool has %d directory links; SIGKILL could leave files", stat.Nlink)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("spool permissions: %v", info.Mode())
		}
	}
	// Closing one scan must not remove another scan's spool or unrelated files.
	other, err := newSpoolInDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	marker := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(marker, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s.Close()
	if _, err := other.findings.Write([]byte("still active")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal(err)
	}
}
