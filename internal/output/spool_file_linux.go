//go:build linux

package output

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openSpoolFile(dir string) (*os.File, error) {
	// O_TMPFILE allocates an inode on this filesystem without creating a
	// directory entry. Even SIGKILL cannot leave an abandoned spool file.
	fd, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err == nil {
		return os.NewFile(uintptr(fd), filepath.Join(dir, "saase-spool")), nil
	}
	if err != unix.EOPNOTSUPP && err != unix.EINVAL && err != unix.EISDIR && err != unix.ENOSYS {
		return nil, fmt.Errorf("open result spool in %s: %w", dir, err)
	}
	// Older filesystems may not support O_TMPFILE. Unlink immediately after
	// opening so the kernel still reclaims the file when the process exits.
	return openUnlinkedSpoolFile(dir)
}
