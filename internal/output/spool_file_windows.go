//go:build windows

package output

import (
	"crypto/rand"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func openSpoolFile(dir string) (*os.File, error) {
	name := filepath.Join(dir, "saase-spool-"+rand.Text()+".jsonl")
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}
