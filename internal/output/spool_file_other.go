//go:build !linux && !windows

package output

import "os"

func openSpoolFile(dir string) (*os.File, error) { return openUnlinkedSpoolFile(dir) }
