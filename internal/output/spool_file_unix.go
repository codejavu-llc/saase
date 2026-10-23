//go:build !windows

package output

import "os"

func openUnlinkedSpoolFile(dir string) (*os.File, error) {
	f, err := os.CreateTemp(dir, "saase-spool-*.jsonl")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}
