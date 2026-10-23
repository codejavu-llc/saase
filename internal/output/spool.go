package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/codejavu-llc/saase/v2/internal/model"
)

// Spool holds report records on disk. Only one record is decoded at a time
// when exporting, so memory does not grow with the number of results.
// Add and Write must be called serially.
type Spool struct {
	findings, errors         *os.File
	closeOnce                sync.Once
	FindingCount, ErrorCount int
}

func NewSpool() (*Spool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locate home directory for result spool: %w", err)
	}
	return newSpoolInDir(filepath.Join(home, ".saase", "tmp"))
}

func newSpoolInDir(dir string) (*Spool, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create result spool directory: %w", err)
	}
	s := &Spool{}
	var err error
	s.findings, err = openSpoolFile(dir)
	if err != nil {
		return nil, err
	}
	s.errors, err = openSpoolFile(dir)
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Close is safe during cancellation while an operation is using the spool.
// The OS deletes the backing files when their last handles close.
func (s *Spool) Close() {
	s.closeOnce.Do(func() {
		for _, f := range []*os.File{s.findings, s.errors} {
			if f != nil {
				_ = f.Close()
			}
		}
	})
}

func (s *Spool) Add(findings []model.Finding, errors []model.ProbeError) error {
	for _, f := range findings {
		if err := json.NewEncoder(s.findings).Encode(f); err != nil {
			return fmt.Errorf("spool finding: %w", err)
		}
		s.FindingCount++
	}
	for _, e := range errors {
		if err := json.NewEncoder(s.errors).Encode(e); err != nil {
			return fmt.Errorf("spool error: %w", err)
		}
		s.ErrorCount++
	}
	return nil
}

func (s *Spool) Write(w io.Writer, metadata model.ScanMetadata, format string) error {
	if _, err := s.findings.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if format == "jsonl" {
		_, err := io.Copy(w, s.findings)
		return err
	}
	if format != "json" {
		return fmt.Errorf("unsupported spool format %q", format)
	}
	// A fixed-size buffer makes small writes efficient without encoding the
	// complete report in memory (encoding/json normally does that).
	out := bufio.NewWriter(w)
	if _, err := io.WriteString(out, "{\"metadata\":"); err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(metadata); err != nil {
		return err
	}
	if _, err := io.WriteString(out, ",\"findings\":"); err != nil {
		return err
	}
	if err := writeSpoolArray(out, s.findings, s.FindingCount); err != nil {
		return err
	}
	if s.ErrorCount > 0 {
		if _, err := s.errors.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.WriteString(out, ",\"errors\":"); err != nil {
			return err
		}
		if err := writeSpoolArray(out, s.errors, s.ErrorCount); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(out, "}\n"); err != nil {
		return err
	}
	return out.Flush()
}

func writeSpoolArray(w io.Writer, r io.Reader, count int) error {
	if count == 0 {
		_, err := io.WriteString(w, "null")
		return err
	}
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	decoder := json.NewDecoder(r)
	for i := 0; i < count; i++ {
		var record json.RawMessage
		if err := decoder.Decode(&record); err != nil {
			return err
		}
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if _, err := w.Write(record); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "]")
	return err
}
