package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/codejavu-llc/saase/v2/internal/model"
)

func TestSpoolRoundTripAndCleanup(t *testing.T) {
	s, err := newSpoolInDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	names := []string{s.findings.Name(), s.errors.Name()}
	findings := []model.Finding{{Target: "example.com", ProviderID: "slack", Evidence: []model.Evidence{{Value: strings.Repeat("x", 100000)}}}, {Target: "example.org", ProviderID: "google-workspace"}}
	failures := []model.ProbeError{{Target: "example.org", Kind: "timeout", Message: "DNS timeout"}}
	if err := s.Add(findings, failures); err != nil {
		t.Fatal(err)
	}
	metadata := model.ScanMetadata{Targets: 2, TargetNames: []string{"example.com", "example.org"}}
	var buf bytes.Buffer
	if err := s.Write(&buf, metadata, "json"); err != nil {
		t.Fatal(err)
	}
	var report model.ScanReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.Findings, findings) || !reflect.DeepEqual(report.Errors, failures) || !reflect.DeepEqual(report.Metadata, metadata) {
		t.Fatal("spool changed report data")
	}
	buf.Reset()
	if err := s.Write(&buf, metadata, "jsonl"); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&buf)
	for _, want := range findings {
		var got model.Finding
		if err := decoder.Decode(&got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("JSONL changed finding")
		}
	}
	s.Close()
	for _, name := range names {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("temporary spool remains: %s", name)
		}
	}
}

func TestSpoolEmptyAndIOErrors(t *testing.T) {
	s, err := newSpoolInDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var buf bytes.Buffer
	if err := s.Write(&buf, model.ScanMetadata{}, "json"); err != nil {
		t.Fatal(err)
	}
	var report model.ScanReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil || report.Findings != nil || report.Errors != nil {
		t.Fatalf("empty report: %s err=%v", &buf, err)
	}
	if err := s.Write(failingSpoolWriter{}, model.ScanMetadata{}, "json"); err == nil {
		t.Fatal("ignored output failure")
	}
	_ = s.findings.Close()
	if err := s.Add([]model.Finding{{Target: "example.com"}}, nil); err == nil {
		t.Fatal("ignored spool failure")
	}
}

type failingSpoolWriter struct{}

func (failingSpoolWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }
