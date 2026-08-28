package output

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/model"
)

func sampleReport() model.ScanReport {
	return model.ScanReport{Metadata: model.ScanMetadata{ScanID: "scan-1", DurationMS: 12, Profile: "passive", Targets: 1, TargetNames: []string{"example.com"}, ProviderRules: 266}, Findings: []model.Finding{{
		SchemaVersion: model.SchemaVersion, Target: "example.com", ProviderID: "slack", Provider: "Slack", Category: "communication",
		Confidence: model.ConfidenceHigh, Tenant: "https://example.slack.com", ObservedAt: time.Unix(0, 0).UTC(),
		Evidence: []model.Evidence{{Signal: model.SignalTXT, Subject: "example.com", Value: "slack-domain-verification=<redacted>"}},
	}}}
}

func TestFormats(t *testing.T) {
	for _, format := range []string{"text", "json", "jsonl", "csv"} {
		t.Run(format, func(t *testing.T) {
			var buffer bytes.Buffer
			if err := Write(&buffer, sampleReport(), Options{Format: format, Verbose: true}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buffer.String(), "Slack") {
				t.Fatalf("output missing finding: %s", buffer.String())
			}
			if format == "jsonl" {
				var finding model.Finding
				if err := json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &finding); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, sampleReport(), Options{Format: "xml"}); err == nil {
		t.Fatal("unknown format accepted")
	}
	if err := WriteChanges(&bytes.Buffer{}, nil, "xml"); err == nil {
		t.Fatal("unknown diff format accepted")
	}
	if err := WriteScanList(&bytes.Buffer{}, nil, "xml"); err == nil {
		t.Fatal("unknown scan-list format accepted")
	}
}

func TestSilentAndColorText(t *testing.T) {
	var buffer bytes.Buffer
	if err := Write(&buffer, sampleReport(), Options{Format: "text", Silent: true}); err != nil {
		t.Fatal(err)
	}
	if got := buffer.String(); got != "example.com\tslack\thttps://example.slack.com\n" {
		t.Fatalf("silent output = %q", got)
	}
	buffer.Reset()
	if err := Write(&buffer, sampleReport(), Options{Format: "text", Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "\x1b[32mHIGH\x1b[0m") {
		t.Fatalf("color output = %q", buffer.String())
	}
}

func TestModernTextConsole(t *testing.T) {
	var buffer bytes.Buffer
	if err := Write(&buffer, sampleReport(), Options{Format: "text", Verbose: true}); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	for _, expected := range []string{
		"SAASE // EXPOSURE INTELLIGENCE",
		"SESSION   scan-1",
		"◆ 01  [HIGH]  Slack // slack",
		"└─ EVIDENCE",
		"DNS TXT",
		"SCAN COMPLETE",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("modern text output missing %q:\n%s", expected, output)
		}
	}
	if strings.Contains(output, "\x1b[") {
		t.Fatalf("non-color output contains ANSI escapes: %q", output)
	}
}

func TestModernEmptyScan(t *testing.T) {
	report := sampleReport()
	report.Findings = []model.Finding{}
	var buffer bytes.Buffer
	if err := Write(&buffer, report, Options{Format: "text"}); err != nil {
		t.Fatal(err)
	}
	if output := buffer.String(); !strings.Contains(output, "NO MATCHED SAAS SIGNALS") || !strings.Contains(output, "FINDINGS 0") {
		t.Fatalf("empty scan output = %q", output)
	}
}

func TestLiveWriterStreamsAndFinalizesFindings(t *testing.T) {
	report := sampleReport()
	report.Metadata.StartedAt = time.Now().Add(-time.Second)
	observed := report.Findings[0]
	observed.Confidence = model.ConfidenceMedium
	finalized := observed
	finalized.Confidence = model.ConfidenceConfirmed
	finalized.Evidence = append(finalized.Evidence, model.Evidence{Signal: model.SignalCNAME, Subject: "app.example.com", Value: "example.slack.com"})
	report.Findings = []model.Finding{finalized}

	var buffer bytes.Buffer
	live := NewLiveWriter(&buffer, Options{Format: "text", Verbose: true})
	metadata := report.Metadata
	live.Handle(model.ScanEvent{Type: model.ScanEventStarted, Metadata: &metadata})
	live.Handle(model.ScanEvent{Type: model.ScanEventFinding, Finding: &observed})
	if !strings.Contains(buffer.String(), "LIVE FINDINGS") || !strings.Contains(buffer.String(), "Slack // slack") {
		t.Fatalf("finding was not written before finish: %s", buffer.String())
	}
	if err := live.Finish(report); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if !strings.Contains(output, "finalized at [CONFIRMED]") || !strings.Contains(output, "SCAN COMPLETE") {
		t.Fatalf("live finalization output = %s", output)
	}
}

func TestLiveWriterSilentDeduplicatesImmediately(t *testing.T) {
	finding := sampleReport().Findings[0]
	var buffer bytes.Buffer
	live := NewLiveWriter(&buffer, Options{Format: "text", Silent: true})
	live.Handle(model.ScanEvent{Type: model.ScanEventFinding, Finding: &finding})
	live.Handle(model.ScanEvent{Type: model.ScanEventFinding, Finding: &finding})
	if got := buffer.String(); got != "example.com\tslack\thttps://example.slack.com\n" {
		t.Fatalf("live silent output = %q", got)
	}
	if err := live.Finish(sampleReport()); err != nil {
		t.Fatal(err)
	}
}

func TestLiveWriterSuppressesRepeatedSignalNoiseUnlessVerbose(t *testing.T) {
	base := sampleReport().Findings[0]
	base.Evidence = []model.Evidence{{Signal: model.SignalMX, Subject: "example.com", Value: "mx1.provider.test"}}
	update := base
	update.Evidence = []model.Evidence{{Signal: model.SignalMX, Subject: "example.com", Value: "mx2.provider.test"}}

	for _, test := range []struct {
		name    string
		verbose bool
		want    int
	}{
		{name: "default", want: 0},
		{name: "verbose", verbose: true, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var buffer bytes.Buffer
			live := NewLiveWriter(&buffer, Options{Format: "text", Verbose: test.verbose})
			live.Handle(model.ScanEvent{Type: model.ScanEventFinding, Finding: &base})
			live.Handle(model.ScanEvent{Type: model.ScanEventFinding, Finding: &update})
			if got := strings.Count(buffer.String(), "added DNS MX"); got != test.want {
				t.Fatalf("repeated MX updates = %d, want %d: %s", got, test.want, buffer.String())
			}
		})
	}
}

func TestLiveWriterReportsWriteErrors(t *testing.T) {
	live := NewLiveWriter(failingWriter{}, Options{Format: "text"})
	metadata := sampleReport().Metadata
	live.Handle(model.ScanEvent{Type: model.ScanEventStarted, Metadata: &metadata})
	if err := live.Finish(sampleReport()); err == nil {
		t.Fatal("live writer error lost")
	}
}

func TestChangesAndScanListFormats(t *testing.T) {
	before, after := model.ConfidenceMedium, model.ConfidenceHigh
	changes := []model.Change{{Type: model.ChangeConfidence, Target: "example.com", Provider: "Slack", Before: &before, After: &after}}
	for _, format := range []string{"text", "json", "jsonl"} {
		var buffer bytes.Buffer
		if err := WriteChanges(&buffer, changes, format); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buffer.String(), "Slack") {
			t.Fatalf("changes %s = %q", format, buffer.String())
		}
	}
	scans := []model.StoredScan{{ID: "scan-1", StartedAt: time.Unix(0, 0).UTC(), Profile: "passive", TargetList: []string{"example.com"}}}
	for _, format := range []string{"text", "json"} {
		var buffer bytes.Buffer
		if err := WriteScanList(&buffer, scans, format); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buffer.String(), "scan-1") {
			t.Fatalf("scan list %s = %q", format, buffer.String())
		}
	}
}

func TestEmptyChangesEncodeAsJSONArray(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteChanges(&buffer, []model.Change{}, "json"); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(buffer.String()); got != "[]" {
		t.Fatalf("empty JSON changes = %q, want []", got)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriterErrors(t *testing.T) {
	if err := Write(failingWriter{}, sampleReport(), Options{Format: "json"}); err == nil {
		t.Fatal("JSON writer error lost")
	}
	if err := WriteChanges(failingWriter{}, []model.Change{{Provider: "Slack"}}, "text"); err == nil {
		t.Fatal("change writer error lost")
	}
	if err := WriteScanList(failingWriter{}, []model.StoredScan{{ID: "one"}}, "text"); err == nil {
		t.Fatal("scan-list writer error lost")
	}
}
