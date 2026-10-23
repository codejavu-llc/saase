package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codejavu-llc/saase/v2/internal/catalog"
	"github.com/codejavu-llc/saase/v2/internal/engine"
	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
	builtin "github.com/codejavu-llc/saase/v2/rules"
)

type lowMemoryResolver struct{}

func (lowMemoryResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{"slack-domain-verification=test"}, nil
}
func (lowMemoryResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	return name, nil
}
func (lowMemoryResolver) LookupMX(context.Context, string) ([]*net.MX, error) { return nil, nil }
func (lowMemoryResolver) LookupNS(context.Context, string) ([]*net.NS, error) { return nil, nil }
func (lowMemoryResolver) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", nil, nil
}
func (lowMemoryResolver) LookupHost(context.Context, string) ([]string, error) { return nil, nil }

func TestLowMemoryScanJSONAndJSONL(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(home, ".saase", "tmp")
	c, err := catalog.Load(builtin.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "jsonl"} {
		cfg := engine.DefaultConfig()
		cfg.TrackDNSProgress = true
		scanner, err := engine.New(cfg, c)
		if err != nil {
			t.Fatal(err)
		}
		scanner.SetResolver(lowMemoryResolver{})
		path := filepath.Join(t.TempDir(), "report."+format)
		options := scanOptions{format: format, outputFile: path, progress: true, providers: stringList{"slack"}}
		var stdout, stderr bytes.Buffer
		err = runLowMemoryScan(context.Background(), scanner, []target.Target{{Host: "example.com"}}, options, &stdout, &stderr)
		if err != nil {
			t.Fatal(err)
		}
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(saved, stdout.Bytes()) {
			t.Fatal("saved report differs from stdout")
		}
		if format == "json" {
			var report model.ScanReport
			if err := json.Unmarshal(saved, &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) != 1 || report.Findings[0].ProviderID != "slack" || report.Metadata.Targets != 1 {
				t.Fatalf("report: %+v", report)
			}
		} else {
			var finding model.Finding
			if err := json.Unmarshal(saved, &finding); err != nil || finding.ProviderID != "slack" {
				t.Fatalf("finding=%+v err=%v", finding, err)
			}
		}
		if strings.Contains(stdout.String(), "[DNS") || !strings.Contains(stderr.String(), "0 remaining") {
			t.Fatal("progress missing or mixed into JSON")
		}
		leftovers, err := filepath.Glob(filepath.Join(temporary, "saase-*.jsonl"))
		if err != nil || len(leftovers) > 0 {
			t.Fatalf("temporary files remain: %v err=%v", leftovers, err)
		}
	}
}

type failingTXTResolver struct{ lowMemoryResolver }

func (failingTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, context.DeadlineExceeded
}

func TestTXTOnlyFailureExit(t *testing.T) {
	c, err := catalog.Load(builtin.FS)
	if err != nil {
		t.Fatal(err)
	}
	cfg := engine.DefaultConfig()
	cfg.RecordType = "TXT"
	scanner, err := engine.New(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	scanner.SetResolver(failingTXTResolver{})
	var stdout, stderr bytes.Buffer
	err = runLowMemoryScan(context.Background(), scanner, []target.Target{{Host: "example.com"}}, scanOptions{format: "json"}, &stdout, &stderr)
	failure, ok := err.(exitError)
	if !ok || failure.code != 2 {
		t.Fatalf("expected primary DNS failure exit, got %v", err)
	}
	var report model.ScanReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Errors) != 1 || report.Errors[0].Detector != "dns/txt" || report.Metadata.RecordType != "TXT" {
		t.Fatalf("report: %+v", report)
	}
}
