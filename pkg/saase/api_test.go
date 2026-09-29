package saase

import (
	"context"
	"strings"
	"testing"
)

func TestPublicAPI(t *testing.T) {
	cfg := DefaultConfig()
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(scanner.Providers()) != 266 {
		t.Fatalf("providers = %d, want 266", len(scanner.Providers()))
	}
	if _, err := scanner.Scan(context.Background(), []string{"invalid"}, nil); err == nil {
		t.Fatal("invalid target accepted")
	}
	target, err := NormalizeTarget("sub.example.co.uk", TargetOverrides{})
	if err != nil || target.Apex != "example.co.uk" {
		t.Fatalf("target = %#v, err=%v", target, err)
	}
}

func TestScanDeduplicatesFullHostnames(t *testing.T) {
	scanner, err := NewScanner(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	scanner.SetEventHandler(func(event ScanEvent) {
		if event.Type == ScanEventStarted {
			names = event.Metadata.TargetNames
		}
	})
	// Capture normalized scope without making network requests.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = scanner.Scan(ctx, []string{"example.com", "one.example.com", "two.example.com", "https://ONE.example.com.:443/path"}, nil)
	if strings.Join(names, ",") != "example.com,one.example.com,two.example.com" {
		t.Fatalf("scan targets = %v", names)
	}
}

func TestScanSlugs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Active = true
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Selecting only a domain-based provider must make no network requests.
	report, err := scanner.ScanSlugs(context.Background(), []string{"ACME", "acme", "beta"}, []string{"microsoft-365"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(report.Metadata.TargetNames, ",") != "acme,beta" || report.Metadata.Targets != 2 || len(report.Findings) != 0 || len(report.Errors) != 0 {
		t.Fatalf("report = %#v", report)
	}
	for _, slugs := range [][]string{nil, {"example.com"}} {
		if _, err := scanner.ScanSlugs(context.Background(), slugs, nil); err == nil {
			t.Fatalf("invalid slugs accepted: %v", slugs)
		}
	}
}
