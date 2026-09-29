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
