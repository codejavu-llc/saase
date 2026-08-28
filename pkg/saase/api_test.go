package saase

import (
	"context"
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
