package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/model"
)

func TestSaveLoadRecentAndDiff(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "saase.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	before := model.ScanReport{Metadata: model.ScanMetadata{ScanID: "one", StartedAt: time.Now().Add(-time.Hour), Profile: "passive", TargetNames: []string{"example.com"}}, Findings: []model.Finding{{Target: "example.com", ProviderID: "slack", Provider: "Slack", Confidence: model.ConfidenceMedium}, {Target: "example.com", ProviderID: "github", Provider: "GitHub", Confidence: model.ConfidenceHigh}}}
	after := model.ScanReport{Metadata: model.ScanMetadata{ScanID: "two", StartedAt: time.Now(), Profile: "passive", TargetNames: []string{"example.com"}}, Findings: []model.Finding{{Target: "example.com", ProviderID: "slack", Provider: "Slack", Confidence: model.ConfidenceHigh}, {Target: "example.com", ProviderID: "okta", Provider: "Okta", Confidence: model.ConfidenceHigh}}}
	ctx := context.Background()
	if err := database.Save(ctx, before); err != nil {
		t.Fatal(err)
	}
	if err := database.Save(ctx, after); err != nil {
		t.Fatal(err)
	}
	loaded, err := database.Load(ctx, "two")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Findings) != 2 {
		t.Fatalf("loaded findings = %d", len(loaded.Findings))
	}
	scans, err := database.Recent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 || scans[0].ID != "two" {
		t.Fatalf("recent scans = %#v", scans)
	}
	changes := Diff(before, after)
	if len(changes) != 3 {
		t.Fatalf("changes = %#v", changes)
	}
}

func TestCacheExpiryAndVersion(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "saase.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if err := database.PutCache(ctx, "key", "v1", time.Now().Add(time.Hour), []byte("value")); err != nil {
		t.Fatal(err)
	}
	value, ok, err := database.GetCache(ctx, "key", "v1")
	if err != nil || !ok || string(value) != "value" {
		t.Fatalf("cache = %q %v %v", value, ok, err)
	}
	if _, ok, _ := database.GetCache(ctx, "key", "v2"); ok {
		t.Fatal("cache ignored detector version")
	}
	if err := database.PutCache(ctx, "expired", "v1", time.Now().Add(-time.Second), []byte("old")); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := database.GetCache(ctx, "expired", "v1"); err != nil || ok {
		t.Fatalf("expired cache ok=%v err=%v", ok, err)
	}
}
