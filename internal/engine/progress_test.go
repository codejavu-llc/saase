package engine

import (
	"context"
	"testing"

	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
)

func TestDNSProgressCountsAndCache(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrackDNSProgress = true
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{cnames: map[string]string{"example.com": "acme.zendesk.com."}})
	s.SetCache(&memoryCache{})
	targets := []target.Target{{Host: "example.com"}, {Host: "example.org"}}
	var events []model.DNSProgress
	s.SetEventHandler(func(event model.ScanEvent) {
		if event.DNSProgress != nil {
			events = append(events, *event.DNSProgress)
		}
	})
	if _, err := s.Scan(context.Background(), targets, nil); err != nil {
		t.Fatal(err)
	}
	first, last := events[0], events[len(events)-1]
	if first.Total != 210 || first.Remaining != 210 {
		t.Fatalf("initial progress: %+v", first)
	}
	// One root CNAME adds a single address lookup to the original plan.
	if last.Total != 211 || last.Completed != 211 || last.Remaining != 0 || last.Skipped != 0 || !last.Finished {
		t.Fatalf("final progress: %+v", last)
	}
	for _, event := range events {
		if event.Remaining < 0 || event.Remaining != event.Total-event.Completed-event.Skipped {
			t.Fatalf("inconsistent progress: %+v", event)
		}
	}
	events = nil
	if _, err := s.Scan(context.Background(), targets, nil); err != nil {
		t.Fatal(err)
	}
	last = events[len(events)-1]
	if last.Total != 210 || last.Completed != 0 || last.Skipped != 210 || last.Remaining != 0 || !last.Finished {
		t.Fatalf("cache progress: %+v", last)
	}
}

func TestDNSProgressProviderFilterAndOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := DefaultConfig()
		cfg.TrackDNSProgress = enabled
		s := testScanner(t, cfg)
		s.SetResolver(fakeResolver{})
		var events []model.DNSProgress
		s.SetEventHandler(func(e model.ScanEvent) {
			if e.DNSProgress != nil {
				events = append(events, *e.DNSProgress)
			}
		})
		targets := []target.Target{{Host: "example.com"}}
		if _, err := s.Scan(context.Background(), targets, []string{"slack"}); err != nil {
			t.Fatal(err)
		}
		if !enabled {
			if len(events) != 0 {
				t.Fatal("progress emitted without opt-in")
			}
			continue
		}
		selected, err := s.catalog.ResolveSelectors([]string{"slack"})
		if err != nil {
			t.Fatal(err)
		}
		planned := s.plannedDNSLookups(targets[0], selected)
		last := events[len(events)-1]
		if planned >= 105 || last.Total != planned || last.Completed != planned || last.Remaining != 0 {
			t.Fatalf("filtered progress: %+v, planned=%d", last, planned)
		}
	}
}

func TestDNSProgressInterrupted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrackDNSProgress = true
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{})
	var last model.DNSProgress
	s.SetEventHandler(func(e model.ScanEvent) {
		if e.DNSProgress != nil {
			last = *e.DNSProgress
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = s.Scan(ctx, []target.Target{{Host: "example.com"}}, nil)
	if !last.Finished || !last.Interrupted || last.Total != 105 || last.Remaining != last.Total-last.Completed-last.Skipped {
		t.Fatalf("interrupted progress: %+v", last)
	}
}
