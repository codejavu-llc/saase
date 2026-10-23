package engine

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
)

type recordCountingResolver struct {
	fakeResolver
	mu    sync.Mutex
	calls map[string]int
}

func (r *recordCountingResolver) count(kind string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[kind]++
}
func (r *recordCountingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.count("TXT")
	return r.fakeResolver.LookupTXT(ctx, name)
}
func (r *recordCountingResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	r.count("MX")
	return r.fakeResolver.LookupMX(ctx, name)
}
func (r *recordCountingResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	r.count("NS")
	return r.fakeResolver.LookupNS(ctx, name)
}
func (r *recordCountingResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	r.count("CNAME")
	return r.fakeResolver.LookupCNAME(ctx, name)
}
func (r *recordCountingResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	r.count("SRV")
	return r.fakeResolver.LookupSRV(ctx, service, proto, name)
}
func (r *recordCountingResolver) LookupHost(ctx context.Context, name string) ([]string, error) {
	r.count("HOST")
	return r.fakeResolver.LookupHost(ctx, name)
}

func TestRecordTypeFilterSkipsOtherLookups(t *testing.T) {
	for kind, want := range map[string]int{"TXT": 1, "MX": 1, "NS": 5, "CNAME": 93, "SRV": 5} {
		t.Run(kind, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.RecordType = kind
			cfg.TrackDNSProgress = true
			s := testScanner(t, cfg)
			r := &recordCountingResolver{fakeResolver: fakeResolver{txt: []string{"slack-domain-verification=test"}}, calls: make(map[string]int)}
			s.SetResolver(r)
			var progress model.DNSProgress
			s.SetEventHandler(func(e model.ScanEvent) {
				if e.DNSProgress != nil {
					progress = *e.DNSProgress
				}
			})
			report, err := s.Scan(context.Background(), []target.Target{{Host: "example.com"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.calls) != 1 || r.calls[kind] != want {
				t.Fatalf("unexpected lookups: %v", r.calls)
			}
			if progress.Total != want || progress.Completed != want || progress.Remaining != 0 {
				t.Fatalf("progress: %+v", progress)
			}
			if report.Metadata.RecordType != kind {
				t.Fatalf("metadata: %+v", report.Metadata)
			}
			if kind == "TXT" && (len(report.Findings) != 1 || report.Findings[0].ProviderID != "slack") {
				t.Fatalf("TXT findings: %+v", report.Findings)
			}
		})
	}
}

func TestRecordTypeCacheIsolation(t *testing.T) {
	cfg := DefaultConfig()
	s := testScanner(t, cfg)
	base := s.cacheKey(target.Target{Host: "example.com"}, nil)
	cfg.RecordType = "all"
	all := testScanner(t, cfg)
	if all.cacheKey(target.Target{Host: "example.com"}, nil) != base {
		t.Fatal("explicit all changed cache identity")
	}
	cfg.RecordType = " txt "
	txt := testScanner(t, cfg)
	if txt.cfg.RecordType != "TXT" || txt.cacheKey(target.Target{Host: "example.com"}, nil) == base {
		t.Fatal("record filter not normalized or isolated")
	}
	cache := &memoryCache{}
	resolver := &recordCountingResolver{fakeResolver: fakeResolver{txt: []string{"slack-domain-verification=test"}}, calls: make(map[string]int)}
	s.SetCache(cache)
	s.SetResolver(resolver)
	txt.SetCache(cache)
	txt.SetResolver(resolver)
	targets := []target.Target{{Host: "example.com"}}
	if _, err := s.Scan(context.Background(), targets, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := txt.Scan(context.Background(), targets, nil); err != nil {
		t.Fatal(err)
	}
	if resolver.calls["TXT"] != 2 {
		t.Fatal("TXT-only scan reused full-scan cache")
	}
	if _, err := txt.Scan(context.Background(), targets, nil); err != nil {
		t.Fatal(err)
	}
	if resolver.calls["TXT"] != 2 {
		t.Fatal("TXT-only cache was not reused")
	}
	cfg.RecordType = "TXT,MX"
	if _, err := New(cfg, s.catalog); err == nil {
		t.Fatal("unsupported record type accepted")
	}
}
