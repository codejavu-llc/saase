package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/catalog"
	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/output"
	"github.com/codejavu-llc/saase/v2/internal/target"
	builtin "github.com/codejavu-llc/saase/v2/rules"
)

func TestScanToDoesNotRetainResults(t *testing.T) {
	s := testScanner(t, DefaultConfig())
	s.SetResolver(fakeResolver{txt: []string{"slack-domain-verification=a", "slack-domain-verification=b"}})
	targets := make([]target.Target, 1000)
	for i := range targets {
		targets[i] = target.Target{Host: fmt.Sprintf("test%d.example.com", i)}
	}
	delivered := 0
	report, err := s.ScanTo(context.Background(), targets, []string{"slack"}, func(findings []model.Finding, failures []model.ProbeError) error {
		if len(findings) != 1 || len(failures) != 0 {
			t.Fatalf("target results: %d findings, %d errors", len(findings), len(failures))
		}
		delivered++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if delivered != 1000 || report.Metadata.Targets != 1000 || len(report.Findings) != 0 || len(report.Errors) != 0 {
		t.Fatalf("delivered=%d retained=%d errors=%d", delivered, len(report.Findings), len(report.Errors))
	}
}

func TestScanToSinkFailureCancels(t *testing.T) {
	s := testScanner(t, DefaultConfig())
	s.SetResolver(fakeResolver{})
	targets := make([]target.Target, 1000)
	for i := range targets {
		targets[i] = target.Target{Host: fmt.Sprintf("test%d.example.com", i)}
	}
	want := errors.New("disk full")
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.ScanTo(ctx, targets, nil, func([]model.Finding, []model.ProbeError) error { calls++; return want })
	if !errors.Is(err, want) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	if _, err := s.ScanTo(ctx, targets, nil, nil); err == nil {
		t.Fatal("nil sink accepted")
	}
}

type memoryBenchmarkResolver struct{ fakeResolver }

func (r memoryBenchmarkResolver) LookupTXT(context.Context, string) ([]string, error) {
	records := make([]string, len(r.txt))
	for i, value := range r.txt {
		records[i] = strings.Clone(value)
	}
	return records, nil
}

// This synthetic workload retains 32 large TXT evidence values per domain.
// The metric measures peak live heap growth, not total allocations.
func BenchmarkScanResultMemory(b *testing.B) {
	for _, stream := range []bool{false, true} {
		name := "retained"
		if stream {
			name = "spool"
		}
		b.Run(name, func(b *testing.B) {
			c, err := catalog.Load(builtin.FS)
			if err != nil {
				b.Fatal(err)
			}
			cfg := DefaultConfig()
			cfg.ShowSensitiveEvidence = true
			s, err := New(cfg, c)
			if err != nil {
				b.Fatal(err)
			}
			records := make([]string, 32)
			for i := range records {
				records[i] = fmt.Sprintf("slack-domain-verification=%d%s", i, strings.Repeat("x", 1024))
			}
			s.SetResolver(memoryBenchmarkResolver{fakeResolver{txt: records}})
			targets := make([]target.Target, 1000)
			for i := range targets {
				targets[i] = target.Target{Host: fmt.Sprintf("test%d.example.com", i)}
			}
			runtime.GC()
			runtime.GC() // Drop encoding/json pool buffers from the previous sub-benchmark.
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			var peak atomic.Uint64
			peak.Store(before.HeapAlloc)
			sample := func() {
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				for old := peak.Load(); m.HeapAlloc > old; old = peak.Load() {
					if peak.CompareAndSwap(old, m.HeapAlloc) {
						break
					}
				}
			}
			done := make(chan struct{})
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				ticker := time.NewTicker(5 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						sample()
					case <-done:
						return
					}
				}
			}()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var report model.ScanReport
				if stream {
					spool, createErr := output.NewSpool()
					if createErr != nil {
						b.Fatal(createErr)
					}
					report, err = s.ScanTo(context.Background(), targets, []string{"slack"}, spool.Add)
					if err == nil {
						err = spool.Write(io.Discard, report.Metadata, "json")
					}
					spool.Close()
				} else {
					report, err = s.Scan(context.Background(), targets, []string{"slack"})
					if err == nil {
						err = output.Write(io.Discard, report, output.Options{Format: "json"})
					}
				}
				sample()
				runtime.KeepAlive(report)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			close(done)
			<-stopped
			b.ReportMetric(float64(peak.Load()-before.HeapAlloc)/(1024*1024), "peak-extra-MiB")
		})
	}
}
