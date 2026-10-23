package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingTXTResolver struct {
	fakeResolver
	entered chan struct{}
	unblock chan struct{}
	active  atomic.Int32
	peak    atomic.Int32
}

func (r *blockingTXTResolver) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	active := r.active.Add(1)
	defer r.active.Add(-1)
	for peak := r.peak.Load(); active > peak; peak = r.peak.Load() {
		if r.peak.CompareAndSwap(peak, active) {
			break
		}
	}
	r.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.unblock:
		return nil, nil
	}
}

func TestDNSConcurrencyLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Concurrency = 20
	cfg.DNSConcurrency = 2
	s := testScanner(t, cfg)
	r := &blockingTXTResolver{entered: make(chan struct{}, 20), unblock: make(chan struct{})}
	s.SetResolver(r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.lookupTXT(ctx, "example.test"); err != nil {
				t.Error(err)
			}
		}()
	}
	for range 2 {
		select {
		case <-r.entered:
		case <-ctx.Done():
			t.Fatal("DNS lookups failed to start")
		}
	}
	// Every lookup type must respect the same saturated semaphore and cancel
	// while waiting, rather than invoking the resolver.
	canceled, stop := context.WithCancel(ctx)
	stop()
	calls := []func() error{
		func() error { _, err := s.lookupTXT(canceled, "example.test"); return err },
		func() error { _, err := s.lookupMX(canceled, "example.test"); return err },
		func() error { _, err := s.lookupNS(canceled, "example.test"); return err },
		func() error { _, err := s.lookupCNAME(canceled, "example.test"); return err },
		func() error { _, _, err := s.lookupSRV(canceled, "sip", "tcp", "example.test"); return err },
		func() error { _, err := s.lookupHost(canceled, "example.test"); return err },
	}
	for i, call := range calls {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Errorf("lookup %d: got %v, want cancellation", i, err)
		}
	}
	close(r.unblock)
	wg.Wait()
	if peak := r.peak.Load(); peak != 2 {
		t.Fatalf("peak DNS concurrency=%d, want 2", peak)
	}
	if len(s.sem) != 0 {
		t.Fatal("DNS permits leaked")
	}
}

func TestDNSConcurrencyConfig(t *testing.T) {
	for _, tc := range []struct{ workers, dns, want int }{{20, 0, 20}, {5, 0, 5}, {20, 3, 3}, {2, 10, 10}, {20, 500, 500}} {
		cfg := DefaultConfig()
		cfg.Concurrency = tc.workers
		cfg.DNSConcurrency = tc.dns
		s := testScanner(t, cfg)
		if cap(s.sem) != tc.want || s.cfg.Concurrency != tc.workers {
			t.Fatalf("config %+v: DNS capacity=%d workers=%d", tc, cap(s.sem), s.cfg.Concurrency)
		}
	}
	cfg := DefaultConfig()
	s := testScanner(t, cfg)
	for _, invalid := range []int{-1, 501} {
		cfg.DNSConcurrency = invalid
		if _, err := New(cfg, s.catalog); err == nil {
			t.Errorf("accepted DNS concurrency %d", invalid)
		}
	}
}
