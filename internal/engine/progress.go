package engine

import (
	"context"
	"sync"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
)

type dnsProgressKey struct{}
type dnsProgressTracker struct {
	mu    sync.Mutex
	state model.DNSProgress
	last  time.Time
	emit  func(model.ScanEvent)
}

func (p *dnsProgressTracker) update(total, completed, skipped int, final, interrupted bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state.Total += total
	p.state.Completed += completed
	p.state.Skipped += skipped
	p.state.Remaining = p.state.Total - p.state.Completed - p.state.Skipped
	p.state.Finished, p.state.Interrupted = final, interrupted
	if !final && !p.last.IsZero() && time.Since(p.last) < time.Second {
		return
	}
	p.last = time.Now()
	snapshot := p.state
	p.emit(model.ScanEvent{Type: model.ScanEventDNSProgress, DNSProgress: &snapshot})
}

func updateDNSProgress(ctx context.Context, total, completed, skipped int) {
	if p, ok := ctx.Value(dnsProgressKey{}).(*dnsProgressTracker); ok {
		p.update(total, completed, skipped, false, false)
	}
}

func (s *Scanner) nsNames(host string) map[string]bool {
	names := map[string]bool{host: true}
	for _, rule := range s.catalog.DNS {
		if len(rule.NSTargets) == 0 {
			continue
		}
		for _, sub := range rule.SubdomainsToCheck {
			names[sub+"."+host] = true
		}
	}
	return names
}

func (s *Scanner) cnameNames(host string, selected map[string]bool) map[string]bool {
	names := map[string]bool{host: true}
	for _, rule := range s.catalog.DNS {
		provider, ok := s.catalog.Provider(rule.Name)
		if !ok || (len(selected) > 0 && !selected[provider.ID]) {
			continue
		}
		for _, sub := range rule.SubdomainsToCheck {
			names[sub+"."+host] = true
		}
	}
	return names
}

func (s *Scanner) plannedDNSLookups(t target.Target, selected map[string]bool) int {
	if t.IsSlugOnly() {
		return 0
	}
	count := 0
	if s.recordEnabled("TXT") {
		count++
	}
	if s.recordEnabled("MX") {
		count++
	}
	if s.recordEnabled("NS") {
		count += len(s.nsNames(t.Host))
	}
	if s.recordEnabled("CNAME") {
		count += len(s.cnameNames(t.Host, selected))
	}
	if s.recordEnabled("SRV") {
		count += 5
	}
	return count
}
