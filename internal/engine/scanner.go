package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/catalog"
	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
)

type Config struct {
	Profile               string
	Active                bool
	Concurrency           int
	RateLimit             float64
	Timeout               time.Duration
	Retries               int
	Proxy                 string
	InsecureTLS           bool
	ShowSensitiveEvidence bool
	UserAgent             string
	CacheTTL              time.Duration
	DisableCache          bool
}

func DefaultConfig() Config {
	return Config{
		Profile: "passive", Concurrency: 20, RateLimit: 2, Timeout: 10 * time.Second, Retries: 2,
		UserAgent: "saase/2.0 (+https://github.com/codejavu-llc/saase)", CacheTTL: 24 * time.Hour,
	}
}

type Cache interface {
	GetCache(context.Context, string, string) ([]byte, bool, error)
	PutCache(context.Context, string, string, time.Time, []byte) error
}

type Scanner struct {
	cfg           Config
	catalog       *catalog.Catalog
	dns           DNSResolver
	http          *http.Client
	rate          *rateGate
	sem           chan struct{}
	cache         Cache
	eventMu       sync.RWMutex
	eventDispatch sync.Mutex
	eventHandler  func(model.ScanEvent)
}

func New(cfg Config, providerCatalog *catalog.Catalog) (*Scanner, error) {
	if providerCatalog == nil {
		return nil, fmt.Errorf("provider catalog is required")
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > 500 {
		return nil, fmt.Errorf("concurrency must be between 1 and 500")
	}
	if cfg.Timeout <= 0 || cfg.Timeout > 5*time.Minute {
		return nil, fmt.Errorf("timeout must be between 1ns and 5m")
	}
	if cfg.Retries < 0 || cfg.Retries > 10 {
		return nil, fmt.Errorf("retries must be between 0 and 10")
	}
	if cfg.RateLimit <= 0 || cfg.RateLimit > 1000 {
		return nil, fmt.Errorf("rate limit must be greater than 0 and no more than 1000")
	}
	if cfg.CacheTTL <= 0 || cfg.CacheTTL > 30*24*time.Hour {
		return nil, fmt.Errorf("cache TTL must be greater than 0 and no more than 720h")
	}
	if cfg.Profile == "" {
		cfg.Profile = "passive"
	}
	switch cfg.Profile {
	case "passive":
	case "standard", "deep":
		cfg.Active = true
	default:
		return nil, fmt.Errorf("unknown profile %q", cfg.Profile)
	}
	client, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Scanner{cfg: cfg, catalog: providerCatalog, dns: newNetResolver(), http: client, rate: newRateGate(cfg.RateLimit), sem: make(chan struct{}, cfg.Concurrency)}, nil
}

func (s *Scanner) SetResolver(resolver DNSResolver) {
	if resolver != nil {
		s.dns = resolver
	}
}

func (s *Scanner) SetHTTPClient(client *http.Client) {
	if client != nil {
		s.http = client
	}
}

func (s *Scanner) SetCache(cache Cache) { s.cache = cache }

// SetEventHandler registers a synchronous, ordered progress callback. Set it
// before Scan; handlers should return quickly to avoid slowing discovery.
func (s *Scanner) SetEventHandler(handler func(model.ScanEvent)) {
	s.eventMu.Lock()
	s.eventHandler = handler
	s.eventMu.Unlock()
}

func (s *Scanner) emit(event model.ScanEvent) {
	s.eventMu.RLock()
	handler := s.eventHandler
	s.eventMu.RUnlock()
	if handler == nil {
		return
	}
	s.eventDispatch.Lock()
	handler(event)
	s.eventDispatch.Unlock()
}

func (s *Scanner) observeFinding(finding model.Finding) model.Finding {
	copyOfFinding := finding
	copyOfFinding.Evidence = append([]model.Evidence(nil), finding.Evidence...)
	s.emit(model.ScanEvent{Type: model.ScanEventFinding, Finding: &copyOfFinding})
	return finding
}

func (s *Scanner) Scan(ctx context.Context, targets []target.Target, providerSelectors []string) (model.ScanReport, error) {
	if len(targets) == 0 {
		return model.ScanReport{}, fmt.Errorf("at least one target is required")
	}
	selected, err := s.catalog.ResolveSelectors(providerSelectors)
	if err != nil {
		return model.ScanReport{}, err
	}
	started := time.Now().UTC()
	report := model.ScanReport{Metadata: model.ScanMetadata{
		SchemaVersion: model.SchemaVersion, ScanID: scanID(), StartedAt: started, Profile: s.cfg.Profile,
		Active: s.cfg.Active, InsecureTLS: s.cfg.InsecureTLS, Targets: len(targets), ProviderRules: len(s.catalog.Providers()),
	}}
	for _, item := range targets {
		report.Metadata.TargetNames = append(report.Metadata.TargetNames, item.Apex)
	}
	startedMetadata := report.Metadata
	startedMetadata.TargetNames = append([]string(nil), report.Metadata.TargetNames...)
	s.emit(model.ScanEvent{Type: model.ScanEventStarted, Metadata: &startedMetadata})

	type targetResult struct {
		findings []model.Finding
		errors   []model.ProbeError
	}
	jobs := make(chan target.Target)
	results := make(chan targetResult, len(targets))
	workers := s.cfg.Concurrency
	if workers > len(targets) {
		workers = len(targets)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				findings, probeErrors := s.scanTargetCached(ctx, item, selected)
				results <- targetResult{findings: findings, errors: probeErrors}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, item := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- item:
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	for result := range results {
		report.Findings = append(report.Findings, result.findings...)
		report.Errors = append(report.Errors, result.errors...)
	}
	report.Findings = aggregate(report.Findings)
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Target != report.Findings[j].Target {
			return report.Findings[i].Target < report.Findings[j].Target
		}
		return report.Findings[i].Provider < report.Findings[j].Provider
	})
	finished := time.Now().UTC()
	report.Metadata.FinishedAt = finished
	report.Metadata.Duration = finished.Sub(started)
	report.Metadata.DurationMS = report.Metadata.Duration.Milliseconds()
	finishedMetadata := report.Metadata
	finishedMetadata.TargetNames = append([]string(nil), report.Metadata.TargetNames...)
	s.emit(model.ScanEvent{Type: model.ScanEventFinished, Metadata: &finishedMetadata})
	if ctx.Err() != nil && len(report.Findings) == 0 {
		return report, ctx.Err()
	}
	return report, nil
}

type cachedTargetResult struct {
	Findings []model.Finding    `json:"findings"`
	Errors   []model.ProbeError `json:"errors"`
}

func (s *Scanner) scanTargetCached(ctx context.Context, t target.Target, selected map[string]bool) ([]model.Finding, []model.ProbeError) {
	key := s.cacheKey(t, selected)
	version := catalog.CatalogVersion + ":" + s.catalog.Fingerprint() + ":engine-v2"
	if s.cache != nil && !s.cfg.DisableCache {
		if payload, ok, err := s.cache.GetCache(ctx, key, version); err == nil && ok {
			var cached cachedTargetResult
			if json.Unmarshal(payload, &cached) == nil {
				for _, finding := range cached.Findings {
					s.observeFinding(finding)
				}
				return cached.Findings, cached.Errors
			}
		}
	}
	findings, probeErrors := s.scanTarget(ctx, t, selected)
	if s.cache != nil && !s.cfg.DisableCache && ctx.Err() == nil {
		payload, _ := json.Marshal(cachedTargetResult{Findings: findings, Errors: probeErrors})
		_ = s.cache.PutCache(ctx, key, version, time.Now().Add(s.cfg.CacheTTL), payload)
	}
	return findings, probeErrors
}

func (s *Scanner) cacheKey(t target.Target, selected map[string]bool) string {
	providers := make([]string, 0, len(selected))
	for provider := range selected {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	value := strings.Join([]string{t.Apex, strings.Join(t.SlugCandidates, ","), strings.Join(providers, ","), s.cfg.Profile,
		fmt.Sprint(s.cfg.Active), fmt.Sprint(s.cfg.InsecureTLS), fmt.Sprint(s.cfg.ShowSensitiveEvidence),
		fmt.Sprintf("%d:%d:%d", len(s.catalog.Providers()), len(s.catalog.TXT), len(s.catalog.DNS))}, "|")
	sum := sha256.Sum256([]byte(value))
	return "target:" + hex.EncodeToString(sum[:])
}

func (s *Scanner) scanTarget(ctx context.Context, t target.Target, selected map[string]bool) ([]model.Finding, []model.ProbeError) {
	findings, probeErrors := s.passiveFindings(ctx, t, selected)
	if s.cfg.Active && ctx.Err() == nil {
		active, activeErrors := s.activeFindings(ctx, t, selected)
		findings = append(findings, active...)
		probeErrors = append(probeErrors, activeErrors...)
	}
	return findings, probeErrors
}

func (s *Scanner) passiveFindings(ctx context.Context, t target.Target, selected map[string]bool) ([]model.Finding, []model.ProbeError) {
	var findings []model.Finding
	var probeErrors []model.ProbeError

	txt, err := s.lookupTXT(ctx, t.Apex)
	if err != nil && !isDNSNotFound(err) {
		probeErrors = append(probeErrors, dnsError(t.Apex, "dns/txt", t.Apex, err))
	}
	for _, record := range txt {
		for _, rule := range s.catalog.TXT {
			provider, ok := s.catalog.Provider(rule.Name)
			if !ok || (len(selected) > 0 && !selected[provider.ID]) || !rule.Match(record) {
				continue
			}
			signal := model.SignalTXT
			confidence := model.ConfidenceHigh
			if rule.MatchType == "spf_include" {
				signal, confidence = model.SignalSPF, model.ConfidenceMedium
			}
			found := s.finding(t, provider, confidence, "passive/txt-v1", model.Evidence{
				Signal: signal, Subject: t.Apex, Value: s.safeTXT(record), Reference: rule.Reference, Sensitive: rule.MatchType != "spf_include",
			})
			found.RiskLead = "verification_record_review"
			findings = append(findings, s.observeFinding(found))
		}
	}

	mxRecords, err := s.lookupMX(ctx, t.Apex)
	if err != nil && !isDNSNotFound(err) {
		probeErrors = append(probeErrors, dnsError(t.Apex, "dns/mx", t.Apex, err))
	}
	for _, mx := range mxRecords {
		for _, rule := range s.catalog.DNS {
			provider, ok := s.catalog.Provider(rule.Name)
			if !ok || (len(selected) > 0 && !selected[provider.ID]) || !matchesAnyDNS(mx.Host, rule.MXTargets) {
				continue
			}
			found := s.finding(t, provider, model.ConfidenceMedium, "passive/mx-v1", model.Evidence{Signal: model.SignalMX, Subject: t.Apex, Value: strings.TrimSuffix(mx.Host, "."), Reference: rule.Reference})
			findings = append(findings, s.observeFinding(found))
		}
	}

	nsNames := map[string]bool{t.Apex: true}
	for _, rule := range s.catalog.DNS {
		if len(rule.NSTargets) == 0 {
			continue
		}
		for _, sub := range rule.SubdomainsToCheck {
			nsNames[sub+"."+t.Apex] = true
		}
	}
	for name := range nsNames {
		nsRecords, lookupErr := s.lookupNS(ctx, name)
		if lookupErr != nil {
			if !isDNSNotFound(lookupErr) && name == t.Apex {
				probeErrors = append(probeErrors, dnsError(t.Apex, "dns/ns", name, lookupErr))
			}
			continue
		}
		for _, ns := range nsRecords {
			for _, rule := range s.catalog.DNS {
				provider, ok := s.catalog.Provider(rule.Name)
				if !ok || (len(selected) > 0 && !selected[provider.ID]) || !matchesAnyDNS(ns.Host, rule.NSTargets) {
					continue
				}
				found := s.finding(t, provider, model.ConfidenceMedium, "passive/ns-v1", model.Evidence{Signal: model.SignalNS, Subject: name, Value: strings.TrimSuffix(ns.Host, "."), Reference: rule.Reference})
				findings = append(findings, s.observeFinding(found))
			}
		}
	}

	// The registrable domain can itself be a provider CNAME (for example,
	// hosted sites), so inspect it in addition to provider-specific labels.
	hosts := map[string]bool{t.Apex: true}
	for _, rule := range s.catalog.DNS {
		provider, ok := s.catalog.Provider(rule.Name)
		if !ok || (len(selected) > 0 && !selected[provider.ID]) {
			continue
		}
		for _, sub := range rule.SubdomainsToCheck {
			hosts[sub+"."+t.Apex] = true
		}
	}
	findings = append(findings, s.cnameFindings(ctx, t, selected, hosts, "passive/cname-v1", "")...)

	for _, service := range [][2]string{{"sip", "tcp"}, {"sip", "tls"}, {"autodiscover", "tcp"}, {"xmpp-server", "tcp"}, {"ldap", "tcp"}} {
		_, records, lookupErr := s.lookupSRV(ctx, service[0], service[1], t.Apex)
		if lookupErr != nil {
			continue
		}
		for _, record := range records {
			for _, rule := range s.catalog.DNS {
				provider, ok := s.catalog.Provider(rule.Name)
				if !ok || (len(selected) > 0 && !selected[provider.ID]) || !matchesAnyDNS(record.Target, rule.CNAMETargets) {
					continue
				}
				found := s.finding(t, provider, model.ConfidenceMedium, "passive/srv-v1", model.Evidence{Signal: model.SignalSRV, Subject: "_" + service[0] + "._" + service[1] + "." + t.Apex, Value: strings.TrimSuffix(record.Target, "."), Reference: rule.Reference})
				findings = append(findings, s.observeFinding(found))
			}
		}
	}
	return findings, probeErrors
}

func (s *Scanner) cnameFindings(ctx context.Context, t target.Target, selected map[string]bool, hosts map[string]bool, detector, reference string) []model.Finding {
	type cnameResult struct {
		host, cname string
		err         error
	}
	results := make(chan cnameResult, len(hosts))
	var wg sync.WaitGroup
	for host := range hosts {
		host := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := s.lookupCNAME(ctx, host)
			results <- cnameResult{host: host, cname: value, err: err}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	var findings []model.Finding
	for result := range results {
		if result.err != nil || catalog.DNSNameMatches(result.cname, result.host) {
			continue
		}
		dangling := false
		if _, hostErr := s.lookupHost(ctx, strings.TrimSuffix(result.cname, ".")); hostErr != nil && isDNSNotFound(hostErr) {
			dangling = true
		}
		for _, rule := range s.catalog.DNS {
			provider, ok := s.catalog.Provider(rule.Name)
			if !ok || (len(selected) > 0 && !selected[provider.ID]) || !matchesAnyDNS(result.cname, rule.CNAMETargets) {
				continue
			}
			evidenceReference := rule.Reference
			if evidenceReference == "" {
				evidenceReference = reference
			}
			finding := s.finding(t, provider, model.ConfidenceMedium, detector, model.Evidence{Signal: model.SignalCNAME, Subject: result.host, Value: strings.TrimSuffix(result.cname, "."), Reference: evidenceReference})
			if dangling {
				finding.RiskLead = "potential_dangling_tenant"
			}
			findings = append(findings, s.observeFinding(finding))
		}
	}
	return findings
}

func (s *Scanner) finding(t target.Target, p catalog.Provider, confidence model.Confidence, detector string, evidence model.Evidence) model.Finding {
	return model.Finding{SchemaVersion: model.SchemaVersion, Target: t.Apex, ProviderID: p.ID, Provider: p.Name, Category: p.Category,
		Description: p.Description, Website: p.Website, Confidence: confidence, Impact: p.Impact, Evidence: []model.Evidence{evidence},
		Detector: detector, ObservedAt: time.Now().UTC()}
}

func (s *Scanner) safeTXT(record string) string {
	record = strings.TrimSpace(record)
	if s.cfg.ShowSensitiveEvidence || strings.HasPrefix(strings.ToLower(record), "v=spf1") {
		return record
	}
	for _, delimiter := range []string{"=", ":"} {
		if index := strings.Index(record, delimiter); index >= 0 {
			return record[:index+1] + "<redacted>"
		}
	}
	if len(record) > 32 {
		return record[:16] + "…<redacted>"
	}
	return "<redacted>"
}

func matchesAnyDNS(value string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if catalog.DNSNameMatches(value, suffix) {
			return true
		}
	}
	return false
}

func aggregate(input []model.Finding) []model.Finding {
	byKey := make(map[string]model.Finding)
	for _, item := range input {
		key := item.Target + "\x00" + item.ProviderID
		current, exists := byKey[key]
		if !exists {
			byKey[key] = item
			continue
		}
		if item.Confidence.Rank() > current.Confidence.Rank() {
			current.Confidence = item.Confidence
		}
		if current.Tenant == "" {
			current.Tenant = item.Tenant
		}
		if current.RiskLead == "" {
			current.RiskLead = item.RiskLead
		}
		current.Evidence = appendUniqueEvidence(current.Evidence, item.Evidence...)
		if distinctSignals(current.Evidence) >= 2 {
			current.Confidence = model.ConfidenceConfirmed
		}
		if item.LatencyMS > current.LatencyMS {
			current.LatencyMS = item.LatencyMS
		}
		byKey[key] = current
	}
	output := make([]model.Finding, 0, len(byKey))
	for _, item := range byKey {
		output = append(output, item)
	}
	return output
}

func appendUniqueEvidence(existing []model.Evidence, additions ...model.Evidence) []model.Evidence {
	for _, addition := range additions {
		found := false
		for _, item := range existing {
			if item.Signal == addition.Signal && item.Subject == addition.Subject && item.Value == addition.Value {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, addition)
		}
	}
	return existing
}

func distinctSignals(evidence []model.Evidence) int {
	values := make(map[model.Signal]bool)
	for _, item := range evidence {
		values[item.Signal] = true
	}
	return len(values)
}

func dnsError(targetName, detector, subject string, err error) model.ProbeError {
	kind := "network"
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		kind = "timeout"
	}
	return model.ProbeError{Target: targetName, Detector: detector, Subject: subject, Kind: kind, Message: err.Error()}
}

func scanID() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("scan-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

func (s *Scanner) acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.sem <- struct{}{}:
		return nil
	}
}

func (s *Scanner) release() { <-s.sem }

func (s *Scanner) lookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	return s.dns.LookupTXT(lookupCtx, name)
}
func (s *Scanner) lookupCNAME(ctx context.Context, name string) (string, error) {
	if err := s.acquire(ctx); err != nil {
		return "", err
	}
	defer s.release()
	lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	return s.dns.LookupCNAME(lookupCtx, name)
}
func (s *Scanner) lookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	return s.dns.LookupMX(lookupCtx, name)
}
func (s *Scanner) lookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	return s.dns.LookupNS(lookupCtx, name)
}
func (s *Scanner) lookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	if err := s.acquire(ctx); err != nil {
		return "", nil, err
	}
	defer s.release()
	lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	return s.dns.LookupSRV(lookupCtx, service, proto, name)
}
func (s *Scanner) lookupHost(ctx context.Context, name string) ([]string, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	return s.dns.LookupHost(lookupCtx, name)
}
