package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/catalog"
	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
	builtin "github.com/codejavu-llc/saase/v2/rules"
)

type fakeResolver struct {
	txt    []string
	cnames map[string]string
	mx     []*net.MX
	ns     []*net.NS
}

func (f fakeResolver) LookupTXT(context.Context, string) ([]string, error) { return f.txt, nil }
func (f fakeResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	if value := f.cnames[name]; value != "" {
		return value, nil
	}
	return name + ".", &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
func (f fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) { return f.mx, nil }
func (f fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) { return f.ns, nil }
func (f fakeResolver) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}
func (f fakeResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	if strings.Contains(name, "zendesk.com") {
		return []string{"192.0.2.1"}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type memoryCache struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (m *memoryCache) GetCache(_ context.Context, key, version string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.values[version+key]
	return value, ok, nil
}
func (m *memoryCache) PutCache(_ context.Context, key, version string, _ time.Time, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		m.values = make(map[string][]byte)
	}
	m.values[version+key] = value
	return nil
}

func testScanner(t *testing.T, cfg Config) *Scanner {
	t.Helper()
	c, err := catalog.Load(builtin.FS)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func normalizedTarget(t *testing.T) target.Target {
	t.Helper()
	value, err := target.Normalize("example.com", target.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPassiveEvidenceAggregationAndRedaction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{
		txt:    []string{"slack-domain-verification=super-secret"},
		cnames: map[string]string{"support.example.com": "acme.zendesk.com."},
		mx:     []*net.MX{{Host: "example-com.mail.protection.outlook.com."}},
	})
	report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	providers := make(map[string]model.Finding)
	for _, finding := range report.Findings {
		providers[finding.ProviderID] = finding
	}
	if providers["slack"].Confidence != model.ConfidenceHigh {
		t.Fatalf("Slack finding missing or wrong: %#v", providers["slack"])
	}
	if got := providers["slack"].Evidence[0].Value; strings.Contains(got, "super-secret") || !strings.Contains(got, "redacted") {
		t.Fatalf("TXT evidence was not redacted: %q", got)
	}
	if _, ok := providers["zendesk"]; !ok {
		t.Fatal("CNAME finding for Zendesk missing")
	}
	if _, ok := providers["microsoft-365"]; !ok {
		t.Fatal("MX finding for Microsoft 365 missing")
	}
}

func TestScanEventsAreOrderedAndPositiveOnly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{txt: []string{"slack-domain-verification=secret"}})
	var events []model.ScanEvent
	s.SetEventHandler(func(event model.ScanEvent) { events = append(events, event) })
	report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"slack"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Type != model.ScanEventStarted || events[1].Type != model.ScanEventFinding || events[2].Type != model.ScanEventFinished {
		t.Fatalf("scan events = %#v", events)
	}
	if events[1].Finding == nil || events[1].Finding.ProviderID != "slack" || len(report.Findings) != 1 {
		t.Fatalf("finding event/report mismatch: event=%#v report=%#v", events[1], report.Findings)
	}
}

func TestPassiveScanDoesNotCallHTTPDiscoveryServices(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{txt: []string{"slack-domain-verification=secret"}})
	requests := 0
	s.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected passive HTTP request")
	})})
	report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"slack"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("passive scan made %d HTTP discovery request(s)", requests)
	}
	if len(report.Findings) != 1 || report.Findings[0].ProviderID != "slack" {
		t.Fatalf("passive DNS finding = %#v", report.Findings)
	}
}

func TestPassiveApexCNAME(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{cnames: map[string]string{"example.com": "site.proxy-ssl.webflow.com."}})
	report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"webflow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].ProviderID != "webflow" || report.Findings[0].Evidence[0].Subject != "example.com" {
		t.Fatalf("apex CNAME finding = %#v", report.Findings)
	}
}

func TestNewProviderCNAMEFingerprintsAndReferences(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{cnames: map[string]string{
		"auth.example.com":   "tenant.cname.workos-dns.com.",
		"docs.example.com":   "tenant.readmessl.com.",
		"status.example.com": "statuspage.betteruptime.com.",
	}})
	report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"workos", "readme", "better-stack"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("new provider findings = %#v", report.Findings)
	}
	for _, finding := range report.Findings {
		if len(finding.Evidence) != 1 || finding.Evidence[0].Reference == "" {
			t.Errorf("%s finding lacks official evidence reference: %#v", finding.ProviderID, finding)
		}
	}
}

func TestNewProviderCNAMEFingerprintsRejectLookalikes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{cnames: map[string]string{
		"auth.example.com":   "cname.workos-dns.com.evil.test.",
		"docs.example.com":   "notreadmessl.com.",
		"status.example.com": "statuspage.betteruptime.com.attacker.net.",
	}})
	report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"workos", "readme", "better-stack"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("look-alike targets produced findings: %#v", report.Findings)
	}
}

func TestActiveProbeRejectsErrorStatuses(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Active = true
			cfg.Retries = 0
			cfg.RateLimit = 1000
			cfg.Timeout = time.Second
			s := testScanner(t, cfg)
			s.SetResolver(fakeResolver{})
			s.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("generic response"))}, nil
			})})
			report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"slack"})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) != 0 {
				t.Fatalf("HTTP %d produced a finding: %#v", status, report.Findings)
			}
		})
	}
}

func TestActiveProbePositiveAndNegativeFingerprint(t *testing.T) {
	for _, test := range []struct {
		name, body, location string
		want                 int
	}{
		{"positive", "Welcome to Example", "https://example.slack.com/signin", 1},
		{"negative body", "This workspace doesn't exist", "", 0},
		{"negative redirect", "", "https://slack.com/?redir=1", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Active = true
			cfg.Retries = 0
			cfg.RateLimit = 1000
			cfg.Timeout = time.Second
			s := testScanner(t, cfg)
			s.SetResolver(fakeResolver{})
			s.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set("Location", test.location)
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})})
			report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"slack"})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) != test.want {
				t.Fatalf("findings = %d, want %d: %#v", len(report.Findings), test.want, report.Findings)
			}
		})
	}
}

func TestTLSVerificationDefaultAndExplicitOverride(t *testing.T) {
	for _, test := range []struct{ insecure, want bool }{{false, false}, {true, true}} {
		cfg := DefaultConfig()
		cfg.InsecureTLS = test.insecure
		client, err := newHTTPClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		transport := client.Transport.(*http.Transport)
		if transport.TLSClientConfig.InsecureSkipVerify != test.want {
			t.Fatalf("InsecureSkipVerify = %v, want %v", transport.TLSClientConfig.InsecureSkipVerify, test.want)
		}
	}
}

func TestHTTPClientProxyAndRedirectPolicy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Proxy = "://invalid"
	if _, err := newHTTPClient(cfg); err == nil {
		t.Fatal("invalid proxy URL accepted")
	}
	cfg.Proxy = "http://127.0.0.1:8080"
	client, err := newHTTPClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	proxy, err := client.Transport.(*http.Transport).Proxy(request)
	if err != nil || proxy.String() != cfg.Proxy {
		t.Fatalf("proxy = %v, err = %v", proxy, err)
	}
	if err := client.CheckRedirect(request, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy returned %v", err)
	}
}

func TestNetworkClassificationHelpers(t *testing.T) {
	if transientHTTPError(nil) || isDNSNotFound(nil) {
		t.Fatal("nil errors were classified as transient or not-found")
	}
	if !transientHTTPError(&net.DNSError{IsTimeout: true}) {
		t.Fatal("timeout was not classified as transient")
	}
	if !transientHTTPError(fmt.Errorf("connection reset by peer")) {
		t.Fatal("connection reset was not classified as transient")
	}
	if transientHTTPError(fmt.Errorf("certificate rejected")) {
		t.Fatal("permanent error was classified as transient")
	}
	if !isDNSNotFound(&net.DNSError{IsNotFound: true}) || !isDNSNotFound(fmt.Errorf("lookup: no such host")) {
		t.Fatal("DNS not-found error was not recognized")
	}
}

func TestRateGateCancellationAndDefaults(t *testing.T) {
	gate := newRateGate(0)
	if err := gate.Wait(context.Background(), "provider"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.Wait(ctx, "provider"); !errors.Is(err, context.Canceled) {
		t.Fatalf("rate gate returned %v, want context cancellation", err)
	}
}

func TestActiveProviderHelpers(t *testing.T) {
	ids := ActiveProviderIDs()
	if len(ids) != len(activeProbes) || !sort.StringsAreSorted(ids) {
		t.Fatalf("active provider IDs are incomplete or unsorted: %v", ids)
	}
	if !allowedStatus(http.StatusOK, []int{http.StatusCreated, http.StatusOK}) || allowedStatus(http.StatusNotFound, []int{http.StatusOK}) {
		t.Fatal("allowed status matching is incorrect")
	}
}

func TestActiveProbeCatalogCoverage(t *testing.T) {
	c, err := catalog.Load(builtin.FS)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, probe := range activeProbes {
		if seen[probe.ProviderID] {
			t.Errorf("duplicate active probe for %s", probe.ProviderID)
		}
		seen[probe.ProviderID] = true
		if _, ok := c.Provider(probe.ProviderID); !ok {
			t.Errorf("active probe provider %q is absent from catalog", probe.ProviderID)
		}
		if strings.Count(probe.URL, "%s") != 1 {
			t.Errorf("probe %s URL must contain exactly one placeholder: %s", probe.ProviderID, probe.URL)
		}
	}
	if len(activeProbes) < 30 {
		t.Fatalf("active probes = %d, want at least 30", len(activeProbes))
	}
}

func TestScannerConfigurationValidation(t *testing.T) {
	c, err := catalog.Load(builtin.FS)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"concurrency", func(c *Config) { c.Concurrency = 0 }},
		{"timeout", func(c *Config) { c.Timeout = 0 }},
		{"retries", func(c *Config) { c.Retries = -1 }},
		{"rate", func(c *Config) { c.RateLimit = 0 }},
		{"cache", func(c *Config) { c.CacheTTL = 0 }},
		{"profile", func(c *Config) { c.Profile = "dangerous" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			test.mutate(&cfg)
			if _, err := New(cfg, c); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	if _, err := New(DefaultConfig(), nil); err == nil {
		t.Fatal("nil catalog accepted")
	}
}

func TestTargetResultCache(t *testing.T) {
	cfg := DefaultConfig()
	s := testScanner(t, cfg)
	cache := &memoryCache{}
	s.SetCache(cache)
	s.SetResolver(fakeResolver{txt: []string{"slack-domain-verification=secret"}})
	first, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"slack"})
	if err != nil {
		t.Fatal(err)
	}
	s.SetResolver(fakeResolver{})
	second, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"slack"})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) != 1 || len(second.Findings) != 1 {
		t.Fatalf("cache results: first=%d second=%d", len(first.Findings), len(second.Findings))
	}
}

func TestHTTPRetryAndAggregation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.Retries = 1
	cfg.RateLimit = 1000
	cfg.Timeout = time.Second
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{txt: []string{"slack-domain-verification=secret"}})
	requests := 0
	s.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		status := http.StatusInternalServerError
		if requests == 2 {
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("Welcome"))}, nil
	})})
	report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"slack"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if len(report.Findings) != 1 || report.Findings[0].Confidence != model.ConfidenceConfirmed {
		t.Fatalf("aggregated finding = %#v", report.Findings)
	}
	if report.Findings[0].RiskLead != "verification_record_review" {
		t.Fatalf("risk lead = %q", report.Findings[0].RiskLead)
	}
}

func TestCancelledScan(t *testing.T) {
	cfg := DefaultConfig()
	s := testScanner(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, []target.Target{normalizedTarget(t)}, nil); err == nil {
		t.Fatal("cancelled scan returned no error")
	}
}

func TestActiveNetworkFailureIsErrorNotFinding(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.Retries = 0
	cfg.Timeout = time.Second
	s := testScanner(t, cfg)
	s.SetResolver(fakeResolver{})
	s.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })})
	report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"slack"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 || len(report.Errors) == 0 {
		t.Fatalf("report = %#v", report)
	}
}

func BenchmarkPassiveRuleMatching(b *testing.B) {
	c, err := catalog.Load(builtin.FS)
	if err != nil {
		b.Fatal(err)
	}
	records := []string{"slack-domain-verification=abc", "v=spf1 include:_spf.google.com -all", "unmatched=value"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, record := range records {
			for _, rule := range c.TXT {
				_ = rule.Match(record)
			}
		}
	}
}
