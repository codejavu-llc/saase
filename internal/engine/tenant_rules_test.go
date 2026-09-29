package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/catalog"
	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
)

func TestTenantExistenceRules(t *testing.T) {
	type responseCase struct {
		name     string
		status   int
		location string
		headers  http.Header
		want     bool
		err      error
	}
	providers := []struct {
		id, request, absent, present string
	}{
		{"freshdesk", "https://acme.freshdesk.com/", "https://www.freshworks.com/", "https://acme.freshdesk.com/support/login"},
		{"monday-com", "https://acme.monday.com/", "https://monday.com/slug_not_found", "https://acme.monday.com/auth/login"},
		{"okta", "https://acme.okta.com/", "", "https://acme.okta.com/login/login.htm"},
		{"onelogin", "https://acme.onelogin.com/", "https://app.onelogin.com/login", "https://other.onelogin.com/login"},
		{"bamboohr", "https://acme.bamboohr.com/home/", "https://www.bamboohr.com", "https://acme.bamboohr.com/login.php"},
		{"talentlms", "https://acme.talentlms.com/", "https://talentlms.com", "https://acme.talentlms.com/dashboard"},
	}
	for _, provider := range providers {
		t.Run(provider.id, func(t *testing.T) {
			tests := []responseCase{
				{name: "existing tenant", status: 200, want: true},
				{name: "tenant redirect", status: 302, location: provider.present, want: true},
				{name: "relative tenant redirect", status: 302, location: "/login", want: true},
				{name: "404", status: 404},
				{name: "403", status: 403},
				{name: "429", status: 429},
				{name: "500", status: 500},
				{name: "timeout", err: context.DeadlineExceeded},
				{name: "malformed redirect", status: 302, location: "https://%zz"},
			}
			if provider.absent != "" {
				tests = append(tests, responseCase{name: "absent tenant redirect", status: 302, location: provider.absent})
				// Root URLs with and without a trailing slash identify the same page.
				alternate := strings.TrimSuffix(provider.absent, "/") + "/"
				if strings.HasSuffix(provider.absent, "/") {
					alternate = strings.TrimSuffix(provider.absent, "/")
				}
				tests = append(tests, responseCase{name: "absent redirect trailing slash", status: 302, location: alternate})
			}
			if provider.id == "okta" {
				for mask := 0; mask < 8; mask++ {
					headers := make(http.Header)
					for i, name := range []string{"x-rate-limit-limit", "X-Rate-Limit-Remaining", "X-RATE-LIMIT-RESET"} {
						if mask&(1<<i) != 0 {
							headers[name] = []string{""}
						}
					}
					tests = append(tests, responseCase{name: "header combination " + string(rune('0'+mask)), status: 200, headers: headers, want: mask != 7})
				}
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					cfg := DefaultConfig()
					cfg.Active = true
					cfg.Retries = 0
					s := testScanner(t, cfg)
					s.dns = nil
					requests := 0
					s.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
						requests++
						if req.URL.String() != provider.request {
							t.Errorf("request = %s, want %s", req.URL, provider.request)
						}
						if test.err != nil {
							return nil, test.err
						}
						headers := test.headers.Clone()
						if headers == nil {
							headers = make(http.Header)
						}
						headers.Set("Location", test.location)
						// Old body substrings and URLs mentioned in content must not
						// override the requested header/status-based rules.
						body := "account not found; domain not found; org not found; company not found; portal not found; invalid subdomain; doesn't exist; 404 not found; " + provider.absent
						return &http.Response{StatusCode: test.status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}, nil
					})
					targets, err := target.NormalizeSlugs([]string{"acme"})
					if err != nil {
						t.Fatal(err)
					}
					report, err := s.Scan(context.Background(), targets, []string{provider.id})
					if err != nil {
						t.Fatal(err)
					}
					if requests != 1 {
						t.Fatalf("requests = %d; redirects must not be followed", requests)
					}
					want := 0
					if test.want {
						want = 1
					}
					if len(report.Findings) != want {
						t.Fatalf("findings = %#v, want %d; errors = %#v", report.Findings, want, report.Errors)
					}
					if test.want && (report.Findings[0].Confidence != model.ConfidenceMedium || report.Findings[0].Target != "acme") {
						t.Fatalf("tenant finding must have medium confidence: %#v", report.Findings[0])
					}
				})
			}
		})
	}
}

func TestSumoLogicSlugDetectionDisabled(t *testing.T) {
	for _, id := range ActiveProviderIDs() {
		if id == "sumo-logic" {
			t.Fatal("Sumo Logic is still advertised as an active detector")
		}
	}
	cfg := DefaultConfig()
	cfg.Active = true
	s := testScanner(t, cfg)
	s.dns = nil
	s.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("disabled Sumo Logic probe made an HTTP request")
		return nil, context.DeadlineExceeded
	})
	targets, err := target.NormalizeSlugs([]string{"acme"})
	if err != nil {
		t.Fatal(err)
	}
	report, err := s.Scan(context.Background(), targets, []string{"sumo-logic"})
	if err != nil || len(report.Findings) != 0 || len(report.Errors) != 0 {
		t.Fatalf("disabled probe report = %#v, err = %v", report, err)
	}
}

func TestTenantRuleChangeInvalidatesOldCache(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Active = true
	s := testScanner(t, cfg)
	s.dns = nil
	targets, err := target.NormalizeSlugs([]string{"acme"})
	if err != nil {
		t.Fatal(err)
	}
	cache := &memoryCache{}
	s.SetCache(cache)
	payload, err := json.Marshal(cachedTargetResult{Findings: []model.Finding{{Target: "acme", ProviderID: "freshworks", Confidence: model.ConfidenceMedium}}})
	if err != nil {
		t.Fatal(err)
	}
	oldVersion := catalog.CatalogVersion + ":" + s.catalog.Fingerprint() + ":engine-v4"
	_ = cache.PutCache(context.Background(), s.cacheKey(targets[0], map[string]bool{"freshworks": true}), oldVersion, time.Now().Add(time.Hour), payload)
	requests := 0
	s.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://www.freshworks.com/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	report, err := s.Scan(context.Background(), targets, []string{"freshworks"})
	if err != nil || len(report.Findings) != 0 || requests != 1 {
		t.Fatalf("old positive was reused: report=%#v requests=%d err=%v", report, requests, err)
	}
}

func TestFreshworksGenericRedirectDoesNotEmitFinding(t *testing.T) {
	for _, test := range []struct {
		name, location string
		want           int
	}{
		{"observed missing tenant", "https://www.freshworks.com/", 0},
		{"homepage without slash", "https://www.freshworks.com", 0},
		{"homepage case variant", "https://WWW.FRESHWORKS.COM/", 0},
		{"tenant login", "https://random123test.freshworks.com/login", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Active = true
			cfg.Retries = 0
			s := testScanner(t, cfg)
			s.dns = nil
			requests, events := 0, 0
			s.SetEventHandler(func(event model.ScanEvent) {
				if event.Type == model.ScanEventFinding {
					events++
				}
			})
			s.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.String() != "https://random123test.freshworks.com/" {
					t.Errorf("unexpected request: %s", req.URL)
				}
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": {test.location}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			})
			targets, err := target.NormalizeSlugs([]string{"random123test"})
			if err != nil {
				t.Fatal(err)
			}
			report, err := s.Scan(context.Background(), targets, []string{"freshworks"})
			if err != nil {
				t.Fatal(err)
			}
			if requests != 1 || len(report.Findings) != test.want || events != test.want {
				t.Fatalf("requests=%d live findings=%d report=%#v", requests, events, report)
			}
			if test.want == 1 && report.Findings[0].Confidence != model.ConfidenceMedium {
				t.Fatalf("confidence = %s", report.Findings[0].Confidence)
			}
		})
	}
}
