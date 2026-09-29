package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/codejavu-llc/saase/v2/internal/target"
)

func TestSlugOnlyScanSkipsDNSAndDomainProbes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.Retries = 0
	s := testScanner(t, cfg)
	// Any attempt at DNS discovery panics, even if its results would be ignored.
	s.dns = nil
	targets, err := target.NormalizeSlugs([]string{"acme"})
	if err != nil {
		t.Fatal(err)
	}
	wantURLs := make(map[string]bool)
	for _, probe := range activeProbes {
		if !probe.Domain {
			wantURLs[fmt.Sprintf(probe.URL, "acme")] = true
		}
	}
	seen := make(map[string]bool)
	s.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		address := req.URL.String()
		if !wantURLs[address] || seen[address] {
			t.Errorf("unexpected or repeated HTTP request: %s", address)
		}
		seen[address] = true
		status := http.StatusNotFound
		switch req.URL.Host {
		case "acme.slack.com":
			status = http.StatusOK
		case "acme.zendesk.com":
			status = http.StatusTooManyRequests
		case "acme.onelogin.com":
			return nil, context.DeadlineExceeded
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("Welcome"))}, nil
	})})
	report, err := s.Scan(context.Background(), targets, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(seen, wantURLs) {
		t.Fatalf("requested %d URLs, want %d slug-only services", len(seen), len(wantURLs))
	}
	if !report.Metadata.Active || !reflect.DeepEqual(report.Metadata.TargetNames, []string{"acme"}) {
		t.Fatalf("metadata = %#v", report.Metadata)
	}
	if len(report.Findings) != 1 || report.Findings[0].Target != "acme" || report.Findings[0].ProviderID != "slack" || report.Findings[0].Tenant != "https://acme.slack.com/" {
		t.Fatalf("findings = %#v", report.Findings)
	}
	if len(report.Errors) != 2 {
		t.Fatalf("errors = %#v", report.Errors)
	}
	for _, probeError := range report.Errors {
		if probeError.Target != "acme" {
			t.Errorf("error lost slug target: %#v", probeError)
		}
	}
}

func TestSlugOnlyRequiresActiveMode(t *testing.T) {
	s := testScanner(t, DefaultConfig())
	s.dns = nil
	targets, err := target.NormalizeSlugs([]string{"acme"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Scan(context.Background(), targets, nil); err == nil || !strings.Contains(err.Error(), "require --active") {
		t.Fatalf("passive slug scan error = %v", err)
	}
}

func TestSlugOnlyCacheAndProviderFiltering(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IncludeSlugs = true
	cfg.Active = true
	cfg.RateLimit = 1000
	s := testScanner(t, cfg)
	s.SetCache(&memoryCache{})
	s.SetResolver(fakeResolver{})
	requests := 0
	s.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Host != "alpha.slack.com" && req.URL.Host != "beta.slack.com" {
			t.Errorf("unexpected provider request: %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("Welcome"))}, nil
	})})
	for _, slug := range []string{"alpha", "beta", "alpha"} {
		targets, err := target.NormalizeSlugs([]string{slug})
		if err != nil {
			t.Fatal(err)
		}
		report, err := s.Scan(context.Background(), targets, []string{"slack", "microsoft-365"})
		if err != nil || len(report.Findings) != 1 || report.Findings[0].Target != slug {
			t.Fatalf("slug=%s report=%#v err=%v", slug, report, err)
		}
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2 with cached alpha", requests)
	}
	domain, err := target.Normalize("alpha.example", target.Overrides{Slugs: []string{"alpha"}})
	if err != nil {
		t.Fatal(err)
	}
	report, err := s.Scan(context.Background(), []target.Target{domain}, []string{"slack"})
	if err != nil || len(report.Findings) != 1 || report.Findings[0].Target != domain.Host || requests != 3 {
		t.Fatalf("domain scan report=%#v requests=%d err=%v", report, requests, err)
	}
}
