package engine

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
)

func TestDomainScansRequireSlugOptIn(t *testing.T) {
	for _, test := range []struct {
		name, profile        string
		active, includeSlugs bool
	}{
		{"passive", "passive", false, false},
		{"active domains only", "passive", true, false},
		{"standard domains only", "standard", false, false},
		{"deep domains only", "deep", false, false},
		{"active with slugs", "passive", true, true},
		{"standard with slugs", "standard", false, true},
		{"deep with slugs", "deep", false, true},
		{"slug option does not enable HTTP", "passive", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Profile, cfg.Active, cfg.IncludeSlugs = test.profile, test.active, test.includeSlugs
			s := testScanner(t, cfg)
			s.SetResolver(fakeResolver{txt: []string{"slack-domain-verification=secret"}})
			seen := make(map[string]bool)
			s.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				seen[req.URL.String()] = true
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"authorization_endpoint":"https://example.test/authorize"}`))}, nil
			})
			item, err := target.Normalize("sub.example.co.uk", target.Overrides{})
			if err != nil {
				t.Fatal(err)
			}
			report, err := s.Scan(context.Background(), []target.Target{item}, []string{"slack", "microsoft-365"})
			if err != nil {
				t.Fatal(err)
			}
			want := make(map[string]bool)
			if s.cfg.Active {
				want["https://login.microsoftonline.com/sub.example.co.uk/v2.0/.well-known/openid-configuration"] = true
				if test.includeSlugs {
					want["https://example.slack.com/"] = true
				}
			}
			if !reflect.DeepEqual(seen, want) {
				t.Fatalf("requests = %v, want %v", seen, want)
			}
			if report.Metadata.IncludeSlugs != test.includeSlugs {
				t.Fatalf("metadata lost slug opt-in: %#v", report.Metadata)
			}
			foundDNS := false
			for _, finding := range report.Findings {
				for _, evidence := range finding.Evidence {
					if evidence.Signal == model.SignalTXT && evidence.Subject == item.Host {
						foundDNS = true
					}
				}
			}
			if !foundDNS {
				t.Fatal("domain DNS discovery was skipped")
			}
		})
	}
}

func TestDomainSlugOptInSeparatesCachedResults(t *testing.T) {
	cache := &memoryCache{}
	requests := 0
	for _, includeSlugs := range []bool{true, false, true, false} {
		cfg := DefaultConfig()
		cfg.Active = true
		cfg.IncludeSlugs = includeSlugs
		s := testScanner(t, cfg)
		s.SetCache(cache)
		s.SetResolver(fakeResolver{})
		s.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			if req.URL.String() != "https://example.slack.com/" {
				t.Errorf("unexpected request: %s", req.URL)
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("Welcome"))}, nil
		})
		report, err := s.Scan(context.Background(), []target.Target{normalizedTarget(t)}, []string{"slack"})
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if includeSlugs {
			want = 1
		}
		if len(report.Findings) != want {
			t.Fatalf("includeSlugs=%v findings=%#v", includeSlugs, report.Findings)
		}
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one cached tenant probe", requests)
	}
}
