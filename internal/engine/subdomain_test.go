package engine

import (
	"context"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
)

// Fail if a DNS detector escapes the supplied hostname to query its parent.
type scopedResolver struct {
	fakeResolver
	t    *testing.T
	host string
}

func (r scopedResolver) check(name string) {
	r.t.Helper()
	if name != r.host && !strings.HasSuffix(name, "."+r.host) {
		r.t.Errorf("DNS query %q is outside target %q", name, r.host)
	}
}
func (r scopedResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.check(name)
	return r.fakeResolver.LookupTXT(ctx, name)
}
func (r scopedResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	r.check(name)
	return r.fakeResolver.LookupMX(ctx, name)
}
func (r scopedResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	r.check(name)
	return r.fakeResolver.LookupNS(ctx, name)
}
func (r scopedResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	r.check(name)
	return r.fakeResolver.LookupCNAME(ctx, name)
}
func (r scopedResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	r.check(name)
	return r.fakeResolver.LookupSRV(ctx, service, proto, name)
}

func TestSubdomainDNSAndCacheIsolation(t *testing.T) {
	s := testScanner(t, DefaultConfig())
	s.SetCache(&memoryCache{})
	for _, host := range []string{"example.com", "subdomains.example.com", "nested.subdomains.example.com"} {
		item, err := target.Normalize(host, target.Overrides{})
		if err != nil {
			t.Fatal(err)
		}
		s.SetResolver(scopedResolver{
			t: t, host: host,
			fakeResolver: fakeResolver{cnames: map[string]string{host: "acme.zendesk.com."}},
		})
		report, err := s.Scan(context.Background(), []target.Target{item}, []string{"zendesk"})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(report.Metadata.TargetNames, []string{host}) {
			t.Fatalf("target names = %v, want %s", report.Metadata.TargetNames, host)
		}
		if len(report.Findings) != 1 || report.Findings[0].Target != host {
			t.Fatalf("findings for %s = %#v", host, report.Findings)
		}
		evidence := report.Findings[0].Evidence
		if len(evidence) != 1 || evidence[0].Subject != host || evidence[0].Signal != model.SignalCNAME {
			t.Fatalf("CNAME evidence for %s = %#v", host, evidence)
		}
	}
}

func TestSiblingSubdomainFindingsRemainSeparate(t *testing.T) {
	s := testScanner(t, DefaultConfig())
	s.SetResolver(fakeResolver{txt: []string{"slack-domain-verification=secret"}})
	var targets []target.Target
	for _, host := range []string{"one.example.com", "two.example.com"} {
		item, err := target.Normalize(host, target.Overrides{})
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, item)
	}
	report, err := s.Scan(context.Background(), targets, []string{"slack"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %#v, want two distinct targets", report.Findings)
	}
	for i, finding := range report.Findings {
		if finding.Target != targets[i].Host || finding.Evidence[0].Subject != targets[i].Host {
			t.Fatalf("finding = %#v, want target %s", finding, targets[i].Host)
		}
	}
}

func TestSubdomainActiveDomainProbe(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.Retries = 0
	item, err := target.Normalize("login.example.com", target.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{http.StatusOK, http.StatusTooManyRequests} {
		s := testScanner(t, cfg)
		s.SetResolver(fakeResolver{})
		requests := 0
		s.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			if req.URL.Path != "/login.example.com/v2.0/.well-known/openid-configuration" {
				t.Errorf("SSO path = %s", req.URL.Path)
			}
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"authorization_endpoint":"https://login.example.com/"}`))}, nil
		})})
		report, err := s.Scan(context.Background(), []target.Target{item}, []string{"microsoft-365"})
		if err != nil {
			t.Fatal(err)
		}
		if requests != 1 {
			t.Fatalf("requests = %d, want 1", requests)
		}
		if status == http.StatusOK {
			if len(report.Findings) != 1 || report.Findings[0].Target != item.Host {
				t.Fatalf("active findings = %#v", report.Findings)
			}
		} else if len(report.Errors) != 1 || report.Errors[0].Target != item.Host {
			t.Fatalf("active errors = %#v", report.Errors)
		}
	}
}
