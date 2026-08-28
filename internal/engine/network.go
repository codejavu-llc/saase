package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxResponseBody = 2 << 20

type DNSResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupCNAME(context.Context, string) (string, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupNS(context.Context, string) ([]*net.NS, error)
	LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error)
	LookupHost(context.Context, string) ([]string, error)
}

type netResolver struct{ resolver *net.Resolver }

func newNetResolver() DNSResolver { return &netResolver{resolver: net.DefaultResolver} }

func (r *netResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, name)
}
func (r *netResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	return r.resolver.LookupCNAME(ctx, name)
}
func (r *netResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return r.resolver.LookupMX(ctx, name)
}
func (r *netResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return r.resolver.LookupNS(ctx, name)
}
func (r *netResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	return r.resolver.LookupSRV(ctx, service, proto, name)
}
func (r *netResolver) LookupHost(ctx context.Context, name string) ([]string, error) {
	return r.resolver.LookupHost(ctx, name)
}

type httpResponse struct {
	StatusCode int
	Header     http.Header
	Body       string
	Latency    time.Duration
}

type rateGate struct {
	mu   sync.Mutex
	last map[string]time.Time
	gap  time.Duration
}

func newRateGate(requestsPerSecond float64) *rateGate {
	if requestsPerSecond <= 0 {
		requestsPerSecond = 2
	}
	return &rateGate{last: make(map[string]time.Time), gap: time.Duration(float64(time.Second) / requestsPerSecond)}
}

func (g *rateGate) Wait(ctx context.Context, key string) error {
	g.mu.Lock()
	next := g.last[key].Add(g.gap)
	wait := time.Until(next)
	if wait < 0 {
		wait = 0
	}
	g.last[key] = time.Now().Add(wait)
	g.mu.Unlock()
	if wait == 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func newHTTPClient(cfg Config) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS} // #nosec G402 -- explicit opt-in CLI setting.
	transport.MaxIdleConns = cfg.Concurrency * 2
	transport.MaxIdleConnsPerHost = 4
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil || proxyURL.Scheme == "" || proxyURL.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL %q", cfg.Proxy)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func (s *Scanner) doHTTP(ctx context.Context, providerID, method, address string) (httpResponse, error) {
	var lastErr error
	for attempt := 0; attempt <= s.cfg.Retries; attempt++ {
		if err := s.rate.Wait(ctx, providerID); err != nil {
			return httpResponse{}, err
		}
		req, err := http.NewRequestWithContext(ctx, method, address, nil)
		if err != nil {
			return httpResponse{}, err
		}
		req.Header.Set("User-Agent", s.cfg.UserAgent)
		req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
		started := time.Now()
		resp, err := s.http.Do(req)
		if err != nil {
			lastErr = err
			if attempt < s.cfg.Retries && transientHTTPError(err) {
				continue
			}
			return httpResponse{}, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
		result := httpResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: string(body), Latency: time.Since(started)}
		if readErr != nil {
			return result, readErr
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < s.cfg.Retries {
			continue
		}
		return result, nil
	}
	return httpResponse{}, lastErr
}

func transientHTTPError(err error) bool {
	if err == nil {
		return false
	}
	if nerr, ok := err.(net.Error); ok {
		return nerr.Timeout() || nerr.Temporary()
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "connection reset") || strings.Contains(message, "connection refused")
}

func isDNSNotFound(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	return strings.Contains(strings.ToLower(err.Error()), "no such host") || (errors.As(err, &dnsErr) && dnsErr.IsNotFound)
}
