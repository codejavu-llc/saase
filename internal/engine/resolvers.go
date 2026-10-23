package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type resolverAddressKey struct{}

// normalizeResolvers accepts literal IP addresses with an optional port.
func normalizeResolvers(values []string) ([]string, error) {
	var addresses []string
	seen := make(map[string]bool)
	for _, value := range values {
		value = strings.TrimSpace(value)
		var address string
		if ip, err := netip.ParseAddr(value); err == nil {
			address = net.JoinHostPort(ip.String(), "53")
		} else {
			host, port, err := net.SplitHostPort(value)
			if err != nil {
				return nil, fmt.Errorf("invalid DNS resolver %q: expected IP or IP:port", value)
			}
			ip, err := netip.ParseAddr(host)
			n, portErr := strconv.Atoi(port)
			if err != nil || portErr != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("invalid DNS resolver %q", value)
			}
			address = net.JoinHostPort(ip.String(), strconv.Itoa(n))
		}
		if !seen[address] {
			addresses = append(addresses, address)
			seen[address] = true
		}
	}
	return addresses, nil
}

func (s *Scanner) resolverContext(ctx context.Context) context.Context {
	if len(s.cfg.Resolvers) == 0 {
		return ctx
	}
	return context.WithValue(ctx, resolverAddressKey{}, s.cfg.Resolvers[rand.IntN(len(s.cfg.Resolvers))])
}

func newCustomResolver(cfg Config) (DNSResolver, error) {
	dial, err := dnsDialer(cfg.Proxy, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &netResolver{resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			address, ok := ctx.Value(resolverAddressKey{}).(string)
			if !ok {
				return nil, fmt.Errorf("missing target DNS resolver")
			}
			return dial(ctx, network, address)
		},
	}}, nil
}

type dnsDialFunc func(context.Context, string, string) (net.Conn, error)

func dnsDialer(rawProxy string, timeout time.Duration) (dnsDialFunc, error) {
	direct := &net.Dialer{Timeout: timeout}
	if rawProxy == "" {
		return direct.DialContext, nil
	}
	u, err := url.Parse(rawProxy)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid DNS proxy URL")
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		address := u.Host
		if u.Port() == "" {
			address = net.JoinHostPort(u.Hostname(), "1080")
		}
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: password}
		}
		d, err := proxy.SOCKS5("tcp", address, auth, direct)
		if err != nil {
			return nil, fmt.Errorf("configure DNS SOCKS proxy: %w", err)
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("DNS SOCKS proxy does not support context dialing")
		}
		return func(ctx context.Context, _, address string) (net.Conn, error) {
			return cd.DialContext(ctx, "tcp", address)
		}, nil
	case "http", "https":
		address := u.Host
		if u.Port() == "" {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			address = net.JoinHostPort(u.Hostname(), port)
		}
		return func(ctx context.Context, _, target string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			var conn net.Conn
			var err error
			if u.Scheme == "https" {
				d := &tls.Dialer{NetDialer: direct, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}}
				conn, err = d.DialContext(ctx, "tcp", address)
			} else {
				conn, err = direct.DialContext(ctx, "tcp", address)
			}
			if err != nil {
				return nil, err
			}
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			success := false
			defer func() {
				stop()
				if !success {
					_ = conn.Close()
				}
			}()
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				return nil, err
			}
			req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
			if u.User != nil {
				password, _ := u.User.Password()
				req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+password)))
			}
			if err := req.Write(conn); err != nil {
				return nil, err
			}
			reader := bufio.NewReader(conn)
			resp, err := http.ReadResponse(reader, req)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("DNS proxy CONNECT failed: %s", resp.Status)
			}
			if !stop() {
				return nil, ctx.Err()
			}
			if err := conn.SetDeadline(time.Time{}); err != nil {
				return nil, err
			}
			success = true
			return &bufferedDNSConn{Conn: conn, reader: reader}, nil
		}, nil
	default:
		return nil, fmt.Errorf("DNS proxy scheme %q is unsupported; use socks5, socks5h, http, or https", u.Scheme)
	}
}

type bufferedDNSConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedDNSConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
