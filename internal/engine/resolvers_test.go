package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/target"
	"golang.org/x/net/dns/dnsmessage"
)

func dnsReply(t *testing.T, query []byte) []byte {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(query); err != nil {
		t.Error(err)
		return nil
	}
	msg.Header.Response = true
	msg.Header.RecursionAvailable = true
	for _, q := range msg.Questions {
		if q.Type == dnsmessage.TypeTXT {
			msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.TXTResource{TXT: []string{"slack-domain-verification=test"}}})
		}
	}
	data, err := msg.Pack()
	if err != nil {
		t.Error(err)
	}
	return data
}

func serveDNSStream(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		var size uint16
		if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		response := dnsReply(t, query)
		_ = binary.Write(conn, binary.BigEndian, uint16(len(response)))
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

func TestCustomResolverDirect(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(dnsReply(t, buf[:n]), addr)
		}
	}()
	defer func() { conn.Close(); <-done }()
	cfg := DefaultConfig()
	cfg.Resolvers = []string{conn.LocalAddr().String()}
	scanner := testScanner(t, cfg)
	ctx, cancel := context.WithTimeout(scanner.resolverContext(context.Background()), time.Second)
	defer cancel()
	records, err := scanner.dns.LookupTXT(ctx, "example.test")
	if err != nil || len(records) != 1 || records[0] != "slack-domain-verification=test" {
		t.Fatalf("records=%v err=%v", records, err)
	}
}

func TestCustomResolverHTTPProxy(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "192.0.2.53:53" {
			t.Errorf("unexpected request %s %s", r.Method, r.Host)
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			t.Error("missing proxy credentials")
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		requests.Add(1)
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		serveDNSStream(t, conn)
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Resolvers = []string{"192.0.2.53"}
	cfg.Proxy = strings.Replace(server.URL, "://", "://user:pass@", 1)
	scanner := testScanner(t, cfg)
	ctx, cancel := context.WithTimeout(scanner.resolverContext(context.Background()), time.Second)
	defer cancel()
	records, err := scanner.dns.LookupTXT(ctx, "example.test")
	if err != nil || len(records) != 1 || requests.Load() == 0 {
		t.Fatalf("records=%v requests=%d err=%v", records, requests.Load(), err)
	}
}

func TestCustomResolverSOCKSProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		greeting := make([]byte, 2)
		if _, err := io.ReadFull(reader, greeting); err != nil {
			t.Error(err)
			return
		}
		methods := make([]byte, int(greeting[1]))
		_, _ = io.ReadFull(reader, methods)
		_, _ = conn.Write([]byte{5, 0})
		request := make([]byte, 10)
		if _, err := io.ReadFull(reader, request); err != nil {
			t.Error(err)
			return
		}
		if request[1] != 1 || request[3] != 1 || net.IP(request[4:8]).String() != "192.0.2.53" || binary.BigEndian.Uint16(request[8:]) != 53 {
			t.Errorf("unexpected SOCKS request: %v", request)
			return
		}
		_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 53})
		serveDNSStream(t, conn)
	}()
	cfg := DefaultConfig()
	cfg.Resolvers = []string{"192.0.2.53"}
	cfg.Proxy = "socks5://" + listener.Addr().String()
	scanner := testScanner(t, cfg)
	ctx, cancel := context.WithTimeout(scanner.resolverContext(context.Background()), time.Second)
	defer cancel()
	records, err := scanner.dns.LookupTXT(ctx, "example.test")
	if err != nil || len(records) != 1 {
		t.Errorf("records=%v err=%v", records, err)
	}
	listener.Close()
	<-done
}

func TestResolverValidationAndSelection(t *testing.T) {
	for _, value := range []string{"example.com", "127.0.0.1:0", "127.0.0.1:65536", "invalid", ""} {
		if _, err := normalizeResolvers([]string{value}); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	addresses, err := normalizeResolvers([]string{"1.1.1.1", "1.1.1.1:53", "::1", "[::1]:5353"})
	if err != nil || len(addresses) != 3 {
		t.Fatalf("addresses=%v err=%v", addresses, err)
	}
	cfg := DefaultConfig()
	cfg.Resolvers = addresses
	s := testScanner(t, cfg)
	seen := make(map[string]bool)
	for range 100 {
		ctx := s.resolverContext(context.Background())
		address := ctx.Value(resolverAddressKey{}).(string)
		seen[address] = true
		child, cancel := context.WithTimeout(ctx, time.Second)
		if child.Value(resolverAddressKey{}) != address {
			t.Error("resolver changed within target")
		}
		cancel()
	}
	if len(seen) != 3 {
		t.Fatalf("selection did not cover pool: %v", seen)
	}
	if _, err := dnsDialer("ftp://localhost", time.Second); err == nil {
		t.Error("accepted unsupported proxy")
	}
}

func TestDNSProxyFailureAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	dial, err := dnsDialer(server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := dial(context.Background(), "udp", "192.0.2.53:53"); err == nil {
		conn.Close()
		t.Fatal("accepted refused tunnel")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := dial(ctx, "udp", "192.0.2.53:53"); err == nil {
		conn.Close()
		t.Fatal("ignored cancellation")
	}
}

func TestCustomResolverCacheIsolation(t *testing.T) {
	cfg := DefaultConfig()
	system := testScanner(t, cfg)
	cfg.Resolvers = []string{"1.1.1.1"}
	custom := testScanner(t, cfg)
	cfg.Proxy = "socks5://127.0.0.1:1080"
	proxied := testScanner(t, cfg)
	item := target.Target{Host: "example.com"}
	if system.cacheKey(item, nil) == custom.cacheKey(item, nil) || custom.cacheKey(item, nil) == proxied.cacheKey(item, nil) {
		t.Fatal("DNS configuration must distinguish cache entries")
	}
}
