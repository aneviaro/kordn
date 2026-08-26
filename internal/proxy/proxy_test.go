// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/runtime"
)

const testUser = "proxy-user"
const testPassword = "proxy-secret"

func TestAuthenticatorUsesCompleteCredentialDigest(t *testing.T) {
	auth, err := NewAuthenticator(testUser, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(testUser + ":" + testPassword))
	if auth.expectedDigest != want {
		t.Fatal("authenticator did not precompute the complete credential digest")
	}
	for _, credential := range []string{
		testUser + ":wrong-password",
		"wrong-user:" + testPassword,
		"wrong-user:wrong-password",
	} {
		req, err := http.NewRequest(http.MethodGet, "http://proxy.invalid/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Proxy-Authorization", "Basic "+basic(credential))
		if auth.Authenticate(req) {
			t.Errorf("Authenticate accepted invalid complete credential %q", credential)
		}
	}
	req, err := http.NewRequest(http.MethodGet, "http://proxy.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Basic "+basic(testUser+":"+testPassword))
	if !auth.Authenticate(req) {
		t.Fatal("Authenticate rejected valid complete credential")
	}
	for _, malformed := range []string{"", "not-basic", basic(testUser), "%%%"} {
		req.Header.Set("Proxy-Authorization", "Basic "+malformed)
		if auth.Authenticate(req) {
			t.Errorf("Authenticate accepted malformed Basic credential %q", malformed)
		}
	}
}

func TestProxy_RequiresAuthBeforeLookup(t *testing.T) {
	var lookups, dials atomic.Int32
	server := newTestProxy(t, Config{
		Resolver: ResolverFunc(func(context.Context, string, string) ([]net.IP, error) {
			lookups.Add(1)
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}),
		Dialer: DialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, fmt.Errorf("unexpected dial")
		}),
	})
	for _, header := range []string{"", "Basic " + basic("wrong:credential")} {
		conn := openProxy(t, server)
		fmt.Fprintf(conn, "CONNECT public.example:443 HTTP/1.1\r\nHost: public.example:443\r\n")
		if header != "" {
			fmt.Fprintf(conn, "Proxy-Authorization: %s\r\n", header)
		}
		fmt.Fprint(conn, "\r\n")
		response := readProxyResponse(t, conn)
		_ = conn.Close()
		if response.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status for unauthenticated request = %d, want 407", response.StatusCode)
		}
	}
	if lookups.Load() != 0 || dials.Load() != 0 {
		t.Fatalf("destination handling occurred before auth: lookups=%d dials=%d", lookups.Load(), dials.Load())
	}
}

func TestProxy_RejectsUnsafeDestinations(t *testing.T) {
	var dials atomic.Int32
	resolver := ResolverFunc(func(_ context.Context, _ string, host string) ([]net.IP, error) {
		switch host {
		case "mixed.example":
			return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}, nil
		case "metadata.example":
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		case "metadata6.example":
			return []net.IP{net.ParseIP("fd00:ec2::254")}, nil
		case "rebind.example":
			return []net.IP{net.ParseIP("8.8.4.4")}, nil
		default:
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
	})
	server := newTestProxy(t, Config{
		Resolver: resolver,
		Dialer: DialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, fmt.Errorf("unexpected outbound dial")
		}),
		TargetAllow: func(string, net.IP) bool { return false },
	})
	for _, authority := range []string{
		"127.0.0.1:443",
		"[::1]:443",
		"169.254.169.254:80",
		"[fd00:ec2::254]:443",
		"mixed.example:443",
		"metadata.example:443",
		"metadata6.example:443",
	} {
		conn := openProxy(t, server)
		writeConnect(t, conn, authority, true)
		response := readProxyResponse(t, conn)
		_ = conn.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Errorf("unsafe %q status = %d, want 403", authority, response.StatusCode)
		}
	}
	if dials.Load() != 0 {
		t.Fatalf("unsafe destinations reached a dialer: %d", dials.Load())
	}

	// An unsafe DNS answer must also be rejected when a corporate proxy is
	// configured. The parent proxy cannot become a validation bypass.
	corporate := newTestProxy(t, Config{
		Resolver: resolver,
		Dialer: DialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, fmt.Errorf("unexpected corporate dial")
		}),
		ParentProxy: runtime.CapturedProxySettings{HTTPSProxy: "http://corp.example:8080"},
	})
	conn := openProxy(t, corporate)
	writeConnect(t, conn, "mixed.example:443", true)
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusForbidden {
		t.Fatalf("corporate mixed-answer status = %d, want 403", response.StatusCode)
	}
	_ = conn.Close()
	if dials.Load() != 0 {
		t.Fatal("corporate proxy was contacted for an unsafe answer")
	}

	// The direct path must dial a validated literal, not ask a dialer to
	// resolve the hostname again after the resolver has returned its answer.
	var address string
	pinned := newTestProxy(t, Config{
		Resolver: ResolverFunc(func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("8.8.4.4")}, nil
		}),
		Dialer: DialerFunc(func(_ context.Context, _, got string) (net.Conn, error) {
			address = got
			return nil, fmt.Errorf("expected test dial failure")
		}),
	})
	conn = openProxy(t, pinned)
	writeConnect(t, conn, "rebind.example:443", true)
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusBadGateway {
		t.Fatalf("pinned dial status = %d, want 502", response.StatusCode)
	}
	_ = conn.Close()
	if address != "8.8.4.4:443" {
		t.Fatalf("dialer received unpinned destination %q", address)
	}
}

func TestProxy_TunnelsNonAWSOpaque(t *testing.T) {
	var requestURI string
	var receivedBody []byte
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.URL.RequestURI()
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("X-Opaque", "preserved")
		_, _ = w.Write([]byte("opaque response"))
	}))
	defer upstream.Close()
	upstreamPort := mustPort(t, upstream.Listener.Addr())
	resolver := ResolverFunc(func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	})
	server := newTestProxy(t, Config{
		Resolver: resolver,
		TargetAllow: func(host string, ip net.IP) bool {
			return host == "not-aws.example" && ip.Equal(net.ParseIP("127.0.0.1"))
		},
	})
	conn := openProxy(t, server)
	writeConnect(t, conn, "not-aws.example:"+strconv.Itoa(upstreamPort), true)
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", response.StatusCode)
	}
	clientTLS := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "not-aws.example", NextProtos: []string{"http/1.1"}}) // test fixture's cert is intentionally not trusted
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	wantFingerprint := sha256.Sum256(upstream.Certificate().Raw)
	gotFingerprint := sha256.Sum256(clientTLS.ConnectionState().PeerCertificates[0].Raw)
	if gotFingerprint != wantFingerprint {
		t.Fatal("non-AWS tunnel did not preserve the upstream certificate")
	}
	payload := []byte{'o', 'p', 'a', 'q', 'u', 'e', 0x00, ' ', 0xff}
	fmt.Fprintf(clientTLS, "POST /opaque?do-not-log=1 HTTP/1.1\r\nHost: not-aws.example\r\nContent-Length: %d\r\n\r\n", len(payload))
	if _, err := clientTLS.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := readProxyResponse(t, clientTLS)
	responseBody, _ := io.ReadAll(response.Body)
	_ = clientTLS.Close()
	if string(responseBody) != "opaque response" || response.Header.Get("X-Opaque") != "preserved" {
		t.Fatalf("unexpected opaque response: %q, headers=%v", responseBody, response.Header)
	}
	if requestURI != "/opaque?do-not-log=1" || !bytes.Equal(receivedBody, payload) {
		t.Fatalf("opaque request changed: URI=%q body=%q", requestURI, receivedBody)
	}
	if gotFingerprint == sha256.Sum256(server.CA().Certificate().Raw) {
		t.Fatal("non-AWS connection used the Kordn CA")
	}
}

func TestProxy_InterceptsRecognizedAWS(t *testing.T) {
	const host = "sts.example.test"
	var called atomic.Int32
	classifier := testAWSClassifier(host)
	server := newTestProxy(t, Config{
		Classifier: classifier,
		AWSHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called.Add(1)
			endpoint, ok := EndpointFromContext(r.Context())
			if !ok || endpoint.Host != host || r.ProtoMajor != 1 || r.ProtoMinor != 1 {
				http.Error(w, "bad intercepted request", http.StatusInternalServerError)
				return
			}
			w.Header().Set("X-Kordn-Intercepted", "yes")
			_, _ = io.WriteString(w, "intercepted")
		}),
	})
	conn := openProxy(t, server)
	writeConnect(t, conn, host+":443", true)
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusOK {
		t.Fatalf("AWS CONNECT status = %d, want 200", response.StatusCode)
	}
	clientTLS := tls.Client(conn, &tls.Config{RootCAs: server.CA().CertPool(), ServerName: host, NextProtos: []string{"h2", "http/1.1"}})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := clientTLS.ConnectionState()
	if state.NegotiatedProtocol != "http/1.1" || len(state.PeerCertificates) == 0 || state.PeerCertificates[0].DNSNames[0] != host {
		t.Fatalf("unexpected intercepted TLS state: protocol=%q certs=%d names=%v", state.NegotiatedProtocol, len(state.PeerCertificates), state.PeerCertificates[0].DNSNames)
	}
	fmt.Fprintf(clientTLS, "GET /intercepted HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	response := readProxyResponse(t, clientTLS)
	body, _ := io.ReadAll(response.Body)
	_ = clientTLS.Close()
	if response.StatusCode != http.StatusOK || string(body) != "intercepted" || response.Header.Get("X-Kordn-Intercepted") != "yes" {
		t.Fatalf("unexpected intercepted response: %d %q %v", response.StatusCode, body, response.Header)
	}
	if called.Load() != 1 {
		t.Fatalf("AWS handler call count = %d, want 1", called.Load())
	}
}

func TestProxy_RejectsHostMismatch(t *testing.T) {
	const host = "sts.example.test"
	var called atomic.Int32
	server := newTestProxy(t, Config{
		Classifier: testAWSClassifier(host),
		AWSHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Add(1) }),
	})
	conn := openProxy(t, server)
	writeConnect(t, conn, host+":443", true)
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusOK {
		t.Fatalf("AWS CONNECT status = %d, want 200", response.StatusCode)
	}
	clientTLS := tls.Client(conn, &tls.Config{RootCAs: server.CA().CertPool(), ServerName: host})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(clientTLS, "GET / HTTP/1.1\r\nHost: other.example.test:443\r\nConnection: close\r\n\r\n")
	response := readProxyResponse(t, clientTLS)
	_ = clientTLS.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched Host status = %d, want 400", response.StatusCode)
	}
	if called.Load() != 0 {
		t.Fatal("mismatched Host reached the AWS handler")
	}
}

func TestProxy_RejectsPlaintextAWSAndAppliesHopHeaders(t *testing.T) {
	const awsHost = "sts.example.test"
	server := newTestProxy(t, Config{Classifier: testAWSClassifier(awsHost)})
	conn := openProxy(t, server)
	fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", awsHost, awsHost, basic(testUser+":"+testPassword))
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusForbidden {
		t.Fatalf("plaintext AWS status = %d, want 403", response.StatusCode)
	}
	_ = conn.Close()

	var sawHop, sawProxyAuth atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHop.Store(r.Header.Get("X-Remove") != "")
		sawProxyAuth.Store(r.Header.Get("Proxy-Authorization") != "")
		body, _ := io.ReadAll(r.Body)
		if string(body) != "plain body" {
			http.Error(w, "body changed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Connection", "should-not-cross")
		_, _ = io.WriteString(w, "plain response")
	}))
	defer upstream.Close()
	port := mustPort(t, upstream.Listener.Addr())
	plain := newTestProxy(t, Config{
		Resolver: ResolverFunc(func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}),
		TargetAllow: func(host string, ip net.IP) bool { return host == "plain.example" && ip.IsLoopback() },
		Limits:      Limits{MaxBodyBytes: 64},
	})
	conn = openProxy(t, plain)
	fmt.Fprintf(conn, "POST http://plain.example:%d/path?query=1 HTTP/1.1\r\nHost: plain.example:%d\r\nProxy-Authorization: Basic %s\r\nConnection: X-Remove\r\nX-Remove: removed\r\nContent-Length: 10\r\n\r\nplain body", port, port, basic(testUser+":"+testPassword))
	response := readProxyResponse(t, conn)
	body, _ := io.ReadAll(response.Body)
	_ = conn.Close()
	if response.StatusCode != http.StatusOK || string(body) != "plain response" {
		t.Fatalf("plaintext forwarding failed: %d %q", response.StatusCode, body)
	}
	if sawHop.Load() || sawProxyAuth.Load() {
		t.Fatal("hop-by-hop or proxy authentication header crossed the boundary")
	}
}

func TestProxy_RejectsUnsupportedParentSchemeBeforeResolution(t *testing.T) {
	var lookups, dials atomic.Int32
	server := newTestProxy(t, Config{
		ParentProxy: runtime.CapturedProxySettings{
			HTTPProxy:  "socks5://corp.example:1080",
			HTTPSProxy: "socks5h://corp.example:1080",
		},
		Resolver: ResolverFunc(func(context.Context, string, string) ([]net.IP, error) {
			lookups.Add(1)
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}),
		Dialer: DialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, fmt.Errorf("unexpected dial")
		}),
	})

	conn := openProxy(t, server)
	fmt.Fprintf(conn, "GET http://public.example/ HTTP/1.1\r\nHost: public.example\r\nProxy-Authorization: Basic %s\r\n\r\n", basic(testUser+":"+testPassword))
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusBadGateway {
		t.Fatalf("unsupported plain parent scheme status = %d, want 502", response.StatusCode)
	}
	_ = conn.Close()

	conn = openProxy(t, server)
	writeConnect(t, conn, "public.example:443", true)
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusBadGateway {
		t.Fatalf("unsupported CONNECT parent scheme status = %d, want 502", response.StatusCode)
	}
	_ = conn.Close()
	if lookups.Load() != 0 || dials.Load() != 0 {
		t.Fatalf("unsupported parent scheme reached destination handling: lookups=%d dials=%d", lookups.Load(), dials.Load())
	}
}

func TestProxy_RejectsChunkedBodyOverLimitAndRequestLineLimit(t *testing.T) {
	var lookups atomic.Int32
	server := newTestProxy(t, Config{
		Resolver: ResolverFunc(func(context.Context, string, string) ([]net.IP, error) {
			lookups.Add(1)
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}),
		Limits: Limits{MaxBodyBytes: 4, MaxRequestLine: 32},
	})
	conn := openProxy(t, server)
	fmt.Fprintf(conn, "POST http://public.example:80/ HTTP/1.1\r\nHost: public.example\r\nProxy-Authorization: Basic %s\r\nTransfer-Encoding: chunked\r\n\r\n5\r\ntoo-big\r\n0\r\n\r\n", basic(testUser+":"+testPassword))
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized chunked body status = %d, want 413", response.StatusCode)
	}
	_ = conn.Close()
	if lookups.Load() != 1 {
		t.Fatalf("body was not classified/resolved exactly once: %d", lookups.Load())
	}
	conn = openProxy(t, server)
	fmt.Fprintf(conn, "GET http://public.example:80/%s HTTP/1.1\r\nHost: public.example\r\nProxy-Authorization: Basic %s\r\n\r\n", strings.Repeat("x", 80), basic(testUser+":"+testPassword))
	if response := readProxyResponse(t, conn); response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized request line status = %d, want 431", response.StatusCode)
	}
	_ = conn.Close()
	if lookups.Load() != 1 {
		t.Fatal("request-line rejection reached destination handling")
	}
}

func TestProxy_CorporateConnectUsesValidatedLiteral(t *testing.T) {
	proxyConn, corporateConn := net.Pipe()
	defer proxyConn.Close()
	defer corporateConn.Close()
	proxyURL, err := url.Parse("http://user:secret@corp.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	gotRequest := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(corporateConn)
		var data strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				gotRequest <- data.String()
				return
			}
			data.WriteString(line)
			if line == "\r\n" {
				gotRequest <- data.String()
				_, _ = io.WriteString(corporateConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				return
			}
		}
	}()
	got, err := connectThroughCorporateProxy(context.Background(), proxyURL, "8.8.8.8:443", DialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return proxyConn, nil
	}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Close()
	request := <-gotRequest
	if !strings.Contains(request, "CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n") || !strings.Contains(request, "Proxy-Authorization: Basic "+basic("user:secret")) {
		t.Fatalf("corporate CONNECT was not bounded/pinned/authenticated: %q", request)
	}
}

func TestProxy_CorporateConnectPreservesBufferedTunnelBytes(t *testing.T) {
	proxyConn, corporateConn := net.Pipe()
	defer proxyConn.Close()
	defer corporateConn.Close()
	go func() {
		reader := bufio.NewReader(corporateConn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(corporateConn, "HTTP/1.1 200 Connection Established\r\n\r\npayload-after-header")
	}()
	proxyURL, err := url.Parse("http://corp.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := connectThroughCorporateProxy(context.Background(), proxyURL, "8.8.8.8:443", DialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return proxyConn, nil
	}), Limits{MaxHeaderBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := make([]byte, len("payload-after-header"))
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "payload-after-header" {
		t.Fatalf("buffered tunnel payload changed: %q", payload)
	}
}

func TestProxy_CleanupRemovesOnlyOwnedRunMaterial(t *testing.T) {
	server, err := NewServer(Config{Username: testUser, Password: testPassword})
	if err != nil {
		t.Fatal(err)
	}
	caPath := server.CAPEMPath()
	if _, err := os.Stat(caPath); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Fatalf("owned CA material survived server cleanup: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProxy_OutboundTransportUsesCapturedSettingsAndPublicTLS(t *testing.T) {
	settings := runtime.CapturedProxySettings{HTTPSProxy: "http://captured.example:8080"}
	transport := NewOutboundTransport(settings)
	defer transport.CloseIdleConnections()
	if transport.Proxy == nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify || transport.ForceAttemptHTTP2 {
		t.Fatal("outbound transport did not retain safe explicit settings")
	}
	req, err := http.NewRequest(http.MethodGet, "https://public.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := transport.Proxy(req)
	if err != nil || proxyURL == nil || proxyURL.Host != "captured.example:8080" {
		t.Fatalf("transport did not use captured parent proxy: %v, %v", proxyURL, err)
	}
}

func TestProxy_TunnelCancellationClosesBothDirections(t *testing.T) {
	client, upstream := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tunnel(ctx, client, nil, upstream, Limits{IdleTimeout: time.Second})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tunnel did not stop after cancellation")
	}
}

func newTestProxy(t *testing.T, config Config) *Server {
	t.Helper()
	if config.Username == "" {
		config.Username = testUser
	}
	if config.Password == "" {
		config.Password = testPassword
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func openProxy(t *testing.T, server *Server) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", server.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func writeConnect(t *testing.T, conn net.Conn, authority string, authenticated bool) {
	t.Helper()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", authority, authority)
	if authenticated {
		fmt.Fprintf(conn, "Proxy-Authorization: Basic %s\r\n", basic(testUser+":"+testPassword))
	}
	fmt.Fprint(conn, "\r\n")
}

func readProxyResponse(t *testing.T, conn net.Conn) *http.Response {
	t.Helper()
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	return response
}

func basic(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

func testAWSClassifier(host string) awsrequest.EndpointClassifier {
	return endpointClassifierFunc(func(got string) (awsrequest.AWSEndpoint, error) {
		if got != host {
			return awsrequest.AWSEndpoint{}, fmt.Errorf("unknown endpoint")
		}
		return awsrequest.AWSEndpoint{Partition: "aws", Host: host, Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}, nil
	})
}

type endpointClassifierFunc func(string) (awsrequest.AWSEndpoint, error)

func (f endpointClassifierFunc) Classify(host string) (awsrequest.AWSEndpoint, error) {
	return f(host)
}

func mustPort(t *testing.T, address net.Addr) int {
	t.Helper()
	_, port, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
