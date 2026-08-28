//go:build compat

// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package compatibility

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/kordn-ai/kordn/internal/proxy"
	"github.com/kordn-ai/kordn/internal/runtime"
)

func TestCorporateProxyAuthenticatedRelayReconnectAndStreaming(t *testing.T) {
	var mu sync.Mutex
	var authHeaders []string
	var targets []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Payload-Len", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()
	upstreamPort := mustPortText(t, upstream.Listener.Addr().String())
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		authHeaders = append(authHeaders, r.Header.Get("Proxy-Authorization"))
		targets = append(targets, r.Host)
		mu.Unlock()
		if r.Header.Get("Proxy-Authorization") != "Basic Y29ycC11c2VyOmNvcnAtc2VjcmV0" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("parent does not support hijacking")
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		destination, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", upstreamPort))
		if err != nil {
			_ = client.Close()
			return
		}
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(destination, buffered); _ = destination.Close() }()
		go func() { _, _ = io.Copy(client, destination); _ = client.Close() }()
	}))
	defer parent.Close()
	parsed, _ := url.Parse(parent.URL)
	parentURL := "http://corp-user:corp-secret@" + parsed.Host
	names := []string{"corporate-a.example.test", "corporate-b.example.test", "corporate-b.example.test"}
	server, err := proxy.NewServer(proxy.Config{Username: "local", Password: "local-secret", ParentProxy: runtimeSettings(parentURL),
		Resolver: proxy.ResolverFunc(func(_ context.Context, _, host string) ([]net.IP, error) {
			if strings.HasPrefix(host, "corporate-") {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, fmt.Errorf("unexpected lookup %s", host)
		}),
		TargetAllow: func(host string, ip net.IP) bool { return strings.HasPrefix(host, "corporate-") && ip.IsLoopback() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for i, name := range names {
		conn, err := net.Dial("tcp", server.Addr())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic bG9jYWw6bG9jYWwtc2VjcmV0\r\n\r\n", name, upstreamPort, name, upstreamPort)
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT %d response=%v err=%v", i, response, err)
		}
		clientTLS := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: name})
		if err := clientTLS.Handshake(); err != nil {
			t.Fatal(err)
		}
		chunks := [][]byte{bytes.Repeat([]byte{byte(i + 1)}, 257), bytes.Repeat([]byte{0xff}, 4099), []byte("final")}
		total := 0
		for _, chunk := range chunks {
			total += len(chunk)
		}
		fmt.Fprintf(clientTLS, "POST /chunks HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", name, total)
		for _, chunk := range chunks {
			if _, err := clientTLS.Write(chunk); err != nil {
				t.Fatal(err)
			}
		}
		result, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(result.Body)
		_ = clientTLS.Close()
		if len(body) != total {
			t.Fatalf("streaming payload %d bytes, want %d", len(body), total)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(authHeaders) != len(names) {
		t.Fatalf("parent CONNECT count=%d, want %d", len(authHeaders), len(names))
	}
	for _, auth := range authHeaders {
		if auth != "Basic Y29ycC11c2VyOmNvcnAtc2VjcmV0" {
			t.Fatalf("parent saw wrong auth %q", auth)
		}
	}
	for _, target := range targets {
		if strings.Contains(target, server.Addr()) {
			t.Fatalf("corporate parent recursively targeted local Kordn: %q", target)
		}
	}
}

func runtimeSettings(value string) runtime.CapturedProxySettings {
	return runtime.CapturedProxySettings{HTTPSProxy: value, HTTPProxy: value}
}
func mustPortText(t *testing.T, address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
