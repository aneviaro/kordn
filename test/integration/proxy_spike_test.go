// Copyright 2026 Kordn AI contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package integration contains executable protocol spikes. These helpers are
// intentionally test-local: Task 1 proves the trust and tunnel boundaries
// without prematurely becoming the production proxy implementation.
package integration

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type certificateTestingT interface {
	Helper()
	Fatalf(string, ...interface{})
}

type spikeCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newSpikeCA(t *testing.T, commonName string) *spikeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("generate CA serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return &spikeCA{
		cert: cert,
		key:  key,
		certPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}),
	}
}

func (ca *spikeCA) issue(t certificateTestingT, host string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("generate leaf serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-2 * time.Minute),
		NotAfter:     time.Now().Add(30 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create %s leaf: %v", host, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s leaf: %v", host, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal %s leaf key: %v", host, err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("make %s TLS pair: %v", host, err)
	}
	return pair, cert
}

func (ca *spikeCA) roots(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.certPEM) {
		t.Fatal("append spike CA to trust pool")
	}
	return pool
}

type tlsFixtureServer struct {
	server *http.Server
	addr   string
	cert   *x509.Certificate
}

func startTLSFixtureServer(t *testing.T, host string, ca *spikeCA, handler http.Handler) *tlsFixtureServer {
	t.Helper()
	pair, cert := ca.issue(t, host)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TLS fixture: %v", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	})
	server := &http.Server{Handler: handler}
	fixture := &tlsFixtureServer{server: server, addr: listener.Addr().String(), cert: cert}
	go func() {
		_ = server.Serve(tlsListener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
	})
	return fixture
}

type spikeRoute struct {
	addr  string
	roots *x509.CertPool
}

type spikeProxy struct {
	listener   net.Listener
	addr       string
	ca         *spikeCA
	classifies func(string) bool
	routes     map[string]spikeRoute

	mu             sync.Mutex
	interceptCount int
	tunnelCount    int
}

func startSpikeProxy(t *testing.T, ca *spikeCA, classifier func(string) bool, routes map[string]spikeRoute) *spikeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback CONNECT proxy: %v", err)
	}
	proxy := &spikeProxy{
		listener:   listener,
		addr:       listener.Addr().String(),
		ca:         ca,
		classifies: classifier,
		routes:     routes,
	}
	go proxy.accept()
	t.Cleanup(func() {
		_ = listener.Close()
	})
	return proxy
}

func (p *spikeProxy) accept() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *spikeProxy) handle(client net.Conn) {
	defer client.Close()
	request, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil || request.Method != http.MethodConnect {
		return
	}
	host := authorityHost(request.Host)
	route, ok := p.routes[host]
	if !ok {
		return
	}
	upstream, err := net.DialTimeout("tcp", route.addr, 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	if p.classifies(host) {
		upstreamTLS := tls.Client(upstream, &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    route.roots,
			ServerName: host,
		})
		if err := upstreamTLS.Handshake(); err != nil {
			return
		}
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		leaf, _ := p.ca.issue(testT{}, host)
		// The production implementation will issue a leaf from its run CA. The
		// test-only adapter below supplies a testing context without calling
		// Fatal from a proxy goroutine.
		serverTLS := tls.Server(client, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{leaf},
		})
		if err := serverTLS.Handshake(); err != nil {
			return
		}
		p.mu.Lock()
		p.interceptCount++
		p.mu.Unlock()
		duplex(serverTLS, upstreamTLS)
		return
	}

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	p.mu.Lock()
	p.tunnelCount++
	p.mu.Unlock()
	duplex(client, upstream)
}

// testT implements the tiny portion of testing.T used by issue. It is safe to
// pass through a handler goroutine because all certificate errors are returned
// by issue before the certificate is used.
type testT struct{}

func (testT) Helper() {}
func (testT) Fatalf(format string, args ...interface{}) {
	panic(fmt.Sprintf(format, args...))
}
func (testT) Fatal(args ...interface{}) { panic(fmt.Sprint(args...)) }

func authorityHost(authority string) string {
	host, _, err := net.SplitHostPort(authority)
	if err == nil {
		return strings.TrimSuffix(strings.ToLower(host), ".")
	}
	return strings.TrimSuffix(strings.ToLower(authority), ".")
}

func duplex(left, right net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(left, right)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(right, left)
		done <- struct{}{}
	}()
	<-done
	_ = left.Close()
	_ = right.Close()
	<-done
}

func proxyClient(t *testing.T, proxy *spikeProxy, tlsConfig *tls.Config) *http.Client {
	t.Helper()
	proxyURL := &url.URL{Scheme: "http", Host: proxy.addr}
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func childRootsFromCA(t *testing.T) *x509.CertPool {
	t.Helper()
	path := os.Getenv("AWS_CA_BUNDLE")
	if path == "" {
		t.Fatal("AWS_CA_BUNDLE is not set for child TLS configuration")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read child AWS_CA_BUNDLE: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Fatal("child AWS_CA_BUNDLE contains no certificate")
	}
	return pool
}

func systemPoolHasSubject(pool *x509.CertPool, cert *x509.Certificate) bool {
	if pool == nil {
		return false
	}
	for _, subject := range pool.Subjects() {
		if bytes.Equal(subject, cert.RawSubject) {
			return true
		}
	}
	return false
}

func readBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return body
}

func TestProxySpike_InterceptAWSWithRunCA(t *testing.T) {
	const awsHost = "sts.us-east-1.amazonaws.com"
	beforeSystem, _ := x509.SystemCertPool()
	t.Setenv("AWS_CA_BUNDLE", "")

	runCA := newSpikeCA(t, "Kordn Task 1 run CA")
	upstreamCA := newSpikeCA(t, "Task 1 upstream test CA")
	var upstreamCalls atomic.Int32
	upstream := startTLSFixtureServer(t, awsHost, upstreamCA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.URL.Path != "/caller-identity" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, "aws-like-upstream")
	}))
	proxy := startSpikeProxy(t, runCA, func(host string) bool {
		// This is the injected positive classifier required by the spike. It
		// deliberately does not model the production endpoint registry.
		return host == awsHost
	}, map[string]spikeRoute{
		awsHost: {addr: upstream.addr, roots: upstreamCA.roots(t)},
	})

	// An empty, child-local pool cannot validate the generated run leaf. This
	// is the negative control and does not consult or modify system roots.
	withoutRunCA := proxyClient(t, proxy, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    x509.NewCertPool(),
		ServerName: awsHost,
	})
	if response, err := withoutRunCA.Get("https://" + awsHost + "/caller-identity"); err == nil {
		response.Body.Close()
		t.Fatal("AWS-like TLS unexpectedly worked without AWS_CA_BUNDLE")
	}

	bundlePath := filepath.Join(t.TempDir(), "run-ca.pem")
	if err := os.WriteFile(bundlePath, runCA.certPEM, 0o600); err != nil {
		t.Fatalf("write child CA bundle: %v", err)
	}
	t.Setenv("AWS_CA_BUNDLE", bundlePath)
	info, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatalf("stat child CA bundle: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("child CA bundle mode = %04o, want 0600", got)
	}

	var peer *x509.Certificate
	withRunCA := proxyClient(t, proxy, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    childRootsFromCA(t),
		ServerName: awsHost,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) > 0 {
				peer = state.PeerCertificates[0]
			}
			return nil
		},
	})
	response, err := withRunCA.Get("https://" + awsHost + "/caller-identity")
	if err != nil {
		t.Fatalf("AWS-like request through run CA: %v", err)
	}
	if got, want := string(readBody(t, response)), "aws-like-upstream"; got != want {
		t.Fatalf("upstream body = %q, want %q", got, want)
	}
	if peer == nil || !bytes.Equal(peer.RawIssuer, runCA.cert.RawSubject) {
		t.Fatalf("client did not receive a leaf issued by the per-run CA")
	}
	if len(peer.DNSNames) != 1 || peer.DNSNames[0] != awsHost {
		t.Fatalf("run leaf DNS SAN = %v, want [%s]", peer.DNSNames, awsHost)
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls.Load())
	}
	if systemPoolHasSubject(beforeSystem, runCA.cert) {
		t.Fatal("random per-run CA was already present in the system trust pool")
	}
	afterSystem, _ := x509.SystemCertPool()
	if systemPoolHasSubject(afterSystem, runCA.cert) {
		t.Fatal("test CA appeared in the system trust pool")
	}
}

func TestProxySpike_TunnelNonAWSOpaque(t *testing.T) {
	const nonAWSHost = "agent.example.test"
	t.Setenv("AWS_CA_BUNDLE", "")

	runCA := newSpikeCA(t, "Kordn Task 1 unrelated run CA")
	externalCA := newSpikeCA(t, "Task 1 external service CA")
	requestPayload := []byte{0x00, 0x01, 0x02, 'o', 'p', 'a', 'q', 'u', 'e', 0xff}
	responsePayload := []byte{0x10, 0x00, 'e', 'n', 'd', '-', 't', 'o', '-', 'e', 'n', 'd'}
	var received atomic.Value
	external := startTLSFixtureServer(t, nonAWSHost, externalCA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		received.Store(append([]byte(nil), body...))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(responsePayload)
	}))
	proxy := startSpikeProxy(t, runCA, func(host string) bool {
		return host == "sts.us-east-1.amazonaws.com"
	}, map[string]spikeRoute{
		nonAWSHost: {addr: external.addr},
	})

	var peer *x509.Certificate
	client := proxyClient(t, proxy, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    externalCA.roots(t),
		ServerName: nonAWSHost,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) > 0 {
				peer = state.PeerCertificates[0]
			}
			return nil
		},
	})
	request, err := http.NewRequest(http.MethodPost, "https://"+nonAWSHost+"/opaque", bytes.NewReader(requestPayload))
	if err != nil {
		t.Fatalf("make opaque request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("opaque CONNECT request: %v", err)
	}
	if got := response.StatusCode; got != http.StatusCreated {
		t.Fatalf("opaque response status = %d, want %d", got, http.StatusCreated)
	}
	if got := readBody(t, response); !bytes.Equal(got, responsePayload) {
		t.Fatalf("opaque response bytes = %x, want %x", got, responsePayload)
	}
	gotRequest := received.Load()
	if gotRequest == nil || !bytes.Equal(gotRequest.([]byte), requestPayload) {
		t.Fatalf("opaque request bytes = %x, want %x", gotRequest, requestPayload)
	}
	if peer == nil || !bytes.Equal(peer.Raw, external.cert.Raw) {
		t.Fatal("opaque CONNECT did not preserve the external server certificate")
	}
	proxy.mu.Lock()
	intercepts, tunnels := proxy.interceptCount, proxy.tunnelCount
	proxy.mu.Unlock()
	if intercepts != 0 {
		t.Fatalf("non-AWS request was intercepted %d times", intercepts)
	}
	if tunnels != 1 {
		t.Fatalf("opaque tunnel count = %d, want 1", tunnels)
	}
}
