// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kordn-ai/kordn/internal/runtime"
)

// Resolver is deliberately injectable. Production uses net.Resolver, while
// tests can return deterministic complete answer sets.
type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type ResolverFunc func(context.Context, string, string) ([]net.IP, error)

func (f ResolverFunc) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f(ctx, network, host)
}

// ContextDialer is the only socket seam used by direct tunnel dialing.
type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type DialerFunc func(context.Context, string, string) (net.Conn, error)

func (f DialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// TargetAllowFunc is an explicit test/integration seam for a local fixture.
// Returning true opts one exact resolved IP into the otherwise prohibited
// destination policy; production callers should leave it nil.
type TargetAllowFunc func(host string, ip net.IP) bool

// DefaultResolver and DefaultDialer are variables rather than process-global
// mutable settings, making production behavior obvious and tests injectable.
var DefaultResolver Resolver = net.DefaultResolver
var DefaultDialer ContextDialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}

var prohibitedMetadata = map[string]struct{}{
	"169.254.169.254": {},
	"169.254.170.2":   {},
	"fd00:ec2::254":   {},
}

// IsUnsafeIP rejects local, special-use, and private/internal addresses. The
// policy is intentionally conservative because this package is a proxy relay.
func IsUnsafeIP(ip net.IP) bool {
	ip = normalizedIP(ip)
	if ip == nil {
		return true
	}
	if _, ok := prohibitedMetadata[ip.String()]; ok {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || !ip.IsGlobalUnicast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// CGNAT, benchmarking, documentation, and reserved IPv4 ranges are
		// not public destinations and must not become proxy relays.
		if (v4[0] == 100 && v4[1]&0xc0 == 64) ||
			(v4[0] == 192 && v4[1] == 0 && v4[2] == 0) ||
			(v4[0] == 198 && v4[1]&0xfe == 18) ||
			(v4[0] == 192 && v4[1] == 0 && v4[2] == 2) ||
			(v4[0] == 198 && v4[1] == 51 && v4[2] == 100) ||
			(v4[0] == 203 && v4[1] == 0 && v4[2] == 113) ||
			v4[0] >= 240 {
			return true
		}
	}
	return false
}

func normalizedIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if four := ip.To4(); four != nil {
		return four
	}
	return ip.To16()
}

func ValidateResolvedIPs(host string, ips []net.IP, allow TargetAllowFunc) error {
	if len(ips) == 0 {
		return errors.New("destination has no DNS answers")
	}
	for _, original := range ips {
		ip := normalizedIP(original)
		if ip == nil || (IsUnsafeIP(ip) && (allow == nil || !allow(host, ip))) {
			return errors.New("destination resolves to a prohibited address")
		}
	}
	return nil
}

// ResolveAndValidate resolves once and validates the entire answer set. The
// returned slice is the pinned answer set; callers must not pass the original
// hostname to a second resolving Dialer.
func ResolveAndValidate(ctx context.Context, host string, resolver Resolver, allow TargetAllowFunc) ([]net.IP, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if resolver == nil {
		resolver = DefaultResolver
	}
	if net.ParseIP(host) != nil {
		ip := net.ParseIP(host)
		if err := ValidateResolvedIPs(host, []net.IP{ip}, allow); err != nil {
			return nil, err
		}
		return []net.IP{normalizedIP(ip)}, nil
	}
	if host == "" || strings.ContainsAny(host, "\x00\r\n /:@[]%\\") {
		return nil, errors.New("destination hostname is malformed")
	}
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("destination resolution failed")
	}
	if err := ValidateResolvedIPs(host, ips, allow); err != nil {
		return nil, err
	}
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		result = append(result, normalizedIP(ip))
	}
	return result, nil
}

// DialValidated resolves and validates exactly once, then dials a selected
// validated literal address. This prevents a resolver result from changing
// underneath net.Dialer during connection establishment.
func DialValidated(ctx context.Context, network, hostport string, resolver Resolver, dialer ContextDialer, allow TargetAllowFunc) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || host == "" || parsePort(port) == 0 {
		return nil, errors.New("destination address is malformed")
	}
	if dialer == nil {
		dialer = DefaultDialer
	}
	ips, err := ResolveAndValidate(ctx, host, resolver, allow)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		address := net.JoinHostPort(ip.String(), port)
		conn, dialErr := dialer.DialContext(ctx, network, address)
		if dialErr == nil {
			return conn, nil
		}
		last = dialErr
	}
	if last == nil {
		last = errors.New("destination connection failed")
	}
	return nil, last
}

// TransportConfig provides an immutable parent-proxy snapshot and optional
// deterministic seams. Parent proxy values are captured before the child env
// is built; no HTTP proxy environment lookup occurs here.
type TransportConfig struct {
	ParentProxy runtime.CapturedProxySettings
	Resolver    Resolver
	Dialer      ContextDialer
	TargetAllow TargetAllowFunc
	RootCAs     *x509.CertPool
}

// NewOutboundTransport creates a separate public-PKI transport. If a parent
// proxy is present it is used explicitly; otherwise direct target dialing is
// pinned to the validated DNS answer set by the caller's request path.
func NewOutboundTransport(settings runtime.CapturedProxySettings, options ...TransportConfig) *http.Transport {
	config := TransportConfig{ParentProxy: settings}
	if len(options) > 0 {
		config = options[0]
		config.ParentProxy = settings
	}
	transport := settings.NewOutboundTransport()
	transport.ForceAttemptHTTP2 = false
	if config.Dialer != nil {
		transport.DialContext = config.Dialer.DialContext
	}
	if config.RootCAs != nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.RootCAs}
	}
	return transport
}

// parentProxyFor is the single parent-proxy validation seam used by CONNECT
// and plaintext forwarding. runtime.ProxyFunc intentionally honors NO_PROXY;
// validate the selected value before invoking it so an unsupported scheme
// cannot be hidden by a bypass entry.
func parentProxyFor(settings runtime.CapturedProxySettings, scheme, host string) (*url.URL, error) {
	if !strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https") {
		return nil, errors.New("unsupported parent proxy target scheme")
	}
	value := settings.HTTPProxy
	if strings.EqualFold(scheme, "https") {
		value = settings.HTTPSProxy
	}
	if value == "" {
		value = settings.AllProxy
	}
	if value != "" {
		if _, err := validateParentProxyURL(value); err != nil {
			return nil, err
		}
	}
	reqURL := &url.URL{Scheme: strings.ToLower(scheme), Host: host}
	req := &http.Request{URL: reqURL}
	proxy, err := settings.ProxyFunc()(req)
	if err != nil {
		return nil, err
	}
	if proxy == nil {
		return nil, nil
	}
	if err := validateParsedParentProxyURL(proxy); err != nil {
		return nil, err
	}
	return proxy, nil
}

func validateParentProxyURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, errors.New("parent proxy URL is invalid")
	}
	if err := validateParsedParentProxyURL(parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func validateParsedParentProxyURL(parsed *url.URL) error {
	if parsed == nil || parsed.Host == "" || parsed.Hostname() == "" ||
		(!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) ||
		parsed.Opaque != "" || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return errors.New("parent proxy URL is invalid")
	}
	if parsed.Port() != "" && parsePort(parsed.Port()) == 0 {
		return errors.New("parent proxy port is invalid")
	}
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		if strings.ContainsAny(parsed.User.Username()+password, "\x00\r\n") {
			return errors.New("parent proxy credentials are invalid")
		}
	}
	return nil
}

func proxyAuthority(proxyURL *url.URL) (string, error) {
	if err := validateParsedParentProxyURL(proxyURL); err != nil {
		return "", err
	}
	port := proxyURL.Port()
	if port == "" {
		if strings.EqualFold(proxyURL.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("corporate proxy port is invalid")
	}
	return net.JoinHostPort(proxyURL.Hostname(), strconv.Itoa(portNumber)), nil
}

func dialCorporateProxy(ctx context.Context, proxyURL *url.URL, dialer ContextDialer) (net.Conn, error) {
	address, err := proxyAuthority(proxyURL)
	if err != nil {
		return nil, err
	}
	if dialer == nil {
		dialer = DefaultDialer
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errors.New("corporate proxy connection failed")
	}
	setContextDeadline(conn, ctx)
	if strings.EqualFold(proxyURL.Scheme, "https") {
		tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: proxyURL.Hostname()})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, errors.New("corporate proxy TLS failed")
		}
		return tlsConn, nil
	}
	return conn, nil
}

type responseHeaderReader struct {
	reader *bufio.Reader
	limit  int
	read   int
}

// Read returns at most one byte so the parser cannot read tunnel payload into
// a one-shot header limit. The underlying buffered reader still reads the
// socket efficiently, and its buffered payload is returned after parsing.
func (r *responseHeaderReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.read >= r.limit {
		return 0, errors.New("corporate proxy response header is too large")
	}
	n, err := r.reader.Read(p[:1])
	r.read += n
	return n, err
}

func readBoundedProxyResponse(conn net.Conn, limits Limits) (*http.Response, *bufio.Reader, error) {
	if conn == nil {
		return nil, nil, errors.New("corporate proxy response is unavailable")
	}
	limits = limits.withDefaults()
	source := bufio.NewReader(conn)
	parser := bufio.NewReader(&responseHeaderReader{reader: source, limit: limits.MaxHeaderBytes})
	response, err := http.ReadResponse(parser, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, nil, errors.New("corporate proxy response is malformed")
	}
	if response.StatusCode < 100 || response.StatusCode > 599 || response.StatusCode/100 == 1 {
		return nil, nil, errors.New("corporate proxy response status is invalid")
	}
	if response.ContentLength > 0 || len(response.TransferEncoding) != 0 {
		return nil, nil, errors.New("corporate proxy CONNECT response has a body")
	}
	headerCount := 0
	for key, values := range response.Header {
		headerCount += len(values)
		if len(key) > limits.MaxHeaderBytes {
			return nil, nil, errors.New("corporate proxy response header is too large")
		}
		for _, value := range values {
			if len(value) > limits.MaxHeaderBytes || len(key)+len(value) > limits.MaxHeaderBytes {
				return nil, nil, errors.New("corporate proxy response header is too large")
			}
		}
	}
	if headerCount > limits.MaxHeaderCount {
		return nil, nil, errors.New("corporate proxy response has too many headers")
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	// The outer parser reads one byte at a time, so at most a small prefix can
	// remain buffered. Preserve it, then resume from the socket reader whose
	// own buffer may already contain arbitrary tunnel payload.
	prefix := make([]byte, parser.Buffered())
	if len(prefix) > 0 {
		if _, err := io.ReadFull(parser, prefix); err != nil {
			return nil, nil, errors.New("corporate proxy response is malformed")
		}
	}
	if len(prefix) == 0 {
		return response, source, nil
	}
	return response, bufio.NewReader(io.MultiReader(bytes.NewReader(prefix), source)), nil
}

func connectThroughCorporateProxy(ctx context.Context, proxyURL *url.URL, target string, dialer ContextDialer, limits Limits) (net.Conn, error) {
	conn, err := dialCorporateProxy(ctx, proxyURL, dialer)
	if err != nil {
		return nil, err
	}
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := proxyURL.User.Username() + ":" + password
		if strings.ContainsAny(credentials, "\x00\r\n") {
			_ = conn.Close()
			return nil, errors.New("corporate proxy credentials are malformed")
		}
		request += "Proxy-Authorization: Basic " + base64Encode(credentials) + "\r\n"
	}
	request += "\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		_ = conn.Close()
		return nil, errors.New("corporate proxy CONNECT failed")
	}
	response, reader, err := readBoundedProxyResponse(conn, limits)
	if err != nil || response.StatusCode/100 != 2 {
		_ = conn.Close()
		return nil, errors.New("corporate proxy rejected CONNECT")
	}
	clearDeadline(conn)
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func base64Encode(value string) string {
	// Proxy credentials are generated from URL-safe material, but standard
	// Basic encoding is required on the corporate wire.
	return encodeStdBase64([]byte(value))
}

func encodeStdBase64(value []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(value)+2)/3*4)
	for i := 0; i < len(value); i += 3 {
		left := len(value) - i
		a, b, c := value[i], byte(0), byte(0)
		if left > 1 {
			b = value[i+1]
		}
		if left > 2 {
			c = value[i+2]
		}
		result = append(result, alphabet[a>>2], alphabet[((a&3)<<4)|(b>>4)])
		if left > 1 {
			result = append(result, alphabet[((b&15)<<2)|(c>>6)])
		} else {
			result = append(result, '=')
		}
		if left > 2 {
			result = append(result, alphabet[c&63])
		} else {
			result = append(result, '=')
		}
	}
	return string(result)
}

func setContextDeadline(conn net.Conn, ctx context.Context) {
	if conn == nil || ctx == nil {
		return
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
}

func clearDeadline(conn net.Conn) {
	if conn != nil {
		_ = conn.SetDeadline(time.Time{})
	}
}

func (c TransportConfig) String() string {
	return fmt.Sprintf("TransportConfig{resolver:%t dialer:%t}", c.Resolver != nil, c.Dialer != nil)
}
