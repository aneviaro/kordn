// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

// Package proxy implements Kordn's authenticated loopback proxy. AWS endpoint
// classification happens before any outbound operation; only a recognized AWS
// TLS CONNECT is terminated. All other permitted CONNECT streams are bytes.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kordn-ai/kordn/internal/audit"
	"github.com/kordn-ai/kordn/internal/awserror"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/cache"
	"github.com/kordn-ai/kordn/internal/observe"
	"github.com/kordn-ai/kordn/internal/pki"
	"github.com/kordn-ai/kordn/internal/policy"
	"github.com/kordn-ai/kordn/internal/runtime"
	"github.com/kordn-ai/kordn/internal/sigv4"
)

// Config is immutable after NewServer. Username/Password are the per-run
// Basic credentials produced by credentials.GenerateRunSecrets. Auth may be
// supplied instead when a caller already owns an Authenticator.
type Config struct {
	ListenAddr string
	Addr       string

	Username      string
	Password      string
	ProxyUsername string
	ProxySecret   string
	Auth          *Authenticator

	Classifier  awsrequest.EndpointClassifier
	Resolver    Resolver
	Dialer      ContextDialer
	TargetAllow TargetAllowFunc

	// ParentProxy is captured before child environment construction. The
	// explicit URL is convenient for an application composition root and is
	// copied into an immutable settings value by NewServer.
	ParentProxy       runtime.CapturedProxySettings
	CorporateProxyURL string

	CA           *pki.CA
	LeafCache    *pki.LeafCache
	CADir        string
	LeafCapacity int

	Limits Limits

	// AWSHandler is invoked only after a recognized AWS CONNECT has been
	// terminated and the inner Host independently agrees. Handler is an alias
	// for simple compositions; neither path forwards AWS automatically.
	AWSHandler       http.Handler
	InterceptHandler http.Handler
	Handler          http.Handler

	// Pipeline dependencies are supplied by the run composition root. A
	// missing dependency is a safety failure, never a permissive fallback.
	InboundAuthenticator awsrequest.InboundAuthenticator
	Decoder              awsrequest.AWSRequestDecoder
	Mapper               awsrequest.IAMMapper
	Policy               policy.PolicyEngine
	Audit                audit.AuditWriter
	Resigner             *sigv4.Resigner
	Upstream             http.RoundTripper
	RunID                string
	PolicyHash           string
	// Resource logging is copied from the validated run configuration. These
	// flags are immutable runtime policy, not request-controlled options.
	LogResourceARNs   bool
	HashResourceNames bool
	// Optional immutable implementation versions participate in cache keys.
	MapperVersion            string
	AdapterVersion           string
	DataVersion              string
	Metrics                  *observe.Metrics
	MaxConcurrentRequests    int
	MaxConcurrentConnections int

	// Caches are run-scoped and bounded. A nil value creates fresh caches for
	// this server; callers may provide smaller caches for deterministic tests.
	Caches *cache.RunCaches
}

// Server is an authenticated, loopback-only HTTP proxy.
type Server struct {
	config          Config
	limits          Limits
	auth            *Authenticator
	classifier      awsrequest.EndpointClassifier
	resolver        Resolver
	dialer          ContextDialer
	ca              *pki.CA
	leaves          *pki.LeafCache
	listener        net.Listener
	httpServer      *http.Server
	addr            string
	ownedCA         bool
	ownedDir        string
	ownedDirTemp    bool
	closed          bool
	active          map[net.Conn]struct{}
	mu              sync.Mutex
	closeOnce       sync.Once
	closeErr        error
	requestSlots    chan struct{}
	connectionSlots chan struct{}
	metrics         *observe.Metrics
	caches          *cache.RunCaches
}

// NewServer validates security-sensitive configuration and creates the
// private per-run CA/leaf cache when the composition root did not provide one.
func NewServer(config Config) (*Server, error) {
	listenAddr := config.ListenAddr
	if listenAddr == "" {
		listenAddr = config.Addr
	}
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	if err := validateListenAddr(listenAddr); err != nil {
		return nil, err
	}
	limits := config.Limits.withDefaults()
	username, password := config.Username, config.Password
	if username == "" {
		username = config.ProxyUsername
	}
	if password == "" {
		password = config.ProxySecret
	}
	auth := config.Auth
	var err error
	if auth == nil {
		auth, err = NewAuthenticator(username, password)
		if err != nil {
			return nil, err
		}
	}
	classifier := config.Classifier
	if classifier == nil {
		classifier = awsrequest.DefaultClassifier()
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = DefaultResolver
	}
	dialer := config.Dialer
	if dialer == nil {
		dialer = DefaultDialer
	}
	metrics := config.Metrics
	if metrics == nil {
		metrics = observe.NewMetrics()
	}
	maxRequests, maxConnections := config.MaxConcurrentRequests, config.MaxConcurrentConnections
	if maxRequests <= 0 {
		maxRequests = 128
	}
	if maxConnections <= 0 {
		maxConnections = 256
	}
	runCaches := config.Caches
	if runCaches == nil {
		runCaches, err = cache.NewRunCaches(cache.CacheOptions{})
		if err != nil {
			return nil, errors.New("create run caches")
		}
	}
	server := &Server{config: config, limits: limits, auth: auth, classifier: classifier, resolver: resolver, dialer: dialer, active: make(map[net.Conn]struct{}), requestSlots: make(chan struct{}, maxRequests), connectionSlots: make(chan struct{}, maxConnections), metrics: metrics, caches: runCaches}
	server.config.ListenAddr = listenAddr
	if config.CorporateProxyURL != "" {
		if err := server.setCorporateProxy(config.CorporateProxyURL); err != nil {
			return nil, err
		}
	}
	if config.CA != nil {
		server.ca = config.CA
	} else {
		dir := config.CADir
		created := false
		if dir == "" {
			dir, err = os.MkdirTemp("", "kordn-run-")
			if err != nil {
				return nil, errors.New("create private CA runtime directory")
			}
			_ = os.Chmod(dir, 0o700)
			created = true
		}
		server.ca, err = pki.NewCA(dir)
		if err != nil {
			if created {
				_ = os.RemoveAll(dir)
			}
			return nil, err
		}
		server.ownedCA = true
		server.ownedDir = dir
		server.ownedDirTemp = created
	}
	if config.LeafCache != nil {
		server.leaves = config.LeafCache
	} else {
		server.leaves, err = pki.NewLeafCache(server.ca, config.LeafCapacity)
		if err != nil {
			if server.ownedCA {
				_ = server.ca.Cleanup()
			}
			return nil, err
		}
	}
	return server, nil
}

func New(config Config) (*Server, error) { return NewServer(config) }

func validateListenAddr(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host != "127.0.0.1" || portText == "" {
		return errors.New("proxy must bind to 127.0.0.1")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("proxy listen port is invalid")
	}
	return nil
}

func (s *Server) setCorporateProxy(value string) error {
	if _, err := validateParentProxyURL(value); err != nil {
		return err
	}
	s.config.ParentProxy.HTTPProxy = value
	s.config.ParentProxy.HTTPSProxy = value
	return nil
}

// Listen binds the configured loopback address and returns its ephemeral
// address. It does not start a serving goroutine.
func (s *Server) Listen() error {
	if s == nil {
		return errors.New("proxy server is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("proxy server is closed")
	}
	if s.listener != nil {
		return nil
	}
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return errors.New("bind loopback proxy")
	}
	s.listener = listener
	s.addr = listener.Addr().String()
	return nil
}

// Start binds and starts serving in a background goroutine. Use Serve when
// the caller wants to own the serving goroutine and returned error.
func (s *Server) Start() error {
	if err := s.Listen(); err != nil {
		return err
	}
	go func() { _ = s.Serve(nil) }()
	return nil
}

func (s *Server) ListenAndServe() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve(nil)
}

// Serve serves on l, or the listener created by Listen when l is nil.
func (s *Server) Serve(l net.Listener) error {
	if s == nil {
		return errors.New("proxy server is nil")
	}
	if l != nil {
		if err := validateListener(l); err != nil {
			return err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return errors.New("proxy server is closed")
		}
		s.listener = l
		s.addr = l.Addr().String()
		s.mu.Unlock()
	} else if err := s.Listen(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.httpServer == nil {
		s.httpServer = &http.Server{Handler: s, ConnState: s.connState, ReadHeaderTimeout: s.limits.ReadHeaderTimeout, ReadTimeout: s.limits.ReadTimeout, WriteTimeout: s.limits.WriteTimeout, IdleTimeout: s.limits.IdleTimeout, MaxHeaderBytes: s.limits.MaxHeaderBytes}
	}
	httpServer := s.httpServer
	listener := s.listener
	s.mu.Unlock()
	err := httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func validateListener(listener net.Listener) error {
	tcp, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcp.IP == nil || !tcp.IP.IsLoopback() || !tcp.IP.Equal(net.ParseIP("127.0.0.1")) {
		return errors.New("proxy listener must be IPv4 loopback")
	}
	return nil
}

func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}
func (s *Server) Address() string { return s.Addr() }
func (s *Server) CA() *pki.CA {
	if s == nil {
		return nil
	}
	return s.ca
}
func (s *Server) CAPEMPath() string {
	if s == nil || s.ca == nil {
		return ""
	}
	return s.ca.PEMPath()
}

// MetricsSnapshot returns a private, copy-on-read exit snapshot. No exporter
// or network endpoint is exposed.
func (s *Server) MetricsSnapshot() observe.Snapshot {
	if s == nil || s.metrics == nil {
		return observe.Snapshot{Counters: map[string]uint64{}, Histograms: map[string]observe.Histogram{}}
	}
	return s.metrics.Snapshot()
}

// IncMetric is intentionally a narrow composition-root seam for lifecycle
// counters (child exit and cleanup) that occur outside ServeHTTP.
func (s *Server) IncMetric(name string) {
	if s != nil && s.metrics != nil {
		s.metrics.Inc(name)
	}
}

// Close stops accepting requests and cleans only CA material owned by this
// server. A caller-provided CA remains owned by the caller.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		httpServer, listener := s.httpServer, s.listener
		active := make([]net.Conn, 0, len(s.active))
		for conn := range s.active {
			active = append(active, conn)
		}
		s.mu.Unlock()
		if httpServer != nil {
			s.closeErr = httpServer.Close()
		} else if listener != nil {
			s.closeErr = listener.Close()
		}
		for _, conn := range active {
			_ = conn.Close()
		}
		if s.leaves != nil {
			_ = s.leaves.Close()
		}
		if s.ownedCA && s.ca != nil {
			if err := s.ca.Cleanup(); s.closeErr == nil {
				s.closeErr = err
			}
			if s.ownedDirTemp && s.ownedDir != "" {
				if err := os.Remove(s.ownedDir); err != nil && !errors.Is(err, os.ErrNotExist) && s.closeErr == nil {
					s.closeErr = err
				}
			}
		}
		// Caches are run-scoped even when the CA is caller-owned. Do not retain
		// authenticated request material past the server lifecycle.
		if s.caches != nil {
			s.caches.Clear()
		}
	})
	return s.closeErr
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	// Authentication is intentionally the first operation. In particular, no
	// request URL, CONNECT authority, classifier, resolver, or dialer is
	// touched before this check.
	if s == nil || !s.auth.Authenticate(req) {
		if s != nil {
			s.auditProxyEvent(audit.AuthenticationFailed, "invalid_proxy_auth")
		}
		writer.Header().Set("Proxy-Authenticate", `Basic realm="kordn"`)
		writer.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	if err := s.limits.validateRequest(req); err != nil {
		http.Error(writer, "proxy request rejected", http.StatusRequestHeaderFieldsTooLarge)
		return
	}
	// CONNECT admits a connection, not an application request. An idle
	// intercepted tunnel must not occupy a request slot.
	if req.Method == http.MethodConnect {
		s.handleConnect(writer, req)
		return
	}
	if !s.acquireRequestSlot() {
		s.metrics.Inc(observe.RequestBackpressure)
		http.Error(writer, "proxy is busy", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseRequestSlot()
	s.handleHTTP(writer, req)
}

func (s *Server) handleConnect(writer http.ResponseWriter, req *http.Request) {
	dest, err := parseRequestDestination(req, true)
	if err != nil {
		http.Error(writer, "invalid CONNECT authority", http.StatusBadRequest)
		return
	}
	endpoint, aws, err := s.classifyDestination(dest)
	if err != nil {
		s.metrics.Inc(observe.Unsupported)
		s.auditProxyEvent(audit.UnsupportedRequest, "unsupported_destination")
		http.Error(writer, "destination rejected", http.StatusForbidden)
		return
	}
	// Validate the selected parent proxy before resolving a destination. This
	// applies even when NO_PROXY would otherwise bypass it, so an unsupported
	// parent scheme can never become a request-path fallback.
	proxyURL, err := parentProxyFor(s.config.ParentProxy, "https", dest.authority())
	if err != nil {
		http.Error(writer, "proxy configuration rejected", http.StatusBadGateway)
		return
	}
	if aws {
		s.handleAWSConnect(writer, req, dest, endpoint)
		return
	}
	// Non-AWS CONNECT is still an outbound relay, so validate every DNS
	// answer before opening either a direct socket or a corporate proxy.
	ctx, cancel := context.WithTimeout(req.Context(), s.limits.ConnectTimeout)
	defer cancel()
	ips, err := ResolveAndValidate(ctx, dest.Host, s.resolver, s.config.TargetAllow)
	if err != nil {
		http.Error(writer, "destination rejected", http.StatusForbidden)
		return
	}
	upstream, err := s.dialDestination(ctx, dest, ips, proxyURL)
	if err != nil {
		http.Error(writer, "destination unavailable", http.StatusBadGateway)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(writer, "proxy connection hijacking is unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if err := writeConnectEstablished(client); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	// One CONNECT is one admitted client connection. Its upstream half is not
	// another client and must not consume a second connection slot.
	if !s.trackConn(client) {
		s.metrics.Inc(observe.ConnectionBackpressure)
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	tunnel(ctx, client, buffered.Reader, upstream, s.limits)
	s.untrackConn(client)
}

func (s *Server) handleAWSConnect(writer http.ResponseWriter, req *http.Request, dest destination, endpoint awsrequest.AWSEndpoint) {
	// Issue the leaf before acknowledging CONNECT, so a closed/invalid CA can
	// never produce a successful tunnel that cannot complete TLS.
	if _, err := s.leaves.Get(dest.Host); err != nil {
		http.Error(writer, "AWS interception unavailable", http.StatusBadGateway)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "proxy connection hijacking is unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if err := writeConnectEstablished(client); err != nil {
		_ = client.Close()
		return
	}
	if !s.trackConn(client) {
		s.metrics.Inc(observe.ConnectionBackpressure)
		_ = client.Close()
		return
	}
	// The nested HTTP server used for interception returns from its one-conn
	// listener before the hijacked connection itself is closed. Keep the
	// connection slot tied to the actual net.Conn Close event rather than that
	// listener return; otherwise a live TLS tunnel could admit another client.
	client = s.promoteHijackedConn(client)
	_ = endpoint // endpoint is independently rechecked against inner Host.
	go serveInterceptedTLS(client, buffered.Reader, s, dest)
}

func (s *Server) classifyDestination(dest destination) (awsrequest.AWSEndpoint, bool, error) {
	if s != nil && s.caches != nil {
		key := (cache.EndpointKey{RunID: s.config.RunID, Host: dest.Host}).String()
		if value, ok := s.caches.Endpoints.Get(key); ok {
			if endpoint, valid := value.(awsrequest.AWSEndpoint); valid && endpoint.Host == dest.Host && dest.Port == 443 {
				s.metrics.Inc(observe.CacheEndpointHits)
				return endpoint, true, nil
			}
		}
		s.metrics.Inc(observe.CacheEndpointMisses)
	}
	endpoint, aws, err := classifyDestination(s.classifier, dest)
	if err == nil && aws && s != nil && s.caches != nil {
		key := (cache.EndpointKey{RunID: s.config.RunID, Host: dest.Host}).String()
		if _, evicted := s.caches.Endpoints.Add(key, endpoint); evicted {
			s.metrics.Inc(observe.CacheEvictions)
		}
	}
	return endpoint, aws, err
}

func (s *Server) dialDestination(ctx context.Context, dest destination, ips []net.IP, proxyURL *url.URL) (net.Conn, error) {
	if proxyURL != nil {
		// CONNECTing by the validated literal prevents the parent proxy from
		// resolving the attacker-controlled hostname a second time.
		target := net.JoinHostPort(ips[0].String(), strconv.Itoa(dest.Port))
		return connectThroughCorporateProxy(ctx, proxyURL, target, s.dialer, s.limits)
	}
	for _, ip := range ips {
		conn, dialErr := s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(dest.Port)))
		if dialErr == nil {
			return conn, nil
		}
	}
	return nil, errors.New("destination connection failed")
}

func (s *Server) handleHTTP(writer http.ResponseWriter, req *http.Request) {
	scheme := "http"
	if req.URL != nil && req.URL.Scheme != "" {
		scheme = strings.ToLower(req.URL.Scheme)
		if scheme != "http" && scheme != "https" {
			http.Error(writer, "unsupported proxy scheme", http.StatusBadRequest)
			return
		}
	}
	dest, err := parseRequestDestination(req, false)
	if err != nil {
		http.Error(writer, "invalid proxy destination", http.StatusBadRequest)
		return
	}
	if _, aws, err := s.classifyDestination(dest); err != nil {
		s.auditProxyEvent(audit.UnsupportedRequest, "unsupported_destination")
		http.Error(writer, "destination rejected", http.StatusForbidden)
		return
	} else if aws {
		// AWS plaintext is never forwarded. AWS policy starts only on a TLS
		// CONNECT and later authenticated interception seam.
		http.Error(writer, "AWS requests require TLS CONNECT", http.StatusForbidden)
		return
	}
	// Validate the selected parent proxy before DNS resolution or request
	// forwarding. This rejects unsupported schemes even when NO_PROXY would
	// otherwise make runtime.ProxyFunc return no proxy.
	proxyURL, err := parentProxyFor(s.config.ParentProxy, scheme, dest.authority())
	if err != nil {
		http.Error(writer, "proxy configuration rejected", http.StatusBadGateway)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), s.limits.ConnectTimeout)
	defer cancel()
	ips, err := ResolveAndValidate(ctx, dest.Host, s.resolver, s.config.TargetAllow)
	if err != nil {
		http.Error(writer, "destination rejected", http.StatusForbidden)
		return
	}
	outgoing := req.Clone(ctx)
	outgoing.RequestURI = ""
	outgoing.Host = dest.authority()
	removeHopByHopHeaders(outgoing.Header)
	if outgoing.Body != nil && outgoing.Body != http.NoBody {
		body, err := readBoundedBody(req.Body, s.limits.MaxBodyBytes)
		if err != nil {
			http.Error(writer, "proxy request body exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}
		outgoing.Body = io.NopCloser(bytes.NewReader(body))
		outgoing.ContentLength = int64(len(body))
	}
	settings := s.config.ParentProxy
	transport := NewOutboundTransport(settings, TransportConfig{Resolver: s.resolver, Dialer: s.dialer})
	if proxyURL == nil {
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			for _, ip := range ips {
				conn, dialErr := s.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(dest.Port)))
				if dialErr == nil {
					return conn, nil
				}
			}
			return nil, errors.New("destination connection failed")
		}
	} else {
		// The parent proxy must not perform a second, potentially rebinding DNS
		// lookup for the destination. Use the first validated address for the
		// proxy's CONNECT/request target and retain the original Host/SNI name.
		pinnedHost := net.JoinHostPort(ips[0].String(), strconv.Itoa(dest.Port))
		if outgoing.URL != nil {
			outgoing.URL.Host = pinnedHost
		}
		outgoing.Host = dest.authority()
		transport.Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return s.dialer.DialContext(ctx, network, address)
		}
		if strings.EqualFold(scheme, "https") {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: dest.Host}
		}
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(outgoing)
	if err != nil {
		http.Error(writer, "destination unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	removeHopByHopHeaders(response.Header)
	copyHeaders(writer.Header(), response.Header)
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, response.Body)
}

type limitedReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *limitedReadCloser) Close() error { return r.closer.Close() }

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func (s *Server) handleIntercepted(writer http.ResponseWriter, req *http.Request, connectDest destination) {
	innerDest, err := parseInnerDestination(req)
	if err != nil || !innerDest.equal(connectDest) {
		http.Error(writer, "inner Host does not match CONNECT authority", http.StatusBadRequest)
		return
	}
	endpoint, aws, err := s.classifyDestination(innerDest)
	if err != nil || !aws || endpoint.Host != connectDest.Host {
		http.Error(writer, "inner Host is not a recognized AWS endpoint", http.StatusBadRequest)
		return
	}
	// Clone before normalization: verification, decoding, and mapping observe a
	// stable request snapshot and cannot mutate the caller-owned HTTP request.
	req = req.Clone(req.Context())
	removeHopByHopHeaders(req.Header)
	// The CONNECT path deliberately holds no request slot. Charge exactly one
	// slot to each application request, including the legacy handler seam.
	if !s.acquireRequestSlot() {
		s.metrics.Inc(observe.RequestBackpressure)
		http.Error(writer, "proxy is busy", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseRequestSlot()
	if s.pipelineConfigured() {
		s.handlePipeline(writer, req, innerDest, endpoint)
		return
	}
	handler := s.config.AWSHandler
	if handler == nil {
		handler = s.config.InterceptHandler
	}
	if handler == nil {
		handler = s.config.Handler
	}
	if handler == nil {
		http.Error(writer, "AWS request handler is not configured", http.StatusNotImplemented)
		return
	}
	if req.Body != nil && req.Body != http.NoBody {
		body, err := readBoundedBody(req.Body, s.limits.MaxBodyBytes)
		if err != nil {
			http.Error(writer, "proxy request body exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	// The endpoint is made available without requiring later pipeline code to
	// reparse a potentially attacker-controlled authority. No request data is
	// logged here.
	req = req.WithContext(context.WithValue(req.Context(), endpointContextKey{}, endpoint))
	handler.ServeHTTP(writer, req)
}

type endpointContextKey struct{}

func EndpointFromContext(ctx context.Context) (awsrequest.AWSEndpoint, bool) {
	if ctx == nil {
		return awsrequest.AWSEndpoint{}, false
	}
	endpoint, ok := ctx.Value(endpointContextKey{}).(awsrequest.AWSEndpoint)
	return endpoint, ok
}

func parseInnerDestination(req *http.Request) (destination, error) {
	if req == nil || req.Host == "" {
		return destination{}, errors.New("inner Host is required")
	}
	name, port, err := NormalizeAuthority(req.Host)
	if err != nil {
		return destination{}, err
	}
	inner := destination{Host: name, Port: port}
	// Absolute-form requests inside a CONNECT tunnel are unusual but valid
	// HTTP. Their authority must agree with Host as well; otherwise a client
	// could hide a different destination in URL.Host.
	if req.URL != nil && req.URL.IsAbs() && req.URL.Host != "" {
		urlName, urlPort, err := NormalizeAuthority(req.URL.Host)
		if err != nil || urlName != name || urlPort != port {
			return destination{}, errors.New("inner URL authority does not match Host")
		}
	}
	return inner, nil
}

func readBoundedBody(body io.ReadCloser, limit int64) ([]byte, error) {
	if body == nil || body == http.NoBody {
		return nil, nil
	}
	defer body.Close()
	if limit < 0 || limit == int64(^uint64(0)>>1) {
		return nil, errors.New("proxy body limit is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("proxy request body exceeds limit")
	}
	return data, nil
}

// connState accounts for ordinary net/http connections as well as hijacked
// tunnels. A connection slot is reserved once per client connection; the
// upstream side of a CONNECT is intentionally never passed to trackConn.
func (s *Server) connState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		if !s.trackConn(conn) {
			_ = conn.Close()
		}
	case http.StateClosed:
		s.untrackConn(conn)
	case http.StateHijacked:
		// Hijacked handlers own release; keeping the entry prevents a race
		// between this callback and the handler's explicit accounting.
	}
}

type promotedHijackedConn struct {
	net.Conn
	server *Server
	closed atomic.Bool
}

func (c *promotedHijackedConn) Close() error {
	err := c.Conn.Close()
	if c.closed.CompareAndSwap(false, true) {
		c.server.untrackConn(c)
	}
	return err
}

func (c *promotedHijackedConn) isClosed() bool { return c == nil || c.closed.Load() }

// promoteHijackedConn replaces the net/http-owned connection key without
// changing its already-admitted connection slot. The wrapper observes the
// close that the nested interception server performs.
func (s *Server) promoteHijackedConn(conn net.Conn) net.Conn {
	if s == nil || conn == nil {
		return conn
	}
	wrapped := &promotedHijackedConn{Conn: conn, server: s}
	s.mu.Lock()
	if _, exists := s.active[conn]; exists {
		delete(s.active, conn)
		s.active[wrapped] = struct{}{}
		s.mu.Unlock()
		return wrapped
	}
	s.mu.Unlock()
	return conn
}

func (s *Server) trackConn(conn net.Conn) bool {
	if s == nil || conn == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.active == nil {
		s.active = make(map[net.Conn]struct{})
	}
	// ConnState and the explicit hijack path can both observe one connection.
	// Make admission idempotent so active/peak accounting cannot drift.
	if _, exists := s.active[conn]; exists {
		return true
	}
	if s.connectionSlots != nil {
		select {
		case s.connectionSlots <- struct{}{}:
			s.metrics.ConnectionStarted()
		default:
			return false
		}
	}
	s.active[conn] = struct{}{}
	return true
}

func (s *Server) untrackConn(conn net.Conn) {
	if s == nil || conn == nil {
		return
	}
	if promoted, ok := conn.(*promotedHijackedConn); ok && !promoted.isClosed() {
		// serveInterceptedTLS may return before net/http closes the wrapped
		// connection. Its close callback performs the eventual release.
		return
	}
	s.mu.Lock()
	if _, exists := s.active[conn]; !exists {
		s.mu.Unlock()
		return
	}
	delete(s.active, conn)
	s.mu.Unlock()
	if s.connectionSlots != nil {
		select {
		case <-s.connectionSlots:
			s.metrics.ConnectionFinished()
		default:
		}
	}
}

func (s *Server) corporateURL(scheme string, host string) *url.URL {
	proxy, _ := parentProxyFor(s.config.ParentProxy, scheme, host)
	return proxy
}

type PipelineDependencies struct {
	Inbound  awsrequest.InboundAuthenticator
	Decoder  awsrequest.AWSRequestDecoder
	Mapper   awsrequest.IAMMapper
	Policy   policy.PolicyEngine
	Audit    audit.AuditWriter
	Resigner *sigv4.Resigner
	Upstream http.RoundTripper
	RunID    string
}

func (s *Server) pipelineConfigured() bool {
	return s != nil && (s.config.InboundAuthenticator != nil || s.config.Decoder != nil || s.config.Mapper != nil || s.config.Policy != nil || s.config.Audit != nil || s.config.Resigner != nil)
}
func (s *Server) acquireRequestSlot() bool {
	if s == nil || s.requestSlots == nil {
		return true
	}
	select {
	case s.requestSlots <- struct{}{}:
		s.metrics.RequestStarted()
		return true
	default:
		return false
	}
}

func (s *Server) releaseRequestSlot() {
	if s == nil || s.requestSlots == nil {
		return
	}
	<-s.requestSlots
	s.metrics.RequestFinished()
}

func (s *Server) auditProxyEvent(typ audit.EventType, code string) {
	if s == nil || s.config.Audit == nil || s.config.RunID == "" {
		return
	}
	e := audit.NewEvent(s.config.RunID, typ)
	e.ConnectionID = audit.NewID()
	e.ErrorCode = code
	if err := s.config.Audit.Write(context.Background(), e); err != nil {
		s.metrics.Inc(observe.AuditFailures)
	}
}
func (s *Server) finishAuthenticationFailure(w http.ResponseWriter, req *http.Request, ep awsrequest.AWSEndpoint, runID, code string) {
	s.metrics.Inc("auth.failure." + safeMetricLabel(code))
	if s.config.Audit != nil && runID != "" {
		e := audit.NewEvent(runID, audit.AuthenticationFailed)
		e.ConnectionID = audit.NewID()
		e.ErrorCode = code
		if err := s.config.Audit.Write(req.Context(), e); err != nil {
			s.metrics.Inc(observe.AuditFailures)
		}
	}
	s.metrics.Inc(observe.AuthFailures)
	s.respondPipelineDeny(w, ep, req, "invalid_inbound_signature", audit.NewID())
}

func (s *Server) handlePipeline(w http.ResponseWriter, req *http.Request, dest destination, endpoint awsrequest.AWSEndpoint) {
	ctx := req.Context()
	started := time.Now()
	var upstreamElapsed time.Duration
	defer func() {
		// LocalLatency is the complete handler lifetime, including response
		// processing, minus only the measured upstream RoundTrip. Keeping the
		// subtraction here (rather than stopping the timer around RoundTrip)
		// preserves classification, audit, resign, and response-copy time while
		// excluding remote/network time on both success and error paths.
		localElapsed := time.Since(started) - upstreamElapsed
		if localElapsed < 0 {
			localElapsed = 0
		}
		s.metrics.Observe(observe.LocalLatency, localElapsed)
	}()
	runID := s.config.RunID
	if runID == "" {
		runID = "run-unknown"
	}
	// Authentication is a hard boundary. None of the later stages are called on
	// failure, and all error text is reduced to a stable reason code.
	s.metrics.Inc(observe.Intercepted)
	if s.config.InboundAuthenticator == nil {
		s.finishAuthenticationFailure(w, req, endpoint, runID, "internal_fail_closed")
		return
	}
	verified, err := s.config.InboundAuthenticator.Verify(ctx, req, endpoint)
	if err != nil {
		s.finishAuthenticationFailure(w, req, endpoint, runID, verifyReason(err))
		return
	}
	if verified == nil || verified.Validate() != nil || verified.Endpoint.Host != endpoint.Host || verified.Endpoint.Service != endpoint.Service || verified.Endpoint.Partition != endpoint.Partition {
		s.finishAuthenticationFailure(w, req, endpoint, runID, "invalid_inbound_signature")
		return
	}
	// The verifier's prepared body owns any private spool file. Keep it alive
	// through decode, resign, and forwarding, then release it on every outcome.
	defer sigv4.CloseBody(verified.Request)
	if s.config.Decoder == nil {
		s.finishFailedPipeline(w, req, endpoint, runID, started, "internal_fail_closed", "decode", nil)
		return
	}
	decodeStart := time.Now()
	decoded, err := s.config.Decoder.Decode(ctx, verified, endpoint)
	decodeElapsed := time.Since(decodeStart)
	s.metrics.Observe(observe.DecodeLatency, decodeElapsed)
	if err != nil || decoded == nil {
		s.finishFailedPipeline(w, req, endpoint, runID, started, "unknown_operation", "decode", err)
		return
	}
	if err = decoded.Validate(); err != nil || decoded.EndpointHost != endpoint.Host || decoded.Service != endpoint.Service || decoded.Partition != endpoint.Partition {
		s.finishFailedPipeline(w, req, endpoint, runID, started, "internal_fail_closed", "decode", err)
		return
	}
	if s.config.Mapper == nil {
		s.finishFailedPipeline(w, req, endpoint, runID, started, "internal_fail_closed", "map", nil)
		return
	}
	mappingKey := s.mappingCacheKey(runID, endpoint, decoded)
	var mapping *awsrequest.MappingResult
	var mapElapsed time.Duration
	if s.caches != nil {
		if value, ok := s.caches.Operations.Get(mappingKey); ok {
			if cached, valid := value.(*awsrequest.MappingResult); valid && cached != nil {
				mapping = cloneMapping(cached)
				s.metrics.Inc(observe.CacheMappingHits)
			}
		}
		if mapping == nil {
			s.metrics.Inc(observe.CacheMappingMisses)
		}
	}
	if mapping == nil {
		mapStart := time.Now()
		mapCtx, mapCancel := context.WithTimeout(ctx, time.Second)
		mapping, err = s.config.Mapper.Map(mapCtx, decoded)
		mapCancel()
		mapElapsed = time.Since(mapStart)
		s.metrics.Observe(observe.MapLatency, mapElapsed)
	}
	if err != nil || mapping == nil {
		s.finishFailedPipeline(w, req, endpoint, runID, started, mapReason(err), "map", err)
		return
	}
	if err = mapping.Validate(); err != nil || mapping.Service != decoded.Service || mapping.Operation != decoded.Operation {
		s.finishFailedPipeline(w, req, endpoint, runID, started, "mapping_low_confidence", "map", err)
		return
	}
	if s.caches != nil && mappingKey != "" {
		if _, evicted := s.caches.Operations.Add(mappingKey, cloneMapping(mapping)); evicted {
			s.metrics.Inc(observe.CacheEvictions)
		}
	}
	if s.config.Policy == nil {
		s.finishFailedPipeline(w, req, endpoint, runID, started, "internal_fail_closed", "policy", nil)
		return
	}
	input := policy.DecisionInput{RunID: runID, Endpoint: endpoint, Request: decoded, Mapping: mapping, PolicyHash: s.config.PolicyHash, MapperVersion: mapping.MapperVersion}
	if err := input.Validate(); err != nil {
		s.finishFailedPipeline(w, req, endpoint, runID, started, "internal_fail_closed", "policy", err)
		return
	}
	decisionKey := s.decisionCacheKey(runID, endpoint, decoded, mapping)
	var decision policy.Decision
	var policyElapsed time.Duration
	decisionCached := false
	if s.caches != nil {
		if value, ok := s.caches.Decisions.Get(decisionKey); ok {
			if cached, valid := value.(policy.Decision); valid && cached.Valid() {
				decision = cloneDecision(cached)
				decisionCached = true
				s.metrics.Inc(observe.CacheDecisionHits)
			}
		}
		if !decisionCached {
			s.metrics.Inc(observe.CacheDecisionMisses)
		}
	}
	if !decisionCached {
		policyStart := time.Now()
		decision = safeEvaluate(s.config.Policy, ctx, input)
		policyElapsed = time.Since(policyStart)
		s.metrics.Observe(observe.PolicyLatency, policyElapsed)
		evaluatedValid := decision.Valid()
		if !evaluatedValid {
			decision = policy.Decision{Result: policy.DecisionDeny, ReasonCode: awserror.ReasonInternalFailClosed}
		}
		// Only complete, immutable decisions enter the cache. A fail-closed
		// replacement for an engine failure is not a policy result and must not
		// suppress a later retry. Audit and upstream outcomes are also outside.
		if s.caches != nil && evaluatedValid {
			if _, evicted := s.caches.Decisions.Add(decisionKey, cloneDecision(decision)); evicted {
				s.metrics.Inc(observe.CacheEvictions)
			}
		}
	}
	s.metrics.Inc(observe.DecisionCounter(decoded.Service, decoded.Operation, string(decision.ReasonCode)))
	s.metrics.Add(observe.PayloadBytes, uint64(decoded.PayloadBytes))
	if body := sigv4.BodyFromRequest(verified.Request); body != nil && body.SpoolPath() != "" {
		// Body switches to a file exactly when the configured in-memory
		// threshold is crossed. Size is the prepared payload size and includes
		// the prefix copied into the spool, i.e. the actual file bytes.
		s.metrics.Add(observe.SpoolBytes, uint64(body.Size()))
	}
	eventID := audit.NewID()
	ev := decisionEvent(runID, eventID, req, decoded, mapping, decision, started, s.config.PolicyHash, s.config.LogResourceARNs, s.config.HashResourceNames)
	if ev.Timing != nil {
		ev.Timing.Decode = float64(decodeElapsed) / float64(time.Millisecond)
		ev.Timing.Map = float64(mapElapsed) / float64(time.Millisecond)
		ev.Timing.Policy = float64(policyElapsed) / float64(time.Millisecond)
	}
	if err := s.acceptAudit(ctx, ev); err != nil {
		s.respondPipelineDeny(w, endpoint, decoded, "audit_unavailable", eventID)
		return
	}
	if decision.Result == policy.DecisionDeny {
		s.metrics.Inc(observe.Denied)
		s.respondPipelineDeny(w, endpoint, decoded, string(decision.ReasonCode), eventID)
		return
	}
	if s.config.Resigner == nil || s.config.Upstream == nil {
		s.metrics.Inc("upstream.credential_failure")
		s.respondPipelineDeny(w, endpoint, decoded, "upstream_credential_unavailable", eventID)
		return
	}
	outgoing, err := s.config.Resigner.Resign(ctx, verified.Request, endpoint)
	if err != nil {
		s.metrics.Inc("upstream.credential_failure")
		s.respondPipelineDeny(w, endpoint, decoded, "upstream_credential_unavailable", eventID)
		return
	}
	if failed, ok := s.config.Audit.(interface{ Failed() bool }); ok && failed.Failed() {
		s.respondPipelineDeny(w, endpoint, decoded, "audit_unavailable", eventID)
		return
	}
	s.metrics.Inc(observe.Allowed)
	upstreamStart := time.Now()
	response, err := s.config.Upstream.RoundTrip(outgoing)
	upstreamElapsed = time.Since(upstreamStart)
	s.metrics.Observe(observe.UpstreamLatency, upstreamElapsed)
	if err != nil || response == nil {
		s.metrics.Inc(observe.UpstreamErrors)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			s.metrics.Inc(observe.UpstreamCancellation)
		} else {
			s.metrics.Inc(observe.UpstreamTransport)
		}
		if err == nil {
			err = errors.New("upstream returned no response")
		}
		s.acceptAudit(ctx, forwardEvent(runID, req, decoded, err))
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	s.metrics.Inc("upstream.status." + strconv.Itoa(response.StatusCode))
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		s.metrics.Inc(observe.UpstreamAuth)
	case response.StatusCode == http.StatusTooManyRequests:
		s.metrics.Inc(observe.UpstreamThrottled)
	case response.StatusCode >= 400 && response.StatusCode < 500:
		s.metrics.Inc(observe.UpstreamClient)
	case response.StatusCode >= 500:
		s.metrics.Inc(observe.UpstreamServer)
	}
	defer response.Body.Close()
	removeHopByHopHeaders(response.Header)
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = ioCopy(w, response.Body)
}

// ioCopy is kept as a small seam to keep pipeline response handling explicit.
func ioCopy(dst http.ResponseWriter, src interface{ Read([]byte) (int, error) }) (int64, error) {
	return copyResponse(dst, src)
}
func copyResponse(dst http.ResponseWriter, src interface{ Read([]byte) (int, error) }) (int64, error) {
	var n int64
	buf := make([]byte, 32*1024)
	for {
		r, e := src.Read(buf)
		if r > 0 {
			x, ee := dst.Write(buf[:r])
			n += int64(x)
			if ee != nil {
				return n, ee
			}
		}
		if e != nil {
			return n, e
		}
	}
}
func safeEvaluate(e policy.PolicyEngine, ctx context.Context, in policy.DecisionInput) (d policy.Decision) {
	defer func() {
		if recover() != nil {
			d = policy.Decision{Result: policy.DecisionDeny, ReasonCode: awserror.ReasonInternalFailClosed}
		}
	}()
	return e.Evaluate(ctx, in)
}
func (s *Server) acceptAudit(ctx context.Context, e audit.Event) error {
	if s.config.Audit == nil {
		s.metrics.Inc(observe.AuditFailures)
		return errors.New("audit unavailable")
	}
	if err := s.config.Audit.Write(ctx, e); err != nil {
		s.metrics.Inc(observe.AuditFailures)
		if errors.Is(err, audit.ErrBackpressure) {
			s.metrics.Inc(observe.AuditBackpressure)
		}
		if q, ok := s.config.Audit.(interface{ QueueLength() int }); ok {
			s.metrics.SetGauge(observe.QueueDepth, q.QueueLength())
		}
		return err
	}
	if q, ok := s.config.Audit.(interface{ QueueLength() int }); ok {
		s.metrics.SetGauge(observe.QueueDepth, q.QueueLength())
	}
	return nil
}
func (s *Server) finishFailedPipeline(w http.ResponseWriter, req *http.Request, ep awsrequest.AWSEndpoint, runID string, start time.Time, reason, stage string, cause error) {
	_ = cause
	s.metrics.Inc("pipeline." + safeMetricLabel(stage) + "." + safeMetricLabel(reason))
	id := audit.NewID()
	d := policy.Decision{Result: policy.DecisionDeny, ReasonCode: awserror.ReasonCode(reason)}
	decoded := fallbackDecoded(req, ep)
	mapping := fallbackMapping(ep, decoded, stage)
	ev := decisionEvent(runID, id, req, decoded, mapping, d, start, s.config.PolicyHash, s.config.LogResourceARNs, s.config.HashResourceNames)
	if s.acceptAudit(req.Context(), ev) != nil {
		reason = "audit_unavailable"
	} else {
		s.metrics.Inc(observe.Denied)
	}
	s.respondPipelineDeny(w, ep, decoded, reason, id)
}
func fallbackDecoded(req *http.Request, ep awsrequest.AWSEndpoint) *awsrequest.DecodedAWSRequest {
	method := "POST"
	if req != nil && req.Method != "" {
		method = req.Method
	}
	return &awsrequest.DecodedAWSRequest{Partition: ep.Partition, EndpointHost: ep.Host, Service: ep.Service, Region: ep.Region, CallerAccountID: "000000000000", Protocol: awsrequest.ProtocolJSON11, Operation: "Unknown", Method: method, CanonicalPath: "/", PayloadHashMode: awsrequest.PayloadHashEmpty, Parameters: map[string]awsrequest.Value{}}
}
func fallbackMapping(ep awsrequest.AWSEndpoint, r *awsrequest.DecodedAWSRequest, stage string) *awsrequest.MappingResult {
	return &awsrequest.MappingResult{Service: ep.Service, Operation: r.Operation, MapperVersion: "kordn/unknown", Confidence: awsrequest.ConfidenceUnknown, Requirements: []awsrequest.IAMRequirement{{Action: ep.Service + ":Unknown", Resources: []string{"unknown"}, ScopeKind: awsrequest.ScopeUnresolved}}, Evidence: []awsrequest.MappingEvidence{{Source: stage, Field: "status", Value: "rejected"}}}
}
func decisionEvent(run, id string, req *http.Request, decoded *awsrequest.DecodedAWSRequest, m *awsrequest.MappingResult, d policy.Decision, start time.Time, policyHash string, logResourceARNs, hashResourceNames bool) audit.Event {
	e := audit.NewEvent(run, audit.RequestDecision)
	e.EventID = id
	e.ConnectionID = audit.NewID()
	e.Request = &audit.RequestInfo{Host: decoded.EndpointHost, Partition: decoded.Partition, Service: decoded.Service, Operation: decoded.Operation, Region: decoded.Region, Protocol: decoded.Protocol, Method: decoded.Method, PayloadBytes: decoded.PayloadBytes}
	// Resource values are never copied from the request into audit. The
	// composition root can choose visible ARNs or run-scoped hashes; the
	// default is redaction.
	e.IAMRequirements = audit.RequirementsForRun(run, m.Requirements, logResourceARNs, hashResourceNames)
	e.Mapping = &audit.MappingInfo{Confidence: m.Confidence, MapperVersion: m.MapperVersion}
	e.Decision = &audit.DecisionInfo{Result: string(d.Result), ReasonCode: string(d.ReasonCode), MatchedRuleIDs: append([]string(nil), d.MatchedRuleIDs...), PolicyHash: validPolicyHash(policyHash)}
	e.Timing = &audit.TimingInfo{LocalTotal: float64(time.Since(start)) / float64(time.Millisecond)}
	return e
}
func safeMetricLabel(value string) string {
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func validPolicyHash(value string) string {
	if len(value) == 71 && strings.HasPrefix(value, "sha256:") {
		return value
	}
	return "sha256:" + strings.Repeat("0", 64)
}

func forwardEvent(run string, req *http.Request, r *awsrequest.DecodedAWSRequest, err error) audit.Event {
	e := audit.NewEvent(run, audit.ForwardError)
	e.ConnectionID = audit.NewID()
	e.Request = &audit.RequestInfo{Host: r.EndpointHost, Partition: r.Partition, Service: r.Service, Operation: r.Operation, Region: r.Region, Protocol: r.Protocol, Method: r.Method, PayloadBytes: r.PayloadBytes}
	e.ErrorCode = "upstream_transport_error"
	return e
}
func mapReason(err error) string {
	if err == nil {
		return "mapping_low_confidence"
	}
	x := strings.ToLower(err.Error())
	if strings.Contains(x, "unknown operation") {
		return "unknown_operation"
	}
	if strings.Contains(x, "dependent") {
		return "dependent_permission_unresolved"
	}
	if strings.Contains(x, "unresolved") {
		return "resource_unresolved"
	}
	return "mapping_low_confidence"
}
func verifyReason(err error) string {
	c := sigv4.CodeOf(err)
	switch c {
	case sigv4.CodeUnsupportedSigning:
		return "unsupported_signing_scheme"
	case sigv4.CodeUnsupportedPayload:
		return "unsupported_payload_mode"
	case sigv4.CodeOversizedBody:
		return "request_too_large"
	}
	return "invalid_inbound_signature"
}
func (s *Server) respondPipelineDeny(w http.ResponseWriter, ep awsrequest.AWSEndpoint, r interface{}, reason, id string) {
	service, operation, protocol := "unknown", "Unknown", awsrequest.ProtocolJSON11
	switch x := r.(type) {
	case *awsrequest.DecodedAWSRequest:
		service, operation, protocol = x.Service, x.Operation, x.Protocol
	case *http.Request:
		if x != nil {
			service = ep.Service
		}
	}
	resp := awserror.Encode(protocol, awserror.Denial{Service: service, Operation: operation, ReasonCode: awserror.ReasonCode(reason), EventID: id, Classification: awserror.ClassificationLocalDeny})
	if resp == nil {
		http.Error(w, "request denied", http.StatusForbidden)
		return
	}
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		_, _ = ioCopy(w, resp.Body)
		_ = resp.Body.Close()
	}
}
func (s *Server) respondPipelineDenyHTTP(w http.ResponseWriter, ep awsrequest.AWSEndpoint, req *http.Request, reason, id string) {
	s.respondPipelineDeny(w, ep, req, reason, id)
}

func (s *Server) mappingCacheKey(runID string, endpoint awsrequest.AWSEndpoint, req *awsrequest.DecodedAWSRequest) string {
	if s == nil || req == nil || s.caches == nil {
		return ""
	}
	request := struct {
		Partition, Host, Service, Region, Protocol, Operation, Method string
		Path                                                          string
		Query                                                         interface{}
		Parameters                                                    map[string]awsrequest.Value
		Account, PayloadMode                                          string
		PayloadBytes                                                  int64
	}{req.Partition, req.EndpointHost, req.Service, req.Region, string(req.Protocol), req.Operation, req.Method,
		req.CanonicalPath, req.CanonicalQuery, req.Parameters, req.CallerAccountID, string(req.PayloadHashMode), req.PayloadBytes}
	data, _ := json.Marshal(request)
	mapper, adapter, version := s.mappingVersions()
	return cache.HashKey("mapping", runID, endpoint.Partition, endpoint.Host, endpoint.Service, endpoint.Region,
		string(data), mapper, adapter, version)
}

func (s *Server) decisionCacheKey(runID string, endpoint awsrequest.AWSEndpoint, req *awsrequest.DecodedAWSRequest, mapping *awsrequest.MappingResult) string {
	if s == nil || req == nil || mapping == nil || s.caches == nil {
		return ""
	}
	// Marshal the complete normalized post-auth inputs. encoding/json sorts map
	// keys, while RequirementsKey additionally normalizes set-like resources
	// and condition values.
	request, _ := json.Marshal(struct {
		Partition, Host, Service, Region, Protocol, Operation, Method, Path, Account, PayloadMode string
		Query                                                                                     interface{}
		Parameters                                                                                map[string]awsrequest.Value
		PayloadBytes                                                                              int64
	}{req.Partition, req.EndpointHost, req.Service, req.Region, string(req.Protocol), req.Operation, req.Method, req.CanonicalPath,
		req.CallerAccountID, string(req.PayloadHashMode), req.CanonicalQuery, req.Parameters, req.PayloadBytes})
	mappingInput := cache.RequirementsKey(mapping.Requirements)
	// Keep metadata that a policy implementation may inspect in the key too;
	// requirements are normalized separately so set-like resource ordering does
	// not create needless misses.
	mappingMetadata, _ := json.Marshal(struct {
		Confidence               awsrequest.MappingConfidence
		MapperVersion            string
		IamLiveVersion           string
		AuthorizationDataVersion string
		Evidence                 []awsrequest.MappingEvidence
	}{mapping.Confidence, mapping.MapperVersion, mapping.IamLiveVersion, mapping.AuthorizationDataVersion, mapping.Evidence})
	mapper, adapter, version := s.mappingVersions()
	return cache.HashKey("decision", runID, s.config.PolicyHash, endpoint.Partition, endpoint.Host, endpoint.Service,
		endpoint.Region, req.CallerAccountID, mapping.MapperVersion, mapper, adapter, version, string(request), mappingInput, string(mappingMetadata))
}

func (s *Server) mappingVersions() (mapper, adapter, data string) {
	mapper, adapter, data = s.config.MapperVersion, s.config.AdapterVersion, s.config.DataVersion
	if mapper == "" {
		if x, ok := s.config.Mapper.(interface{ Version() string }); ok {
			mapper = x.Version()
		}
	}
	if adapter == "" {
		if x, ok := s.config.Mapper.(interface{ IamLiveVersion() string }); ok {
			adapter = x.IamLiveVersion()
		}
	}
	if data == "" {
		if x, ok := s.config.Mapper.(interface{ AuthorizationDataVersion() string }); ok {
			data = x.AuthorizationDataVersion()
		}
	}
	if mapper == "" {
		mapper = "unknown"
	}
	if adapter == "" {
		adapter = "unknown"
	}
	if data == "" {
		data = "unknown"
	}
	return mapper, adapter, data
}

func cloneDecision(in policy.Decision) policy.Decision {
	out := in
	out.MatchedRuleIDs = append([]string(nil), in.MatchedRuleIDs...)
	return out
}

func cloneMapping(in *awsrequest.MappingResult) *awsrequest.MappingResult {
	if in == nil {
		return nil
	}
	out := *in
	out.Requirements = append([]awsrequest.IAMRequirement(nil), in.Requirements...)
	for i := range out.Requirements {
		out.Requirements[i].Resources = append([]string(nil), in.Requirements[i].Resources...)
		if in.Requirements[i].ConditionHint != nil {
			out.Requirements[i].ConditionHint = make(map[string][]string, len(in.Requirements[i].ConditionHint))
			for k, values := range in.Requirements[i].ConditionHint {
				out.Requirements[i].ConditionHint[k] = append([]string(nil), values...)
			}
		}
	}
	out.Evidence = append([]awsrequest.MappingEvidence(nil), in.Evidence...)
	return &out
}
