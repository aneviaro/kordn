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
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/pki"
	"github.com/kordn-ai/kordn/internal/runtime"
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
}

// Server is an authenticated, loopback-only HTTP proxy.
type Server struct {
	config       Config
	limits       Limits
	auth         *Authenticator
	classifier   awsrequest.EndpointClassifier
	resolver     Resolver
	dialer       ContextDialer
	ca           *pki.CA
	leaves       *pki.LeafCache
	listener     net.Listener
	httpServer   *http.Server
	addr         string
	ownedCA      bool
	ownedDir     string
	ownedDirTemp bool
	closed       bool
	active       map[net.Conn]struct{}
	mu           sync.Mutex
	closeOnce    sync.Once
	closeErr     error
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
	server := &Server{config: config, limits: limits, auth: auth, classifier: classifier, resolver: resolver, dialer: dialer, active: make(map[net.Conn]struct{})}
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
		s.httpServer = &http.Server{Handler: s, ReadHeaderTimeout: s.limits.ReadHeaderTimeout, ReadTimeout: s.limits.ReadTimeout, WriteTimeout: s.limits.WriteTimeout, IdleTimeout: s.limits.IdleTimeout, MaxHeaderBytes: s.limits.MaxHeaderBytes}
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
	})
	return s.closeErr
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	// Authentication is intentionally the first operation. In particular, no
	// request URL, CONNECT authority, classifier, resolver, or dialer is
	// touched before this check.
	if s == nil || !s.auth.Authenticate(req) {
		writer.Header().Set("Proxy-Authenticate", `Basic realm="kordn"`)
		writer.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	if err := s.limits.validateRequest(req); err != nil {
		http.Error(writer, "proxy request rejected", http.StatusRequestHeaderFieldsTooLarge)
		return
	}
	if req.Method == http.MethodConnect {
		s.handleConnect(writer, req)
		return
	}
	s.handleHTTP(writer, req)
}

func (s *Server) handleConnect(writer http.ResponseWriter, req *http.Request) {
	dest, err := parseRequestDestination(req, true)
	if err != nil {
		http.Error(writer, "invalid CONNECT authority", http.StatusBadRequest)
		return
	}
	endpoint, aws, err := classifyDestination(s.classifier, dest)
	if err != nil {
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
	clientTracked := s.trackConn(client)
	upstreamTracked := s.trackConn(upstream)
	if !clientTracked || !upstreamTracked {
		if clientTracked {
			s.untrackConn(client)
		}
		if upstreamTracked {
			s.untrackConn(upstream)
		}
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	tunnel(ctx, client, buffered.Reader, upstream, s.limits)
	s.untrackConn(client)
	s.untrackConn(upstream)
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
		_ = client.Close()
		return
	}
	_ = endpoint // endpoint is independently rechecked against inner Host.
	go serveInterceptedTLS(client, buffered.Reader, s, dest)
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
	if _, aws, err := classifyDestination(s.classifier, dest); err != nil {
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
	endpoint, aws, err := classifyDestination(s.classifier, innerDest)
	if err != nil || !aws || endpoint.Host != connectDest.Host {
		http.Error(writer, "inner Host is not a recognized AWS endpoint", http.StatusBadRequest)
		return
	}
	removeHopByHopHeaders(req.Header)
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
	s.active[conn] = struct{}{}
	return true
}

func (s *Server) untrackConn(conn net.Conn) {
	if s == nil || conn == nil {
		return
	}
	s.mu.Lock()
	delete(s.active, conn)
	s.mu.Unlock()
}

func (s *Server) corporateURL(scheme string, host string) *url.URL {
	proxy, _ := parentProxyFor(s.config.ParentProxy, scheme, host)
	return proxy
}
