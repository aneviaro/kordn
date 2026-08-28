// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

// Package fakeaws provides a local TLS-only upstream that independently
// validates the header signature produced by the resigner. It never opens a
// real AWS connection.
package fakeaws

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	Host    = "sts.us-east-1.amazonaws.com"
	Service = "sts"
	Region  = "us-east-1"
)

// ProtocolOptions describes a local, TLS-only AWS protocol fixture. The
// endpoint name is deliberately configurable: compatibility tests can use a
// resolvable fake name while the proxy still makes the endpoint decision.
type ProtocolOptions struct {
	Host        string
	Service     string
	Region      string
	Credentials aws.Credentials
	// CredentialGenerations models STS refresh transitions. The first entry is
	// also used when CredentialGenerations is empty.
	CredentialGenerations []aws.Credentials
	Clock                 func() time.Time
	Failures              map[string]Failure
}

type Request struct {
	Host        string
	Service     string
	Operation   string
	AccessKeyID string
	Forwarded   bool
}

// ProtocolServer models a small stateful subset of an AWS JSON/Query
// endpoint. It records only requests that actually arrive upstream; a local
// policy denial therefore cannot create a ledger entry.
type ProtocolServer struct {
	*httptest.Server
	Options ProtocolOptions
	mu      sync.Mutex
	ledger  []Request
	state   map[string]string
}

func NewProtocolServer(options ProtocolOptions) *ProtocolServer {
	if options.Host == "" {
		options.Host = Host
	}
	if options.Service == "" {
		options.Service = Service
	}
	if options.Region == "" {
		options.Region = Region
	}
	if options.Clock == nil {
		options.Clock = func() time.Time { return time.Now().UTC() }
	}
	if options.Failures == nil {
		options.Failures = make(map[string]Failure)
	}
	fixture := &ProtocolServer{Options: options, state: make(map[string]string)}
	fixture.Server = httptest.NewUnstartedServer(http.HandlerFunc(fixture.handle))
	fixture.Server.StartTLS()
	return fixture
}

func (s *ProtocolServer) handle(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "request body unavailable", http.StatusBadRequest)
		return
	}
	operation := operationName(req, body)
	accessKey := accessKeyFromAuthorization(req.Header.Get("Authorization"))
	if req.Host != s.Options.Host || !s.verify(body, req) {
		http.Error(w, "upstream signature rejected", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	s.ledger = append(s.ledger, Request{Host: req.Host, Service: s.Options.Service, Operation: operation, AccessKeyID: accessKey, Forwarded: true})
	s.mu.Unlock()
	if failure, ok := s.takeFailure(operation); ok {
		if failure.Status == 0 {
			failure.Status = http.StatusBadRequest
		}
		if failure.RequestID != "" {
			w.Header().Set("x-amzn-requestid", failure.RequestID)
		}
		if failure.Code != "" {
			w.Header().Set("x-amzn-errortype", failure.Code)
		}
		if strings.Contains(req.Header.Get("Content-Type"), "x-www-form-urlencoded") {
			w.Header().Set("content-type", "text/xml")
		}
		w.WriteHeader(failure.Status)
		_, _ = w.Write(failure.Body)
		return
	}
	var response []byte
	s.mu.Lock()
	switch operation {
	case "GetCallerIdentity":
		response = []byte(`{"UserId":"fixture-user","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/fixture"}`)
	case "CreateThing", "GetSessionToken":
		s.state["thing"] = "created"
		if operation == "GetSessionToken" {
			response = []byte(`{"Credentials":{"AccessKeyId":"fixture-access","SecretAccessKey":"fixture-secret","SessionToken":"fixture-token","Expiration":"2030-01-01T00:00:00Z"}}`)
		} else {
			response = []byte(`{"thing":"created"}`)
		}
	case "GetThing":
		if s.state["thing"] != "created" {
			s.mu.Unlock()
			writeProtocolError(w, "ResourceNotFoundException", "fixture-request-id", http.StatusNotFound)
			return
		}
		response = []byte(`{"thing":"created"}`)
	case "DeleteThing":
		delete(s.state, "thing")
		response = []byte(`{"deleted":true}`)
	default:
		s.mu.Unlock()
		writeProtocolError(w, "UnknownOperationException", "fixture-request-id", http.StatusBadRequest)
		return
	}
	s.mu.Unlock()
	w.Header().Set("x-amzn-requestid", "fixture-request-id")
	if strings.Contains(req.Header.Get("Content-Type"), "x-www-form-urlencoded") {
		w.Header().Set("content-type", "text/xml")
		if operation == "GetCallerIdentity" {
			response = []byte(`<?xml version="1.0"?><GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><UserId>fixture-user</UserId><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/fixture</Arn></GetCallerIdentityResult><ResponseMetadata><RequestId>fixture-request-id</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
		} else if operation == "GetSessionToken" {
			response = []byte(`<?xml version="1.0"?><GetSessionTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetSessionTokenResult><Credentials><AccessKeyId>fixture-access</AccessKeyId><SecretAccessKey>fixture-secret</SecretAccessKey><SessionToken>fixture-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></GetSessionTokenResult><ResponseMetadata><RequestId>fixture-request-id</RequestId></ResponseMetadata></GetSessionTokenResponse>`)
		}
	} else {
		w.Header().Set("content-type", "application/x-amz-json-1.1")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func writeProtocolError(w http.ResponseWriter, code, id string, status int) {
	w.Header().Set("x-amzn-requestid", id)
	w.Header().Set("x-amzn-errortype", code)
	w.Header().Set("content-type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": code})
}

func (s *ProtocolServer) verify(body []byte, req *http.Request) bool {
	credentials := s.Options.CredentialGenerations
	if len(credentials) == 0 {
		credentials = []aws.Credentials{s.Options.Credentials}
	}
	for _, candidate := range credentials {
		if verifyKnownSignatureFor(req, body, candidate, s.Options.Clock(), s.Options.Service, s.Options.Region) {
			return true
		}
	}
	return false
}

// SetFailure installs a one-shot failure while synchronizing with serving
// requests. Compatibility tests may update the fixture after it has started.
func (s *ProtocolServer) SetFailure(operation string, failure Failure) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Options.Failures == nil {
		s.Options.Failures = make(map[string]Failure)
	}
	failure.Body = append([]byte(nil), failure.Body...)
	s.Options.Failures[operation] = failure
}

func (s *ProtocolServer) takeFailure(operation string) (Failure, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	failure, ok := s.Options.Failures[operation]
	if ok {
		delete(s.Options.Failures, operation)
	}
	return failure, ok
}

func (s *ProtocolServer) Ledger() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.ledger...)
}
func (s *ProtocolServer) State(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state[key]
}

// RoundTripper routes a signed request to the local TLS fixture while
// retaining its AWS Host header and request bytes.
func (s *ProtocolServer) RoundTripper() http.RoundTripper {
	base := s.Client().Transport.(*http.Transport).Clone()
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		copyReq := req.Clone(req.Context())
		urlCopy := *req.URL
		urlCopy.Scheme, urlCopy.Host = "https", strings.TrimPrefix(s.URL, "https://")
		copyReq.URL = &urlCopy
		return base.RoundTrip(copyReq)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func operationName(req *http.Request, body []byte) string {
	if target := req.Header.Get("X-Amz-Target"); target != "" {
		if i := strings.LastIndexByte(target, '.'); i >= 0 {
			return target[i+1:]
		}
		return target
	}
	values := string(body)
	if i := strings.Index(values, "Action="); i >= 0 {
		value := values[i+len("Action="):]
		if j := strings.IndexAny(value, "& "); j >= 0 {
			value = value[:j]
		}
		return value
	}
	return "Unknown"
}
func accessKeyFromAuthorization(value string) string {
	const prefix = "Credential="
	i := strings.Index(value, prefix)
	if i < 0 {
		return ""
	}
	value = value[i+len(prefix):]
	if j := strings.IndexByte(value, '/'); j >= 0 {
		return value[:j]
	}
	return value
}

// Server is a deterministic local upstream. Credentials are known fixture
// values and are never returned in an error or response body.
//
// Its implementation lives alongside the independent verifier below so both
// the legacy signing tests and the richer protocol fixture use the same
// endpoint and TLS plumbing.
func New(credentials aws.Credentials, clock func() time.Time) *Server {
	return NewWithConfig(Config{Credentials: credentials, Clock: clock})
}

func (s *Server) handle(writer http.ResponseWriter, req *http.Request) {
	started := s.Clock().UTC()
	sequence := atomic.AddUint64(&s.requestSeq, 1)
	requestID := fmt.Sprintf("fixture-request-%06d", sequence)
	if sequence == 1 {
		requestID = "fixture-request-id"
	}
	status := http.StatusInternalServerError
	var body []byte
	defer func() { s.record(req, body, started, status, requestID) }()
	if req == nil || req.Host != s.Host {
		status = http.StatusBadRequest
		http.Error(writer, "unexpected endpoint", status)
		return
	}
	maxBody := s.maxBodyBytes
	if maxBody <= 0 {
		maxBody = 8 << 20
	}
	var err error
	body, err = io.ReadAll(io.LimitReader(req.Body, maxBody+1))
	if err != nil || int64(len(body)) > maxBody {
		status = http.StatusBadRequest
		http.Error(writer, "request body unavailable", status)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	for _, key := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-IP", "Via"} {
		if req.Header.Get(key) != "" {
			status = http.StatusBadRequest
			http.Error(writer, "proxy material crossed upstream boundary", status)
			return
		}
	}
	if strings.Contains(req.Header.Get("Authorization"), "KORDN") || req.Header.Get("X-Amz-Security-Token") == "fake-token" {
		status = http.StatusBadRequest
		http.Error(writer, "fake material crossed upstream boundary", status)
		return
	}
	if !verifyKnownSignatureFor(req, body, s.Credentials, s.Clock(), s.Service, s.Region) {
		status = http.StatusForbidden
		http.Error(writer, "upstream signature rejected", status)
		return
	}
	if failure, ok := s.failures.next(actionFromRequest(req, body)); ok {
		if failure.Latency > 0 {
			time.Sleep(failure.Latency)
		}
		if failure.Disconnect {
			if h, ok := writer.(http.Hijacker); ok {
				if conn, _, err := h.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			status = 0
			return
		}
		status = failure.Status
		if status == 0 {
			status = http.StatusInternalServerError
		}
		writer.Header().Set("x-amzn-requestid", requestID)
		if failure.RequestID != "" {
			writer.Header().Set("x-amzn-requestid", failure.RequestID)
		}
		if failure.RetryAfter != "" {
			writer.Header().Set("Retry-After", failure.RetryAfter)
		}
		if failure.Code != "" {
			writer.Header().Set("x-amzn-errortype", failure.Code)
		}
		writer.WriteHeader(status)
		if len(failure.Body) > 0 {
			chunk := len(failure.Body)
			if failure.Streaming && failure.StreamingChunk > 0 {
				chunk = failure.StreamingChunk
			}
			for offset := 0; offset < len(failure.Body); offset += chunk {
				end := offset + chunk
				if end > len(failure.Body) {
					end = len(failure.Body)
				}
				_, _ = writer.Write(failure.Body[offset:end])
				if failure.Streaming && failure.StreamingDelay > 0 {
					time.Sleep(failure.StreamingDelay)
				}
			}
		}
		return
	}
	s.mu.Lock()
	s.requests++
	s.last = sanitizedRequest(req)
	s.mu.Unlock()
	writer.Header().Set("x-amzn-requestid", requestID)
	status = s.writeModeled(writer, req, body, requestID)
	if status == 0 {
		status = http.StatusOK
	}
}

func sanitizedRequest(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}
	copy := req.Clone(req.Context())
	copy.Body = io.NopCloser(strings.NewReader(""))
	for key := range copy.Header {
		copy.Header[key] = []string{""}
	}
	return copy
}

func (s *Server) RequestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *Server) LastRequest() *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		return nil
	}
	return s.last.Clone(s.last.Context())
}

func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
}

func verifyKnownSignature(req *http.Request, body []byte, credentials aws.Credentials, signingTime time.Time) bool {
	return verifyKnownSignatureFor(req, body, credentials, signingTime, Service, Region)
}

func verifyKnownSignatureFor(req *http.Request, body []byte, credentials aws.Credentials, signingTime time.Time, service, region string) bool {
	if req == nil || req.URL == nil || signingTime.IsZero() || service == "" || region == "" {
		return false
	}
	requestTime, err := time.Parse("20060102T150405Z", req.Header.Get("X-Amz-Date"))
	if err != nil || requestTime.UTC().Sub(signingTime.UTC()) > 5*time.Minute || signingTime.UTC().Sub(requestTime.UTC()) > 5*time.Minute {
		return false
	}
	var authorization string
	var authorizationValues []string
	for key, values := range req.Header {
		if strings.EqualFold(key, "authorization") {
			authorizationValues = append(authorizationValues, values...)
		}
	}
	if len(authorizationValues) != 1 {
		return false
	}
	authorization = authorizationValues[0]
	if authorization == "" || strings.Contains(authorization, "KORDN") {
		return false
	}
	if values := req.Header.Values("X-Amz-Security-Token"); len(values) != 1 || values[0] != credentials.SessionToken {
		return false
	}
	payloadHash := req.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	} else if payloadHash != "UNSIGNED-PAYLOAD" {
		sum := sha256.Sum256(body)
		actualHash := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(payloadHash), []byte(actualHash)) != 1 {
			return false
		}
	}
	signedHeaders, ok := signedHeadersFromAuthorization(authorization)
	if !ok {
		return false
	}
	copyReq := req.Clone(req.Context())
	for key := range copyReq.Header {
		if strings.EqualFold(key, "authorization") || !signedHeaders[strings.ToLower(key)] {
			delete(copyReq.Header, key)
		}
	}
	copyReq.Body = io.NopCloser(bytes.NewReader(body))
	urlCopy := *req.URL
	urlCopy.Scheme = "https"
	urlCopy.Host = req.Host
	if urlCopy.Host == "" {
		urlCopy.Host = Host
	}
	copyReq.URL = &urlCopy
	// Recreate the signature at the request's timestamp. Using the verifier's
	// current clock makes valid requests fail whenever transit crosses a second.
	if err := v4.NewSigner().SignHTTP(context.Background(), credentials, copyReq, payloadHash, service, region, requestTime); err != nil {
		return false
	}
	expectedValues := copyReq.Header.Values("Authorization")
	if len(expectedValues) != 1 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(authorization), []byte(expectedValues[0])) == 1
}

func signedHeadersFromAuthorization(authorization string) (map[string]bool, bool) {
	parts := strings.Split(authorization, ", ")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "AWS4-HMAC-SHA256 ") {
		return nil, false
	}
	var value string
	for _, part := range parts[1:] {
		key, item, ok := strings.Cut(part, "=")
		if ok && key == "SignedHeaders" {
			value = item
		}
	}
	if value == "" {
		return nil, false
	}
	result := make(map[string]bool)
	for _, header := range strings.Split(value, ";") {
		if header == "" {
			return nil, false
		}
		result[strings.ToLower(header)] = true
	}
	return result, true
}
