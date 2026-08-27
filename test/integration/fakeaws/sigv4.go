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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	Host    = "sts.us-east-1.amazonaws.com"
	Service = "sts"
	Region  = "us-east-1"
)

// Server is a deterministic local upstream. Credentials are known fixture
// values and are never returned in an error or response body.
type Server struct {
	*httptest.Server
	Credentials aws.Credentials
	Clock       func() time.Time

	mu       sync.Mutex
	requests int
	last     *http.Request
}

func New(credentials aws.Credentials, clock func() time.Time) *Server {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	fixture := &Server{Credentials: credentials, Clock: clock}
	fixture.Server = httptest.NewUnstartedServer(http.HandlerFunc(fixture.handle))
	fixture.Server.StartTLS()
	return fixture
}

func (s *Server) handle(writer http.ResponseWriter, req *http.Request) {
	if req == nil || req.Host != Host {
		http.Error(writer, "unexpected endpoint", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(writer, "request body unavailable", http.StatusBadRequest)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	for _, key := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-IP", "Via"} {
		if req.Header.Get(key) != "" {
			http.Error(writer, "proxy material crossed upstream boundary", http.StatusBadRequest)
			return
		}
	}
	if strings.Contains(req.Header.Get("Authorization"), "KORDN") || req.Header.Get("X-Amz-Security-Token") == "fake-token" {
		http.Error(writer, "fake material crossed upstream boundary", http.StatusBadRequest)
		return
	}
	// httptest's URL points at 127.0.0.1, while the signed Host is the
	// recognized AWS endpoint. Re-sign a clone with the independently known
	// fixture key and compare the complete Authorization value. This uses the
	// SDK signer rather than Kordn's verifier, so a shared canonicalization bug
	// cannot make this acceptance test pass.
	if !verifyKnownSignature(req, body, s.Credentials, s.Clock()) {
		http.Error(writer, "upstream signature rejected", http.StatusForbidden)
		return
	}

	s.mu.Lock()
	s.requests++
	s.last = req.Clone(req.Context())
	s.mu.Unlock()
	writer.Header().Set("x-amzn-requestid", "fixture-request-id")
	writer.Header().Set("content-type", "application/x-amz-json-1.1")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(`{"ok":true}`))
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
	if req == nil || req.URL == nil || signingTime.IsZero() {
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
	urlCopy.Host = Host
	copyReq.URL = &urlCopy
	if err := v4.NewSigner().SignHTTP(context.Background(), credentials, copyReq, payloadHash, Service, Region, signingTime); err != nil {
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
