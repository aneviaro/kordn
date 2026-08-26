// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package proxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// Authenticator verifies the proxy's per-run Basic credential. It compares
// one fixed-size digest for the complete decoded username:password value, so
// neither credential field can short-circuit comparison of the other.
type Authenticator struct {
	expectedDigest [sha256.Size]byte
}

func NewAuthenticator(username, password string) (*Authenticator, error) {
	if username == "" || password == "" || strings.ContainsAny(username+password, "\x00\r\n") {
		return nil, errors.New("proxy Basic credentials are required")
	}
	return &Authenticator{expectedDigest: sha256.Sum256([]byte(username + ":" + password))}, nil
}

func (a *Authenticator) Authenticate(req *http.Request) bool {
	if a == nil || req == nil {
		return false
	}
	value := strings.TrimSpace(req.Header.Get("Proxy-Authorization"))
	if len(value) < len("Basic ") || !strings.EqualFold(value[:len("Basic ")], "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[len("Basic "):]))
	if err != nil || !hasBasicCredentialSeparator(decoded) {
		return false
	}
	actualDigest := sha256.Sum256(decoded)
	return subtle.ConstantTimeCompare(actualDigest[:], a.expectedDigest[:]) == 1
}

func hasBasicCredentialSeparator(decoded []byte) bool {
	return strings.IndexByte(string(decoded), ':') >= 0
}

// CheckBasicAuth is a small functional seam useful to callers and tests.
func CheckBasicAuth(req *http.Request, username, password string) bool {
	auth, err := NewAuthenticator(username, password)
	return err == nil && auth.Authenticate(req)
}
