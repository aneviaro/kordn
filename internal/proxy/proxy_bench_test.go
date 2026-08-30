// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package proxy

import (
	"encoding/base64"
	"net"
	"net/http"
	"testing"
)

func BenchmarkProxyAuthentication(b *testing.B) {
	auth, err := NewAuthenticator("benchmark", "secret")
	if err != nil {
		b.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("benchmark:secret")))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !auth.Authenticate(req) {
			b.Fatal("authentication failed")
		}
	}
}

func BenchmarkSafeDestinationValidation(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidateResolvedIPs("api.us-east-1.amazonaws.com", []net.IP{net.ParseIP("52.95.1.1")}, nil); err != nil {
			b.Fatal(err)
		}
	}
}
