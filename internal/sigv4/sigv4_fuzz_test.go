// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package sigv4

import (
	"net/http"
	"net/url"
	"testing"
)

func FuzzCanonicalRequest(f *testing.F) {
	f.Add("/", "a=1&b=2", "normal value")
	f.Add("/a%2Fb/..", "x=+&x=%2F&empty=", "  tabs\tand spaces  ")
	f.Add("/%zz", "%", "\x00")
	f.Fuzz(func(t *testing.T, rawPath, rawQuery, headerValue string) {
		if len(rawPath) > 4096 || len(rawQuery) > 4096 || len(headerValue) > 4096 {
			t.Skip()
		}
		req := &http.Request{
			Method: http.MethodGet,
			URL:    &url.URL{Path: rawPath, RawPath: rawPath, RawQuery: rawQuery},
			Host:   "example.com",
			Header: make(http.Header),
		}
		req.Header.Set("X-Amz-Date", "20260827T120000Z")
		req.Header.Set("X-Test", headerValue)
		_, _ = BuildCanonicalRequest(req, []string{"host", "x-amz-date", "x-test"}, emptyPayloadHash)
	})
}
