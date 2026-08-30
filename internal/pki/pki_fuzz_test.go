// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package pki

import "testing"

func FuzzDNSNameValidation(f *testing.F) {
	f.Add("api.us-east-1.amazonaws.com")
	f.Add("bad host")
	f.Fuzz(func(t *testing.T, host string) { _, _ = normalizeDNSName(host) })
}
