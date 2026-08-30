package pki

import "testing"

func FuzzDNSNameValidation(f *testing.F) {
	f.Add("api.us-east-1.amazonaws.com")
	f.Add("bad host")
	f.Fuzz(func(t *testing.T, host string) { _, _ = normalizeDNSName(host) })
}
