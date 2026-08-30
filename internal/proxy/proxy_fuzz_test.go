package proxy

import (
	"net"
	"testing"
)

func FuzzSafeIPClassification(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte{52, 95, 1, 1})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) != net.IPv4len {
			return
		}
		_ = IsUnsafeIP(net.IP(raw))
	})
}
