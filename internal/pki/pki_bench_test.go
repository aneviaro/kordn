// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package pki

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func benchmarkCA(b *testing.B) *CA {
	b.Helper()
	// b.TempDir is harness-owned and may be shared-mode on some platforms.
	// Use a separate private writable directory for the CA contract.
	dir := filepath.Join(b.TempDir(), "private-ca")
	if err := os.Mkdir(dir, 0700); err != nil {
		b.Fatal(err)
	}
	ca, err := NewCA(dir)
	if err != nil {
		b.Fatal(err)
	}
	return ca
}

func BenchmarkLeafGeneration(b *testing.B) {
	ca := benchmarkCA(b)
	defer ca.Cleanup()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ca.IssueLeaf(fmt.Sprintf("uncached-%d.example.com", i)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLeafCacheHit(b *testing.B) {
	ca := benchmarkCA(b)
	defer ca.Cleanup()
	cache, err := NewLeafCache(ca, 128)
	if err != nil {
		b.Fatal(err)
	}
	defer cache.Close()
	if _, err := cache.Get("cached.example.com"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cache.Get("cached.example.com"); err != nil {
			b.Fatal(err)
		}
	}
}
