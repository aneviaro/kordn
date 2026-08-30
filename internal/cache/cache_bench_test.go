// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package cache

import "testing"

func BenchmarkLRUHit(b *testing.B) {
	c, err := NewLRU[string, string](1024)
	if err != nil {
		b.Fatal(err)
	}
	c.Put("hot", "value")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get("hot"); !ok {
			b.Fatal("cache miss")
		}
	}
}

func BenchmarkLRUMissAndEviction(b *testing.B) {
	c, err := NewLRU[int, int](1024)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Put(i, i)
		_, _ = c.Get(i - 1)
	}
}
