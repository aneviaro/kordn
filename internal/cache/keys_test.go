// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package cache

import (
	"sync"
	"testing"
)

type keyRequirement struct {
	Action    string
	Resources []string
	ScopeKind string
	Dependent bool
}

func TestCanonicalKeysSeparateCompleteDimensions(t *testing.T) {
	if CanonicalKey("ab", "c") == CanonicalKey("a", "bc") {
		t.Fatal("ambiguous canonical key")
	}
	a := EndpointKey{RunID: "run-a", Host: "x", Partition: "aws", Region: "us-east-1", Service: "s", Account: "1", Operation: "a"}
	b := a
	b.RunID = "run-b"
	if a.String() == b.String() {
		t.Fatal("run crossed endpoint cache key")
	}
	r := []keyRequirement{{Action: "s:Get", Resources: []string{"b", "a"}, ScopeKind: "set"}}
	r2 := []keyRequirement{{Action: "s:Get", Resources: []string{"a", "b"}, ScopeKind: "set"}}
	if RequirementsKey(r) != RequirementsKey(r2) {
		t.Fatal("set resource ordering changed key")
	}
}
func TestLRUStatsTrackHitsMissesAndEvictionsExactly(t *testing.T) {
	c := MustNewLRU[string, int](1)
	if _, ok := c.Get("missing"); ok {
		t.Fatal("missing key returned a value")
	}
	c.Put("a", 1)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("resident key was not found")
	}
	c.Put("b", 2)
	stats := c.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Evictions != 1 || stats.Size != 1 || stats.Capacity != 1 {
		t.Fatalf("LRU stats=%+v", stats)
	}
}

func TestLRUConcurrentBound(t *testing.T) {
	c := MustNewLRU[string, int](8)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.Put(string(rune('a'+(n+j)%32)), j)
				c.Get(string(rune('a' + j%32)))
			}
		}(i)
	}
	wg.Wait()
	if c.Len() > 8 {
		t.Fatal("cache exceeded bound")
	}
}
