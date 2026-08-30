package cache

import (
	"sync"
	"testing"
)

func TestLRUHitUpdateAndEviction(t *testing.T) {
	cache, err := NewLRU[string, int](2)
	if err != nil {
		t.Fatal(err)
	}
	if replaced, evicted := cache.Add("a", 1); replaced || evicted {
		t.Fatalf("first insert reported replaced=%v evicted=%v", replaced, evicted)
	}
	cache.Put("b", 2)
	if got, ok := cache.Get("a"); !ok || got != 1 {
		t.Fatalf("cache miss for a: %v, %v", got, ok)
	}
	if replaced, evicted := cache.Add("a", 3); !replaced || evicted {
		t.Fatalf("update reported replaced=%v evicted=%v", replaced, evicted)
	}
	cache.Put("c", 4)
	if _, ok := cache.Get("b"); ok {
		t.Fatal("least recently used entry was not evicted")
	}
	if got, ok := cache.Get("a"); !ok || got != 3 {
		t.Fatalf("updated entry missing: %v, %v", got, ok)
	}
	if !cache.Remove("a") || cache.Remove("a") {
		t.Fatal("remove presence semantics are incorrect")
	}
	if cache.Len() != 1 || cache.Capacity() != 2 {
		t.Fatalf("unexpected cache size/capacity: %d/%d", cache.Len(), cache.Capacity())
	}
	cache.Clear()
	if cache.Len() != 0 || len(cache.Snapshot()) != 0 {
		t.Fatal("clear did not empty cache")
	}
}

func TestLRURejectsNonPositiveCapacity(t *testing.T) {
	for _, capacity := range []int{0, -1, -100} {
		if cache, err := NewLRU[string, string](capacity); err == nil || cache != nil {
			t.Fatalf("capacity %d was accepted: cache=%v err=%v", capacity, cache, err)
		}
	}
	var nilCache *LRU[string, string]
	if _, ok := nilCache.Get("missing"); ok || nilCache.Len() != 0 || nilCache.Remove("missing") {
		t.Fatal("nil cache operations are not safe")
	}
}

func TestLRUConcurrentAccess(t *testing.T) {
	cache := MustNewLRU[int, int](32)
	var wg sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				key := (worker*17 + i) % 64
				cache.Add(key, i)
				cache.Get(key)
				if i%11 == 0 {
					cache.Remove(key)
				}
			}
		}()
	}
	wg.Wait()
	if cache.Len() > cache.Capacity() {
		t.Fatalf("cache exceeded capacity: %d > %d", cache.Len(), cache.Capacity())
	}
}
