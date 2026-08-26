// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

// Package cache contains small bounded caches used by security-sensitive
// request paths.  LRU deliberately exposes values, rather than callbacks, so
// it never holds its mutex while running caller code.
package cache

import (
	"container/list"
	"errors"
	"sync"
)

type entry[K comparable, V any] struct {
	key   K
	value V
}

// LRU is a bounded, concurrency-safe least-recently-used cache.  Capacity is
// fixed after construction and an insertion evicts exactly one oldest entry
// when the cache is full.
type LRU[K comparable, V any] struct {
	mu       sync.Mutex
	capacity int
	items    map[K]*list.Element
	order    *list.List
}

// NewLRU creates a cache with a positive bounded capacity.
func NewLRU[K comparable, V any](capacity int) (*LRU[K, V], error) {
	if capacity <= 0 {
		return nil, errors.New("cache capacity must be positive")
	}
	return &LRU[K, V]{
		capacity: capacity,
		items:    make(map[K]*list.Element, capacity),
		order:    list.New(),
	}, nil
}

// MustNewLRU is useful for immutable package-level caches.  It panics only on
// a programmer-supplied invalid capacity, never on an operation or callback.
func MustNewLRU[K comparable, V any](capacity int) *LRU[K, V] {
	cache, err := NewLRU[K, V](capacity)
	if err != nil {
		panic(err)
	}
	return cache
}

// Get returns a value and marks it most recently used.
func (c *LRU[K, V]) Get(key K) (V, bool) {
	if c == nil {
		var zero V
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(item)
	return item.Value.(entry[K, V]).value, true
}

// Add inserts or replaces a value and reports whether an existing value was
// replaced.  The returned evicted key is useful for observability while
// keeping eviction deterministic; evicted is false when no eviction happened.
func (c *LRU[K, V]) Add(key K, value V) (replaced bool, evicted bool) {
	if c == nil {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if item, ok := c.items[key]; ok {
		item.Value = entry[K, V]{key: key, value: value}
		c.order.MoveToFront(item)
		return true, false
	}
	item := c.order.PushFront(entry[K, V]{key: key, value: value})
	c.items[key] = item
	if c.order.Len() <= c.capacity {
		return false, false
	}
	oldest := c.order.Back()
	if oldest == nil {
		return false, false
	}
	old := oldest.Value.(entry[K, V])
	delete(c.items, old.key)
	c.order.Remove(oldest)
	return false, true
}

// Put is an alias for Add for callers that do not need replacement metadata.
func (c *LRU[K, V]) Put(key K, value V) { _, _ = c.Add(key, value) }

// Remove deletes one key and reports whether it was present.
func (c *LRU[K, V]) Remove(key K) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[key]
	if !ok {
		return false
	}
	delete(c.items, key)
	c.order.Remove(item)
	return true
}

// Len returns the number of currently resident values.
func (c *LRU[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// Capacity returns the immutable maximum number of resident values.
func (c *LRU[K, V]) Capacity() int {
	if c == nil {
		return 0
	}
	return c.capacity
}

// Clear removes all values.  It does not call user code.
func (c *LRU[K, V]) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[K]*list.Element, c.capacity)
	c.order.Init()
}

// Snapshot returns a deterministic most-recently-used-first copy.  It is
// intended for diagnostics and tests and does not expose internal elements.
func (c *LRU[K, V]) Snapshot() []V {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]V, 0, c.order.Len())
	for item := c.order.Front(); item != nil; item = item.Next() {
		result = append(result, item.Value.(entry[K, V]).value)
	}
	return result
}
