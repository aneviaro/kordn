// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package pki

import (
	"crypto/tls"
	"errors"
	"sync"

	"github.com/kordn-ai/kordn/internal/cache"
)

const defaultLeafCacheCapacity = 128

// LeafCache lazily creates exact-host leaves and retains at most capacity
// certificates. Generation is serialized per cache to avoid duplicate key
// material for concurrent requests for one host.
type LeafCache struct {
	mu       sync.Mutex
	ca       *CA
	entries  *cache.LRU[string, tls.Certificate]
	capacity int
	closed   bool
}

func NewLeafCache(ca *CA, capacity int) (*LeafCache, error) {
	if ca == nil {
		return nil, errors.New("leaf cache CA is required")
	}
	if capacity <= 0 {
		capacity = defaultLeafCacheCapacity
	}
	entries, err := cache.NewLRU[string, tls.Certificate](capacity)
	if err != nil {
		return nil, err
	}
	return &LeafCache{ca: ca, entries: entries, capacity: capacity}, nil
}

func NewBoundedLeafCache(ca *CA, capacity int) (*LeafCache, error) {
	return NewLeafCache(ca, capacity)
}

// Get returns the cached leaf or lazily issues one. Host keys are canonicalized
// by CA.IssueLeaf; cache callers should supply the already-normalized exact
// hostname used in the CONNECT agreement.
func (c *LeafCache) Get(host string) (tls.Certificate, error) {
	if c == nil {
		return tls.Certificate{}, errors.New("leaf cache is unavailable")
	}
	host, err := normalizeDNSName(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return tls.Certificate{}, errors.New("leaf cache is closed")
	}
	if leaf, ok := c.entries.Get(host); ok {
		return leaf, nil
	}
	leaf, err := c.ca.IssueLeaf(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	c.entries.Put(host, leaf)
	return leaf, nil
}

func (c *LeafCache) GetOrCreate(host string) (tls.Certificate, error) { return c.Get(host) }
func (c *LeafCache) Certificate(host string) (tls.Certificate, error) { return c.Get(host) }

func (c *LeafCache) Len() int {
	if c == nil {
		return 0
	}
	return c.entries.Len()
}

func (c *LeafCache) Capacity() int {
	if c == nil {
		return 0
	}
	return c.capacity
}

// Close stops future issuance and releases in-memory private keys. The CA's
// on-disk material is owned by CA.Cleanup and is intentionally not removed by
// this method.
func (c *LeafCache) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.entries.Clear()
	return nil
}
