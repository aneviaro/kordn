// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package fakeaws

import (
	"errors"
	"sort"
	"sync"
)

// Resource is a small stateful object used by producer and partial-execution
// tests. Values are intentionally opaque to the ledger.
type Resource struct {
	ID    string
	Value string
	ETag  string
}

type State struct {
	mu        sync.RWMutex
	resources map[string]Resource
}

func NewState() *State { return &State{resources: make(map[string]Resource)} }

func (s *State) Read(id string) (Resource, bool) {
	if s == nil {
		return Resource{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.resources[id]
	return r, ok
}

func (s *State) Put(id, value string) Resource {
	if s == nil {
		return Resource{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := Resource{ID: id, Value: value, ETag: "etag-" + id}
	s.resources[id] = r
	return r
}

func (s *State) Delete(id string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.resources[id]
	delete(s.resources, id)
	return ok
}

// Snapshot returns a deep copy suitable for assertions and cannot expose
// mutable fake state to another test goroutine.
func (s *State) Snapshot() map[string]Resource {
	result := map[string]Resource{}
	if s == nil {
		return result
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.resources {
		result[k] = v
	}
	return result
}

func (s *State) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resources = make(map[string]Resource)
}

// Sequence implements the release-gate A-read/B-derived-write/C-denied
// fixture without pretending that the three requests are transactional.
type Sequence struct{ ReadID, WriteID, DerivedValue string }

func (s *State) ApplySequence(seq Sequence, operation string, allowed bool) error {
	if s == nil {
		return errors.New("fake state is unavailable")
	}
	switch operation {
	case "A", "read":
		if _, ok := s.Read(seq.ReadID); !ok {
			s.Put(seq.ReadID, "source")
		}
		return nil
	case "B", "write":
		if !allowed {
			return errors.New("write denied")
		}
		if _, ok := s.Read(seq.ReadID); !ok {
			return errors.New("source was not read")
		}
		s.Put(seq.WriteID, seq.DerivedValue)
		return nil
	case "C", "delete":
		if !allowed {
			return errors.New("delete denied")
		}
		s.Delete(seq.WriteID)
		return nil
	default:
		return errors.New("unknown sequence operation")
	}
}

func sortedResourceIDs(resources map[string]Resource) []string {
	ids := make([]string, 0, len(resources))
	for id := range resources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
