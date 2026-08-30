// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package integration

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kordn-ai/kordn/internal/audit"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

// TestBoundedResourcesAfterMixedSoak is the single release soak. All 10,000
// operations cross one real CONNECT/TLS/pipeline harness; no helper-only
// cache or direct fake handler stands in for the proxy.
func runActualMixedSoak(t *testing.T, raceRun bool) {
	if os.Getenv("KORDN_SOAK") != "1" {
		t.Skip("10,000-request soak requires KORDN_SOAK=1")
	}

	root := t.TempDir()
	writer, err := audit.NewWriter(filepath.Join(root, "events.jsonl"), audit.Options{QueueCapacity: 512, BatchSize: 64, BatchInterval: 20 * time.Millisecond, Fsync: audit.Batch})
	if err != nil {
		t.Fatal(err)
	}
	h := newSecurityHarnessWithPolicy(t, securityPolicy{denyOperation: "DeniedOperation"}, writer)
	// The harness owns the fixture used by the real outbound transport. Its
	// failure script is the same bounded fake AWS server, not a substitute path.
	h.upstream.Failures().Set("GetCallerIdentity",
		fakeaws.Failure{Status: 400, Code: "ValidationException", Body: []byte(`{"message":"bad request"}`)},
		fakeaws.Failure{Status: 500, Code: "InternalFailure", Body: []byte(`{"message":"server error"}`)},
		fakeaws.Failure{Status: http.StatusTooManyRequests, RetryAfter: "1", Code: "ThrottlingException", Body: []byte(`{"message":"slow down"}`)},
		fakeaws.Failure{Status: 200, Streaming: true, StreamingChunk: 3, StreamingDelay: time.Microsecond, Body: []byte(`{"stream":"ok"}`)},
	)

	beforeG, beforeFD, beforeRSS, beforeHeap := resourceSnapshot(t)
	for i := 0; i < 10000; i++ {
		action := "GetCallerIdentity"
		if i%10 == 0 {
			action = "DeniedOperation"
		}
		response := h.call(t, h.fake, h.clock, action)
		if response == nil {
			t.Fatalf("request %d returned no response", i)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		status := response.StatusCode
		_ = response.Body.Close()
		if action == "DeniedOperation" && status != http.StatusForbidden {
			t.Fatalf("denied request %d status=%d", i, status)
		}
		if action == "GetCallerIdentity" && status == http.StatusForbidden {
			t.Fatalf("allowed request %d was denied", i)
		}
		if i%64 == 63 {
			if err := writer.Flush(context.Background()); err != nil {
				t.Fatalf("audit flush at request %d: %v", i, err)
			}
		}
	}
	if err := writer.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	ledger := h.upstream.Ledger()
	for _, record := range ledger {
		if record.Action == "DeniedOperation" {
			t.Fatal("denied operation reached the upstream ledger")
		}
	}
	for name, cache := range map[string]cacheStats{
		"endpoints":  cacheStats{size: h.RunCaches().Endpoints.Len(), capacity: h.RunCaches().Endpoints.Capacity()},
		"leaves":     cacheStats{size: h.RunCaches().Leaves.Len(), capacity: h.RunCaches().Leaves.Capacity()},
		"operations": cacheStats{size: h.RunCaches().Operations.Len(), capacity: h.RunCaches().Operations.Capacity()},
		"decisions":  cacheStats{size: h.RunCaches().Decisions.Len(), capacity: h.RunCaches().Decisions.Capacity()},
	} {
		if cache.size > cache.capacity {
			t.Fatalf("%s cache size=%d capacity=%d", name, cache.size, cache.capacity)
		}
	}
	if writer.QueueLength() != 0 || writer.Failed() {
		t.Fatalf("audit queue/failure after flush: queue=%d failed=%v", writer.QueueLength(), writer.Failed())
	}

	// Close every owner explicitly, then settle before taking after metrics.
	if err := h.proxy.Close(); err != nil {
		t.Fatal(err)
	}
	h.upstream.Close()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", h.proxy.Addr(), 50*time.Millisecond); err == nil {
		t.Fatal("proxy listener remained reachable after shutdown")
	}
	for i := 0; i < 5; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	afterG, afterFD, afterRSS, afterHeap := resourceSnapshot(t)

	// Clearing the exposed run caches is part of shutdown settlement; the
	// capacities must remain fixed and all resident request material must go.
	caches := h.RunCaches()
	for name, cache := range map[string]cacheStats{
		"endpoints":  cacheStats{size: caches.Endpoints.Len(), capacity: caches.Endpoints.Capacity()},
		"leaves":     cacheStats{size: caches.Leaves.Len(), capacity: caches.Leaves.Capacity()},
		"operations": cacheStats{size: caches.Operations.Len(), capacity: caches.Operations.Capacity()},
		"decisions":  cacheStats{size: caches.Decisions.Len(), capacity: caches.Decisions.Capacity()},
	} {
		if cache.size > cache.capacity || cache.capacity != 256 {
			t.Fatalf("%s cache after shutdown=%+v", name, cache)
		}
	}
	caches.Clear()
	if writer.QueueLength() != 0 || writer.Failed() {
		t.Fatalf("audit queue/failure after close: queue=%d failed=%v", writer.QueueLength(), writer.Failed())
	}
	files, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != "events.jsonl" {
		t.Fatalf("unexpected temp/spool files: %+v", files)
	}
	file, err := os.Open(filepath.Join(root, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines++
	}
	_ = file.Close()
	if err := scanner.Err(); err != nil || lines < 10000 {
		t.Fatalf("audit records=%d scan error=%v, want at least 10000", lines, err)
	}

	if afterG > beforeG+2 {
		t.Fatalf("goroutine leak: before=%d after=%d delta=%d", beforeG, afterG, afterG-beforeG)
	}
	if beforeFD < 0 || afterFD < 0 {
		t.Fatalf("portable FD count unavailable: before=%d after=%d", beforeFD, afterFD)
	}
	if afterFD > beforeFD+2 {
		t.Fatalf("FD leak: before=%d after=%d delta=%d", beforeFD, afterFD, afterFD-beforeFD)
	}
	if !raceRun {
		if afterHeap > beforeHeap+8<<20 || afterRSS > beforeRSS+16<<20 {
			t.Fatalf("live memory grew beyond soak tolerance: heap %d->%d RSS %d->%d", beforeHeap, afterHeap, beforeRSS, afterRSS)
		}
	} else {
		t.Logf("soak memory budgets explicitly excluded for race-instrumented run: heap=%d->%d rss=%d->%d", beforeHeap, afterHeap, beforeRSS, afterRSS)
	}
	t.Logf("soak raw: requests=10000 denied=100 upstream_ledger=%d audit_records=%d goroutines=%d->%d fds=%d->%d heap=%d->%d rss=%d->%d", len(ledger), lines, beforeG, afterG, beforeFD, afterFD, beforeHeap, afterHeap, beforeRSS, afterRSS)
}

type cacheStats struct{ size, capacity int }

func resourceSnapshot(t *testing.T) (goroutines, fds int, rss, heap uint64) {
	t.Helper()
	fds = fdCount()
	if fds < 0 {
		t.Fatalf("portable FD count unavailable")
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return runtime.NumGoroutine(), fds, uint64(processRSSBytes(t)), memory.HeapAlloc
}

func fdCount() int {
	entries, err := os.ReadDir("/dev/fd")
	if err == nil {
		return len(entries)
	}
	output, err := exec.Command("lsof", "-p", strconv.Itoa(os.Getpid()), "-Fn").Output()
	if err != nil {
		return -1
	}
	count := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "n") {
			count++
		}
	}
	return count
}
