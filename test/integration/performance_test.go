// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kordn-ai/kordn/internal/observe"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

// TestStrictPerformance measures complete local request work around each
// deliberately fresh, real no-replay upstream request. The fake-AWS exchange
// remains real, but its connect/TLS/response network interval is excluded from
// the local-added samples.
func TestStrictPerformance(t *testing.T) {
	if os.Getenv("KORDN_STRICT_PERFORMANCE") != "1" {
		t.Skip("strict performance requires KORDN_STRICT_PERFORMANCE=1")
	}
	const workers, requests = 100, 10000

	var gateMu sync.RWMutex
	var gate *outboundDialGate
	hook := func() {
		gateMu.RLock()
		current := gate
		gateMu.RUnlock()
		if current != nil {
			current.reached <- struct{}{}
			<-current.release
		}
	}
	const responseBody = `{"ok":true}`
	h := newSecurityHarnessWithTimedOutboundDial(t, securityPolicy{}, nil, hook, func(_ context.Context, dialStart time.Time, conn net.Conn) net.Conn {
		gateMu.RLock()
		current := gate
		gateMu.RUnlock()
		if current == nil {
			return conn
		}
		wrapped := &performanceTimingConn{Conn: conn, dialStart: dialStart}
		current.records <- wrapped
		return wrapped
	}, nil)
	clients, inboundDials := performanceClients(t, h, workers)
	h.upstream.SetResponse("GetCallerIdentity", fakeaws.Response{Status: http.StatusOK, Body: []byte(responseBody)})

	// Establish one persistent inbound CONNECT/TLS tunnel per client while the
	// fake AWS endpoint holds each first request. This is a separate barrier
	// from the timed workload, so its samples cannot pollute the final 4096-ring
	// LocalLatency percentile window.
	failures := make([]fakeaws.Failure, workers)
	for i := range failures {
		failures[i] = fakeaws.Failure{Latency: time.Second, Status: http.StatusOK, Body: []byte(`{"ok":true}`)}
	}
	h.upstream.Failures().Set("GetCallerIdentity", failures...)
	ready := make(chan struct{}, workers)
	start := make(chan struct{})
	results := make(chan error, workers)
	var warmWG sync.WaitGroup
	for i := range clients {
		warmWG.Add(1)
		go func(client *http.Client) {
			defer warmWG.Done()
			ready <- struct{}{}
			<-start
			response := h.callWithClient(t, client, h.fake, h.clock, "GetCallerIdentity")
			if response == nil {
				results <- fmt.Errorf("nil warm response")
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				results <- fmt.Errorf("warm status=%d", response.StatusCode)
			}
		}(clients[i])
	}
	for i := 0; i < workers; i++ {
		<-ready
	}
	close(start)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := h.proxy.MetricsSnapshot()
		if snapshot.ActiveConnections >= workers && snapshot.ActiveRequests >= workers {
			break
		}
		time.Sleep(time.Millisecond)
	}
	blocking := h.proxy.MetricsSnapshot()
	if blocking.ActiveConnections < workers || blocking.ActiveRequests < workers {
		warmWG.Wait()
		t.Fatalf("warm barrier observed connections=%d requests=%d, want %d", blocking.ActiveConnections, blocking.ActiveRequests, workers)
	}
	warmWG.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := inboundDialsTotal(inboundDials); got != workers {
		t.Fatalf("warm inbound proxy dials=%d, want exactly %d", got, workers)
	}
	if got := len(h.upstream.Ledger()); got != workers {
		t.Fatalf("warm upstream ledger=%d, want %d", got, workers)
	}
	if snapshot := h.proxy.MetricsSnapshot(); snapshot.ActiveRequests != 0 {
		t.Fatalf("warm phase did not drain: %+v", snapshot)
	}
	before := h.proxy.MetricsSnapshot()

	// Every round releases 100 requests together. The dialer publishes exactly
	// one timing connection per fresh no-replay upstream request; timestamps are
	// aggregated after every response body is fully drained, so no request-level
	// dial association is required.
	var aggregateLocalDuration time.Duration
	var wallStart = time.Now()
	var responseErrors atomic.Int64
	for round := 0; round < requests/workers; round++ {
		current := &outboundDialGate{reached: make(chan struct{}, workers), release: make(chan struct{}), records: make(chan *performanceTimingConn, workers)}
		gateMu.Lock()
		gate = current
		gateMu.Unlock()
		ready = make(chan struct{}, workers)
		startRound := make(chan struct{})
		starts := make([]time.Time, workers)
		dones := make([]time.Time, workers)
		var roundWG sync.WaitGroup
		for i, client := range clients {
			roundWG.Add(1)
			go func(index int, client *http.Client) {
				defer roundWG.Done()
				ready <- struct{}{}
				<-startRound
				starts[index] = time.Now()
				response := h.callWithClientContext(t, context.Background(), client, h.fake, h.clock, "GetCallerIdentity")
				if response == nil {
					responseErrors.Add(1)
					return
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				dones[index] = time.Now()
				if err != nil || len(body) != len(responseBody) || string(body) != responseBody || response.StatusCode != http.StatusOK {
					responseErrors.Add(1)
				}
			}(i, client)
		}
		for i := 0; i < workers; i++ {
			<-ready
		}
		close(startRound)
		for i := 0; i < workers; i++ {
			<-current.reached
		}
		close(current.release)
		roundWG.Wait()
		gateMu.Lock()
		gate = nil
		gateMu.Unlock()
		if responseErrors.Load() != 0 {
			break
		}
		if len(current.records) != workers {
			t.Fatalf("round %d outbound timing connections=%d, want %d", round, len(current.records), workers)
		}
		var minStart, maxDone time.Time
		for i := range starts {
			if starts[i].IsZero() || dones[i].IsZero() || !dones[i].After(starts[i]) {
				t.Fatalf("round %d client timestamps out of bounds at index %d: start=%s done=%s", round, i, starts[i], dones[i])
			}
			if minStart.IsZero() || starts[i].Before(minStart) {
				minStart = starts[i]
			}
			if maxDone.IsZero() || dones[i].After(maxDone) {
				maxDone = dones[i]
			}
		}
		var sumStarts, sumDones, sumDialStarts, sumFinalReads time.Duration
		for i := range starts {
			sumStarts += starts[i].Sub(minStart)
			sumDones += dones[i].Sub(minStart)
		}
		for i := 0; i < workers; i++ {
			dialStart, finalRead := (<-current.records).Timestamps()
			if dialStart.IsZero() || finalRead.IsZero() || dialStart.Before(minStart) || finalRead.After(maxDone) || finalRead.Before(dialStart) {
				t.Fatalf("round %d outbound timing timestamps out of bounds: dial_start=%s final_read=%s client_start_min=%s client_done_max=%s", round, dialStart, finalRead, minStart, maxDone)
			}
			sumDialStarts += dialStart.Sub(minStart)
			sumFinalReads += finalRead.Sub(minStart)
		}
		roundLocal := sumDialStarts - sumStarts + sumDones - sumFinalReads
		if roundLocal < 0 {
			t.Fatalf("round %d aggregate complete-local duration=%s is negative", round, roundLocal)
		}
		aggregateLocalDuration += roundLocal
	}
	wallElapsed := time.Since(wallStart)
	if responseErrors.Load() != 0 || h.upstream.RequestCount() != requests {
		t.Fatalf("timed workload errors=%d upstream=%d want=%d", responseErrors.Load(), h.upstream.RequestCount(), requests)
	}
	if got := inboundDialsTotal(inboundDials); got != workers {
		t.Fatalf("inbound proxy connection churn=%d total dials, want unchanged %d", got, workers)
	}
	after := h.proxy.MetricsSnapshot()
	local := after.Histograms[observe.LocalLatency]
	localCapacity := float64(requests) / (aggregateLocalDuration.Seconds() / workers)
	wallRPS := float64(requests) / wallElapsed.Seconds()
	processRSS := processRSSBytes(t)
	t.Logf("strict performance aggregate complete-local: requests=%d workers=%d inbound_dials=%d peak_connections=%d peak_requests=%d local_capacity=%.1f aggregate_local=%s wall_elapsed=%s wall_rps=%.1f production_local_count=%d production_local_p50=%.3fms production_local_p95=%.3fms production_local_p99=%.3fms rss=%.1fMiB before_metrics=%+v after_metrics=%+v", requests, workers, inboundDialsTotal(inboundDials), after.PeakConnections, after.PeakRequests, localCapacity, aggregateLocalDuration, wallElapsed, wallRPS, local.Count, local.P50, local.P95, local.P99, float64(processRSS)/(1<<20), before, after)
	if after.PeakConnections < workers || localCapacity < 500 {
		t.Fatalf("Section 21 complete local throughput failed: peak connections=%d local_capacity=%.1f", after.PeakConnections, localCapacity)
	}
	if local.Count == 0 || local.P50 > 3 || local.P95 > 10 || local.P99 > 25 {
		t.Fatalf("Section 21 production LocalLatency thresholds failed: count=%d p50=%.3fms p95=%.3fms p99=%.3fms", local.Count, local.P50, local.P95, local.P99)
	}
	if processRSS > 80<<20 {
		t.Fatalf("idle/ordinary RSS=%d bytes exceeds 80 MiB budget", processRSS)
	}
	for _, client := range clients {
		client.Transport.(*http.Transport).CloseIdleConnections()
	}
	if err := h.proxy.Close(); err != nil {
		t.Fatal(err)
	}
	h.upstream.Close()

	// Each sample uses a fresh real proxy and therefore an uncached leaf. Setup
	// is outside the timer; the request still traverses CONNECT and TLS.
	uncached := make([]time.Duration, 0, workers)
	for i := 0; i < workers; i++ {
		fresh := newSecurityHarness(t, false)
		started := time.Now()
		response := fresh.call(t, fresh.fake, fresh.clock, "GetCallerIdentity")
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		uncached = append(uncached, time.Since(started))
		fresh.client.Transport.(*http.Transport).CloseIdleConnections()
		_ = fresh.proxy.Close()
		fresh.upstream.Close()
	}
	sort.Slice(uncached, func(i, j int) bool { return uncached[i] < uncached[j] })
	uncachedP95 := percentile(uncached, 95)
	t.Logf("uncached leaf raw: samples=%d p95=%s", len(uncached), uncachedP95)
	if uncachedP95 > 25*time.Millisecond {
		t.Fatalf("uncached leaf p95=%s exceeds 25ms", uncachedP95)
	}
}

type outboundDialGate struct {
	reached chan struct{}
	release chan struct{}
	records chan *performanceTimingConn
}

func performanceClients(t *testing.T, h *securityHarness, workers int) ([]*http.Client, []int64) {
	t.Helper()
	proxyURL, err := url.Parse("http://integration-user:integration-password@" + h.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]*http.Client, workers)
	dials := make([]int64, workers)
	for i := range clients {
		index := i
		transport := &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			TLSClientConfig:     (&tlsConfigForPerformance{root: h.proxy.CA().CertPool(), serverName: h.host}).Config(),
			DisableKeepAlives:   false,
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			MaxConnsPerHost:     1,
		}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			atomic.AddInt64(&dials[index], 1)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		clients[i] = &http.Client{Transport: transport}
		t.Cleanup(transport.CloseIdleConnections)
	}
	return clients, dials
}

type performanceTimingConn struct {
	net.Conn
	dialStart time.Time
	mu        sync.Mutex
	finalRead time.Time
}

func (c *performanceTimingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.finalRead = time.Now()
		c.mu.Unlock()
	}
	return n, err
}
func (c *performanceTimingConn) Timestamps() (time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dialStart, c.finalRead
}

// tlsConfigForPerformance avoids mutating the harness's base transport while
// making each deliberately separate inbound transport explicit.
type tlsConfigForPerformance struct {
	root       *x509.CertPool
	serverName string
}

func (c *tlsConfigForPerformance) Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.root, ServerName: c.serverName}
}

func inboundDialsTotal(dials []int64) int64 {
	var total int64
	for i := range dials {
		total += atomic.LoadInt64(&dials[i])
	}
	return total
}

func percentile(values []time.Duration, p int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := (len(values)*p + 99) / 100
	if index < 1 {
		index = 1
	}
	if index > len(values) {
		index = len(values)
	}
	return values[index-1]
}

func processRSSBytes(t *testing.T) int64 {
	t.Helper()
	output, err := os.ReadFile("/proc/self/statm")
	if err == nil {
		fields := strings.Fields(string(output))
		if len(fields) >= 2 {
			pages, parseErr := strconv.ParseInt(fields[1], 10, 64)
			if parseErr == nil && pages >= 0 {
				return pages * int64(os.Getpagesize())
			}
		}
	}
	output, err = execCommand("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid()))
	if err != nil {
		t.Fatalf("read process RSS: %v", err)
	}
	kilobytes, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || kilobytes < 0 {
		t.Fatalf("parse process RSS %q: %v", strings.TrimSpace(string(output)), err)
	}
	return kilobytes * 1024
}

var execCommand = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}
