//go:build compat

package compatibility

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kordn-ai/kordn/internal/observe"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

// TestCompatibilityPerformance uses the real compatibility harness. Complete
// local request work is measured around each fresh no-replay fake-AWS exchange;
// only the outbound connect/TLS/response network interval is excluded.
func TestCompatibilityPerformance(t *testing.T) {
	if os.Getenv("KORDN_STRICT_PERFORMANCE") != "1" {
		t.Skip("strict compatibility performance requires KORDN_STRICT_PERFORMANCE=1")
	}
	const workers, requests = 100, 10000
	// The compatibility run retains the same embedded and parsed AWS catalog as
	// the ordinary integration process. Keep this gate above its expected
	// footprint until the separately planned catalog-representation work lands.
	const compatibilityRSSBudget = 384 << 20

	var gateMu sync.RWMutex
	var gate *compatOutboundDialGate
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
	h := newCompatHarnessWithTimedOutboundDial(t, false, func() time.Time { return compatClock }, hook, func(_ context.Context, dialStart time.Time, conn net.Conn) net.Conn {
		gateMu.RLock()
		current := gate
		gateMu.RUnlock()
		if current == nil {
			return conn
		}
		wrapped := &compatPerformanceTimingConn{Conn: conn, dialStart: dialStart}
		current.records <- wrapped
		return wrapped
	}, nil)
	clients, inboundDials := compatibilityClients(t, h, workers)
	h.upstream.SetResponse("GetCallerIdentity", fakeaws.Response{Status: http.StatusOK, Body: []byte(responseBody)})

	failures := make([]fakeaws.Failure, workers)
	for i := range failures {
		failures[i] = fakeaws.Failure{Latency: time.Second, Status: http.StatusOK, Body: []byte(`{"ok":true}`)}
	}
	h.upstream.Failures().Set("GetCallerIdentity", failures...)
	ready := make(chan struct{}, workers)
	start := make(chan struct{})
	results := make(chan error, workers)
	var warmWG sync.WaitGroup
	for _, client := range clients {
		warmWG.Add(1)
		go func(client *http.Client) {
			defer warmWG.Done()
			ready <- struct{}{}
			<-start
			response := h.callWithClient(t, client, "GetCallerIdentity")
			if response == nil {
				results <- fmt.Errorf("nil warm response")
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				results <- fmt.Errorf("warm status=%d", response.StatusCode)
			}
		}(client)
	}
	for i := 0; i < workers; i++ {
		<-ready
	}
	close(start)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := h.server.MetricsSnapshot()
		if snapshot.ActiveConnections >= workers && snapshot.ActiveRequests >= workers {
			break
		}
		time.Sleep(time.Millisecond)
	}
	blocking := h.server.MetricsSnapshot()
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
	if got := compatibilityDialsTotal(inboundDials); got != workers {
		t.Fatalf("warm inbound proxy dials=%d, want exactly %d", got, workers)
	}
	if got := len(h.upstream.Ledger()); got != workers {
		t.Fatalf("warm upstream ledger=%d, want %d", got, workers)
	}
	if snapshot := h.server.MetricsSnapshot(); snapshot.ActiveRequests != 0 {
		t.Fatalf("warm phase did not drain: %+v", snapshot)
	}
	before := h.server.MetricsSnapshot()

	var aggregateLocalDuration time.Duration
	wallStart := time.Now()
	var responseErrors atomic.Int64
	for round := 0; round < requests/workers; round++ {
		current := &compatOutboundDialGate{reached: make(chan struct{}, workers), release: make(chan struct{}), records: make(chan *compatPerformanceTimingConn, workers)}
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
				response := h.callWithClientContext(t, context.Background(), client, "GetCallerIdentity")
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
	if got := compatibilityDialsTotal(inboundDials); got != workers {
		t.Fatalf("inbound proxy connection churn=%d total dials, want unchanged %d", got, workers)
	}
	after := h.server.MetricsSnapshot()
	local := after.Histograms[observe.LocalLatency]
	localCapacity := float64(requests) / (aggregateLocalDuration.Seconds() / workers)
	wallRPS := float64(requests) / wallElapsed.Seconds()
	rss := compatibilityRSS(t)
	t.Logf("compat performance aggregate complete-local: requests=%d workers=%d inbound_dials=%d peak_requests=%d peak_connections=%d local_capacity=%.1f aggregate_local=%s wall_elapsed=%s wall_rps=%.1f production_local_count=%d production_local_p50=%.3fms production_local_p95=%.3fms production_local_p99=%.3fms rss=%.1fMiB before_metrics=%+v after_metrics=%+v", requests, workers, compatibilityDialsTotal(inboundDials), after.PeakRequests, after.PeakConnections, localCapacity, aggregateLocalDuration, wallElapsed, wallRPS, local.Count, local.P50, local.P95, local.P99, float64(rss)/(1<<20), before, after)
	if after.PeakConnections < workers || localCapacity < 500 {
		t.Fatalf("compatibility complete local throughput failed: peak connections=%d local_capacity=%.1f", after.PeakConnections, localCapacity)
	}
	if local.Count == 0 || local.P50 > 3 || local.P95 > 10 || local.P99 > 25 {
		t.Fatalf("compatibility production LocalLatency thresholds failed: count=%d p50=%.3fms p95=%.3fms p99=%.3fms", local.Count, local.P50, local.P95, local.P99)
	}
	if rss > compatibilityRSSBudget {
		t.Fatalf("compatibility RSS=%d bytes exceeds %d MiB budget", rss, compatibilityRSSBudget/(1<<20))
	}
	for _, client := range clients {
		client.Transport.(*http.Transport).CloseIdleConnections()
	}
	if err := h.server.Close(); err != nil {
		t.Fatal(err)
	}
	h.upstream.Close()
}

type compatOutboundDialGate struct {
	reached chan struct{}
	release chan struct{}
	records chan *compatPerformanceTimingConn
}

type compatPerformanceTimingConn struct {
	net.Conn
	dialStart time.Time
	mu        sync.Mutex
	finalRead time.Time
}

func (c *compatPerformanceTimingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.finalRead = time.Now()
		c.mu.Unlock()
	}
	return n, err
}
func (c *compatPerformanceTimingConn) Timestamps() (time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dialStart, c.finalRead
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

func compatibilityClients(t *testing.T, h *compatHarness, workers int) ([]*http.Client, []int64) {
	t.Helper()
	proxyURL, err := url.Parse("http://compat-user:compat-password@" + h.server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]*http.Client, workers)
	dials := make([]int64, workers)
	for i := range clients {
		index := i
		config := tlsConfigFor(h.server)
		transport := &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			TLSClientConfig:     &config,
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

func compatibilityDialsTotal(dials []int64) int64 {
	var total int64
	for i := range dials {
		total += atomic.LoadInt64(&dials[i])
	}
	return total
}

func compatibilityRSS(t *testing.T) int64 {
	t.Helper()
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		t.Fatal(err)
	}
	kb, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || kb < 0 {
		t.Fatalf("invalid RSS %q: %v", out, err)
	}
	return kb * 1024
}
