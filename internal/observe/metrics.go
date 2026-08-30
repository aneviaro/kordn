// Package observe contains process-local metrics only. It deliberately has no
// exporter or HTTP endpoint.
package observe

import (
	"sync"
	"time"
)

type Metrics struct {
	mu                                                               sync.Mutex
	counters                                                         map[string]uint64
	samples                                                          map[string][]float64
	activeConnections, peakConnections, activeRequests, peakRequests int
}
type Snapshot struct {
	Counters          map[string]uint64    `json:"counters"`
	Histograms        map[string]Histogram `json:"histograms"`
	ActiveConnections int                  `json:"active_connections"`
	PeakConnections   int                  `json:"peak_connections"`
	ActiveRequests    int                  `json:"active_requests"`
	PeakRequests      int                  `json:"peak_requests"`
}
type Histogram struct {
	Count int     `json:"count"`
	P50   float64 `json:"p50_ms"`
	P95   float64 `json:"p95_ms"`
	P99   float64 `json:"p99_ms"`
}

func NewMetrics() *Metrics {
	return &Metrics{counters: make(map[string]uint64), samples: make(map[string][]float64)}
}

const (
	Intercepted            = "requests_intercepted"
	Allowed                = "requests_allowed"
	Denied                 = "requests_denied"
	Unsupported            = "requests_unsupported"
	UpstreamErrors         = "upstream_errors"
	UpstreamTransport      = "upstream.transport"
	UpstreamCancellation   = "upstream.cancel"
	UpstreamAuth           = "upstream.401_403"
	UpstreamThrottled      = "upstream.429"
	UpstreamClient         = "upstream.other_4xx"
	UpstreamServer         = "upstream.5xx"
	AuthFailures           = "authentication_failures"
	AuditFailures          = "audit_writer_failures"
	AuditBackpressure      = "audit_backpressure"
	CacheEndpointHits      = "cache_endpoint_hits"
	CacheEndpointMisses    = "cache_endpoint_misses"
	CacheMappingHits       = "cache_mapping_hits"
	CacheMappingMisses     = "cache_mapping_misses"
	CacheDecisionHits      = "cache_decision_hits"
	CacheDecisionMisses    = "cache_decision_misses"
	CacheEvictions         = "cache_evictions"
	UpstreamLatency        = "upstream_latency_ms"
	QueueDepth             = "audit_queue_depth"
	ConnectionBackpressure = "connection_backpressure"
	RequestBackpressure    = "request_backpressure"
	ChildExit              = "child_exit"
	ChildCleanupFailures   = "child_cleanup_failures"
	PayloadBytes           = "payload_bytes"
	SpoolBytes             = "spool_bytes"
	DecodeLatency          = "decode_latency_ms"
	MapLatency             = "map_latency_ms"
	PolicyLatency          = "policy_latency_ms"
	LocalLatency           = "local_latency_ms"
)

// These are the stable, non-labelled fields emitted in every run snapshot.
// Dynamic decision counters retain their exact service/operation/reason tags,
// while the fixed fields make a zero-request run deterministic.
var deterministicCounters = []string{
	Intercepted, Allowed, Denied, Unsupported, UpstreamErrors,
	UpstreamTransport, UpstreamCancellation, UpstreamAuth,
	UpstreamThrottled, UpstreamClient, UpstreamServer,
	AuthFailures, AuditFailures, AuditBackpressure,
	CacheEndpointHits, CacheEndpointMisses, CacheMappingHits, CacheMappingMisses,
	CacheDecisionHits, CacheDecisionMisses, CacheEvictions,
	QueueDepth, ConnectionBackpressure, RequestBackpressure,
	ChildExit, ChildCleanupFailures, PayloadBytes, SpoolBytes,
}
var deterministicHistograms = []string{
	LocalLatency, UpstreamLatency, DecodeLatency, MapLatency, PolicyLatency,
}

func (m *Metrics) IncCounter(name string) { m.Inc(name) }
func (m *Metrics) Inc(name string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.counters == nil {
		m.counters = make(map[string]uint64)
	}
	m.counters[name]++
	m.mu.Unlock()
}
func (m *Metrics) SetGauge(name string, value int) {
	if m == nil {
		return
	}
	if value < 0 {
		value = 0
	}
	m.mu.Lock()
	if m.counters == nil {
		m.counters = make(map[string]uint64)
	}
	m.counters[name] = uint64(value)
	m.mu.Unlock()
}

func DecisionCounter(service, operation, reason string) string {
	return "decision." + safeLabel(service) + "." + safeLabel(operation) + "." + safeLabel(reason)
}

func safeLabel(value string) string {
	if value == "" {
		return "unknown"
	}
	var b []byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			b = append(b, c)
		} else {
			b = append(b, '_')
		}
	}
	return string(b)
}

func (m *Metrics) Add(name string, n uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.counters == nil {
		m.counters = make(map[string]uint64)
	}
	m.counters[name] += n
	m.mu.Unlock()
}
func (m *Metrics) Observe(name string, d time.Duration) {
	if m == nil {
		return
	}
	if d < 0 {
		d = 0
	}
	m.mu.Lock()
	if m.samples == nil {
		m.samples = make(map[string][]float64)
	}
	values := append(m.samples[name], float64(d)/float64(time.Millisecond))
	const maxSamples = 4096
	if len(values) > maxSamples {
		values = values[len(values)-maxSamples:]
	}
	m.samples[name] = values
	m.mu.Unlock()
}
func (m *Metrics) SetActiveConnections(n int) {
	if m == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeConnections = n
	if n > m.peakConnections {
		m.peakConnections = n
	}
}
func (m *Metrics) SetActiveRequests(n int) {
	if m == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeRequests = n
	if n > m.peakRequests {
		m.peakRequests = n
	}
}
func (m *Metrics) ConnectionStarted() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.activeConnections++
	if m.activeConnections > m.peakConnections {
		m.peakConnections = m.activeConnections
	}
	m.mu.Unlock()
}
func (m *Metrics) ConnectionFinished() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.activeConnections > 0 {
		m.activeConnections--
	}
	m.mu.Unlock()
}
func (m *Metrics) RequestStarted() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.activeRequests++
	if m.activeRequests > m.peakRequests {
		m.peakRequests = m.activeRequests
	}
	m.mu.Unlock()
}
func (m *Metrics) RequestFinished() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.activeRequests > 0 {
		m.activeRequests--
	}
	m.mu.Unlock()
}
func (m *Metrics) SnapshotMetrics() Snapshot { return m.Snapshot() }
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{Counters: map[string]uint64{}, Histograms: map[string]Histogram{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := make(map[string]uint64, len(m.counters)+len(deterministicCounters))
	for _, name := range deterministicCounters {
		c[name] = 0
	}
	for k, v := range m.counters {
		c[k] = v
	}
	h := make(map[string]Histogram, len(m.samples)+len(deterministicHistograms))
	for _, name := range deterministicHistograms {
		h[name] = Histogram{}
	}
	for k, v := range m.samples {
		h[k] = hist(v)
	}
	return Snapshot{c, h, m.activeConnections, m.peakConnections, m.activeRequests, m.peakRequests}
}
func hist(v []float64) Histogram {
	h := Histogram{Count: len(v)}
	if len(v) == 0 {
		return h
	}
	x := append([]float64(nil), v...)
	for i := 1; i < len(x); i++ {
		for j := i; j > 0 && x[j] < x[j-1]; j-- {
			x[j], x[j-1] = x[j-1], x[j]
		}
	}
	pick := func(p float64) float64 { idx := int(float64(len(x)-1) * p); return x[idx] }
	h.P50 = pick(.5)
	h.P95 = pick(.95)
	h.P99 = pick(.99)
	return h
}
