package observe

import (
	"sync"
	"testing"
	"time"
)

func TestMetricsSnapshotHasExactUniqueTagCounters(t *testing.T) {
	m := NewMetrics()
	allow := DecisionCounter("s3", "GetObject", "all_requirements_allowed")
	deny := DecisionCounter("s3", "GetObject", "policy_no_matching_allow")
	m.Inc(allow)
	m.Inc(allow)
	m.Inc(deny)
	m.Add(PayloadBytes, 17)
	m.SetActiveConnections(2)
	m.SetActiveRequests(1)
	snapshot := m.Snapshot()
	if snapshot.Counters[allow] != 2 || snapshot.Counters[deny] != 1 || snapshot.Counters[PayloadBytes] != 17 {
		t.Fatalf("unique counters=%v", snapshot.Counters)
	}
	if snapshot.ActiveConnections != 2 || snapshot.PeakConnections != 2 || snapshot.ActiveRequests != 1 || snapshot.PeakRequests != 1 {
		t.Fatalf("gauge snapshot=%+v", snapshot)
	}
	if DecisionCounter("service/secret", "operation", "reason") != "decision.service_secret.operation.reason" {
		t.Fatal("metric tag was not safely canonicalized")
	}
}

func TestMetricsSnapshotIsPrivateAndBounded(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				m.Inc(Intercepted)
				m.Observe("latency", time.Duration(j)*time.Microsecond)
				m.ConnectionStarted()
				m.ConnectionFinished()
			}
		}()
	}
	wg.Wait()
	s := m.Snapshot()
	if s.Counters[Intercepted] != 10000 {
		t.Fatalf("counter=%d", s.Counters[Intercepted])
	}
	if s.Histograms["latency"].Count > 4096 {
		t.Fatalf("histogram unbounded: %d", s.Histograms["latency"].Count)
	}
	s.Counters[Intercepted] = 0
	if m.Snapshot().Counters[Intercepted] == 0 {
		t.Fatal("snapshot aliases counters")
	}
}
