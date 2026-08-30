package audit

import (
	"context"
	"encoding/json"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baseEvent(t *testing.T, typ EventType) Event {
	t.Helper()
	e := NewEvent("run_test", typ)
	e.RootProcess = &RootProcess{PID: 1, Argv0: "kordn", CommandHash: "sha256:" + strings.Repeat("a", 64)}
	e.Upstream = &UpstreamInfo{Profile: "profile"}
	return e
}
func decisionEventForTest(t *testing.T) Event {
	t.Helper()
	e := NewEvent("run_test", RequestDecision)
	e.ConnectionID = "conn"
	e.Request = &RequestInfo{Host: "sts.amazonaws.com", Partition: "aws", Service: "sts", Operation: "GetCallerIdentity", Region: "us-east-1", Protocol: awsrequest.ProtocolJSON11, Method: "POST"}
	e.IAMRequirements = []Requirement{{Action: "sts:GetCallerIdentity", Resources: []string{"[REDACTED]"}, ScopeKind: awsrequest.ScopeExact}}
	e.Mapping = &MappingInfo{Confidence: awsrequest.ConfidenceHigh, MapperVersion: "mapper"}
	e.Decision = &DecisionInfo{Result: "deny", ReasonCode: "policy_no_matching_allow", PolicyHash: "sha256:" + strings.Repeat("b", 64)}
	e.Timing = &TimingInfo{}
	return e
}
func TestAuditAllEventTypesValidate(t *testing.T) {
	e := baseEvent(t, RunStarted)
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	ended := baseEvent(t, RunEnded)
	ended.Upstream = nil
	ended.Status = "completed"
	code := 0
	ended.ExitCode = &code
	ended.Metrics = &MetricsSnapshot{Counters: map[string]uint64{}, Histograms: map[string]Histogram{}}
	if err := ended.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := decisionEventForTest(t).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []EventType{ForwardError, AuthenticationFailed, UnsupportedRequest, WriterFailed, CleanupFailed} {
		x := NewEvent("run_test", typ)
		x.ConnectionID = "conn"
		x.ErrorCode = "stable_error"
		if typ == ForwardError {
			x.Request = decisionEventForTest(t).Request
		}
		if typ == WriterFailed || typ == CleanupFailed {
			x.ConnectionID = ""
		}
		if err := x.Validate(); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}
}
func TestAuditEventRejectsCrossTypeFields(t *testing.T) {
	e := decisionEventForTest(t)
	e.Status = "leak"
	if err := e.Validate(); err == nil {
		t.Fatal("accepted cross-type field")
	}
}
func TestAuditWriterPrivateAppendAndFlush(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	w, err := NewWriter(p, Options{QueueCapacity: 2, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	e := decisionEventForTest(t)
	if err := w.Write(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	e.Decision.MatchedRuleIDs = []string{"mutated-after-enqueue"}
	if err := w.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	got, err := ReadEvents(p)
	if err != nil || len(got) != 1 {
		t.Fatalf("read: %v (%d)", err, len(got))
	}
	if len(got[0].Decision.MatchedRuleIDs) != 0 {
		t.Fatal("event was not independently owned")
	}
}
func TestAuditWriterRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := NewWriter(link); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestAuditRedactionStructured(t *testing.T) {
	h := http.Header{"Authorization": []string{"Bearer SECRET"}, "X-Test": []string{"secret=VALUE"}}
	r := RedactHeaders(h)
	if strings.Contains(r.Get("Authorization"), "SECRET") || strings.Contains(r.Get("X-Test"), "VALUE") {
		t.Fatal("header secret leaked")
	}
	x := RedactStructured(map[string]interface{}{"nested": []interface{}{map[string]interface{}{"token": "VALUE"}}})
	b, _ := json.Marshal(x)
	if strings.Contains(string(b), "VALUE") {
		t.Fatal("nested secret leaked")
	}
	if HashResourceForRun("a", "name") == HashResourceForRun("b", "name") {
		t.Fatal("hash is not run scoped")
	}
}
func TestRunEndedCarriesPrivateExactMetricsSnapshot(t *testing.T) {
	code := 0
	e := NewEvent("run_metrics", RunEnded)
	e.RootProcess = &RootProcess{PID: 1, Argv0: "kordn", CommandHash: "sha256:" + strings.Repeat("a", 64)}
	e.Status = "completed"
	e.ExitCode = &code
	e.Metrics = &MetricsSnapshot{
		Counters:          map[string]uint64{"decision.s3.GetObject.policy_no_matching_allow": 2, "cache_decision_hits": 1},
		Histograms:        map[string]Histogram{"policy_latency_ms": {Count: 2, P50: 1, P95: 2, P99: 2}},
		ActiveConnections: 0, PeakConnections: 2, ActiveRequests: 0, PeakRequests: 1,
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.EventType != RunEnded || got.Metrics.Counters["cache_decision_hits"] != 1 || got.Metrics.Histograms["policy_latency_ms"].Count != 2 {
		t.Fatalf("metrics snapshot=%+v", got.Metrics)
	}
}

func TestAuditReadEventsRejectsPartial(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEvents(p); err == nil {
		t.Fatal("partial record accepted")
	}
}
