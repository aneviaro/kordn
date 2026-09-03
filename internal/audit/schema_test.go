package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func auditRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate audit test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "api", "audit.schema.json")); err != nil {
		t.Fatalf("repository root is not usable: %v", err)
	}
	return root
}

func TestAuditSchemaCompilesAndValidatesEveryEventType(t *testing.T) {
	path := filepath.Join(auditRepositoryRoot(t), "api", "audit.schema.json")
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(path)
	if err != nil {
		t.Fatalf("compile audit schema: %v", err)
	}

	fixtures := make([]Event, 0, 8)
	started := NewEvent("run_schema", RunStarted)
	started.RootProcess = &RootProcess{PID: 1, Argv0: "kordn", CommandHash: "sha256:" + strings.Repeat("a", 64)}
	started.Upstream = &UpstreamInfo{Profile: "profile"}
	fixtures = append(fixtures, started)
	ended := NewEvent("run_schema", RunEnded)
	ended.RootProcess = started.RootProcess
	ended.Status = "completed"
	exitCode := 0
	ended.ExitCode = &exitCode
	ended.Metrics = &MetricsSnapshot{Counters: map[string]uint64{}, Histograms: map[string]Histogram{}}
	fixtures = append(fixtures, ended)

	decision := NewEvent("run_schema", RequestDecision)
	decision.ConnectionID = "connection"
	decision.Request = &RequestInfo{Host: "sts.amazonaws.com", Partition: "aws", Service: "sts", Operation: "GetCallerIdentity", Region: "us-east-1", Protocol: awsrequest.ProtocolJSON11, Method: "POST", PayloadBytes: 0}
	decision.IAMRequirements = []Requirement{{Action: "sts:GetCallerIdentity", Resources: []string{"[REDACTED]"}, ScopeKind: awsrequest.ScopeExact}}
	decision.Mapping = &MappingInfo{
		Confidence:               awsrequest.ConfidenceHigh,
		MapperVersion:            "kordn-iammap/v3",
		IamLiveVersion:           "iamlive-derived/v2@3ec1a40e560c2f00ec82c50223add810e2567efb",
		AuthorizationDataVersion: "iamlive-catalog/v1@3ec1a40e560c2f00ec82c50223add810e2567efb+sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	decision.Decision = &DecisionInfo{Result: "allow", ReasonCode: "all_requirements_allowed", MatchedRuleIDs: []string{}, PolicyHash: "sha256:" + strings.Repeat("b", 64)}
	decision.Timing = &TimingInfo{LocalTotal: 1}
	fixtures = append(fixtures, decision)

	forward := NewEvent("run_schema", ForwardError)
	forward.ConnectionID = "connection"
	forward.Request = decision.Request
	forward.ErrorCode = "upstream_transport_error"
	fixtures = append(fixtures, forward)
	for _, typ := range []EventType{AuthenticationFailed, UnsupportedRequest} {
		e := NewEvent("run_schema", typ)
		e.ConnectionID, e.ErrorCode = "connection", "stable_error"
		fixtures = append(fixtures, e)
	}
	for _, typ := range []EventType{WriterFailed, CleanupFailed} {
		e := NewEvent("run_schema", typ)
		e.ErrorCode = "stable_error"
		fixtures = append(fixtures, e)
	}
	if len(fixtures) != 8 {
		t.Fatalf("fixture count=%d", len(fixtures))
	}
	for _, event := range fixtures {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal %s: %v", event.EventType, err)
		}
		var instance any
		if err := json.Unmarshal(data, &instance); err != nil {
			t.Fatalf("decode %s: %v", event.EventType, err)
		}
		if err := schema.Validate(instance); err != nil {
			t.Errorf("schema rejected %s: %v", event.EventType, err)
		}
	}
}
