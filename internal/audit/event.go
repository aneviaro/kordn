package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

const SchemaVersion = "kordn.audit/v1"

type AuditWriter interface {
	Write(context.Context, Event) error
	Flush(context.Context) error
}
type EventType string

const (
	RunStarted           EventType = "run.started"
	RunEnded             EventType = "run.ended"
	RequestDecision      EventType = "aws.request.decision"
	ForwardError         EventType = "aws.request.forward_error"
	AuthenticationFailed EventType = "proxy.authentication_failed"
	UnsupportedRequest   EventType = "proxy.unsupported_request"
	WriterFailed         EventType = "audit.writer_failed"
	CleanupFailed        EventType = "runtime.cleanup_failed"
)

type Event struct {
	SchemaVersion   string           `json:"schema_version"`
	EventID         string           `json:"event_id"`
	RunID           string           `json:"run_id"`
	Timestamp       time.Time        `json:"timestamp"`
	EventType       EventType        `json:"event_type"`
	RootProcess     *RootProcess     `json:"root_process,omitempty"`
	ConnectionID    string           `json:"connection_id,omitempty"`
	Request         *RequestInfo     `json:"request,omitempty"`
	IAMRequirements []Requirement    `json:"iam_requirements,omitempty"`
	Mapping         *MappingInfo     `json:"mapping,omitempty"`
	Decision        *DecisionInfo    `json:"decision,omitempty"`
	Upstream        *UpstreamInfo    `json:"upstream,omitempty"`
	Timing          *TimingInfo      `json:"timing_ms,omitempty"`
	Status          string           `json:"status,omitempty"`
	ErrorCode       string           `json:"error_code,omitempty"`
	ExitCode        *int             `json:"exit_code,omitempty"`
	DurationMS      float64          `json:"duration_ms,omitempty"`
	Metrics         *MetricsSnapshot `json:"metrics,omitempty"`
}
type RootProcess struct {
	PID         int    `json:"pid"`
	Argv0       string `json:"argv0"`
	CommandHash string `json:"command_hash"`
}
type RequestInfo struct {
	Host         string                 `json:"host"`
	Partition    string                 `json:"partition"`
	Service      string                 `json:"service"`
	Operation    string                 `json:"operation"`
	Region       string                 `json:"region"`
	Protocol     awsrequest.AWSProtocol `json:"protocol"`
	Method       string                 `json:"method"`
	PayloadBytes int64                  `json:"payload_bytes"`
}
type Requirement struct {
	Action    string               `json:"action"`
	Resources []string             `json:"resources"`
	ScopeKind awsrequest.ScopeKind `json:"scope_kind"`
	Dependent bool                 `json:"dependent"`
}
type MappingInfo struct {
	Confidence    awsrequest.MappingConfidence `json:"confidence"`
	MapperVersion string                       `json:"mapper_version"`
}
type DecisionInfo struct {
	Result         string   `json:"result"`
	ReasonCode     string   `json:"reason_code"`
	MatchedRuleIDs []string `json:"matched_rule_ids"`
	PolicyHash     string   `json:"policy_hash"`
}
type UpstreamInfo struct {
	Profile      string `json:"profile"`
	PrincipalARN string `json:"principal_arn,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	AWSRequestID string `json:"aws_request_id,omitempty"`
}
type TimingInfo struct {
	Decode     float64 `json:"decode,omitempty"`
	Map        float64 `json:"map,omitempty"`
	Policy     float64 `json:"policy,omitempty"`
	LocalTotal float64 `json:"local_total,omitempty"`
	Upstream   float64 `json:"upstream,omitempty"`
}
type MetricsSnapshot struct {
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

func (r Requirement) Validate() error {
	if r.Action == "" || len(r.Resources) == 0 || !r.ScopeKind.Valid() {
		return errors.New("invalid audit IAM requirement")
	}
	for _, x := range r.Resources {
		if x == "" {
			return errors.New("empty audit resource")
		}
	}
	return nil
}
func (r RequestInfo) Validate() error {
	if strings.TrimSpace(r.Host) == "" || r.Partition == "" || r.Service == "" || r.Operation == "" || !r.Protocol.Supported() || r.Method == "" || r.PayloadBytes < 0 {
		return errors.New("invalid request audit information")
	}
	return nil
}
func (e Event) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	// Validate the typed event before redaction, then serialize only the
	// redacted copy. Audit events intentionally have no body field, and this
	// final boundary also protects future callers that populate a diagnostic
	// field with a registered credential value.
	e = redactEvent(e)
	type plain Event
	return json.Marshal(plain(e))
}
func (e Event) Validate() error {
	if e.SchemaVersion != SchemaVersion || e.EventID == "" || len(e.EventID) > 128 || e.RunID == "" || len(e.RunID) > 128 || e.EventType == "" || e.Timestamp.IsZero() || e.Timestamp.Location() != time.UTC {
		return errors.New("invalid audit identity")
	}
	switch e.EventType {
	case RunStarted:
		if e.ConnectionID != "" || e.Request != nil || len(e.IAMRequirements) != 0 || e.Mapping != nil || e.Decision != nil || e.Timing != nil || e.Status != "" || e.ErrorCode != "" || e.ExitCode != nil || e.DurationMS != 0 || e.Metrics != nil {
			return errors.New("run.started contains fields for another event")
		}
		if e.RootProcess == nil || e.Upstream == nil {
			return errors.New("run.started is incomplete")
		}
		if err := validateRoot(e.RootProcess); err != nil {
			return err
		}
		if e.Upstream.Profile == "" {
			return errors.New("run.started profile is required")
		}
	case RunEnded:
		if e.ConnectionID != "" || e.Request != nil || len(e.IAMRequirements) != 0 || e.Mapping != nil || e.Decision != nil || e.Timing != nil || e.ErrorCode != "" || e.Upstream != nil || e.Metrics == nil {
			return errors.New("run.ended contains fields for another event")
		}
		if e.RootProcess == nil || e.Status == "" || e.ExitCode == nil {
			return errors.New("run.ended is incomplete")
		}
		if err := validateRoot(e.RootProcess); err != nil {
			return err
		}
		if *e.ExitCode < 0 || *e.ExitCode > 255 {
			return errors.New("run exit code is invalid")
		}
	case RequestDecision:
		if e.RootProcess != nil || e.Upstream != nil || e.Status != "" || e.ErrorCode != "" || e.ExitCode != nil || e.DurationMS != 0 || e.Metrics != nil {
			return errors.New("decision event contains fields for another event")
		}
		if e.ConnectionID == "" || e.Request == nil || len(e.IAMRequirements) == 0 || e.Mapping == nil || e.Decision == nil || e.Timing == nil {
			return errors.New("decision event is incomplete")
		}
		if err := e.Request.Validate(); err != nil {
			return err
		}
		if e.Decision.Result != "allow" && e.Decision.Result != "deny" {
			return errors.New("decision result is invalid")
		}
		if !validHash(e.Decision.PolicyHash) {
			return errors.New("decision policy hash is invalid")
		}
		if !e.Mapping.Confidence.Valid() || e.Mapping.MapperVersion == "" {
			return errors.New("decision mapping is incomplete")
		}
		for _, r := range e.IAMRequirements {
			if err := r.Validate(); err != nil {
				return err
			}
		}
	case ForwardError:
		if e.RootProcess != nil || e.IAMRequirements != nil || e.Mapping != nil || e.Decision != nil || e.Metrics != nil {
			return errors.New("forward error event contains fields for another event")
		}
		if e.ConnectionID == "" || e.Request == nil || e.ErrorCode == "" {
			return errors.New("forward error event is incomplete")
		}
		if err := e.Request.Validate(); err != nil {
			return err
		}
	case AuthenticationFailed, UnsupportedRequest:
		if e.RootProcess != nil || e.Request != nil || e.IAMRequirements != nil || e.Mapping != nil || e.Decision != nil || e.Upstream != nil || e.Timing != nil || e.Status != "" || e.ExitCode != nil || e.DurationMS != 0 || e.Metrics != nil {
			return errors.New("proxy event contains fields for another event")
		}
		if e.ConnectionID == "" || e.ErrorCode == "" {
			return errors.New("proxy event is incomplete")
		}
	case WriterFailed, CleanupFailed:
		if e.RootProcess != nil || e.ConnectionID != "" || e.Request != nil || e.IAMRequirements != nil || e.Mapping != nil || e.Decision != nil || e.Upstream != nil || e.Timing != nil || e.Status != "" || e.ExitCode != nil || e.DurationMS != 0 || e.Metrics != nil {
			return errors.New("failure event contains fields for another event")
		}
		if e.ErrorCode == "" {
			return errors.New("failure event is incomplete")
		}
	default:
		return fmt.Errorf("unsupported audit event type %q", e.EventType)
	}
	return nil
}
func validateRoot(r *RootProcess) error {
	if r.PID < 1 || r.Argv0 == "" || len(r.Argv0) > 256 || !validHash(r.CommandHash) {
		return errors.New("invalid root process")
	}
	return nil
}
func validHash(v string) bool { return len(v) == 71 && strings.HasPrefix(v, "sha256:") && isHex(v[7:]) }
func isHex(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func NewEvent(runID string, typ EventType) Event {
	return Event{SchemaVersion: SchemaVersion, RunID: runID, EventID: NewID(), Timestamp: time.Now().UTC(), EventType: typ}
}
func NewID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err == nil {
		return "evt_" + hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("evt_%d", time.Now().UTC().UnixNano())
}
func Requirements(in []awsrequest.IAMRequirement, hashNames bool) []Requirement {
	return requirements(in, func(_ awsrequest.IAMRequirement, s string) string {
		if hashNames {
			return HashResource(s)
		}
		return s
	})
}
func RequirementsForRun(runID string, in []awsrequest.IAMRequirement, logARNs, hashNames bool) []Requirement {
	return requirements(in, func(r awsrequest.IAMRequirement, s string) string {
		// A known-global wildcard is a scope marker, not a resource name. Keep
		// it intact so the audit record retains the mapper's authorization
		// semantics in every resource logging mode.
		if r.ScopeKind == awsrequest.ScopeKnownGlobal && s == "*" {
			return s
		}
		// Hashing is its own mode. Config validation rejects the ambiguous
		// combination with raw ARN logging, but keeping this precedence here
		// makes the immutable runtime setting safe even for direct callers.
		if hashNames {
			return HashResourceForRun(runID, s)
		}
		if logARNs {
			return s
		}
		return "[REDACTED]"
	})
}
func requirements(in []awsrequest.IAMRequirement, redact func(awsrequest.IAMRequirement, string) string) []Requirement {
	out := make([]Requirement, 0, len(in))
	for _, r := range in {
		x := make([]string, len(r.Resources))
		for i, s := range r.Resources {
			x[i] = redact(r, s)
		}
		out = append(out, Requirement{Action: r.Action, Resources: x, ScopeKind: r.ScopeKind, Dependent: r.Dependent})
	}
	return out
}
