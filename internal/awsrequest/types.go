package awsrequest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// VerifiedRequest is the output of inbound authentication. Authentication
// implementations must not add access keys, session tokens, or authorization
// values to this shared contract.
type VerifiedRequest struct {
	Request        *http.Request
	Endpoint       AWSEndpoint
	Protocol       AWSProtocol
	SigningScheme  SigningScheme
	SigningRegion  string
	SigningService string
	PayloadMode    PayloadHashMode
}

// EvidenceCertainty records the validation boundary reached by decoder
// evidence. Operation evidence is available only after an exact, unambiguous
// catalog identity has been validated; protocol evidence is available only
// after authentication, endpoint, content type, and catalog agreement.
type EvidenceCertainty string

const (
	EvidenceUnknown       EvidenceCertainty = "unknown"
	EvidenceAuthoritative EvidenceCertainty = "authoritative"
	EvidenceValidated     EvidenceCertainty = "validated"
)

// DecodeFailureEvidence is the bounded, non-secret portion of a decoder
// failure that may safely shape a local denial. It intentionally contains no
// request headers, query values, body bytes, or authentication material.
type DecodeFailureEvidence struct {
	Service            string            `json:"service,omitempty"`
	Protocol           AWSProtocol       `json:"protocol,omitempty"`
	ProtocolAvailable  bool              `json:"protocol_available"`
	ProtocolCertainty  EvidenceCertainty `json:"protocol_certainty"`
	Operation          string            `json:"operation,omitempty"`
	OperationAvailable bool              `json:"operation_available"`
	OperationCertainty EvidenceCertainty `json:"operation_certainty"`
}

func (e DecodeFailureEvidence) Validate() error {
	if e.Service != "" && !validEvidenceService(e.Service) {
		return fmt.Errorf("invalid evidence service %q", e.Service)
	}
	if e.ProtocolAvailable {
		if e.Service == "" || !e.Protocol.Supported() || e.ProtocolCertainty != EvidenceAuthoritative {
			return errors.New("available protocol evidence is not authoritative")
		}
	} else if e.Protocol != "" || (e.ProtocolCertainty != "" && e.ProtocolCertainty != EvidenceUnknown) {
		return errors.New("unavailable protocol evidence must be empty and unknown")
	}
	if e.OperationAvailable {
		if !e.ProtocolAvailable || e.Service == "" || !validEvidenceOperation(e.Operation) || e.OperationCertainty != EvidenceValidated {
			return errors.New("available operation evidence is not validated")
		}
	} else if e.Operation != "" || (e.OperationCertainty != "" && e.OperationCertainty != EvidenceUnknown) {
		return errors.New("unavailable operation evidence must be empty and unknown")
	}
	return nil
}

func (e DecodeFailureEvidence) HasProtocol() bool {
	return e.ProtocolAvailable && e.Protocol.Supported()
}
func (e DecodeFailureEvidence) HasOperation() bool {
	return e.OperationAvailable && validEvidenceOperation(e.Operation)
}

// DecodeFailureError preserves the decoder cause while carrying only
// progressive, validated evidence. It is errors.As-friendly for pipeline
// consumers and does not expose the cause in any wire response.
type DecodeFailureError struct {
	Evidence DecodeFailureEvidence
	Cause    error
}

func (e *DecodeFailureError) Error() string {
	if e == nil || e.Cause == nil {
		return "request decode failed"
	}
	return e.Cause.Error()
}
func (e *DecodeFailureError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type DecodeError = DecodeFailureError

func NewDecodeFailureError(evidence DecodeFailureEvidence, cause error) error {
	if cause == nil {
		return nil
	}
	if !evidence.ProtocolAvailable && evidence.ProtocolCertainty == "" {
		evidence.ProtocolCertainty = EvidenceUnknown
	}
	if !evidence.OperationAvailable && evidence.OperationCertainty == "" {
		evidence.OperationCertainty = EvidenceUnknown
	}
	if evidence.Validate() != nil {
		evidence = DecodeFailureEvidence{ProtocolCertainty: EvidenceUnknown, OperationCertainty: EvidenceUnknown}
	}
	return &DecodeFailureError{Evidence: evidence, Cause: cause}
}

func DecodeFailureEvidenceFromError(err error) (DecodeFailureEvidence, bool) {
	var failure *DecodeFailureError
	if err == nil || !errors.As(err, &failure) || failure == nil || failure.Evidence.Validate() != nil {
		return DecodeFailureEvidence{}, false
	}
	return failure.Evidence, true
}

// AttachDecodeFailureEvidence adds only evidence which is compatible with the
// strongest evidence already attached to an error. Conflicts fail closed.
func AttachDecodeFailureEvidence(err error, evidence DecodeFailureEvidence) error {
	if err == nil {
		return nil
	}
	if evidence.Validate() != nil {
		return err
	}
	if existing, ok := DecodeFailureEvidenceFromError(err); ok {
		if (existing.Service != "" && evidence.Service != "" && existing.Service != evidence.Service) ||
			(existing.ProtocolAvailable && evidence.ProtocolAvailable && existing.Protocol != evidence.Protocol) ||
			(existing.OperationAvailable && evidence.OperationAvailable && existing.Operation != evidence.Operation) {
			return NewDecodeFailureError(DecodeFailureEvidence{ProtocolCertainty: EvidenceUnknown, OperationCertainty: EvidenceUnknown}, err)
		}
		if existing.Service == "" {
			existing.Service = evidence.Service
		}
		if !existing.ProtocolAvailable && evidence.ProtocolAvailable {
			existing.Protocol, existing.ProtocolAvailable, existing.ProtocolCertainty = evidence.Protocol, true, evidence.ProtocolCertainty
		}
		if !existing.OperationAvailable && evidence.OperationAvailable {
			existing.Operation, existing.OperationAvailable, existing.OperationCertainty = evidence.Operation, true, evidence.OperationCertainty
		}
		evidence = existing
	}
	return NewDecodeFailureError(evidence, err)
}

func validEvidenceService(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func validEvidenceOperation(value string) bool { return len(value) <= 128 && validOperation(value) }

func (r VerifiedRequest) Validate() error {
	if r.Request == nil {
		return errors.New("verified request is nil")
	}
	if err := r.Endpoint.Validate(); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if !r.Protocol.Supported() {
		return fmt.Errorf("unsupported AWS protocol %q", r.Protocol)
	}
	if !r.SigningScheme.Supported() {
		return fmt.Errorf("unsupported signing scheme %q", r.SigningScheme)
	}
	if r.SigningRegion == "" || r.SigningService == "" {
		return errors.New("signing Region and service are required")
	}
	if !r.PayloadMode.Valid() {
		return fmt.Errorf("unsupported payload mode %q", r.PayloadMode)
	}
	return nil
}

// ValueKind identifies the concrete type carried by a decoded request
// parameter. There is deliberately no stringly typed fallback.
type ValueKind string

const (
	ValueNull    ValueKind = "null"
	ValueString  ValueKind = "string"
	ValueBoolean ValueKind = "boolean"
	ValueInteger ValueKind = "integer"
	ValueNumber  ValueKind = "number"
	ValueObject  ValueKind = "object"
	ValueArray   ValueKind = "array"
)

// Value is a recursively typed request parameter. Only the field selected by
// Kind is meaningful; decoders preserve integer, number, boolean, object,
// array, and string distinctions rather than coercing everything to text.
type Value struct {
	Kind   ValueKind        `json:"kind"`
	String string           `json:"string,omitempty"`
	Bool   bool             `json:"bool,omitempty"`
	Int    int64            `json:"int,omitempty"`
	Float  float64          `json:"float,omitempty"`
	Object map[string]Value `json:"object,omitempty"`
	Array  []Value          `json:"array,omitempty"`
}

func (v Value) Validate() error { return v.validate(0) }

func (v Value) validate(depth int) error {
	if depth > 64 {
		return errors.New("parameter value nesting exceeds 64 levels")
	}
	switch v.Kind {
	case ValueNull, ValueString, ValueBoolean, ValueInteger:
		return nil
	case ValueNumber:
		// JSON/YAML decoders cannot safely represent NaN or infinity as a
		// request parameter, and neither has an AWS wire representation.
		if v.Float != v.Float || v.Float > 1.7976931348623157e+308 || v.Float < -1.7976931348623157e+308 {
			return errors.New("number parameter is not finite")
		}
		return nil
	case ValueObject:
		for key, value := range v.Object {
			if strings.TrimSpace(key) == "" {
				return errors.New("object parameter key is empty")
			}
			if err := value.validate(depth + 1); err != nil {
				return fmt.Errorf("object parameter %q: %w", key, err)
			}
		}
		return nil
	case ValueArray:
		for i, value := range v.Array {
			if err := value.validate(depth + 1); err != nil {
				return fmt.Errorf("array parameter %d: %w", i, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported parameter value kind %q", v.Kind)
	}
}

// ScopeKind is the mapper's resource-scope classification. The four values
// are intentionally distinct: unresolved is never a synonym for wildcard.
type ScopeKind string

const (
	ScopeExact       ScopeKind = "exact"
	ScopeSet         ScopeKind = "set"
	ScopeKnownGlobal ScopeKind = "known_global"
	ScopeUnresolved  ScopeKind = "unresolved"

	Exact       = ScopeExact
	Set         = ScopeSet
	KnownGlobal = ScopeKnownGlobal
	Unresolved  = ScopeUnresolved
)

func (s ScopeKind) Valid() bool {
	switch s {
	case ScopeExact, ScopeSet, ScopeKnownGlobal, ScopeUnresolved:
		return true
	default:
		return false
	}
}

// IAMRequirement is one mandatory action/resource requirement. Dependent
// requirements are conjunctive, never advisory.
type IAMRequirement struct {
	Action        string              `json:"action"`
	Resources     []string            `json:"resources"`
	ScopeKind     ScopeKind           `json:"scope_kind"`
	Dependent     bool                `json:"dependent"`
	ConditionHint map[string][]string `json:"condition_hint,omitempty"`
}

func (r IAMRequirement) Validate() error {
	if strings.TrimSpace(r.Action) == "" {
		return errors.New("IAM action is required")
	}
	colon := strings.IndexByte(r.Action, ':')
	if colon <= 0 || colon == len(r.Action)-1 || strings.Count(r.Action, ":") != 1 {
		return errors.New("IAM action must contain exactly one service:operation separator")
	}
	for _, part := range strings.Split(r.Action, ":") {
		for _, char := range part {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') || char == '-' || char == '*' || char == '?') {
				return fmt.Errorf("IAM action %q contains unsupported syntax", r.Action)
			}
		}
	}
	if !r.ScopeKind.Valid() {
		return fmt.Errorf("unsupported IAM scope %q", r.ScopeKind)
	}
	seenResources := make(map[string]struct{}, len(r.Resources))
	for i, resource := range r.Resources {
		if resource == "" {
			return fmt.Errorf("resource %d is empty", i)
		}
		if _, exists := seenResources[resource]; exists {
			return fmt.Errorf("resource %q is duplicated", resource)
		}
		seenResources[resource] = struct{}{}
	}
	switch r.ScopeKind {
	case ScopeExact:
		if len(r.Resources) != 1 {
			return errors.New("exact IAM scope requires one resource")
		}
	case ScopeSet:
		if len(r.Resources) == 0 {
			return errors.New("set IAM scope requires at least one resource")
		}
	case ScopeKnownGlobal:
		if len(r.Resources) != 1 || r.Resources[0] != "*" {
			return errors.New("known_global IAM scope requires resource *")
		}
	case ScopeUnresolved:
		// Candidate resources may be retained as evidence, but callers must
		// never interpret them as an enforceable scope.
	}
	return nil
}

// MappingConfidence is an explicit enforcement state. Only high confidence
// is eligible for a future policy engine; all other values fail closed.
type MappingConfidence string

const (
	ConfidenceHigh        MappingConfidence = "high"
	ConfidenceMedium      MappingConfidence = "medium"
	ConfidenceLow         MappingConfidence = "low"
	ConfidenceUnknown     MappingConfidence = "unknown"
	ConfidenceUnsupported MappingConfidence = "unsupported"

	High        = ConfidenceHigh
	Medium      = ConfidenceMedium
	Low         = ConfidenceLow
	Unknown     = ConfidenceUnknown
	Unsupported = ConfidenceUnsupported
)

func (c MappingConfidence) Valid() bool {
	switch c {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceUnknown, ConfidenceUnsupported:
		return true
	default:
		return false
	}
}

// MappingEvidence contains non-secret facts used by a mapper. Raw request
// bodies and authentication material do not belong in this type.
type MappingEvidence struct {
	Source string `json:"source"`
	Field  string `json:"field"`
	Value  string `json:"value"`
}

// MappingResult is the complete mapper output. Requirements are a conjunction
// and every one must be approved by the policy engine.
type MappingResult struct {
	Service                  string            `json:"service"`
	Operation                string            `json:"operation"`
	Requirements             []IAMRequirement  `json:"requirements"`
	MapperVersion            string            `json:"mapper_version"`
	IamLiveVersion           string            `json:"iamlive_version,omitempty"`
	AuthorizationDataVersion string            `json:"authorization_data_version,omitempty"`
	Confidence               MappingConfidence `json:"confidence"`
	Evidence                 []MappingEvidence `json:"evidence"`
}

func (m MappingResult) Validate() error {
	if strings.TrimSpace(m.Service) == "" || strings.TrimSpace(m.Operation) == "" {
		return errors.New("mapping service and operation are required")
	}
	if !m.Confidence.Valid() {
		return fmt.Errorf("unsupported mapping confidence %q", m.Confidence)
	}
	if strings.TrimSpace(m.MapperVersion) == "" {
		return errors.New("mapper version is required")
	}
	if len(m.Requirements) == 0 {
		return errors.New("mapping must contain at least one IAM requirement")
	}
	for i, requirement := range m.Requirements {
		if err := requirement.Validate(); err != nil {
			return fmt.Errorf("requirement %d: %w", i, err)
		}
	}
	for i, evidence := range m.Evidence {
		if strings.TrimSpace(evidence.Source) == "" || strings.TrimSpace(evidence.Field) == "" {
			return fmt.Errorf("evidence %d has no source or field", i)
		}
	}
	return nil
}

// DecodedAWSRequest is the fully resolved request after inbound signature
// verification and before IAM mapping. Headers are runtime data and must be
// redacted before any audit serialization.
type DecodedAWSRequest struct {
	Partition       string           `json:"partition"`
	EndpointHost    string           `json:"endpoint_host"`
	Service         string           `json:"service"`
	Region          string           `json:"region"`
	CallerAccountID string           `json:"caller_account_id"`
	Protocol        AWSProtocol      `json:"protocol"`
	Operation       string           `json:"operation"`
	Method          string           `json:"method"`
	CanonicalPath   string           `json:"canonical_path"`
	CanonicalQuery  url.Values       `json:"canonical_query"`
	Headers         http.Header      `json:"headers"`
	Parameters      map[string]Value `json:"parameters"`
	PayloadHashMode PayloadHashMode  `json:"payload_hash_mode"`
	PayloadBytes    int64            `json:"payload_bytes,omitempty"`
}

func (r DecodedAWSRequest) Validate() error {
	if err := validateCallerAccountID(r.CallerAccountID); err != nil {
		return fmt.Errorf("caller account ID: %w", err)
	}
	if strings.TrimSpace(r.Partition) == "" || strings.TrimSpace(r.EndpointHost) == "" || strings.TrimSpace(r.Service) == "" || strings.TrimSpace(r.Operation) == "" {
		return errors.New("decoded request endpoint, service, and operation are required")
	}
	endpoint := AWSEndpoint{Partition: r.Partition, Host: r.EndpointHost, Service: r.Service, Region: r.Region, Global: r.Region == ""}
	if err := endpoint.Validate(); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if !r.Protocol.Supported() {
		return fmt.Errorf("unsupported AWS protocol %q", r.Protocol)
	}
	method := strings.ToUpper(r.Method)
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return fmt.Errorf("unsupported HTTP method %q", r.Method)
	}
	if r.CanonicalPath == "" || r.CanonicalPath[0] != '/' {
		return errors.New("canonical path must be absolute")
	}
	if !r.PayloadHashMode.Valid() {
		return fmt.Errorf("unsupported payload mode %q", r.PayloadHashMode)
	}
	if r.PayloadBytes < 0 {
		return errors.New("payload size cannot be negative")
	}
	for key, value := range r.Parameters {
		if strings.TrimSpace(key) == "" {
			return errors.New("request parameter name is empty")
		}
		if err := value.Validate(); err != nil {
			return fmt.Errorf("parameter %q: %w", key, err)
		}
	}
	return nil
}

// InboundAuthenticator verifies the fake credential/signature at the local
// boundary and rejects unsupported signing schemes.
type InboundAuthenticator interface {
	Verify(ctx context.Context, req *http.Request, endpoint AWSEndpoint) (*VerifiedRequest, error)
}

// AWSRequestDecoder decodes only an authenticated request and fails closed on
// protocol or payload modes it cannot model.
type AWSRequestDecoder interface {
	Decode(ctx context.Context, req *VerifiedRequest, endpoint AWSEndpoint) (*DecodedAWSRequest, error)
}

// IAMMapper maps one decoded request to all mandatory IAM requirements.
type IAMMapper interface {
	Map(ctx context.Context, req *DecodedAWSRequest) (*MappingResult, error)
}
