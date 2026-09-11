package iammap

import (
	"context"
	"errors"
)

// MappingFailureKind identifies the closed set of fail-closed mapping
// outcomes. The zero value is invalid and is never emitted by a Mapper.
type MappingFailureKind uint8

const (
	// MappingFailureUnknownWireOperation means no authenticated wire record was found.
	MappingFailureUnknownWireOperation MappingFailureKind = iota + 1
	// MappingFailureAmbiguousWireOperation means multiple wire records matched.
	MappingFailureAmbiguousWireOperation
	// MappingFailureCatalogInconsistency means immutable catalog evidence disagreed.
	MappingFailureCatalogInconsistency
	// MappingFailureUnresolvedPrimaryResource means a primary resource was not resolvable.
	MappingFailureUnresolvedPrimaryResource
	// MappingFailureUnresolvedDependency means a required dependency was not resolvable.
	MappingFailureUnresolvedDependency
	// MappingFailureLowConfidence means evidence was insufficient for a safe mapping.
	MappingFailureLowConfidence
	// MappingFailureCancellation means the caller cancelled mapping.
	MappingFailureCancellation
	// MappingFailureTimeout means the mapper deadline expired.
	MappingFailureTimeout
	// MappingFailureInvalidResult means the mapper produced an invalid result.
	MappingFailureInvalidResult
	// MappingFailurePanic means owned mapping code panicked.
	MappingFailurePanic
)

// MappingError is a bounded, structured mapping failure. Its Error method does
// not include request data or the text of its cause; the cause is retained only
// for semantic errors.Is/errors.As matching.
type MappingError struct {
	Kind   MappingFailureKind
	Stage  string
	cause  error
	detail string
}

func (k MappingFailureKind) String() string {
	switch k {
	case MappingFailureUnknownWireOperation:
		return "unknown_wire_operation"
	case MappingFailureAmbiguousWireOperation:
		return "ambiguous_wire_operation"
	case MappingFailureCatalogInconsistency:
		return "catalog_inconsistency"
	case MappingFailureUnresolvedPrimaryResource:
		return "unresolved_primary_resource"
	case MappingFailureUnresolvedDependency:
		return "unresolved_dependency"
	case MappingFailureLowConfidence:
		return "low_confidence"
	case MappingFailureCancellation:
		return "cancellation"
	case MappingFailureTimeout:
		return "timeout"
	case MappingFailureInvalidResult:
		return "invalid_result"
	case MappingFailurePanic:
		return "panic"
	default:
		return "invalid"
	}
}

// Error returns a bounded diagnostic containing only closed-set labels.
func (e *MappingError) Error() string {
	if e == nil {
		return "mapping failure"
	}
	if e.Kind == MappingFailureCatalogInconsistency {
		// Preserve the established high-level diagnostic without copying
		// catalog action names or validation details.
		return "mapping catalog: catalog_inconsistency (static catalog validation failed)"
	}
	stage := safeMappingStage(e.Stage)
	message := "mapping " + e.Kind.String()
	if stage != "" {
		message = "mapping " + stage + ": " + e.Kind.String()
	}
	if detail := safeMappingDetail(e.detail); detail != "" {
		message += ": " + detail
	}
	return message
}

func safeMappingStage(stage string) string {
	switch stage {
	case "context", "input", "mapper", "wire", "adapter", "catalog", "resource", "dependency", "result":
		return stage
	default:
		return ""
	}
}

// Unwrap exposes only the semantic cause, never its text, to standard error
// matching. Callers must use errors.Is/errors.As rather than message parsing.
func (e *MappingError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is matches mapping failure sentinels by kind.
func (e *MappingError) Is(target error) bool {
	other, ok := target.(*MappingError)
	return ok && e != nil && other != nil && e.Kind == other.Kind
}

var (
	// ErrUnknownWireOperation matches unknown wire operation failures.
	ErrUnknownWireOperation = &MappingError{Kind: MappingFailureUnknownWireOperation}
	// ErrAmbiguousWireOperation matches ambiguous wire operation failures.
	ErrAmbiguousWireOperation = &MappingError{Kind: MappingFailureAmbiguousWireOperation}
	// ErrCatalogInconsistency matches catalog inconsistency failures.
	ErrCatalogInconsistency = &MappingError{Kind: MappingFailureCatalogInconsistency}
	// ErrUnresolvedPrimaryResource matches unresolved primary resource failures.
	ErrUnresolvedPrimaryResource = &MappingError{Kind: MappingFailureUnresolvedPrimaryResource}
	// ErrUnresolvedDependency matches unresolved dependency failures.
	ErrUnresolvedDependency = &MappingError{Kind: MappingFailureUnresolvedDependency}
	// ErrMappingLowConfidence matches low-confidence failures.
	ErrMappingLowConfidence = &MappingError{Kind: MappingFailureLowConfidence}
	// ErrMappingCancelled matches caller cancellation failures.
	ErrMappingCancelled = &MappingError{Kind: MappingFailureCancellation}
	// ErrMappingTimeout matches mapper deadline failures.
	ErrMappingTimeout = &MappingError{Kind: MappingFailureTimeout}
	// ErrInvalidMappingResult matches invalid result failures.
	ErrInvalidMappingResult = &MappingError{Kind: MappingFailureInvalidResult}
	// ErrMapperPanic matches recovered panic failures.
	ErrMapperPanic = &MappingError{Kind: MappingFailurePanic}
)

func mappingFailure(kind MappingFailureKind, stage string, cause error) error {
	return mappingFailureWithDetail(kind, stage, cause, "")
}

func mappingFailureWithDetail(kind MappingFailureKind, stage string, cause error, detail string) error {
	if kind == 0 {
		kind = MappingFailureLowConfidence
	}
	return &MappingError{Kind: kind, Stage: stage, cause: cause, detail: detail}
}

func safeMappingDetail(detail string) string {
	if len(detail) > 96 {
		return ""
	}
	for _, r := range detail {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != ':' && r != '-' && r != '_' && r != ' ' {
			return ""
		}
	}
	return detail
}

func mappingContextFailure(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return mappingFailure(MappingFailureTimeout, "context", err)
	case errors.Is(err, context.Canceled):
		return mappingFailure(MappingFailureCancellation, "context", err)
	default:
		return nil
	}
}
