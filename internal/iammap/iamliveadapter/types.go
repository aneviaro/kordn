package iamliveadapter

import (
	"context"
	"net/url"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

// WireIdentity is the authenticated wire identity used to select an API
// model occurrence. It deliberately contains no request body or credentials.
type WireIdentity struct {
	Protocol awsrequest.AWSProtocol
	Method   string
	Path     string
	Query    url.Values
	Target   string
}

// Applicability is the request-time state of one dependency occurrence. The
// zero value is Unknown, which is intentionally fail-closed.
type Applicability uint8

const (
	ApplicabilityUnknown Applicability = iota
	ApplicabilityInapplicable
	ApplicabilityApplicable
)

// PrimaryOccurrence is one immutable, occurrence-bound primary mapping. The
// mapping and definition are copied from the compiled plan; callers must not
// mutate a published plan through this value.
type PrimaryOccurrence struct {
	ID                     uint32
	OperationID            uint32
	DefinitionID           uint32
	Operation              string
	Action                 Action
	Mapping                iamlivecatalog.ActionMapping
	Definition             iamlivecatalog.ActionDefinition
	ResourceType           string
	ResourceTypeOccurrence uint32
	Scope                  string
	DefinitionDependencies []string
}

// DependencyOccurrence binds request-evaluated values to one mapping and one
// definition edge. Inapplicable occurrences remain present in the result.
type DependencyOccurrence struct {
	ID               uint32
	OperationID      uint32
	DefinitionID     uint32
	DefinitionEdgeID uint32
	MappingID        uint32
	Action           Action
	Resources        []string
	ParameterNames   []string
	Applicability    Applicability
}

// LookupResult is the typed output of wire resolution, compiled-plan
// selection, and request-dependent evaluation. Each evidence item occurs once
// and is bound to its source occurrence IDs.
type LookupResult struct {
	Operation             string
	PrimaryOccurrences    []PrimaryOccurrence
	DependencyOccurrences []DependencyOccurrence
}

// WireLookup is the consumer-owned, context-aware wire/plan contract used by
// the mapper. Implementations return immutable evidence values.
type WireLookup interface {
	LookupRequestContext(context.Context, string, string, WireIdentity, map[string]awsrequest.Value) (LookupResult, error)
}

func (p PrimaryOccurrence) clone() PrimaryOccurrence {
	p.Mapping = p.Mapping.Clone()
	p.Definition = p.Definition.Clone()
	p.DefinitionDependencies = append([]string(nil), p.DefinitionDependencies...)
	return p
}

func (d DependencyOccurrence) clone() DependencyOccurrence {
	d.Resources = append([]string(nil), d.Resources...)
	d.ParameterNames = append([]string(nil), d.ParameterNames...)
	return d
}

// Clone returns mutable-boundary copies while preserving occurrence order and
// multiplicity.
func (r LookupResult) Clone() LookupResult {
	r.PrimaryOccurrences = append([]PrimaryOccurrence(nil), r.PrimaryOccurrences...)
	for i := range r.PrimaryOccurrences {
		r.PrimaryOccurrences[i] = r.PrimaryOccurrences[i].clone()
	}
	r.DependencyOccurrences = append([]DependencyOccurrence(nil), r.DependencyOccurrences...)
	for i := range r.DependencyOccurrences {
		r.DependencyOccurrences[i] = r.DependencyOccurrences[i].clone()
	}
	return r
}
