// Package iamlivecatalog is a neutral, read-only boundary over the selected
// data files in the pinned iamlive revision. It does not authorize requests.
package iamlivecatalog

import "encoding/json"

// UpstreamCommit is the exact iamlive gitlink revision used by this catalog.
const UpstreamCommit = "3ec1a40e560c2f00ec82c50223add810e2567efb"

// CatalogSchemaVersion identifies Kordn's parser/index contract. It changes
// when the neutral catalog representation or validation semantics change.
const CatalogSchemaVersion = "iamlive-catalog-schema/v2"

// EvidenceState makes absent and contradictory upstream evidence observable to
// consumers instead of silently manufacturing a wildcard or a default.
type EvidenceState string

const (
	EvidenceKnown          EvidenceState = "known"
	EvidenceAbsent         EvidenceState = "absent"
	EvidencePermissionless EvidenceState = "permissionless"
	EvidenceUndocumented   EvidenceState = "undocumented"
	EvidenceContradictory  EvidenceState = "contradictory"
)

type Catalog struct {
	version              string
	sourceHash           string
	services             []Service
	serviceIndex         map[string][]int
	operations           map[string][]indexedOperation
	operationOccurrences map[string][]operationPosition
	wireServices         []WireService
	actions              map[string][]ActionDefinition
	mappings             map[string][]ActionMapping
	permissionless       map[string]bool
}

type indexedOperation struct {
	modelKey  string
	operation Operation
}

type Service struct {
	Key, ID, EndpointPrefix, SigningName, TargetPrefix, APIVersion string
	Protocols                                                      []string
	Protocol                                                       string
	Aliases                                                        []string
	Operations                                                     []Operation
}

// WireService is the catalog's compact, mapping-free representation of one
// API model. Its operation list contains only evidence needed to identify a
// wire request; IAM mappings and definitions are intentionally excluded.
type WireService struct {
	EndpointPrefix, APIVersion, TargetPrefix string
	Protocols                                []string
	Protocol                                 string
	Operations                               []WireOperation
}

// WireOperation is compact wire evidence for one operation occurrence.
type WireOperation struct {
	Name          string
	State         EvidenceState
	Route         Route
	QueryBindings []QueryBinding
}

// OperationOccurrence identifies one concrete service-model operation and
// retains its complete operation evidence for mapping consumers.
type OperationOccurrence struct {
	Service   WireService
	Operation Operation
}

type operationPosition struct {
	serviceIndex   int
	operationIndex int
}

type Operation struct {
	Service, Name, InputShape, OutputShape string
	Route                                  Route
	QueryBindings                          []QueryBinding
	Mappings                               []ActionMapping
	MappingState                           EvidenceState
	State                                  EvidenceState
}

// QueryBinding describes a modeled REST query-string member. Required is
// derived from the input shape's required list, while LocationName is the wire
// name (or the member name when the model omits locationName).
type QueryBinding struct {
	Member, LocationName string
	Required             bool
}

type Route struct {
	Method, URI        string
	ResponseCode       int
	QueryDiscriminator string
	TargetPrefix       string
	JSONVersion        string
}

type ActionMapping struct {
	Action              string
	State               EvidenceState
	Resources           []ResourceMapping
	ResourceARNMappings map[string]string
	Condition           *Condition
	ConditionMappings   map[string]ResourceMapping
	ARNOverride         string
	Notice              string
}

type ResourceMapping struct {
	Parameter, Template string
	Condition           *Condition
}

type Condition struct {
	LHS, Op, RHS string
	And          *Condition
}

type ActionDefinition struct {
	Service, Name, AccessLevel, Description string
	Resources                               []ResourceType
	State                                   EvidenceState
}

type ResourceType struct {
	Name             string
	ConditionKeys    []string
	DependentActions []string
}

// RawMapping is available for diagnostics and preserves upstream fields not
// needed by the neutral index. Callers receive a defensive copy.
type RawMapping map[string]json.RawMessage

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string{}, in...)
}

func cloneQueryBindings(in []QueryBinding) []QueryBinding {
	if in == nil {
		return nil
	}
	return append([]QueryBinding{}, in...)
}

func (s Service) Clone() Service {
	s.Protocols = cloneStrings(s.Protocols)
	s.Aliases = cloneStrings(s.Aliases)
	s.Operations = cloneOperations(s.Operations)
	return s
}
func cloneOperations(in []Operation) []Operation {
	if in == nil {
		return nil
	}
	out := make([]Operation, len(in))
	for i := range in {
		out[i] = in[i].Clone()
	}
	return out
}

func cloneWireOperations(in []WireOperation) []WireOperation {
	if in == nil {
		return nil
	}
	out := make([]WireOperation, len(in))
	for i := range in {
		out[i] = in[i].Clone()
	}
	return out
}

// Clone returns an isolated copy of the wire service and all of its wire
// operation evidence.
func (s WireService) Clone() WireService {
	s.Protocols = cloneStrings(s.Protocols)
	s.Operations = cloneWireOperations(s.Operations)
	return s
}

// Clone returns an isolated copy of the wire operation and its query
// bindings.
func (o WireOperation) Clone() WireOperation {
	o.QueryBindings = cloneQueryBindings(o.QueryBindings)
	return o
}

// Clone returns an isolated copy of the operation occurrence, including its
// complete selected operation evidence.
func (o OperationOccurrence) Clone() OperationOccurrence {
	o.Service = o.Service.Clone()
	o.Operation = o.Operation.Clone()
	return o
}
func (o Operation) Clone() Operation {
	o.QueryBindings = cloneQueryBindings(o.QueryBindings)
	o.Mappings = cloneMappings(o.Mappings)
	return o
}
func cloneMappings(in []ActionMapping) []ActionMapping {
	if in == nil {
		return nil
	}
	out := make([]ActionMapping, len(in))
	for i := range in {
		out[i] = in[i].Clone()
	}
	return out
}
func cloneCondition(in *Condition) *Condition {
	if in == nil {
		return nil
	}
	out := *in
	out.And = cloneCondition(in.And)
	return &out
}

func (m ActionMapping) Clone() ActionMapping {
	m.Resources = append([]ResourceMapping(nil), m.Resources...)
	for i := range m.Resources {
		m.Resources[i].Condition = cloneCondition(m.Resources[i].Condition)
	}
	if m.ResourceARNMappings != nil {
		x := map[string]string{}
		for k, v := range m.ResourceARNMappings {
			x[k] = v
		}
		m.ResourceARNMappings = x
	}
	if m.ConditionMappings != nil {
		x := map[string]ResourceMapping{}
		for k, v := range m.ConditionMappings {
			v.Condition = cloneCondition(v.Condition)
			x[k] = v
		}
		m.ConditionMappings = x
	}
	m.Condition = cloneCondition(m.Condition)
	return m
}
func cloneActionDefinitions(in []ActionDefinition) []ActionDefinition {
	out := make([]ActionDefinition, len(in))
	for i := range in {
		out[i] = in[i].Clone()
	}
	return out
}

func (a ActionDefinition) Clone() ActionDefinition {
	a.Resources = append([]ResourceType(nil), a.Resources...)
	for i := range a.Resources {
		a.Resources[i].ConditionKeys = cloneStrings(a.Resources[i].ConditionKeys)
		a.Resources[i].DependentActions = cloneStrings(a.Resources[i].DependentActions)
	}
	return a
}
