// Package iamlivecatalog is a neutral, read-only boundary over the selected
// data files in the pinned iamlive revision. It does not authorize requests.
package iamlivecatalog

import "encoding/json"

const UpstreamCommit = "3ec1a40e560c2f00ec82c50223add810e2567efb"

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
	version        string
	sourceHash     string
	services       []Service
	serviceIndex   map[string][]int
	operations     map[string][]Operation
	actions        map[string][]ActionDefinition
	mappings       map[string][]ActionMapping
	permissionless map[string]bool
}

type Service struct {
	Key, ID, EndpointPrefix, SigningName, TargetPrefix, APIVersion string
	Protocols                                                      []string
	Protocol                                                       string
	Aliases                                                        []string
	Operations                                                     []Operation
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

func cloneStrings(in []string) []string { return append([]string(nil), in...) }
func (s Service) Clone() Service {
	s.Protocols = cloneStrings(s.Protocols)
	s.Aliases = cloneStrings(s.Aliases)
	s.Operations = cloneOperations(s.Operations)
	return s
}
func cloneOperations(in []Operation) []Operation {
	out := make([]Operation, len(in))
	for i := range in {
		out[i] = in[i].Clone()
	}
	return out
}
func (o Operation) Clone() Operation {
	o.QueryBindings = append([]QueryBinding(nil), o.QueryBindings...)
	o.Mappings = cloneMappings(o.Mappings)
	return o
}
func cloneMappings(in []ActionMapping) []ActionMapping {
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
