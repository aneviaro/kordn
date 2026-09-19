// Package iamlivecatalog is a neutral, read-only boundary over the selected
// data files in the pinned iamlive revision. It does not authorize requests.
package iamlivecatalog

import "encoding/json"

// UpstreamCommit is the exact iamlive gitlink revision used by this catalog.
const UpstreamCommit = "3ec1a40e560c2f00ec82c50223add810e2567efb"

// CatalogSchemaVersion identifies Kordn's parser/index contract. It changes
// when the neutral catalog representation or validation semantics change.
const CatalogSchemaVersion = "iamlive-catalog-schema/v3"

// EvidenceState makes absent and contradictory upstream evidence observable to
// consumers instead of silently manufacturing a wildcard or a default.
type EvidenceState string

// ValidationCode identifies request-independent catalog evidence failures.
type ValidationCode string

const (
	ValidationMissing       ValidationCode = "missing"
	ValidationContradictory ValidationCode = "contradictory"
	ValidationAmbiguous     ValidationCode = "ambiguous"
	ValidationCyclic        ValidationCode = "cyclic"
	ValidationExtra         ValidationCode = "extra"
	ValidationIncomplete    ValidationCode = "incomplete"
)

type ValidationDiagnostic struct {
	Code          ValidationCode
	Service       string
	Operation     string
	Action        string
	RelatedAction string
	Occurrence    uint32
	RelatedOccur  uint32
	Detail        string
}

type ActionReference struct{ Service, Name string }

type StaticMapping struct {
	Action     ActionReference
	Mapping    ActionMapping
	Definition ActionDefinition
	Dependent  bool
}

func (m StaticMapping) Occurrence() uint32 { return uint32(m.Mapping.occurrenceID) }

type StaticPlan struct {
	Service     string
	Operation   string
	Occurrence  uint32
	Mappings    []StaticMapping
	Diagnostics []ValidationDiagnostic
}

func (p StaticPlan) Clone() StaticPlan {
	p.Mappings = append([]StaticMapping(nil), p.Mappings...)
	for i := range p.Mappings {
		p.Mappings[i].Mapping = p.Mappings[i].Mapping.Clone()
		p.Mappings[i].Definition = p.Mappings[i].Definition.Clone()
	}
	p.Diagnostics = append([]ValidationDiagnostic(nil), p.Diagnostics...)
	return p
}
func (p StaticPlan) Valid() bool { return len(p.Diagnostics) == 0 }

const (
	EvidenceKnown          EvidenceState = "known"
	EvidenceAbsent         EvidenceState = "absent"
	EvidencePermissionless EvidenceState = "permissionless"
	EvidenceUndocumented   EvidenceState = "undocumented"
	EvidenceContradictory  EvidenceState = "contradictory"
)

// Catalog is an immutable publication of the parsed source evidence. Mutable
// public values are reconstructed by the accessors below; the compact stores
// themselves are never exposed to consumers.
type Catalog struct {
	version    string
	sourceHash string
	// store is the sole retained normalized evidence. The fields below are
	// build-only compatibility slots and are cleared before Catalog is
	// published; selectors never read them.
	store                   *compactStore
	services                []Service
	serviceIndex            map[string][]int
	operations              map[string][]indexedOperation
	operationOccurrences    map[string][]operationPosition
	serviceOperationIndexes [][]compactOperationPosition
	plans                   map[occurrenceID]StaticPlan
	// buildActions and buildActionOrder exist only while the parser converts
	// source definitions into compact records; compactEvidence clears them
	// before publication.
	buildActions     map[string][]ActionDefinition
	buildActionOrder []actionPosition
	mappingStore     []ActionMapping
	mappingIndex     map[string][]mappingSpan
	mappingOrder     []mappingPosition
	permissionless   map[string]bool
	strings          []string
	stringIndex      map[string]stringID
	nextEvidenceID   occurrenceID
}

// These bounded IDs are deliberately private: an invalid zero value cannot be
// confused with a source occurrence, and spans are checked while compiling.
type stringID uint32
type occurrenceID uint32
type mappingSpan struct{ start, count uint32 }
type actionPosition struct {
	key   string
	index int
}
type mappingPosition struct {
	storeIndex uint32
	occurrence occurrenceID
	key        string
}

const (
	invalidStringID     stringID     = 0
	invalidOccurrenceID occurrenceID = 0
	maxCatalogItems                  = uint32(^uint32(0) - 1)
)

type wireOperationVisitor func(WireService, WireOperation) error

type indexedOperation struct {
	modelKey                     string
	serviceIndex, operationIndex int
	occurrence                   occurrenceID
}

type compactStore struct {
	strings          []string
	stringBlob       string
	stringOffsets    []uint32
	stringIndex      map[string]stringID
	services         []compactService
	operations       []compactOperation
	serviceOps       [][]compactOperationPosition
	operationIndex   map[string][]compactIndex
	occurrences      map[string][]compactPosition
	mappings         []compactMapping
	mappingIndex     map[string][]mappingSpan
	mappingOrder     []mappingPosition
	actions          []compactAction
	actionIndex      map[string][]compactActionIndex
	actionOrder      []compactActionPosition
	resources        []compactResource
	mappingResources []compactResourceMapping
	dependents       []compactDependent
	conditions       []compactCondition
	mapPairs         []compactMapPair
	queryRecords     []compactQuery
	refs             []stringID
	compactPlans     []compactPlan
}

type compactService struct {
	key, id, endpoint, signing, target, apiVersion, protocol stringID
	protocols, aliases                                       stringSpan
}
type stringSpan struct{ start, count uint32 }
type compactPosition struct {
	operation  int
	occurrence occurrenceID
}
type compactOperationPosition struct {
	operation  int
	occurrence occurrenceID
}
type compactActionPosition struct {
	action     int
	occurrence occurrenceID
}
type compactIndex struct {
	operation  int
	occurrence occurrenceID
}
type compactActionIndex struct {
	action     int
	occurrence occurrenceID
}
type compactOperation struct {
	occurrence                   occurrenceID
	service, name, input, output stringID
	route                        compactRoute
	queries                      stringSpan
	state, mappingState          EvidenceState
	mappings                     []mappingSpan
}
type compactRoute struct {
	method, uri, discriminator, target, jsonVersion stringID
	responseCode                                    int
}
type compactQuery struct {
	member, location stringID
	required         bool
}
type compactMapping struct {
	occurrence             occurrenceID
	action                 stringID
	state                  EvidenceState
	resources              stringSpan
	arn, conditionMappings stringSpan
	condition              int
	arnOverride, notice    stringID
}
type compactResourceMapping struct {
	occurrence          occurrenceID
	parameter, template stringID
	condition           int
}
type compactMapPair struct {
	key, value stringID
	resource   int
}
type compactCondition struct {
	lhs, op, rhs stringID
	and          int
}
type compactAction struct {
	occurrence                         occurrenceID
	service, name, access, description stringID
	resources                          stringSpan
	state                              EvidenceState
}
type compactResource struct {
	occurrence                      occurrenceID
	name                            stringID
	conditionKeys, dependentActions stringSpan
	dependentIDs                    []occurrenceID
	dependents                      stringSpan
}
type compactDependent struct {
	occurrence occurrenceID
	action     stringID
}
type compactStaticMapping struct {
	mapping, action int
	dependent       bool
}
type compactPlan struct {
	mappings    []compactStaticMapping
	diagnostics []ValidationDiagnostic
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
	Plan      StaticPlan
}

type operationPosition struct {
	serviceIndex   int
	operationIndex int
	occurrence     occurrenceID
}

type Operation struct {
	occurrenceID                           occurrenceID
	Service, Name, InputShape, OutputShape string
	Route                                  Route
	QueryBindings                          []QueryBinding
	Mappings                               []ActionMapping
	MappingState                           EvidenceState
	State                                  EvidenceState
	mappingSpans                           []mappingSpan
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
	occurrenceID occurrenceID
	// SourceOrder is intentionally private; occurrenceID is the stable address
	// used by diagnostic selectors and is never reused after normalization.
	Action                string
	State                 EvidenceState
	Resources             []ResourceMapping
	ResourceARNMappings   map[string]string
	Condition             *Condition
	ConditionMappings     map[string]ResourceMapping
	conditionMappingOrder []string
	ARNOverride           string
	Notice                string
}

type ResourceMapping struct {
	occurrenceID        occurrenceID
	Parameter, Template string
	Condition           *Condition
}

type Condition struct {
	LHS, Op, RHS string
	And          *Condition
}

type ActionDefinition struct {
	occurrenceID                            occurrenceID
	Service, Name, AccessLevel, Description string
	Resources                               []ResourceType
	State                                   EvidenceState
}

type ResourceType struct {
	occurrenceID       occurrenceID
	Name               string
	ConditionKeys      []string
	DependentActions   []string
	dependentActionIDs []occurrenceID
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
	o.Plan = o.Plan.Clone()
	return o
}
func (o Operation) Clone() Operation {
	o.QueryBindings = cloneQueryBindings(o.QueryBindings)
	o.Mappings = cloneMappings(o.Mappings)
	o.mappingSpans = nil
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
	m.conditionMappingOrder = nil
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
		a.Resources[i].dependentActionIDs = append([]occurrenceID(nil), a.Resources[i].dependentActionIDs...)
	}
	return a
}
