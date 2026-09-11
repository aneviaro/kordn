package iamlivecatalog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// CatalogVersion identifies the parsed catalog implementation and upstream
// gitlink revision. The selected-content digest is exposed by Catalog.SourceHash.
const CatalogVersion = "iamlive-catalog/v2@" + UpstreamCommit
const catalogVersion = CatalogVersion
const expectedSourceHash = "43e605716ea0ccdaeb625bad52088deece0204ad38e4b6e461e6792a1dd00869"
const maxJSONBytes = 64 << 20

var (
	defaultOnce    sync.Once
	defaultCatalog *Catalog
	defaultErr     error
)

// Load parses the embedded upstream files once and returns a catalog whose
// exported values are defensive copies. It performs no filesystem or network IO.
func Load() (*Catalog, error) {
	defaultOnce.Do(func() { defaultCatalog, defaultErr = parse() })
	return defaultCatalog, defaultErr
}
func Default() (*Catalog, error) { return Load() }
func Version() string            { return catalogVersion }

// SchemaVersion returns the neutral catalog schema implementation version.
func SchemaVersion() string { return CatalogSchemaVersion }

// SchemaVersion returns the neutral catalog representation contract used by
// this catalog, independent of the upstream map schema.
func (c *Catalog) SchemaVersion() string {
	if c == nil {
		return ""
	}
	return CatalogSchemaVersion
}

func (c *Catalog) Version() string {
	if c == nil {
		return ""
	}
	return c.version
}
func (c *Catalog) SourceHash() string {
	if c == nil {
		return ""
	}
	return c.sourceHash
}
func validStringID(s *compactStore, id stringID) bool {
	return id != invalidStringID && uint64(id) < uint64(len(s.strings))
}
func compactString(s *compactStore, id stringID) (string, bool) {
	if id == invalidStringID {
		return "", true
	}
	if !validStringID(s, id) {
		return "", false
	}
	return s.strings[id], true
}
func validSpan(span stringSpan, length int) bool {
	return uint64(span.start)+uint64(span.count) <= uint64(length)
}
func (c *Catalog) compactCondition(index int) (*Condition, bool) {
	if index == -1 {
		return nil, true
	}
	if index < -1 {
		return nil, false
	}
	s := c.store
	if index >= len(s.conditions) {
		return nil, false
	}
	seen := map[int]bool{}
	var walk func(int) (*Condition, bool)
	walk = func(i int) (*Condition, bool) {
		if i < 0 {
			return nil, true
		}
		if i >= len(s.conditions) || seen[i] {
			return nil, false
		}
		seen[i] = true
		r := s.conditions[i]
		lhs, ok := compactString(s, r.lhs)
		if !ok {
			return nil, false
		}
		op, ok := compactString(s, r.op)
		if !ok {
			return nil, false
		}
		rhs, ok := compactString(s, r.rhs)
		if !ok {
			return nil, false
		}
		and, ok := walk(r.and)
		if !ok {
			return nil, false
		}
		return &Condition{LHS: lhs, Op: op, RHS: rhs, And: and}, true
	}
	return walk(index)
}
func (c *Catalog) compactMapping(index int) (ActionMapping, bool) {
	s := c.store
	if index < 0 || index >= len(s.mappings) {
		return ActionMapping{}, false
	}
	m := s.mappings[index]
	if m.occurrence == invalidOccurrenceID {
		return ActionMapping{}, false
	}
	action, ok := compactString(s, m.action)
	if !ok {
		return ActionMapping{}, false
	}
	override, ok := compactString(s, m.arnOverride)
	if !ok {
		return ActionMapping{}, false
	}
	notice, ok := compactString(s, m.notice)
	if !ok || !validSpan(m.resources, len(s.mappingResources)) || !validSpan(m.arn, len(s.mapPairs)) || !validSpan(m.conditionMappings, len(s.mapPairs)) {
		return ActionMapping{}, false
	}
	out := ActionMapping{occurrenceID: m.occurrence, Action: action, State: m.state, ARNOverride: override, Notice: notice, ResourceARNMappings: map[string]string{}, ConditionMappings: map[string]ResourceMapping{}}
	if condition, ok := c.compactCondition(m.condition); !ok {
		return ActionMapping{}, false
	} else {
		out.Condition = condition
	}
	for i := uint32(0); i < m.resources.count; i++ {
		r := s.mappingResources[m.resources.start+i]
		p, ok := compactString(s, r.parameter)
		if !ok {
			return ActionMapping{}, false
		}
		t, ok := compactString(s, r.template)
		if !ok || r.occurrence == invalidOccurrenceID {
			return ActionMapping{}, false
		}
		condition, ok := c.compactCondition(r.condition)
		if !ok {
			return ActionMapping{}, false
		}
		out.Resources = append(out.Resources, ResourceMapping{occurrenceID: r.occurrence, Parameter: p, Template: t, Condition: condition})
	}
	for i := uint32(0); i < m.arn.count; i++ {
		p := s.mapPairs[m.arn.start+i]
		k, ok := compactString(s, p.key)
		if !ok || p.resource != -1 {
			return ActionMapping{}, false
		}
		v, ok := compactString(s, p.value)
		if !ok {
			return ActionMapping{}, false
		}
		if out.ResourceARNMappings == nil {
			out.ResourceARNMappings = map[string]string{}
		}
		out.ResourceARNMappings[k] = v
	}
	for i := uint32(0); i < m.conditionMappings.count; i++ {
		p := s.mapPairs[m.conditionMappings.start+i]
		k, ok := compactString(s, p.key)
		if !ok || p.value != invalidStringID || p.resource < 0 || p.resource >= len(s.mappingResources) {
			return ActionMapping{}, false
		}
		r := s.mappingResources[p.resource]
		parameter, ok := compactString(s, r.parameter)
		if !ok {
			return ActionMapping{}, false
		}
		template, ok := compactString(s, r.template)
		if !ok || r.occurrence == invalidOccurrenceID {
			return ActionMapping{}, false
		}
		condition, ok := c.compactCondition(r.condition)
		if !ok {
			return ActionMapping{}, false
		}
		if out.ConditionMappings == nil {
			out.ConditionMappings = map[string]ResourceMapping{}
		}
		out.ConditionMappings[k] = ResourceMapping{occurrenceID: r.occurrence, Parameter: parameter, Template: template, Condition: condition}
		out.conditionMappingOrder = append(out.conditionMappingOrder, k)
	}
	return out, true
}
func (c *Catalog) compactView(index int) (Operation, bool) {
	if c == nil || c.store == nil || index < 0 || index >= len(c.store.operations) {
		return Operation{}, false
	}
	s := c.store
	r := s.operations[index]
	if r.occurrence == invalidOccurrenceID {
		return Operation{}, false
	}
	service, ok := compactString(s, r.service)
	if !ok {
		return Operation{}, false
	}
	name, ok := compactString(s, r.name)
	if !ok {
		return Operation{}, false
	}
	input, ok := compactString(s, r.input)
	if !ok {
		return Operation{}, false
	}
	output, ok := compactString(s, r.output)
	if !ok {
		return Operation{}, false
	}
	method, ok := compactString(s, r.route.method)
	if !ok {
		return Operation{}, false
	}
	uri, ok := compactString(s, r.route.uri)
	if !ok {
		return Operation{}, false
	}
	discriminator, ok := compactString(s, r.route.discriminator)
	if !ok {
		return Operation{}, false
	}
	target, ok := compactString(s, r.route.target)
	if !ok {
		return Operation{}, false
	}
	version, ok := compactString(s, r.route.jsonVersion)
	if !ok || !validSpan(r.queries, len(s.queryRecords)) {
		return Operation{}, false
	}
	out := Operation{occurrenceID: r.occurrence, Service: service, Name: name, InputShape: input, OutputShape: output, Route: Route{Method: method, URI: uri, ResponseCode: r.route.responseCode, QueryDiscriminator: discriminator, TargetPrefix: target, JSONVersion: version}, MappingState: r.mappingState, State: r.state}
	for i := uint32(0); i < r.queries.count; i++ {
		q := s.queryRecords[r.queries.start+i]
		member, good := compactString(s, q.member)
		if !good {
			return Operation{}, false
		}
		location, good := compactString(s, q.location)
		if !good {
			return Operation{}, false
		}
		out.QueryBindings = append(out.QueryBindings, QueryBinding{Member: member, LocationName: location, Required: q.required})
	}
	for _, span := range r.mappings {
		if !validMappingSpan(span, len(s.mappings)) {
			return Operation{}, false
		}
		for i := uint32(0); i < span.count; i++ {
			mapping, good := c.compactMapping(int(span.start + i))
			if !good {
				return Operation{}, false
			}
			out.Mappings = append(out.Mappings, mapping)
		}
	}
	return out, true
}

func (c *Catalog) compactService(index int) (Service, bool) {
	if c == nil || c.store == nil || index < 0 || index >= len(c.store.services) {
		return Service{}, false
	}
	s := c.store
	r := s.services[index]
	key, ok := compactString(s, r.key)
	if !ok {
		return Service{}, false
	}
	id, ok := compactString(s, r.id)
	if !ok {
		return Service{}, false
	}
	endpoint, ok := compactString(s, r.endpoint)
	if !ok {
		return Service{}, false
	}
	signing, ok := compactString(s, r.signing)
	if !ok {
		return Service{}, false
	}
	target, ok := compactString(s, r.target)
	if !ok {
		return Service{}, false
	}
	version, ok := compactString(s, r.apiVersion)
	if !ok {
		return Service{}, false
	}
	protocol, ok := compactString(s, r.protocol)
	if !ok || !validSpan(r.protocols, len(s.refs)) || !validSpan(r.aliases, len(s.refs)) || index >= len(s.serviceOps) {
		return Service{}, false
	}
	out := Service{Key: key, ID: id, EndpointPrefix: endpoint, SigningName: signing, TargetPrefix: target, APIVersion: version, Protocol: protocol}
	for i := uint32(0); i < r.protocols.count; i++ {
		value, good := compactString(s, s.refs[r.protocols.start+i])
		if !good {
			return Service{}, false
		}
		out.Protocols = append(out.Protocols, value)
	}
	for i := uint32(0); i < r.aliases.count; i++ {
		value, good := compactString(s, s.refs[r.aliases.start+i])
		if !good {
			return Service{}, false
		}
		out.Aliases = append(out.Aliases, value)
	}
	for _, op := range s.serviceOps[index] {
		if op.occurrence == invalidOccurrenceID || op.operation < 0 || op.operation >= len(s.operations) || s.operations[op.operation].occurrence != op.occurrence {
			return Service{}, false
		}
		view, good := c.compactView(op.operation)
		if !good || view.Service != endpoint {
			return Service{}, false
		}
		out.Operations = append(out.Operations, view)
	}
	return out, true
}

func (c *Catalog) compactWireService(index int) (WireService, bool) {
	if c == nil || c.store == nil || index < 0 || index >= len(c.store.services) {
		return WireService{}, false
	}
	r := c.store.services[index]
	endpoint, ok := compactString(c.store, r.endpoint)
	if !ok {
		return WireService{}, false
	}
	version, ok := compactString(c.store, r.apiVersion)
	if !ok {
		return WireService{}, false
	}
	target, ok := compactString(c.store, r.target)
	if !ok {
		return WireService{}, false
	}
	protocol, ok := compactString(c.store, r.protocol)
	if !ok || !validSpan(r.protocols, len(c.store.refs)) || index >= len(c.store.serviceOps) {
		return WireService{}, false
	}
	out := WireService{EndpointPrefix: endpoint, APIVersion: version, TargetPrefix: target, Protocol: protocol}
	for i := uint32(0); i < r.protocols.count; i++ {
		value, good := compactString(c.store, c.store.refs[r.protocols.start+i])
		if !good {
			return WireService{}, false
		}
		out.Protocols = append(out.Protocols, value)
	}
	return out, true
}

// ForEachOperationOccurrence visits each operation with its wire service and
// prevalidated static plan in one bounded pass over immutable indexes.
func (c *Catalog) ForEachOperationOccurrence(fn func(OperationOccurrence) error) error {
	if c == nil || c.store == nil {
		return errors.New("catalog unavailable")
	}
	if fn == nil {
		return errors.New("operation occurrence visitor is nil")
	}
	for serviceIndex := range c.store.serviceOps {
		service, ok := c.compactWireService(serviceIndex)
		if !ok {
			return errors.New("catalog service index is corrupt")
		}
		for _, position := range c.store.serviceOps[serviceIndex] {
			if position.operation < 0 || position.operation >= len(c.store.operations) || c.store.operations[position.operation].occurrence != position.occurrence {
				return errors.New("catalog operation index is corrupt")
			}
			operation, ok := c.compactView(position.operation)
			if !ok {
				return errors.New("catalog operation canonical record is corrupt")
			}
			plan, ok := c.staticPlan(operation.occurrenceID)
			if !ok {
				return errors.New("catalog static plan index is corrupt")
			}
			if operation.Service != service.EndpointPrefix {
				return errors.New("catalog operation service index is corrupt")
			}
			if err := fn(OperationOccurrence{Service: service.Clone(), Operation: operation, Plan: plan}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Catalog) Services() []Service {
	if c == nil || c.store == nil {
		return nil
	}
	out := make([]Service, 0, len(c.store.services))
	for i := range c.store.services {
		service, ok := c.compactService(i)
		if !ok {
			return nil
		}
		out = append(out, service)
	}
	return out
}
func (c *Catalog) WireServices() []WireService {
	if c == nil || c.store == nil {
		return nil
	}
	out := make([]WireService, 0, len(c.store.services))
	for i := range c.store.services {
		service, ok := c.compactService(i)
		if !ok {
			return nil
		}
		wire := WireService{EndpointPrefix: service.EndpointPrefix, APIVersion: service.APIVersion, TargetPrefix: service.TargetPrefix, Protocols: cloneStrings(service.Protocols), Protocol: service.Protocol}
		for _, operation := range service.Operations {
			wire.Operations = append(wire.Operations, WireOperation{Name: operation.Name, State: operation.State, Route: operation.Route, QueryBindings: cloneQueryBindings(operation.QueryBindings)})
		}
		out = append(out, wire)
	}
	return out
}
func (c *Catalog) ForEachWireOperation(fn func(WireService, WireOperation) error) error {
	if c == nil || c.store == nil {
		return errors.New("catalog unavailable")
	}
	if fn == nil {
		return errors.New("wire operation visitor is nil")
	}
	for i := range c.store.services {
		service, ok := c.compactService(i)
		if !ok {
			return errors.New("catalog canonical service is corrupt")
		}
		wire := WireService{EndpointPrefix: service.EndpointPrefix, APIVersion: service.APIVersion, TargetPrefix: service.TargetPrefix, Protocols: cloneStrings(service.Protocols), Protocol: service.Protocol}
		for _, operation := range service.Operations {
			if err := fn(wire.Clone(), WireOperation{Name: operation.Name, State: operation.State, Route: operation.Route, QueryBindings: cloneQueryBindings(operation.QueryBindings)}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (c *Catalog) OperationOccurrences(service, operation string) []OperationOccurrence {
	if c == nil || c.store == nil {
		return nil
	}
	positions := c.store.occurrences[operationKey(service, operation)]
	out := make([]OperationOccurrence, 0, len(positions))
	for _, p := range positions {
		if p.operation < 0 || p.operation >= len(c.store.operations) {
			return nil
		}
		record := c.store.operations[p.operation]
		if record.occurrence != p.occurrence {
			return nil
		}
		view, ok := c.compactView(p.operation)
		if !ok {
			return nil
		}
		serviceIndex := -1
		for i, indexes := range c.store.serviceOps {
			for _, index := range indexes {
				if index.operation == p.operation && index.occurrence == p.occurrence {
					serviceIndex = i
					break
				}
			}
			if serviceIndex >= 0 {
				break
			}
		}
		serviceView, ok := c.compactService(serviceIndex)
		if !ok {
			return nil
		}
		plan, ok := c.staticPlan(view.occurrenceID)
		if !ok {
			return nil
		}
		out = append(out, OperationOccurrence{Service: WireService{EndpointPrefix: serviceView.EndpointPrefix, APIVersion: serviceView.APIVersion, TargetPrefix: serviceView.TargetPrefix, Protocols: cloneStrings(serviceView.Protocols), Protocol: serviceView.Protocol}, Operation: view, Plan: plan})
	}
	return out
}
func (c *Catalog) Service(name string) (Service, error) {
	if c == nil || c.store == nil {
		return Service{}, errors.New("catalog unavailable")
	}
	indexes := c.storeServiceIndex(name)
	if len(indexes) != 1 {
		if len(indexes) == 0 {
			return Service{}, fmt.Errorf("unknown service %q", name)
		}
		return Service{}, fmt.Errorf("ambiguous service %q", name)
	}
	result, ok := c.compactService(indexes[0])
	if !ok {
		return Service{}, errors.New("catalog service canonical record is corrupt")
	}
	return result, nil
}
func (c *Catalog) storeServiceIndex(name string) []int {
	if c == nil || c.store == nil {
		return nil
	}
	normalized := strings.ToLower(strings.TrimSpace(name))
	var out []int
	for i, service := range c.store.services {
		if !validSpan(service.aliases, len(c.store.refs)) {
			return nil
		}
		for j := uint32(0); j < service.aliases.count; j++ {
			value, ok := compactString(c.store, c.store.refs[service.aliases.start+j])
			if !ok {
				return nil
			}
			if strings.ToLower(value) == normalized {
				out = append(out, i)
				break
			}
		}
	}
	return out
}
func (c *Catalog) Operations() []Operation {
	if c == nil || c.store == nil {
		return nil
	}
	out := make([]Operation, 0, len(c.store.operations))
	for i := range c.store.operations {
		operation, ok := c.compactView(i)
		if !ok {
			return nil
		}
		out = append(out, operation)
	}
	return out
}

func operationKey(service, operation string) string {
	return strings.ToLower(strings.TrimSpace(service)) + "\x00" + strings.ToLower(strings.TrimSpace(operation))
}
func (c *Catalog) Operation(service, operation string) (Operation, error) {
	if c == nil || c.store == nil {
		return Operation{}, errors.New("catalog unavailable")
	}
	indexes := c.store.operationIndex[operationKey(service, operation)]
	if len(indexes) != 1 {
		if len(indexes) == 0 {
			return Operation{}, fmt.Errorf("unknown operation %s:%s", service, operation)
		}
		return Operation{}, fmt.Errorf("ambiguous operation %s:%s", service, operation)
	}
	if indexes[0].occurrence == invalidOccurrenceID || indexes[0].operation < 0 || indexes[0].operation >= len(c.store.operations) || c.store.operations[indexes[0].operation].occurrence != indexes[0].occurrence {
		return Operation{}, errors.New("catalog operation index is corrupt")
	}
	view, ok := c.compactView(indexes[0].operation)
	if !ok {
		return Operation{}, errors.New("catalog operation index is corrupt")
	}
	return view, nil
}
func validActionPosition(s *compactStore, position compactActionPosition) bool {
	return position.occurrence != invalidOccurrenceID && position.action >= 0 && position.action < len(s.actions) && s.actions[position.action].occurrence == position.occurrence
}

func (c *Catalog) compactAction(index int) (ActionDefinition, bool) {
	if c == nil || c.store == nil || index < 0 || index >= len(c.store.actions) {
		return ActionDefinition{}, false
	}
	s := c.store
	r := s.actions[index]
	if r.occurrence == invalidOccurrenceID || !validSpan(r.resources, len(s.resources)) {
		return ActionDefinition{}, false
	}
	service, ok := compactString(s, r.service)
	if !ok {
		return ActionDefinition{}, false
	}
	name, ok := compactString(s, r.name)
	if !ok {
		return ActionDefinition{}, false
	}
	access, ok := compactString(s, r.access)
	if !ok {
		return ActionDefinition{}, false
	}
	description, ok := compactString(s, r.description)
	if !ok {
		return ActionDefinition{}, false
	}
	out := ActionDefinition{occurrenceID: r.occurrence, Service: service, Name: name, AccessLevel: access, Description: description, State: r.state}
	for i := uint32(0); i < r.resources.count; i++ {
		resource := s.resources[r.resources.start+i]
		if resource.occurrence == invalidOccurrenceID || !validSpan(resource.conditionKeys, len(s.refs)) || !validSpan(resource.dependentActions, len(s.refs)) || !validSpan(resource.dependents, len(s.dependents)) || len(resource.dependentIDs) != int(resource.dependentActions.count) || resource.dependents.count != resource.dependentActions.count {
			return ActionDefinition{}, false
		}
		name, good := compactString(s, resource.name)
		if !good {
			return ActionDefinition{}, false
		}
		view := ResourceType{occurrenceID: resource.occurrence, Name: name}
		for j := uint32(0); j < resource.conditionKeys.count; j++ {
			value, good := compactString(s, s.refs[resource.conditionKeys.start+j])
			if !good {
				return ActionDefinition{}, false
			}
			view.ConditionKeys = append(view.ConditionKeys, value)
		}
		for j := uint32(0); j < resource.dependentActions.count; j++ {
			value, good := compactString(s, s.refs[resource.dependentActions.start+j])
			dependency := s.dependents[resource.dependents.start+j]
			dependencyValue, dependencyGood := compactString(s, dependency.action)
			if !good || !dependencyGood || resource.dependentIDs[j] == invalidOccurrenceID || dependency.occurrence != resource.dependentIDs[j] || dependencyValue != value {
				return ActionDefinition{}, false
			}
			view.DependentActions = append(view.DependentActions, value)
			view.dependentActionIDs = append(view.dependentActionIDs, resource.dependentIDs[j])
		}
		out.Resources = append(out.Resources, view)
	}
	return out, true
}
func (c *Catalog) Actions() []ActionDefinition {
	if c == nil || c.store == nil {
		return nil
	}
	out := make([]ActionDefinition, 0, len(c.store.actionOrder))
	for _, position := range c.store.actionOrder {
		if !validActionPosition(c.store, position) {
			return nil
		}
		view, ok := c.compactAction(position.action)
		if !ok {
			return nil
		}
		out = append(out, view)
	}
	return out
}
func (c *Catalog) Action(action string) (ActionDefinition, error) {
	if c == nil || c.store == nil {
		return ActionDefinition{}, errors.New("catalog unavailable")
	}
	p := strings.SplitN(action, ":", 2)
	if len(p) != 2 {
		return ActionDefinition{}, fmt.Errorf("malformed action %q", action)
	}
	key := strings.ToLower(p[0]) + "\x00" + strings.ToLower(p[1])
	indexes := c.store.actionIndex[key]
	if len(indexes) == 0 {
		return ActionDefinition{}, fmt.Errorf("unknown action %q", action)
	}
	if len(indexes) != 1 {
		return ActionDefinition{}, fmt.Errorf("contradictory action evidence %q", action)
	}
	if indexes[0].occurrence == invalidOccurrenceID || indexes[0].action < 0 || indexes[0].action >= len(c.store.actions) || c.store.actions[indexes[0].action].occurrence != indexes[0].occurrence {
		return ActionDefinition{}, errors.New("catalog action index is corrupt")
	}
	view, ok := c.compactAction(indexes[0].action)
	if !ok || view.State == EvidenceContradictory {
		return ActionDefinition{}, fmt.Errorf("contradictory action evidence %q", action)
	}
	return view, nil
}

func (c *Catalog) OperationCardinality(service, operation string) int {
	if c == nil || c.store == nil {
		return 0
	}
	positions := c.store.occurrences[operationKey(service, operation)]
	for _, position := range positions {
		if position.occurrence == invalidOccurrenceID || position.operation < 0 || position.operation >= len(c.store.operations) || c.store.operations[position.operation].occurrence != position.occurrence {
			return 0
		}
	}
	return len(positions)
}
func (c *Catalog) InternedStringCardinality() int {
	if c == nil || c.store == nil {
		return 0
	}
	return len(c.store.strings) - 1
}
func (c *Catalog) MappingOccurrenceCardinality() int {
	if c == nil || c.store == nil {
		return 0
	}
	for _, mapping := range c.store.mappings {
		if mapping.occurrence == invalidOccurrenceID {
			return 0
		}
	}
	return len(c.store.mappings)
}
func (c *Catalog) compactMappingList(indices []int) ([]ActionMapping, bool) {
	out := make([]ActionMapping, 0, len(indices))
	for _, index := range indices {
		m, ok := c.compactMapping(index)
		if !ok {
			return nil, false
		}
		out = append(out, m)
	}
	return out, true
}
func (c *Catalog) MappingOccurrences(service, operation string) []ActionMapping {
	if c == nil || c.store == nil {
		return nil
	}
	var indexes []int
	for _, span := range c.store.mappingIndex[operationKey(service, operation)] {
		if !validMappingSpan(span, len(c.store.mappings)) {
			return nil
		}
		for i := uint32(0); i < span.count; i++ {
			indexes = append(indexes, int(span.start+i))
		}
	}
	out, ok := c.compactMappingList(indexes)
	if !ok {
		return nil
	}
	return out
}
func (c *Catalog) AllMappingOccurrences() []ActionMapping {
	if c == nil || c.store == nil {
		return nil
	}
	out := make([]ActionMapping, 0, len(c.store.mappingOrder))
	for _, position := range c.store.mappingOrder {
		if uint64(position.storeIndex) >= uint64(len(c.store.mappings)) {
			return nil
		}
		m := c.store.mappings[position.storeIndex]
		if m.occurrence != position.occurrence {
			return nil
		}
		view, ok := c.compactMapping(int(position.storeIndex))
		if !ok {
			return nil
		}
		out = append(out, view)
	}
	return out
}
func (c *Catalog) ActionDefinitionOccurrences(action string) []ActionDefinition {
	if c == nil || c.store == nil {
		return nil
	}
	p := strings.SplitN(action, ":", 2)
	if len(p) != 2 {
		return nil
	}
	indexes := c.store.actionIndex[strings.ToLower(p[0])+"\x00"+strings.ToLower(p[1])]
	out := make([]ActionDefinition, 0, len(indexes))
	for _, position := range indexes {
		if position.occurrence == invalidOccurrenceID || position.action < 0 || position.action >= len(c.store.actions) || c.store.actions[position.action].occurrence != position.occurrence {
			return nil
		}
		view, ok := c.compactAction(position.action)
		if !ok {
			return nil
		}
		out = append(out, view)
	}
	return out
}
func (c *Catalog) ResourceTypeOccurrences(action string) []ResourceType {
	var out []ResourceType
	for _, definition := range c.ActionDefinitionOccurrences(action) {
		out = append(out, definition.Resources...)
	}
	return out
}
func (c *Catalog) DependentActionOccurrences(action string) []string {
	var out []string
	for _, resource := range c.ResourceTypeOccurrences(action) {
		out = append(out, resource.DependentActions...)
	}
	return out
}
func (c *Catalog) ForEachOperation(fn func(string, Operation) error) error {
	if c == nil || c.store == nil {
		return errors.New("catalog unavailable")
	}
	if fn == nil {
		return errors.New("operation visitor is nil")
	}
	for i, service := range c.store.services {
		endpoint, ok := compactString(c.store, service.endpoint)
		if !ok || i >= len(c.store.serviceOps) {
			return errors.New("catalog operation index is corrupt")
		}
		for _, index := range c.store.serviceOps[i] {
			if index.occurrence == invalidOccurrenceID || index.operation < 0 || index.operation >= len(c.store.operations) || c.store.operations[index.operation].occurrence != index.occurrence {
				return errors.New("catalog operation index is corrupt")
			}
			operation, good := c.compactView(index.operation)
			if !good || operation.Service != endpoint {
				return errors.New("catalog operation canonical record is corrupt")
			}
			if err := fn(endpoint, operation); err != nil {
				return err
			}
		}
	}
	return nil
}
func (c *Catalog) ForEachMappingOccurrence(fn func(ActionMapping) error) error {
	if c == nil || c.store == nil {
		return errors.New("catalog unavailable")
	}
	if fn == nil {
		return errors.New("mapping visitor is nil")
	}
	for _, position := range c.store.mappingOrder {
		if uint64(position.storeIndex) >= uint64(len(c.store.mappings)) || c.store.mappings[position.storeIndex].occurrence != position.occurrence {
			return errors.New("catalog mapping occurrence index is corrupt")
		}
		view, ok := c.compactMapping(int(position.storeIndex))
		if !ok {
			return errors.New("catalog mapping occurrence is corrupt")
		}
		if err := fn(view); err != nil {
			return err
		}
	}
	return nil
}
func (c *Catalog) ForEachActionDefinitionOccurrence(fn func(ActionDefinition) error) error {
	if c == nil || c.store == nil {
		return errors.New("catalog unavailable")
	}
	if fn == nil {
		return errors.New("action visitor is nil")
	}
	for _, position := range c.store.actionOrder {
		if !validActionPosition(c.store, position) {
			return errors.New("catalog action occurrence is corrupt")
		}
		view, ok := c.compactAction(position.action)
		if !ok {
			return errors.New("catalog action occurrence is corrupt")
		}
		if err := fn(view); err != nil {
			return err
		}
	}
	return nil
}
func (c *Catalog) ForEachResourceTypeOccurrence(fn func(ResourceType) error) error {
	if c == nil || c.store == nil {
		return errors.New("catalog unavailable")
	}
	if fn == nil {
		return errors.New("resource visitor is nil")
	}
	for _, position := range c.store.actionOrder {
		if !validActionPosition(c.store, position) {
			return errors.New("catalog resource occurrence is corrupt")
		}
		action, ok := c.compactAction(position.action)
		if !ok {
			return errors.New("catalog resource occurrence is corrupt")
		}
		for _, resource := range action.Resources {
			if err := fn(resource); err != nil {
				return err
			}
		}
	}
	return nil
}
func (c *Catalog) ForEachDependentActionOccurrence(fn func(string) error) error {
	if c == nil || c.store == nil {
		return errors.New("catalog unavailable")
	}
	if fn == nil {
		return errors.New("dependent visitor is nil")
	}
	for _, position := range c.store.actionOrder {
		if !validActionPosition(c.store, position) {
			return errors.New("catalog dependent occurrence is corrupt")
		}
		action, ok := c.compactAction(position.action)
		if !ok {
			return errors.New("catalog dependent occurrence is corrupt")
		}
		for _, resource := range action.Resources {
			for _, dependency := range resource.DependentActions {
				if err := fn(dependency); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// parse is intentionally kept separate from the package-level cache so tests
// can exercise construction through the immutable public API.
func parse() (*Catalog, error) {
	var licenseBytes, noticeBytes, mapBytes, defBytes []byte
	cat := &Catalog{version: catalogVersion, serviceIndex: map[string][]int{}, operations: map[string][]indexedOperation{}, buildActions: map[string][]ActionDefinition{}, mappingIndex: map[string][]mappingSpan{}, permissionless: map[string]bool{}, strings: []string{""}, stringIndex: map[string]stringID{}}
	h := sha256.New()
	err := readBundle(func(name string, data []byte) error {
		// The archive names are the canonical source paths. API entries retain
		// the historical embedded prefix in SourceHash for compatibility.
		var hashName string
		switch name {
		case "LICENSE":
			licenseBytes = data
			hashName = name
		case "NOTICE":
			noticeBytes = data
			hashName = name
		case "iamlivecore/map.json":
			mapBytes = data
			hashName = name
		case "iamlivecore/iam_definition.json":
			defBytes = data
			hashName = name
		default:
			if !strings.HasPrefix(name, "iamlivecore/apis/") {
				return fmt.Errorf("bundle: unexpected entry %q", name)
			}
			hashName = "upstream/" + name
			a, err := decodeAPI("upstream/"+name, data)
			if err != nil {
				return err
			}
			if err := cat.addAPI("upstream/"+name, a); err != nil {
				return err
			}
		}
		h.Write([]byte(hashName))
		h.Write([]byte{0})
		h.Write(data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(licenseBytes) == 0 || len(noticeBytes) == 0 {
		return nil, errors.New("bundle: license or notice is empty")
	}
	if err = validJSON(mapBytes, "map.json"); err != nil {
		return nil, err
	}
	if err = validJSON(defBytes, "iam_definition.json"); err != nil {
		return nil, err
	}
	var rawMap struct {
		Schema         string                  `json:"schema_version"`
		SDK            map[string][]rawMapping `json:"sdk_method_iam_mappings"`
		ServiceSDK     map[string][]string     `json:"service_sdk_mappings"`
		Permissionless []string                `json:"sdk_permissionless_actions"`
	}
	if err = json.Unmarshal(mapBytes, &rawMap); err != nil {
		return nil, fmt.Errorf("map.json: %w", err)
	}
	if rawMap.Schema == "" {
		return nil, errors.New("map.json: missing schema_version")
	}
	orderedSDK, err := orderedObjectValues(mapBytes, "sdk_method_iam_mappings")
	if err != nil {
		return nil, fmt.Errorf("map.json: sdk_method_iam_mappings: %w", err)
	}
	var rawDefs []rawService
	if err = json.Unmarshal(defBytes, &rawDefs); err != nil {
		return nil, fmt.Errorf("iam_definition.json: %w", err)
	}
	if len(rawDefs) == 0 {
		return nil, errors.New("iam_definition.json: empty")
	}
	// API entries are decoded as they leave the archive, so no second
	// uncompressed copy of the selected corpus is retained.
	for _, d := range rawDefs {
		if err = cat.addDefinition(d); err != nil {
			return nil, err
		}
	}
	// Resolve SDK aliases only after every API alias has been indexed. A mapping
	// is evidence for an operation even when its action is absent from the SAR
	// dataset; that disagreement remains visible through Action lookup failure.
	sdkToService := map[string][]string{}
	for service, names := range rawMap.ServiceSDK {
		for _, name := range names {
			sdkToService[strings.ToLower(name)] = append(sdkToService[strings.ToLower(name)], service)
		}
	}
	for _, k := range rawMap.Permissionless {
		parts := strings.SplitN(k, ".", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("map.json: malformed permissionless operation key %q", k)
		}
		services := append([]string{parts[0]}, sdkToService[strings.ToLower(parts[0])]...)
		for _, s := range services {
			key := operationKey(s, parts[1])
			if len(cat.operations[key]) > 0 {
				cat.permissionless[key] = true
				break
			}
		}
	}
	for _, entry := range orderedSDK {
		k := entry.key
		mappingValues, err := orderedArray(entry.value)
		if err != nil {
			return nil, fmt.Errorf("map.json %s: %w", k, err)
		}
		vals := make([]rawMapping, len(mappingValues))
		for i, raw := range mappingValues {
			vals[i], err = decodeRawMapping(raw)
			if err != nil {
				return nil, fmt.Errorf("map.json %s[%d]: %w", k, i, err)
			}
		}
		if len(vals) > int(maxCatalogItems) || uint64(len(cat.mappingStore))+uint64(len(vals)) > uint64(maxCatalogItems) {
			return nil, errors.New("map.json: mapping occurrence count exceeds catalog bound")
		}
		start := uint32(len(cat.mappingStore))
		for i := range vals {
			mappingID, err := cat.nextID()
			if err != nil {
				return nil, err
			}
			m, e := convertMapping(vals[i])
			if e != nil {
				return nil, fmt.Errorf("map.json %s: %w", k, e)
			}
			m.occurrenceID = mappingID
			if err := cat.assignMappingIDs(&m); err != nil {
				return nil, err
			}
			cat.mappingStore = append(cat.mappingStore, m)
			cat.mappingOrder = append(cat.mappingOrder, mappingPosition{storeIndex: uint32(len(cat.mappingStore) - 1), occurrence: m.occurrenceID, key: k})
		}
		// Resolve the normalized operation only after all raw mapping IDs have
		// been allocated, including mappings that do not match an API model.
		parts := strings.SplitN(k, ".", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("map.json: malformed operation key %q", k)
		}
		services := append([]string{parts[0]}, sdkToService[strings.ToLower(parts[0])]...)
		matchedKey := ""
		for _, s := range services {
			key := operationKey(s, parts[1])
			if len(cat.operations[key]) > 0 {
				matchedKey = key
				break
			}
		}
		if matchedKey != "" {
			cat.mappingIndex[matchedKey] = append(cat.mappingIndex[matchedKey], mappingSpan{start: start, count: uint32(len(vals))})
		}
	}
	// Cross-file disagreements must be evaluated only after the SDK map has
	// populated the canonical mapping store. Missing IAM definitions remain
	// absent evidence; contradictory definitions remain contradictory.
	for _, spans := range cat.mappingIndex {
		for _, span := range spans {
			if !validMappingSpan(span, len(cat.mappingStore)) {
				return nil, errors.New("catalog: mapping span exceeds canonical store")
			}
			for i := uint32(0); i < span.count; i++ {
				mapping := &cat.mappingStore[span.start+i]
				parts := strings.SplitN(mapping.Action, ":", 2)
				if len(parts) != 2 {
					mapping.State = EvidenceContradictory
					continue
				}
				defs := cat.buildActions[strings.ToLower(parts[0])+"\x00"+strings.ToLower(parts[1])]
				switch len(defs) {
				case 0:
					mapping.State = EvidenceAbsent
				case 1:
					mapping.State = defs[0].State
				default:
					mapping.State = EvidenceContradictory
				}
			}
		}
	}
	// Attach bounded slices into the canonical mapping store. Alias indexes share
	// the span and never receive a second mapping graph.
	for i := range cat.services {
		for j := range cat.services[i].Operations {
			o := &cat.services[i].Operations[j]
			var ms []ActionMapping
			var spansForOperation []mappingSpan
			for _, alias := range cat.services[i].Aliases {
				if spans, ok := cat.mappingIndex[operationKey(alias, o.Name)]; ok {
					for _, span := range spans {
						if !validMappingSpan(span, len(cat.mappingStore)) {
							return nil, errors.New("catalog: mapping span exceeds canonical store")
						}
						spansForOperation = append(spansForOperation, span)
						ms = append(ms, cat.mappingStore[span.start:span.start+span.count]...)
					}
					if len(ms) > 0 {
						break
					}
				}
			}
			o.mappingSpans = spansForOperation
			o.Mappings = nil
			isPermissionless := cat.permissionless[operationKey(cat.services[i].EndpointPrefix, o.Name)]
			if len(ms) > 0 {
				if isPermissionless {
					o.MappingState = EvidencePermissionless
				} else {
					o.MappingState = EvidenceKnown
					allAbsent := true
					for _, m := range ms {
						if m.State != EvidenceAbsent {
							allAbsent = false
						}
						if m.State == EvidenceContradictory {
							o.MappingState = EvidenceContradictory
						}
					}
					if allAbsent {
						o.MappingState = EvidenceAbsent
					}
				}
			} else if isPermissionless {
				o.MappingState = EvidencePermissionless
			} else {
				o.MappingState = EvidenceAbsent
			}
		}
	}
	if err := cat.compileStaticPlans(); err != nil {
		return nil, err
	}
	if err := cat.buildOccurrenceIndex(); err != nil {
		return nil, err
	}
	if err := cat.compactEvidence(); err != nil {
		return nil, err
	}
	cat.sourceHash = hex.EncodeToString(h.Sum(nil))
	if cat.sourceHash != expectedSourceHash {
		return nil, fmt.Errorf("bundle source hash %s does not match pinned hash", cat.sourceHash)
	}
	return cat, nil
}

func (c *Catalog) buildOccurrenceIndex() error {
	counts := make(map[string]int, len(c.operations))
	for _, service := range c.services {
		for _, operation := range service.Operations {
			counts[operationKey(service.EndpointPrefix, operation.Name)]++
		}
	}
	c.operationOccurrences = make(map[string][]operationPosition, len(counts))
	c.serviceOperationIndexes = make([][]compactOperationPosition, len(c.services))
	for key, count := range counts {
		if count < 0 || uint64(count) > uint64(maxCatalogItems) {
			return fmt.Errorf("catalog: operation occurrence count exceeds bound for %q", key)
		}
		c.operationOccurrences[key] = make([]operationPosition, 0, count)
	}
	localToCanonical := make([][]int, len(c.services))
	canonicalIndex := 0
	for serviceIndex, service := range c.services {
		localToCanonical[serviceIndex] = make([]int, len(service.Operations))
		for operationIndex, operation := range service.Operations {
			if operation.occurrenceID == invalidOccurrenceID || uint64(operation.occurrenceID) > uint64(maxCatalogItems) {
				return errors.New("catalog: operation occurrence ID is invalid")
			}
			key := operationKey(service.EndpointPrefix, operation.Name)
			localToCanonical[serviceIndex][operationIndex] = canonicalIndex
			c.serviceOperationIndexes[serviceIndex] = append(c.serviceOperationIndexes[serviceIndex], compactOperationPosition{operation: canonicalIndex, occurrence: operation.occurrenceID})
			c.operationOccurrences[key] = append(c.operationOccurrences[key], operationPosition{serviceIndex: serviceIndex, operationIndex: canonicalIndex, occurrence: operation.occurrenceID})
			canonicalIndex++
		}
	}
	for key, entries := range c.operations {
		for i := range entries {
			if entries[i].serviceIndex < 0 || entries[i].serviceIndex >= len(localToCanonical) || entries[i].operationIndex < 0 || entries[i].operationIndex >= len(localToCanonical[entries[i].serviceIndex]) {
				return errors.New("catalog operation index is corrupt")
			}
			entries[i].operationIndex = localToCanonical[entries[i].serviceIndex][entries[i].operationIndex]
			c.operations[key] = entries
		}
	}
	return nil
}

func validMappingSpan(span mappingSpan, length int) bool {
	return uint64(span.start)+uint64(span.count) <= uint64(length)
}

func (s *compactStore) addCondition(c *Condition, intern func(string) (stringID, error)) (int, error) {
	if c == nil {
		return -1, nil
	}
	lhs, err := intern(c.LHS)
	if err != nil {
		return -1, err
	}
	op, err := intern(c.Op)
	if err != nil {
		return -1, err
	}
	rhs, err := intern(c.RHS)
	if err != nil {
		return -1, err
	}
	and, err := s.addCondition(c.And, intern)
	if err != nil {
		return -1, err
	}
	s.conditions = append(s.conditions, compactCondition{lhs: lhs, op: op, rhs: rhs, and: and})
	return len(s.conditions) - 1, nil
}

// compactEvidence converts the temporary decoding graph into the canonical
// compact store retained by a loaded catalog. Public compatibility structs and
// compiled plans are not retained as graphs: strings become IDs, nested values
// become checked spans, and plans retain only occurrence references.
func (c *Catalog) compactEvidence() error {
	s := &compactStore{strings: c.strings, stringIndex: c.stringIndex,
		operationIndex: map[string][]compactIndex{}, occurrences: map[string][]compactPosition{},
		mappingIndex: map[string][]mappingSpan{}, actionIndex: map[string][]compactActionIndex{}, compactPlans: map[occurrenceID]compactPlan{}}
	intern := func(value string) (stringID, error) { return c.internString(value) }
	span := func(count int) (stringSpan, error) {
		if count < 0 || uint64(count) > uint64(maxCatalogItems) {
			return stringSpan{}, errors.New("catalog: span count exceeds bound")
		}
		return stringSpan{}, nil
	}
	_ = span
	addStrings := func(values []string) (stringSpan, error) {
		start := len(s.refs)
		for _, value := range values {
			id, err := intern(value)
			if err != nil {
				return stringSpan{}, err
			}
			s.refs = append(s.refs, id)
		}
		return stringSpan{start: uint32(start), count: uint32(len(values))}, nil
	}
	// Interning may append to the shared builder pool; keep the compact store's
	// view synchronized after every conversion phase.
	for _, service := range c.services {
		key, err := intern(service.Key)
		if err != nil {
			return err
		}
		id, err := intern(service.ID)
		if err != nil {
			return err
		}
		endpoint, err := intern(service.EndpointPrefix)
		if err != nil {
			return err
		}
		signing, err := intern(service.SigningName)
		if err != nil {
			return err
		}
		target, err := intern(service.TargetPrefix)
		if err != nil {
			return err
		}
		version, err := intern(service.APIVersion)
		if err != nil {
			return err
		}
		protocol, err := intern(service.Protocol)
		if err != nil {
			return err
		}
		protocols, err := addStrings(service.Protocols)
		if err != nil {
			return err
		}
		aliases, err := addStrings(service.Aliases)
		if err != nil {
			return err
		}
		s.services = append(s.services, compactService{key: key, id: id, endpoint: endpoint, signing: signing, target: target, apiVersion: version, protocol: protocol, protocols: protocols, aliases: aliases})
	}
	for serviceIndex, serviceRecord := range c.services {
		for _, sourceOperation := range serviceRecord.Operations {
			service, err := intern(sourceOperation.Service)
			if err != nil {
				return err
			}
			name, err := intern(sourceOperation.Name)
			if err != nil {
				return err
			}
			input, err := intern(sourceOperation.InputShape)
			if err != nil {
				return err
			}
			output, err := intern(sourceOperation.OutputShape)
			if err != nil {
				return err
			}
			r := sourceOperation.Route
			method, err := intern(r.Method)
			if err != nil {
				return err
			}
			uri, err := intern(r.URI)
			if err != nil {
				return err
			}
			discriminator, err := intern(r.QueryDiscriminator)
			if err != nil {
				return err
			}
			target, err := intern(r.TargetPrefix)
			if err != nil {
				return err
			}
			jsonVersion, err := intern(r.JSONVersion)
			if err != nil {
				return err
			}
			qstart := len(s.queryRecords)
			for _, q := range sourceOperation.QueryBindings {
				qm, e := intern(q.Member)
				if e != nil {
					return e
				}
				ql, e := intern(q.LocationName)
				if e != nil {
					return e
				}
				s.queryRecords = append(s.queryRecords, compactQuery{member: qm, location: ql, required: q.Required})
			}
			s.operations = append(s.operations, compactOperation{occurrence: sourceOperation.occurrenceID, service: service, name: name, input: input, output: output, route: compactRoute{method: method, uri: uri, discriminator: discriminator, target: target, jsonVersion: jsonVersion, responseCode: r.ResponseCode}, queries: stringSpan{start: uint32(qstart), count: uint32(len(sourceOperation.QueryBindings))}, state: sourceOperation.State, mappingState: sourceOperation.MappingState, mappings: append([]mappingSpan(nil), sourceOperation.mappingSpans...)})
			_ = serviceIndex
		}
	}
	for key, entries := range c.operations {
		for _, entry := range entries {
			if entry.operationIndex < 0 || entry.operationIndex >= len(s.operations) {
				return errors.New("catalog: operation index exceeds compact store")
			}
			s.operationIndex[key] = append(s.operationIndex[key], compactIndex{operation: entry.operationIndex, occurrence: entry.occurrence})
		}
	}
	for key, positions := range c.operationOccurrences {
		for _, p := range positions {
			if p.operationIndex < 0 || p.operationIndex >= len(s.operations) {
				return errors.New("catalog: operation occurrence index exceeds compact store")
			}
			s.occurrences[key] = append(s.occurrences[key], compactPosition{operation: p.operationIndex, occurrence: p.occurrence})
		}
	}
	for i, indexes := range c.serviceOperationIndexes {
		for _, index := range indexes {
			if index.occurrence == invalidOccurrenceID || index.operation < 0 || index.operation >= len(s.operations) || s.operations[index.operation].occurrence != index.occurrence {
				return errors.New("catalog: service operation index exceeds compact store")
			}
			for len(s.serviceOps) <= i {
				s.serviceOps = append(s.serviceOps, nil)
			}
			s.serviceOps[i] = append(s.serviceOps[i], index)
		}
	}
	for key, spans := range c.mappingIndex {
		s.mappingIndex[key] = append([]mappingSpan(nil), spans...)
	}
	s.mappingOrder = append(s.mappingOrder, c.mappingOrder...)
	mappingIndexes := make(map[occurrenceID]int, len(s.mappings))
	for i, m := range c.mappingStore {
		mappingIndexes[m.occurrenceID] = i
	}
	for _, m := range c.mappingStore {
		action, err := intern(m.Action)
		if err != nil {
			return err
		}
		override, err := intern(m.ARNOverride)
		if err != nil {
			return err
		}
		notice, err := intern(m.Notice)
		if err != nil {
			return err
		}
		rstart := len(s.mappingResources)
		for _, resource := range m.Resources {
			p, e := intern(resource.Parameter)
			if e != nil {
				return e
			}
			t, e := intern(resource.Template)
			if e != nil {
				return e
			}
			ci, e := s.addCondition(resource.Condition, intern)
			if e != nil {
				return e
			}
			s.mappingResources = append(s.mappingResources, compactResourceMapping{occurrence: resource.occurrenceID, parameter: p, template: t, condition: ci})
		}
		astart := len(s.mapPairs)
		for k, v := range m.ResourceARNMappings {
			kk, e := intern(k)
			if e != nil {
				return e
			}
			vv, e := intern(v)
			if e != nil {
				return e
			}
			s.mapPairs = append(s.mapPairs, compactMapPair{key: kk, value: vv, resource: -1})
		}
		acond := stringSpan{start: uint32(astart), count: uint32(len(s.mapPairs) - astart)}
		cstart := len(s.mapPairs)
		for _, k := range m.conditionMappingOrder {
			v, ok := m.ConditionMappings[k]
			if !ok {
				return fmt.Errorf("catalog: condition mapping %q missing", k)
			}
			kk, e := intern(k)
			if e != nil {
				return e
			}
			p, e := intern(v.Parameter)
			if e != nil {
				return e
			}
			t, e := intern(v.Template)
			if e != nil {
				return e
			}
			ci, e := s.addCondition(v.Condition, intern)
			if e != nil {
				return e
			}
			ri := len(s.mappingResources)
			s.mappingResources = append(s.mappingResources, compactResourceMapping{occurrence: v.occurrenceID, parameter: p, template: t, condition: ci})
			s.mapPairs = append(s.mapPairs, compactMapPair{key: kk, value: invalidStringID, resource: ri})
		}
		_ = cstart
		condition, err := s.addCondition(m.Condition, intern)
		if err != nil {
			return err
		}
		s.mappings = append(s.mappings, compactMapping{occurrence: m.occurrenceID, action: action, state: m.State, resources: stringSpan{start: uint32(rstart), count: uint32(len(m.Resources))}, arn: acond, conditionMappings: stringSpan{start: uint32(cstart), count: uint32(len(s.mapPairs) - cstart)}, condition: condition, arnOverride: override, notice: notice})
	}
	actionCompactIndexes := map[string][]int{}
	for _, position := range c.buildActionOrder {
		definitions := c.buildActions[position.key]
		if position.index < 0 || position.index >= len(definitions) {
			return errors.New("catalog: action occurrence order is corrupt")
		}
		key, d := position.key, definitions[position.index]
		service, e := intern(d.Service)
		if e != nil {
			return e
		}
		name, e := intern(d.Name)
		if e != nil {
			return e
		}
		access, e := intern(d.AccessLevel)
		if e != nil {
			return e
		}
		description, e := intern(d.Description)
		if e != nil {
			return e
		}
		start := len(s.resources)
		for _, r := range d.Resources {
			n, e := intern(r.Name)
			if e != nil {
				return e
			}
			ck, e := addStrings(r.ConditionKeys)
			if e != nil {
				return e
			}
			ds, e := addStrings(r.DependentActions)
			if e != nil {
				return e
			}
			dependentsStart := len(s.dependents)
			for i, dependency := range r.DependentActions {
				dependencyID := invalidOccurrenceID
				if i < len(r.dependentActionIDs) {
					dependencyID = r.dependentActionIDs[i]
				}
				actionID, e := intern(dependency)
				if e != nil {
					return e
				}
				s.dependents = append(s.dependents, compactDependent{occurrence: dependencyID, action: actionID})
			}
			s.resources = append(s.resources, compactResource{occurrence: r.occurrenceID, name: n, conditionKeys: ck, dependentActions: ds, dependentIDs: append([]occurrenceID(nil), r.dependentActionIDs...), dependents: stringSpan{start: uint32(dependentsStart), count: uint32(len(r.DependentActions))}})

		}
		index := len(s.actions)
		s.actions = append(s.actions, compactAction{occurrence: d.occurrenceID, service: service, name: name, access: access, description: description, resources: stringSpan{start: uint32(start), count: uint32(len(d.Resources))}, state: d.State})
		s.actionIndex[key] = append(s.actionIndex[key], compactActionIndex{action: index, occurrence: d.occurrenceID})
		actionCompactIndexes[key] = append(actionCompactIndexes[key], index)
	}
	actionIndexes := make(map[occurrenceID]int, len(s.actions))
	for key, indexes := range actionCompactIndexes {
		for i, index := range indexes {
			if index >= 0 && index < len(s.actions) {
				actionIndexes[c.buildActions[key][i].occurrenceID] = index
			}
		}
	}
	for occurrence, plan := range c.plans {
		compact := compactPlan{occurrence: occurrence, diagnostics: append([]ValidationDiagnostic(nil), plan.Diagnostics...)}
		var err error
		compact.service, err = intern(plan.Service)
		if err != nil {
			return err
		}
		compact.operation, err = intern(plan.Operation)
		if err != nil {
			return err
		}
		for _, compiled := range plan.Mappings {
			mappingIndex, ok := mappingIndexes[compiled.Mapping.occurrenceID]
			if !ok {
				return errors.New("catalog: static mapping occurrence is corrupt")
			}
			definitionIndex, ok := actionIndexes[compiled.Definition.occurrenceID]
			if !ok {
				return errors.New("catalog: static action occurrence is corrupt")
			}
			compact.mappings = append(compact.mappings, compactStaticMapping{mapping: mappingIndex, action: definitionIndex, dependent: compiled.Dependent})
		}
		s.compactPlans[occurrence] = compact
	}
	s.actionOrder = nil
	for _, position := range c.buildActionOrder {
		indexes := actionCompactIndexes[position.key]
		if position.index < 0 || position.index >= len(indexes) || position.index >= len(c.buildActions[position.key]) {
			return errors.New("catalog: action occurrence order is corrupt")
		}
		index := indexes[position.index]
		if index < 0 || index >= len(s.actions) || s.actions[index].occurrence != c.buildActions[position.key][position.index].occurrenceID {
			return errors.New("catalog: action occurrence identity is corrupt")
		}
		s.actionOrder = append(s.actionOrder, compactActionPosition{action: index, occurrence: s.actions[index].occurrence})
	}
	s.strings = c.strings
	s.stringIndex = c.stringIndex
	c.store = s
	c.services = nil
	c.serviceIndex = nil
	c.operations = nil
	c.operationOccurrences = nil
	c.buildActions = nil
	c.permissionless = nil
	c.mappingStore = nil
	c.mappingIndex = nil
	c.mappingOrder = nil
	c.plans = nil
	c.serviceOperationIndexes = nil
	c.strings = nil
	c.stringIndex = nil
	return nil
}

type rawAPI struct {
	Metadata         rawMetadata             `json:"metadata"`
	Operations       map[string]rawOperation `json:"operations"`
	operationOrder   []string
	Shapes           map[string]rawShape `json:"shapes"`
	shapeMemberOrder map[string][]string
}
type rawShape struct {
	Type     string               `json:"type"`
	Required []string             `json:"required"`
	Members  map[string]rawMember `json:"members"`
}
type rawMember struct {
	Shape        string  `json:"shape"`
	Location     string  `json:"location"`
	LocationName *string `json:"locationName"`
}

// decodeAPI is the production API-model construction boundary. Strict JSON
// validation must happen before unmarshalling because encoding/json otherwise
// silently overwrites duplicate object members in maps.
func decodeAPI(file string, b []byte) (rawAPI, error) {
	if err := validJSON(b, file); err != nil {
		return rawAPI{}, err
	}
	var a rawAPI
	if err := json.Unmarshal(b, &a); err != nil {
		return rawAPI{}, fmt.Errorf("%s: %w", file, err)
	}
	order, err := orderedObjectKeys(b, "operations")
	if err != nil {
		return rawAPI{}, fmt.Errorf("%s: operations: %w", file, err)
	}
	a.operationOrder = order
	a.shapeMemberOrder = make(map[string][]string)
	shapeValues, err := orderedObjectValues(b, "shapes")
	if err != nil {
		return rawAPI{}, fmt.Errorf("%s: shapes: %w", file, err)
	}
	for _, shape := range shapeValues {
		fields, err := orderedObjectValues(shape.value, "members")
		if err != nil {
			return rawAPI{}, fmt.Errorf("%s: shape %s members: %w", file, shape.key, err)
		}
		for _, field := range fields {
			a.shapeMemberOrder[shape.key] = append(a.shapeMemberOrder[shape.key], field.key)
		}
	}
	if err := validateAPI(file, a); err != nil {
		return rawAPI{}, err
	}
	return a, nil
}

type orderedJSONValue struct {
	key   string
	value json.RawMessage
}

func orderedObjectValues(data []byte, field string) ([]orderedJSONValue, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	raw, ok := object[field]
	if !ok {
		return nil, nil
	}
	return orderedObject(raw)
}

func orderedObject(data []byte) ([]orderedJSONValue, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, errors.New("expected object")
	}
	var order []orderedJSONValue
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		order = append(order, orderedJSONValue{key: name, value: value})
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("malformed object")
	}
	return order, nil
}

func orderedObjectKeys(data []byte, field string) ([]string, error) {
	values, err := orderedObjectValues(data, field)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(values))
	for i := range values {
		out[i] = values[i].key
	}
	return out, nil
}

func validateAPI(file string, a rawAPI) error {
	for operation, raw := range a.Operations {
		shapeName := raw.Input.Shape
		if shapeName == "" {
			continue
		}
		shape, ok := a.Shapes[shapeName]
		if !ok || shape.Type != "structure" {
			return fmt.Errorf("%s: operation %q input shape %q is missing or malformed", file, operation, shapeName)
		}
		required := map[string]bool{}
		for _, member := range shape.Required {
			if member == "" {
				return fmt.Errorf("%s: operation %q input shape %q has empty required member", file, operation, shapeName)
			}
			if required[member] {
				return fmt.Errorf("%s: operation %q input shape %q has duplicate required member %q", file, operation, shapeName, member)
			}
			if _, ok := shape.Members[member]; !ok {
				return fmt.Errorf("%s: operation %q input shape %q has absent required member %q", file, operation, shapeName, member)
			}
			required[member] = true
		}
		queryNames := map[string]string{}
		for memberName, member := range shape.Members {
			if memberName == "" || member.Shape == "" || a.Shapes[member.Shape].Type == "" {
				return fmt.Errorf("%s: operation %q input shape %q has malformed member %q", file, operation, shapeName, memberName)
			}
			if member.Location != "querystring" {
				continue
			}
			if member.LocationName != nil && strings.TrimSpace(*member.LocationName) == "" {
				return fmt.Errorf("%s: operation %q input shape %q member %q has empty query locationName", file, operation, shapeName, memberName)
			}
			locationName := memberName
			if member.LocationName != nil {
				locationName = *member.LocationName
			}
			if prior, ok := queryNames[locationName]; ok {
				return fmt.Errorf("%s: operation %q input shape %q has duplicate query locationName %q for members %q and %q", file, operation, shapeName, locationName, prior, memberName)
			}
			queryNames[locationName] = memberName
		}
	}
	return nil
}

func queryBindings(a rawAPI, operation, file string, shapeName string) ([]QueryBinding, error) {
	if shapeName == "" {
		return nil, nil
	}
	shape, ok := a.Shapes[shapeName]
	if !ok {
		return nil, fmt.Errorf("%s: operation %q input shape %q is missing", file, operation, shapeName)
	}
	required := map[string]bool{}
	for _, member := range shape.Required {
		required[member] = true
	}
	var out []QueryBinding
	order := a.shapeMemberOrder[shapeName]
	if len(order) == 0 {
		for memberName := range shape.Members {
			order = append(order, memberName)
		}
	}
	for _, memberName := range order {
		member := shape.Members[memberName]
		if member.Location != "querystring" {
			continue
		}
		locationName := memberName
		if member.LocationName != nil {
			locationName = *member.LocationName
		}
		out = append(out, QueryBinding{Member: memberName, LocationName: locationName, Required: required[memberName]})
	}
	return out, nil
}

type rawMetadata struct {
	APIVersion, EndpointPrefix, Protocol, ServiceFullName, ServiceID, SigningName, TargetPrefix, UID, JSONVersion string
	Protocols                                                                                                     []string `json:"protocols"`
}
type rawOperation struct {
	Name string `json:"name"`
	HTTP struct {
		Method, RequestURI string
		ResponseCode       int `json:"responseCode"`
	} `json:"http"`
	Input struct {
		Shape string `json:"shape"`
	} `json:"input"`
	Output struct {
		Shape string `json:"shape"`
	} `json:"output"`
}
type rawService struct {
	Prefix     string         `json:"prefix"`
	Privileges []rawPrivilege `json:"privileges"`
}
type rawPrivilege struct {
	AccessLevel   string        `json:"access_level"`
	Description   string        `json:"description"`
	Privilege     string        `json:"privilege"`
	ResourceTypes []rawResource `json:"resource_types"`
}
type rawResource struct {
	ConditionKeys    []string `json:"condition_keys"`
	DependentActions []string `json:"dependent_actions"`
	ResourceType     string   `json:"resource_type"`
}
type rawMapping struct {
	Action              string                        `json:"action"`
	ResourceMappings    map[string]rawResourceMapping `json:"resource_mappings"`
	ResourceARNMappings map[string]string             `json:"resourcearn_mappings"`
	Condition           *rawCondition                 `json:"conditions"`
	ConditionMappings   map[string]rawResourceMapping `json:"condition_mappings"`
	ARNOverride         *rawTemplate                  `json:"arn_override"`
	Notice              string                        `json:"notice"`
	resourceOrder       []orderedJSONValue
	conditionOrder      []orderedJSONValue
}
type rawResourceMapping struct {
	Template   string        `json:"template"`
	Conditions *rawCondition `json:"conditions"`
}
type rawTemplate struct {
	Template string `json:"template"`
}
type rawCondition struct {
	LHS, Op, RHS string
	And          *rawCondition `json:"andCondition"`
}

func (c *Catalog) nextID() (occurrenceID, error) {
	if c.nextEvidenceID >= occurrenceID(maxCatalogItems) {
		return 0, errors.New("catalog: evidence occurrence ID overflow")
	}
	c.nextEvidenceID++
	return c.nextEvidenceID, nil
}

func (c *Catalog) internString(value string) (stringID, error) {
	if value == "" {
		return invalidStringID, nil
	}
	if id, ok := c.stringIndex[value]; ok {
		return id, nil
	}
	if len(c.strings) >= int(maxCatalogItems) {
		return invalidStringID, errors.New("catalog: interned string count exceeds bound")
	}
	id := stringID(len(c.strings))
	c.strings = append(c.strings, value)
	c.stringIndex[value] = id
	return id, nil
}

func (c *Catalog) addAPI(file string, a rawAPI) error {
	m := a.Metadata
	if m.EndpointPrefix == "" || m.Protocol == "" || m.UID == "" {
		return fmt.Errorf("%s: incomplete API metadata", file)
	}
	key := m.UID
	if _, ok := c.serviceIndex[strings.ToLower(key)]; ok {
		key = path.Dir(file) + "/" + key
	}
	s := Service{Key: key, ID: m.ServiceID, EndpointPrefix: m.EndpointPrefix, SigningName: m.SigningName, TargetPrefix: m.TargetPrefix, APIVersion: m.APIVersion, Protocol: m.Protocol, Protocols: cloneStrings(m.Protocols)}
	if len(s.Protocols) == 0 {
		s.Protocols = []string{m.Protocol}
	}
	s.Aliases = uniqueStrings([]string{m.EndpointPrefix, m.ServiceID, m.ServiceFullName, key})
	operationNames := a.operationOrder
	if len(operationNames) == 0 {
		operationNames = make([]string, 0, len(a.Operations))
		for name := range a.Operations {
			operationNames = append(operationNames, name)
		}
	}
	for _, n := range operationNames {
		o := a.Operations[n]
		occurrence, err := c.nextID()
		if err != nil {
			return err
		}
		name := o.Name
		if name == "" {
			name = n
		}
		if name == "" {
			return fmt.Errorf("%s: operation %q has no name", file, n)
		}
		state := EvidenceKnown
		if name != n {
			// A few historical Smithy models disagree between the operation key
			// and its nested name. Keep the key for lookup and expose the issue.
			state = EvidenceContradictory
		}
		bindings, err := queryBindings(a, n, file, o.Input.Shape)
		if err != nil {
			return err
		}
		discriminator := o.HTTP.RequestURI
		switch strings.ToLower(m.Protocol) {
		case "query":
			discriminator = n
		case "json":
			discriminator = m.TargetPrefix + "." + n
		}
		s.Operations = append(s.Operations, Operation{occurrenceID: occurrence, Service: m.EndpointPrefix, Name: n, State: state, InputShape: o.Input.Shape, OutputShape: o.Output.Shape, QueryBindings: bindings, Route: Route{Method: o.HTTP.Method, URI: o.HTTP.RequestURI, ResponseCode: o.HTTP.ResponseCode, QueryDiscriminator: discriminator, TargetPrefix: m.TargetPrefix, JSONVersion: m.JSONVersion}})
	}
	idx := len(c.services)
	c.services = append(c.services, s)
	for _, alias := range s.Aliases {
		c.serviceIndex[strings.ToLower(alias)] = append(c.serviceIndex[strings.ToLower(alias)], idx)
	}
	for _, alias := range s.Aliases {
		for operationIndex, o := range s.Operations {
			k := operationKey(alias, o.Name)
			equivalent := false
			for _, prior := range c.operations[k] {
				if prior.modelKey != key || prior.serviceIndex < 0 || prior.serviceIndex >= len(c.services) || prior.operationIndex < 0 || prior.operationIndex >= len(c.services[prior.serviceIndex].Operations) {
					continue
				}
				if operationEquivalent(c.services[prior.serviceIndex].Operations[prior.operationIndex], o) {
					equivalent = true
					break
				}
			}
			if !equivalent {
				c.operations[k] = append(c.operations[k], indexedOperation{modelKey: key, serviceIndex: idx, operationIndex: operationIndex, occurrence: o.occurrenceID})
			}
		}
	}
	return nil
}

func operationEquivalent(a, b Operation) bool {
	return a.Service == b.Service && strings.EqualFold(a.Name, b.Name) &&
		a.InputShape == b.InputShape && a.OutputShape == b.OutputShape && a.Route == b.Route &&
		reflect.DeepEqual(a.QueryBindings, b.QueryBindings)
}
func (c *Catalog) replaceOperation(serviceIndex int, o Operation) {
	// Indexed operations point at the service occurrence, so updating the
	// canonical service record is sufficient. Keep this helper as a checked
	// construction hook for callers that build catalogs in stages.
	if serviceIndex < 0 || serviceIndex >= len(c.services) || o.Name == "" {
		return
	}
}
func (c *Catalog) addDefinition(d rawService) error {
	if d.Prefix == "" {
		return errors.New("iam_definition.json: empty service prefix")
	}
	for _, p := range d.Privileges {
		if p.Privilege == "" {
			return fmt.Errorf("iam_definition.json: empty privilege in %s", d.Prefix)
		}
		// Allocate the definition occurrence before key normalization or duplicate
		// handling so source order remains the stable identity order.
		definitionID, err := c.nextID()
		if err != nil {
			return err
		}
		k := strings.ToLower(d.Prefix) + "\x00" + strings.ToLower(p.Privilege)
		state := EvidenceKnown
		if strings.EqualFold(p.AccessLevel, "Unknown") {
			state = EvidenceUndocumented
		}
		a := ActionDefinition{occurrenceID: definitionID, Service: d.Prefix, Name: p.Privilege, AccessLevel: p.AccessLevel, Description: p.Description, State: state}
		seen := map[string]bool{}
		for _, r := range p.ResourceTypes {
			resourceID, err := c.nextID()
			if err != nil {
				return err
			}
			rkey := strings.ToLower(r.ResourceType)
			if seen[rkey] {
				a.State = EvidenceContradictory
			}
			seen[rkey] = true
			resource := ResourceType{occurrenceID: resourceID, Name: r.ResourceType, ConditionKeys: cloneStrings(r.ConditionKeys), DependentActions: cloneStrings(r.DependentActions)}
			for range r.DependentActions {
				dependentID, err := c.nextID()
				if err != nil {
					return err
				}
				resource.dependentActionIDs = append(resource.dependentActionIDs, dependentID)
			}
			a.Resources = append(a.Resources, resource)
		}
		prior := c.buildActions[k]
		if len(prior) > 0 {
			// IAM definitions contain case-variant duplicate evidence in the
			// pinned snapshot. Retain every record and make lookup fail closed
			// rather than selecting one permission silently.
			a.State = EvidenceContradictory
			for i := range prior {
				prior[i].State = EvidenceContradictory
			}
		}
		definitionIndex := len(prior)
		c.buildActions[k] = append(prior, a)
		c.buildActionOrder = append(c.buildActionOrder, actionPosition{key: k, index: definitionIndex})
	}
	return nil
}
func (c *Catalog) assignMappingIDs(m *ActionMapping) error {
	var err error
	if m.occurrenceID == invalidOccurrenceID {
		return errors.New("catalog: mapping occurrence ID is invalid")
	}
	for i := range m.Resources {
		if m.Resources[i].occurrenceID, err = c.nextID(); err != nil {
			return err
		}
	}
	for _, key := range m.conditionMappingOrder {
		value, ok := m.ConditionMappings[key]
		if !ok {
			return fmt.Errorf("catalog: condition mapping %q is not addressable", key)
		}
		if value.occurrenceID, err = c.nextID(); err != nil {
			return err
		}
		m.ConditionMappings[key] = value
	}
	return nil
}

func orderedArray(data []byte) ([]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('[') {
		return nil, errors.New("expected array")
	}
	var out []json.RawMessage
	for decoder.More() {
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
		return nil, errors.New("malformed array")
	}
	return out, nil
}

func decodeRawMapping(data []byte) (rawMapping, error) {
	var out rawMapping
	if err := json.Unmarshal(data, &out); err != nil {
		return out, err
	}
	fields, err := orderedObject(data)
	if err != nil {
		return out, err
	}
	for _, field := range fields {
		switch field.key {
		case "resource_mappings":
			out.resourceOrder, err = orderedObject(field.value)
		case "condition_mappings":
			out.conditionOrder, err = orderedObject(field.value)
		}
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func convertMapping(r rawMapping) (ActionMapping, error) {
	if r.Action == "" {
		return ActionMapping{}, errors.New("mapping has empty action")
	}
	m := ActionMapping{Action: r.Action, State: EvidenceKnown, ResourceARNMappings: map[string]string{}, ConditionMappings: map[string]ResourceMapping{}, Notice: r.Notice}
	for _, entry := range r.resourceOrder {
		x, ok := r.ResourceMappings[entry.key]
		if !ok {
			return ActionMapping{}, fmt.Errorf("resource mapping %q disappeared during ordered decode", entry.key)
		}
		// Empty templates are upstream evidence, not parser instructions. Keep
		// them observable so consumers can reject them without dropping the
		// rest of the pinned catalog.
		m.Resources = append(m.Resources, ResourceMapping{Parameter: entry.key, Template: x.Template, Condition: convertCondition(x.Conditions)})
	}
	if len(r.resourceOrder) == 0 {
		for p, x := range r.ResourceMappings {
			m.Resources = append(m.Resources, ResourceMapping{Parameter: p, Template: x.Template, Condition: convertCondition(x.Conditions)})
		}
	}
	for _, entry := range r.conditionOrder {
		v, ok := r.ConditionMappings[entry.key]
		if !ok {
			return ActionMapping{}, fmt.Errorf("condition mapping %q disappeared during ordered decode", entry.key)
		}
		m.ConditionMappings[entry.key] = ResourceMapping{Parameter: entry.key, Template: v.Template, Condition: convertCondition(v.Conditions)}
		m.conditionMappingOrder = append(m.conditionMappingOrder, entry.key)
	}
	if len(r.conditionOrder) == 0 {
		for k, v := range r.ConditionMappings {
			m.ConditionMappings[k] = ResourceMapping{Parameter: k, Template: v.Template, Condition: convertCondition(v.Conditions)}
			m.conditionMappingOrder = append(m.conditionMappingOrder, k)
		}
	}
	for k, v := range r.ResourceARNMappings {
		m.ResourceARNMappings[k] = v
	}

	if r.ARNOverride != nil {
		m.ARNOverride = r.ARNOverride.Template
	}
	m.Condition = convertCondition(r.Condition)
	return m, nil
}
func convertCondition(c *rawCondition) *Condition {
	if c == nil {
		return nil
	}
	return &Condition{LHS: c.LHS, Op: c.Op, RHS: c.RHS, And: convertCondition(c.And)}
}
func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range in {
		if x != "" && !seen[strings.ToLower(x)] {
			seen[strings.ToLower(x)] = true
			out = append(out, x)
		}
	}
	return out
}

// readBundle validates the deterministic archive and invokes fn for one
// bounded entry at a time. It performs no filesystem or network IO.
func readBundle(fn func(name string, data []byte) error) error {
	return readBundleData(embeddedBundle, fn)
}

func readBundleData(bundle []byte, fn func(name string, data []byte) error) error {
	compressed := bytes.NewReader(bundle)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return fmt.Errorf("bundle gzip: %w", err)
	}
	gz.Multistream(false)
	defer gz.Close()

	tr := tar.NewReader(gz)
	lastAPI := ""
	entries := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("bundle tar: %w", err)
		}
		if header.Typeflag != tar.TypeReg || header.Name != cleanBundlePath(header.Name) || header.Linkname != "" {
			return fmt.Errorf("bundle: invalid entry %q", header.Name)
		}
		if header.Size < 0 || header.Size > maxJSONBytes {
			return fmt.Errorf("bundle entry %q exceeds parser bound", header.Name)
		}
		if !validBundleName(header.Name) {
			return fmt.Errorf("bundle: unexpected entry %q", header.Name)
		}
		if strings.HasPrefix(header.Name, "iamlivecore/apis/") {
			if entries < len(bundleFixedEntries) {
				return fmt.Errorf("bundle: expected %q before API entries", bundleFixedEntries[entries])
			}
			if header.Name <= lastAPI {
				return fmt.Errorf("bundle: API entries are not in canonical order or are duplicated")
			}
			lastAPI = header.Name
		} else if entries >= 4 {
			return fmt.Errorf("bundle: fixed entries are out of order")
		} else if header.Name != bundleFixedEntries[entries] {
			return fmt.Errorf("bundle: expected %q, got %q", bundleFixedEntries[entries], header.Name)
		}
		data := make([]byte, header.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return fmt.Errorf("bundle entry %q is truncated: %w", header.Name, err)
		}
		if err := fn(header.Name, data); err != nil {
			return err
		}
		entries++
	}
	if entries < len(bundleFixedEntries) || lastAPI == "" {
		return errors.New("bundle is missing required entries")
	}
	// archive/tar consumes the two zero end blocks while returning EOF. Any
	// bytes left in the gzip stream are therefore truncation or trailing data.
	trailer, err := io.ReadAll(gz)
	if err != nil {
		return fmt.Errorf("bundle gzip trailer: %w", err)
	}
	if len(trailer) != 0 {
		return errors.New("bundle has malformed or trailing archive data")
	}
	if compressed.Len() != 0 {
		return errors.New("bundle has trailing compressed data")
	}
	return nil
}

var bundleFixedEntries = []string{"LICENSE", "NOTICE", "iamlivecore/map.json", "iamlivecore/iam_definition.json"}

func validBundleName(name string) bool {
	for _, fixed := range bundleFixedEntries {
		if name == fixed {
			return true
		}
	}
	parts := strings.Split(name, "/")
	return len(parts) == 5 && parts[0] == "iamlivecore" && parts[1] == "apis" &&
		parts[2] != "" && parts[3] != "" && parts[4] == "api-2.json"
}

func cleanBundlePath(name string) string {
	if name == "" || strings.Contains(name, "\\") {
		return ""
	}
	return path.Clean(name)
}
func validJSON(b []byte, name string) error {
	if len(b) > maxJSONBytes {
		return fmt.Errorf("%s exceeds parser bound", name)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	state := jsonValidationState{maxDepth: 256}
	if err := state.value(d, "$", 0); err != nil {
		return fmt.Errorf("%s: invalid JSON: %w", name, err)
	}
	var extra json.Token
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: trailing JSON", name)
		}
		return fmt.Errorf("%s: invalid trailing JSON: %w", name, err)
	}
	return nil
}

type jsonValidationState struct {
	tokens   int
	maxDepth int
}

// value validates JSON without materializing it. In particular, object keys
// are checked before any map unmarshal can overwrite an earlier key.
func (s *jsonValidationState) value(d *json.Decoder, jsonPath string, depth int) error {
	s.tokens++
	if s.tokens > maxJSONBytes || depth > s.maxDepth {
		return errors.New("JSON validation limit exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch token := t.(type) {
	case json.Delim:
		switch token {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate object key %q at %s", key, jsonPath)
				}
				seen[key] = true
				if err := s.value(d, jsonPath+"."+jsonPathName(key), depth+1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("malformed JSON object")
			}
		case '[':
			for i := 0; d.More(); i++ {
				if err := s.value(d, fmt.Sprintf("%s[%d]", jsonPath, i), depth+1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("malformed JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	return nil
}

func jsonPathName(key string) string {
	if key == "" {
		return `""`
	}
	for _, r := range key {
		if r != '_' && r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return "[" + strconv.Quote(key) + "]"
		}
	}
	return key
}
