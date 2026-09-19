package iamlivecatalog

import (
	"fmt"
	"strings"
)

const maxPlanDiagnostics = 32
const maxStaticTraversal = 1 << 20

type staticDefinitionIdentity struct {
	occurrence occurrenceID
	key        string
}
type staticDependencyEdge struct {
	key          string
	resource     ResourceType
	dependencyID occurrenceID
	index        int
}
type staticExpectedMapping struct {
	key                                                string
	sourceOccurrence, resourceOccurrence, dependencyID occurrenceID
}

func staticActionKey(value string) (string, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(value, " \t\r\n") {
		return "", false
	}
	return strings.ToLower(parts[0]) + "\x00" + strings.ToLower(parts[1]), true
}
func displayActionKey(value string) string { return strings.Replace(value, "\x00", ":", 1) }
func (p *StaticPlan) diagnostic(code ValidationCode, action, related string, occurrence, relatedOccurrence uint32, detail string) {
	d := ValidationDiagnostic{Code: code, Service: p.Service, Operation: p.Operation, Action: action, RelatedAction: related, Occurrence: occurrence, RelatedOccur: relatedOccurrence, Detail: detail}
	if len(p.Diagnostics) >= maxPlanDiagnostics {
		if code == ValidationCyclic {
			for i, old := range p.Diagnostics {
				if old.Code != ValidationCyclic {
					p.Diagnostics[i] = d
					return
				}
			}
		}
		return
	}
	p.Diagnostics = append(p.Diagnostics, d)
}

func (c *Catalog) compileStaticPlans() error {
	if c == nil {
		return fmt.Errorf("catalog: nil validation target")
	}
	c.plans = make(map[occurrenceID]StaticPlan)
	for _, service := range c.services {
		for _, operation := range service.Operations {
			c.plans[operation.occurrenceID] = compileStaticPlan(service.EndpointPrefix, operation, c.mappingStore, c.buildActions)
		}
	}
	return nil
}

type compactPlanMapping struct {
	mapping, action int
	key             string
	dependent       bool
}

type compactPlanEdge struct {
	key                    string
	resource, dependencyID occurrenceID
	index                  int
}

// compileCompactPlans validates static agreement directly against the compact
// occurrence store. It deliberately avoids rebuilding catalog-wide public
// ActionDefinition and Operation graphs during Load; those views remain
// available on demand through the defensive-copy accessors.
func (c *Catalog) compileCompactPlans() error {
	if c == nil || c.store == nil {
		return fmt.Errorf("catalog: compact validation target unavailable")
	}
	s := c.store
	// Builder lookup maps are no longer needed once mappings have been attached.
	// Release them before plan compilation so they do not overlap with temporary
	// graph-validation state at the allocator high-water mark.
	s.stringIndex = nil
	s.operationIndex = nil
	s.compactPlans = make([]compactPlan, len(s.operations))
	for serviceIndex, positions := range s.serviceOps {
		if serviceIndex < 0 || serviceIndex >= len(s.services) {
			return fmt.Errorf("catalog: compact service index is corrupt")
		}
		serviceID := s.services[serviceIndex].endpoint
		service, ok := compactString(s, serviceID)
		if !ok {
			return fmt.Errorf("catalog: compact service string is corrupt")
		}
		for _, position := range positions {
			if position.operation < 0 || position.operation >= len(s.operations) || s.operations[position.operation].occurrence != position.occurrence {
				return fmt.Errorf("catalog: compact operation index is corrupt")
			}
			plan, err := compileCompactPlan(s, service, position.operation)
			if err != nil {
				return err
			}
			s.compactPlans[position.operation] = plan
		}
	}
	return packCompactStrings(s)
}

func packCompactStrings(s *compactStore) error {
	if s == nil || len(s.strings) == 0 {
		return fmt.Errorf("catalog: compact string store is empty")
	}
	total := uint64(0)
	offsets := make([]uint32, len(s.strings)+1)
	for i, value := range s.strings {
		if total+uint64(len(value)) > uint64(maxCatalogItems) {
			return fmt.Errorf("catalog: compact string data exceeds bound")
		}
		offsets[i] = uint32(total)
		total += uint64(len(value))
	}
	offsets[len(s.strings)] = uint32(total)
	var packed strings.Builder
	packed.Grow(int(total))
	for _, value := range s.strings {
		packed.WriteString(value)
	}
	s.stringBlob = packed.String()
	s.stringOffsets = offsets
	s.strings = nil
	return nil
}

func compileCompactPlan(s *compactStore, service string, operationIndex int) (compactPlan, error) {
	operation := s.operations[operationIndex]
	operationName, ok := compactString(s, operation.name)
	if !ok {
		return compactPlan{}, fmt.Errorf("catalog: compact operation string is corrupt")
	}
	validation := StaticPlan{Service: service, Operation: operationName, Occurrence: uint32(operation.occurrence)}
	result := compactPlan{}
	diagnostic := func(code ValidationCode, action, related string, occurrence, relatedOccurrence uint32, detail string) {
		validation.diagnostic(code, action, related, occurrence, relatedOccurrence, detail)
	}

	mappingCount := 0
	var mappings []compactPlanMapping
	for _, span := range operation.mappings {
		if !validMappingSpan(span, len(s.mappings)) {
			return compactPlan{}, fmt.Errorf("catalog: compact mapping span is corrupt")
		}
		mappingCount += int(span.count)
		for offset := uint32(0); offset < span.count; offset++ {
			mappingIndex := int(span.start + offset)
			mapping := s.mappings[mappingIndex]
			action, ok := compactString(s, mapping.action)
			if !ok {
				return compactPlan{}, fmt.Errorf("catalog: compact mapping action is corrupt")
			}
			key, valid := staticActionKey(action)
			if !valid {
				diagnostic(ValidationIncomplete, action, "", uint32(mapping.occurrence), 0, "malformed action mapping")
				continue
			}
			definitions := s.actionIndex[key]
			if len(definitions) > 1 {
				diagnostic(ValidationAmbiguous, action, "", uint32(mapping.occurrence), uint32(definitions[0].occurrence), "action definition has multiple occurrences")
				continue
			}
			if mapping.state != EvidenceKnown {
				diagnostic(validationState(mapping.state), action, "", uint32(mapping.occurrence), 0, "action mapping evidence is not known")
				continue
			}
			switch len(definitions) {
			case 0:
				diagnostic(ValidationMissing, action, "", uint32(mapping.occurrence), 0, "action definition is absent")
			case 1:
				definition := definitions[0]
				if definition.action < 0 || definition.action >= len(s.actions) || s.actions[definition.action].occurrence != definition.occurrence {
					return compactPlan{}, fmt.Errorf("catalog: compact action index is corrupt")
				}
				if s.actions[definition.action].state != EvidenceKnown {
					diagnostic(validationState(s.actions[definition.action].state), action, "", uint32(mapping.occurrence), uint32(definition.occurrence), "action definition is not known")
					continue
				}
				mappings = append(mappings, compactPlanMapping{mapping: mappingIndex, action: definition.action, key: key})
			}
		}
	}

	edgeNames := make(map[string]bool)
	for _, mapping := range mappings {
		if err := forEachCompactEdge(s, mapping.action, func(edge compactPlanEdge) error {
			if edge.key != "" {
				edgeNames[edge.key] = true
			}
			return nil
		}); err != nil {
			return compactPlan{}, err
		}
	}
	var roots []int
	for i := range mappings {
		mappings[i].dependent = edgeNames[mappings[i].key]
		if !mappings[i].dependent {
			roots = append(roots, i)
		}
	}
	noPrimary := len(mappings) > 0 && len(roots) == 0

	var expected []staticExpectedMapping
	stack := make(map[occurrenceID]bool)
	cycles := make(map[[4]uint32]bool)
	traversed := 0
	budgetReported := false
	var visit func(string, int, uint32, bool) error
	visit = func(source string, actionIndex int, sourceOccurrence uint32, countEdges bool) error {
		if traversed >= maxStaticTraversal {
			if !budgetReported {
				diagnostic(ValidationIncomplete, "", "", sourceOccurrence, 0, "dependency occurrence expansion exceeds parser bound")
				budgetReported = true
			}
			return nil
		}
		traversed++
		if actionIndex < 0 || actionIndex >= len(s.actions) {
			return fmt.Errorf("catalog: compact action index is corrupt")
		}
		identity := s.actions[actionIndex].occurrence
		if stack[identity] {
			return nil
		}
		stack[identity] = true
		err := forEachCompactEdge(s, actionIndex, func(edge compactPlanEdge) error {
			if edge.key == "" {
				diagnostic(ValidationIncomplete, "", displayActionKey(source), uint32(edge.resource), uint32(edge.dependencyID), "malformed dependency edge")
				return nil
			}
			if countEdges {
				expected = append(expected, staticExpectedMapping{key: edge.key, sourceOccurrence: occurrenceID(sourceOccurrence), resourceOccurrence: edge.resource, dependencyID: edge.dependencyID})
			}
			definitions := s.actionIndex[edge.key]
			if len(definitions) == 0 {
				diagnostic(ValidationMissing, displayActionKey(edge.key), displayActionKey(source), uint32(edge.resource), uint32(edge.dependencyID), "dependency action definition is absent")
				return nil
			}
			if len(definitions) > 1 {
				diagnostic(ValidationAmbiguous, displayActionKey(edge.key), displayActionKey(source), uint32(edge.resource), uint32(definitions[0].occurrence), "dependency action definition has multiple occurrences")
				return nil
			}
			definition := definitions[0]
			if definition.action < 0 || definition.action >= len(s.actions) || s.actions[definition.action].occurrence != definition.occurrence {
				return fmt.Errorf("catalog: compact dependency action index is corrupt")
			}
			if s.actions[definition.action].state != EvidenceKnown {
				diagnostic(validationState(s.actions[definition.action].state), displayActionKey(edge.key), displayActionKey(source), uint32(edge.resource), uint32(definition.occurrence), "dependency action definition is not known")
				return nil
			}
			target := s.actions[definition.action].occurrence
			if stack[target] {
				cycle := [4]uint32{uint32(identity), uint32(edge.resource), uint32(edge.dependencyID), uint32(target)}
				if target == invalidOccurrenceID {
					cycle[0] = uint32(edge.index)
				}
				if !cycles[cycle] {
					cycles[cycle] = true
					diagnostic(ValidationCyclic, displayActionKey(edge.key), source, uint32(edge.resource), uint32(definition.occurrence), "dependency graph is cyclic")
				}
				return nil
			}
			return visit(edge.key, definition.action, uint32(edge.resource), countEdges)
		})
		delete(stack, identity)
		return err
	}
	for _, index := range roots {
		mapping := mappings[index]
		expected = append(expected, staticExpectedMapping{key: mapping.key, sourceOccurrence: s.mappings[mapping.mapping].occurrence})
		if err := visit(mapping.key, mapping.action, uint32(s.mappings[mapping.mapping].occurrence), true); err != nil {
			return compactPlan{}, err
		}
	}
	for _, mapping := range mappings {
		if err := visit(mapping.key, mapping.action, uint32(s.mappings[mapping.mapping].occurrence), len(roots) == 0); err != nil {
			return compactPlan{}, err
		}
	}

	actual := make(map[string][]int)
	for i, mapping := range mappings {
		actual[mapping.key] = append(actual[mapping.key], i)
	}
	used := make([]bool, len(mappings))
	for _, slot := range expected {
		matched := -1
		for _, index := range actual[slot.key] {
			if !used[index] {
				matched = index
				break
			}
		}
		if matched >= 0 {
			used[matched] = true
		} else {
			diagnostic(ValidationIncomplete, displayActionKey(slot.key), "", uint32(slot.sourceOccurrence), uint32(slot.dependencyID), "missing dependent action mapping occurrence")
		}
	}
	for i, mapping := range mappings {
		if !used[i] {
			diagnostic(ValidationExtra, displayActionKey(mapping.key), "", uint32(s.mappings[mapping.mapping].occurrence), 0, "mapping occurrence is not explained by dependency evidence")
		}
	}
	if noPrimary {
		diagnostic(ValidationIncomplete, "", "", uint32(operation.occurrence), 0, "mapping has no primary action")
	}
	if operation.state != EvidenceKnown {
		diagnostic(validationState(operation.state), "", "", uint32(operation.occurrence), 0, "operation evidence is not known")
	}
	if operation.mappingState != EvidenceKnown || mappingCount == 0 {
		diagnostic(validationState(operation.mappingState), "", "", uint32(operation.occurrence), 0, "operation mapping evidence is incomplete")
	}
	for _, mapping := range mappings {
		result.mappings = append(result.mappings, compactStaticMapping{mapping: mapping.mapping, action: mapping.action, dependent: mapping.dependent})
	}
	result.diagnostics = validation.Diagnostics
	return result, nil
}

func forEachCompactEdge(s *compactStore, actionIndex int, fn func(compactPlanEdge) error) error {
	if actionIndex < 0 || actionIndex >= len(s.actions) {
		return fmt.Errorf("catalog: compact action index is corrupt")
	}
	action := s.actions[actionIndex]
	if !validSpan(action.resources, len(s.resources)) {
		return fmt.Errorf("catalog: compact action resource span is corrupt")
	}
	for resourceOffset := uint32(0); resourceOffset < action.resources.count; resourceOffset++ {
		resource := s.resources[action.resources.start+resourceOffset]
		if !validSpan(resource.dependents, len(s.dependents)) {
			return fmt.Errorf("catalog: compact dependency span is corrupt")
		}
		for dependencyOffset := uint32(0); dependencyOffset < resource.dependents.count; dependencyOffset++ {
			dependency := s.dependents[resource.dependents.start+dependencyOffset]
			action, ok := compactString(s, dependency.action)
			if !ok {
				return fmt.Errorf("catalog: compact dependency action is corrupt")
			}
			key, _ := staticActionKey(action)
			if err := fn(compactPlanEdge{key: key, resource: resource.occurrence, dependencyID: dependency.occurrence, index: int(dependencyOffset)}); err != nil {
				return err
			}
		}
	}
	return nil
}
func definitionIdentity(key string, definition ActionDefinition) staticDefinitionIdentity {
	if definition.occurrenceID != invalidOccurrenceID {
		return staticDefinitionIdentity{occurrence: definition.occurrenceID}
	}
	return staticDefinitionIdentity{key: key}
}
func definitionEdges(definition ActionDefinition) []staticDependencyEdge {
	var out []staticDependencyEdge
	for _, resource := range definition.Resources {
		for i, dependency := range resource.DependentActions {
			key, _ := staticActionKey(dependency)
			var id occurrenceID
			if i < len(resource.dependentActionIDs) {
				id = resource.dependentActionIDs[i]
			}
			out = append(out, staticDependencyEdge{key: key, resource: resource, dependencyID: id, index: i})
		}
	}
	return out
}
func validationState(state EvidenceState) ValidationCode {
	switch state {
	case EvidenceAbsent:
		return ValidationMissing
	case EvidenceContradictory:
		return ValidationContradictory
	default:
		return ValidationIncomplete
	}
}

func compileStaticPlan(service string, operation Operation, mappings []ActionMapping, definitions map[string][]ActionDefinition) StaticPlan {
	if len(operation.Mappings) == 0 {
		for _, span := range operation.mappingSpans {
			if validMappingSpan(span, len(mappings)) {
				operation.Mappings = append(operation.Mappings, mappings[span.start:span.start+span.count]...)
			}
		}
	}
	plan := StaticPlan{Service: service, Operation: operation.Name, Occurrence: uint32(operation.occurrenceID)}
	for _, mapping := range operation.Mappings {
		key, ok := staticActionKey(mapping.Action)
		if !ok {
			plan.diagnostic(ValidationIncomplete, mapping.Action, "", uint32(mapping.occurrenceID), 0, "malformed action mapping")
			continue
		}
		defs := definitions[key]
		if len(defs) > 1 {
			plan.diagnostic(ValidationAmbiguous, mapping.Action, "", uint32(mapping.occurrenceID), uint32(defs[0].occurrenceID), "action definition has multiple occurrences")
			continue
		}
		if mapping.State != EvidenceKnown {
			plan.diagnostic(validationState(mapping.State), mapping.Action, "", uint32(mapping.occurrenceID), 0, "action mapping evidence is not known")
			continue
		}
		switch len(defs) {
		case 0:
			plan.diagnostic(ValidationMissing, mapping.Action, "", uint32(mapping.occurrenceID), 0, "action definition is absent")
		case 1:
			d := defs[0]
			if d.State != EvidenceKnown {
				plan.diagnostic(validationState(d.State), mapping.Action, "", uint32(mapping.occurrenceID), uint32(d.occurrenceID), "action definition is not known")
				continue
			}
			parts := strings.SplitN(mapping.Action, ":", 2)
			plan.Mappings = append(plan.Mappings, StaticMapping{Action: ActionReference{Service: parts[0], Name: parts[1]}, Mapping: mapping.Clone(), Definition: d.Clone()})
		}
	}
	// An occurrence is a dependency if its action is named by any retained definition.
	edgeNames := map[string]bool{}
	for _, record := range plan.Mappings {
		for _, edge := range definitionEdges(record.Definition) {
			if edge.key != "" {
				edgeNames[edge.key] = true
			}
		}
	}
	var roots []int
	for i := range plan.Mappings {
		key, ok := staticActionKey(plan.Mappings[i].Mapping.Action)
		plan.Mappings[i].Dependent = ok && edgeNames[key]
		if !plan.Mappings[i].Dependent {
			roots = append(roots, i)
		}
	}
	noPrimary := len(plan.Mappings) > 0 && len(roots) == 0

	var expected []staticExpectedMapping
	stack := map[staticDefinitionIdentity]bool{}
	cycles := map[[4]uint32]bool{}
	traversed := 0
	budgetReported := false
	var visit func(string, ActionDefinition, uint32, bool)
	visit = func(source string, definition ActionDefinition, sourceOccurrence uint32, countEdges bool) {
		if traversed >= maxStaticTraversal {
			if !budgetReported {
				plan.diagnostic(ValidationIncomplete, "", "", sourceOccurrence, 0, "dependency occurrence expansion exceeds parser bound")
				budgetReported = true
			}
			return
		}
		traversed++
		identity := definitionIdentity(source, definition)
		if stack[identity] {
			return
		}
		stack[identity] = true
		for _, edge := range definitionEdges(definition) {
			if edge.key == "" {
				plan.diagnostic(ValidationIncomplete, "", displayActionKey(source), uint32(edge.resource.occurrenceID), uint32(edge.dependencyID), "malformed dependency edge")
				continue
			}
			if countEdges {
				expected = append(expected, staticExpectedMapping{key: edge.key, sourceOccurrence: occurrenceID(sourceOccurrence), resourceOccurrence: edge.resource.occurrenceID, dependencyID: edge.dependencyID})
			}
			defs := definitions[edge.key]
			if len(defs) == 0 {
				plan.diagnostic(ValidationMissing, displayActionKey(edge.key), displayActionKey(source), uint32(edge.resource.occurrenceID), uint32(edge.dependencyID), "dependency action definition is absent")
				continue
			}
			if len(defs) > 1 {
				plan.diagnostic(ValidationAmbiguous, displayActionKey(edge.key), displayActionKey(source), uint32(edge.resource.occurrenceID), uint32(defs[0].occurrenceID), "dependency action definition has multiple occurrences")
				continue
			}
			if defs[0].State != EvidenceKnown {
				plan.diagnostic(validationState(defs[0].State), displayActionKey(edge.key), displayActionKey(source), uint32(edge.resource.occurrenceID), uint32(defs[0].occurrenceID), "dependency action definition is not known")
				continue
			}
			target := definitionIdentity(edge.key, defs[0])
			if stack[target] {
				ck := [4]uint32{uint32(identity.occurrence), uint32(edge.resource.occurrenceID), uint32(edge.dependencyID), uint32(target.occurrence)}
				if target.occurrence == invalidOccurrenceID {
					ck[0] = uint32(edge.index)
				}
				if !cycles[ck] {
					cycles[ck] = true
					plan.diagnostic(ValidationCyclic, displayActionKey(edge.key), source, uint32(edge.resource.occurrenceID), uint32(defs[0].occurrenceID), "dependency graph is cyclic")
				}
				continue
			}
			visit(edge.key, defs[0], uint32(edge.resource.occurrenceID), countEdges)
		}
		delete(stack, identity)
	}
	for _, index := range roots {
		record := plan.Mappings[index]
		key, ok := staticActionKey(record.Mapping.Action)
		if ok {
			expected = append(expected, staticExpectedMapping{key: key, sourceOccurrence: record.Mapping.occurrenceID})
			visit(key, record.Definition, uint32(record.Mapping.occurrenceID), true)
		}
	}
	for _, record := range plan.Mappings {
		key, ok := staticActionKey(record.Mapping.Action)
		if ok {
			visit(key, record.Definition, uint32(record.Mapping.occurrenceID), len(roots) == 0)
		}
	}

	actual := map[string][]int{}
	for i, record := range plan.Mappings {
		if key, ok := staticActionKey(record.Mapping.Action); ok {
			actual[key] = append(actual[key], i)
		}
	}
	used := make([]bool, len(plan.Mappings))
	for _, slot := range expected {
		matched := -1
		for _, index := range actual[slot.key] {
			if !used[index] {
				matched = index
				break
			}
		}
		if matched >= 0 {
			used[matched] = true
		} else {
			plan.diagnostic(ValidationIncomplete, displayActionKey(slot.key), "", uint32(slot.sourceOccurrence), uint32(slot.dependencyID), "missing dependent action mapping occurrence")
		}
	}
	for i, record := range plan.Mappings {
		if used[i] {
			continue
		}
		if key, ok := staticActionKey(record.Mapping.Action); ok {
			plan.diagnostic(ValidationExtra, displayActionKey(key), "", uint32(record.Mapping.occurrenceID), 0, "mapping occurrence is not explained by dependency evidence")
		}
	}
	if noPrimary {
		plan.diagnostic(ValidationIncomplete, "", "", uint32(operation.occurrenceID), 0, "mapping has no primary action")
	}
	if operation.State != EvidenceKnown {
		plan.diagnostic(validationState(operation.State), "", "", uint32(operation.occurrenceID), 0, "operation evidence is not known")
	}
	if operation.MappingState != EvidenceKnown || len(operation.Mappings) == 0 {
		plan.diagnostic(validationState(operation.MappingState), "", "", uint32(operation.occurrenceID), 0, "operation mapping evidence is incomplete")
	}
	return plan
}

func (c *Catalog) staticPlan(operationIndex int) (StaticPlan, bool) {
	if c == nil || c.store == nil || operationIndex < 0 || operationIndex >= len(c.store.operations) || operationIndex >= len(c.store.compactPlans) {
		return StaticPlan{}, false
	}
	operation := c.store.operations[operationIndex]
	compact := c.store.compactPlans[operationIndex]
	plan := StaticPlan{Occurrence: uint32(operation.occurrence), Diagnostics: append([]ValidationDiagnostic(nil), compact.diagnostics...)}
	var good bool
	plan.Service, good = compactString(c.store, operation.service)
	if !good {
		return StaticPlan{}, false
	}
	plan.Operation, good = compactString(c.store, operation.name)
	if !good {
		return StaticPlan{}, false
	}
	for _, item := range compact.mappings {
		mapping, ok := c.compactMapping(item.mapping)
		if !ok {
			return StaticPlan{}, false
		}
		definition, ok := c.compactAction(item.action)
		if !ok {
			return StaticPlan{}, false
		}
		parts := strings.SplitN(mapping.Action, ":", 2)
		if len(parts) != 2 {
			return StaticPlan{}, false
		}
		plan.Mappings = append(plan.Mappings, StaticMapping{Action: ActionReference{Service: parts[0], Name: parts[1]}, Mapping: mapping, Definition: definition, Dependent: item.dependent})
	}
	return plan, true
}
