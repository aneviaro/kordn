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

func (c *Catalog) staticPlan(occurrence occurrenceID) (StaticPlan, bool) {
	if c == nil || c.store == nil {
		return StaticPlan{}, false
	}
	compact, ok := c.store.compactPlans[occurrence]
	if !ok {
		return StaticPlan{}, false
	}
	plan := StaticPlan{Occurrence: uint32(compact.occurrence), Diagnostics: append([]ValidationDiagnostic(nil), compact.diagnostics...)}
	var good bool
	plan.Service, good = compactString(c.store, compact.service)
	if !good {
		return StaticPlan{}, false
	}
	plan.Operation, good = compactString(c.store, compact.operation)
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
