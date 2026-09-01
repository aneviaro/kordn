package iamliveadapter

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
	"github.com/kordn-ai/kordn/internal/iammap/data"
)

const UpstreamCommit = iamlivecatalog.UpstreamCommit
const AdapterVersion = "iamlive-derived/v1@" + UpstreamCommit

type Action struct{ Service, Name string }
type DependencyCandidate struct {
	Action             Action
	Resources          []string
	ParameterNames     []string
	ProvenInapplicable bool
}
type DependencyResult struct {
	Candidates []DependencyCandidate
	Certain    bool
}
type LookupResult struct {
	Entry               data.Entry
	Primary             []Action
	PrimaryEntries      []data.Entry
	Dependencies        []DependencyCandidate
	DependenciesCertain bool
}
type Adapter struct{ catalog *iamlivecatalog.Catalog }

// WireIdentity is the portion of an authenticated request which selects an
// API model record. It intentionally contains no body or credential data.
type WireIdentity struct {
	Protocol awsrequest.AWSProtocol
	Method   string
	Path     string
	Query    url.Values
	Target   string
}

func New() (*Adapter, error) {
	c, err := iamlivecatalog.Load()
	if err != nil {
		return nil, err
	}
	return &Adapter{catalog: c}, nil
}

func NormalizeOperation(operation string) string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return ""
	}
	for _, r := range operation {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return ""
		}
	}
	return operation
}

// LookupRequest selects one complete, known wire record. In particular, an
// operation record marked contradictory is never made usable by a wire match.
func (a *Adapter) LookupRequest(service, operation string, identity WireIdentity, parameters map[string]awsrequest.Value) (LookupResult, error) {
	if a == nil || a.catalog == nil {
		return LookupResult{}, fmt.Errorf("adapter unavailable")
	}
	op := NormalizeOperation(operation)
	if op == "" || !identity.Protocol.Supported() || strings.TrimSpace(identity.Method) == "" || identity.Path == "" {
		return LookupResult{}, fmt.Errorf("incomplete wire identity")
	}
	var selected []iamlivecatalog.Operation
	for _, serviceModel := range a.catalog.Services() {
		if !strings.EqualFold(serviceModel.EndpointPrefix, service) {
			continue
		}
		for _, record := range serviceModel.Operations {
			if !strings.EqualFold(record.Name, op) || record.State != iamlivecatalog.EvidenceKnown {
				continue
			}
			protocol, ok := recordProtocol(serviceModel.Protocol, record.Route.JSONVersion)
			if !ok || protocol != identity.Protocol {
				continue
			}
			if !routeMatches(record, serviceModel, op, identity) {
				continue
			}
			selected = append(selected, record)
		}
	}
	if len(selected) != 1 {
		if len(selected) == 0 {
			return LookupResult{}, fmt.Errorf("unknown operation")
		}
		return LookupResult{}, fmt.Errorf("ambiguous operation")
	}
	return a.lookupOperation(service, selected[0], parameters)
}

func recordProtocol(protocol, version string) (awsrequest.AWSProtocol, bool) {
	switch protocol {
	case "query":
		return awsrequest.ProtocolQuery, true
	case "ec2":
		return awsrequest.ProtocolEC2Query, true
	case "rest-json":
		return awsrequest.ProtocolRESTJSON, true
	case "rest-xml":
		return awsrequest.ProtocolRESTXML, true
	case "json":
		switch version {
		case "1.0":
			return awsrequest.ProtocolJSON10, true
		case "1.1":
			return awsrequest.ProtocolJSON11, true
		}
	}
	return "", false
}

func routeMatches(record iamlivecatalog.Operation, service iamlivecatalog.Service, operation string, id WireIdentity) bool {
	if !strings.EqualFold(record.Route.Method, id.Method) {
		return false
	}
	switch id.Protocol {
	case awsrequest.ProtocolQuery, awsrequest.ProtocolEC2Query:
		// Action and Version are both wire identity. url.Values.Get also rejects
		// duplicate values below, rather than choosing one.
		if len(id.Query["Action"]) != 1 || id.Query.Get("Action") != operation || len(id.Query["Version"]) != 1 || id.Query.Get("Version") != service.APIVersion {
			return false
		}
		return true
	case awsrequest.ProtocolJSON10, awsrequest.ProtocolJSON11:
		if len([]string{id.Target}) != 1 {
			return false
		}
		parts := strings.Split(id.Target, ".")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return false
		}
		// Both components are checked. A target for GetItem cannot select a
		// modeled PutItem record sharing its API version and prefix.
		return parts[0] == service.TargetPrefix && parts[1] == operation &&
			record.Route.TargetPrefix == parts[0] && record.Route.JSONVersion == jsonVersion(id.Protocol)
	case awsrequest.ProtocolRESTJSON, awsrequest.ProtocolRESTXML:
		return restPathMatches(record.Route.URI, id.Path)
	}
	return false
}
func jsonVersion(p awsrequest.AWSProtocol) string {
	if p == awsrequest.ProtocolJSON10 {
		return "1.0"
	}
	return "1.1"
}

func restPathMatches(template, actual string) bool {
	if template == "" || actual == "" {
		return false
	}
	if i := strings.IndexByte(template, '?'); i >= 0 {
		template = template[:i]
	}
	if template == "/" {
		return actual == "/"
	}
	t := strings.Split(strings.Trim(template, "/"), "/")
	a := strings.Split(strings.Trim(actual, "/"), "/")
	if len(t) != len(a) {
		return false
	}
	for i := range t {
		if strings.HasPrefix(t[i], "{") && strings.HasSuffix(t[i], "}") {
			continue
		}
		if t[i] != a[i] {
			return false
		}
	}
	return true
}

// Lookup is retained for metadata clients. The production mapper deliberately
// does not use this name-only compatibility method.
func (a *Adapter) Lookup(service, operation string, parameters ...map[string]awsrequest.Value) (LookupResult, error) {
	if a == nil || a.catalog == nil {
		return LookupResult{}, fmt.Errorf("adapter unavailable")
	}
	if len(parameters) > 1 {
		return LookupResult{}, fmt.Errorf("too many parameter maps")
	}
	op := NormalizeOperation(operation)
	if op == "" {
		return LookupResult{}, fmt.Errorf("unknown operation")
	}
	var records []iamlivecatalog.Operation
	for _, s := range a.catalog.Services() {
		if !strings.EqualFold(s.EndpointPrefix, service) {
			continue
		}
		for _, o := range s.Operations {
			if strings.EqualFold(o.Name, op) {
				records = append(records, o)
			}
		}
	}
	if len(records) != 1 {
		return LookupResult{}, fmt.Errorf("ambiguous operation")
	}
	var p map[string]awsrequest.Value
	if len(parameters) == 1 {
		p = parameters[0]
	}
	return a.lookupOperation(service, records[0], p)
}

type mappingRecord struct {
	index        int
	action       Action
	definition   iamlivecatalog.ActionDefinition
	mapping      iamlivecatalog.ActionMapping
	inapplicable bool
	dependent    bool
}

func (a *Adapter) lookupOperation(service string, operation iamlivecatalog.Operation, parameters map[string]awsrequest.Value) (LookupResult, error) {
	if operation.State != iamlivecatalog.EvidenceKnown {
		return LookupResult{}, fmt.Errorf("operation evidence unavailable: %s", operation.State)
	}
	if operation.MappingState != iamlivecatalog.EvidenceKnown || len(operation.Mappings) == 0 {
		return LookupResult{}, fmt.Errorf("operation mapping evidence unavailable: %s", operation.MappingState)
	}
	records := make([]mappingRecord, 0, len(operation.Mappings))
	for i, raw := range operation.Mappings {
		if raw.State != iamlivecatalog.EvidenceKnown {
			return LookupResult{}, fmt.Errorf("mapping action evidence unavailable: %s", raw.State)
		}
		action, ok := parseAction(raw.Action)
		if !ok {
			return LookupResult{}, fmt.Errorf("malformed action mapping")
		}
		definition, err := a.catalog.Action(raw.Action)
		if err != nil || definition.State != iamlivecatalog.EvidenceKnown {
			return LookupResult{}, fmt.Errorf("action definition evidence unavailable: %s", raw.Action)
		}
		state := conditionTrue
		if raw.Condition != nil {
			state = evaluateCondition(raw.Condition, parameters)
		}
		if state == conditionUnknown {
			return LookupResult{}, fmt.Errorf("mapping condition evidence unavailable: %s", raw.Action)
		}
		records = append(records, mappingRecord{index: i, action: action, definition: definition, mapping: raw, inapplicable: state == conditionFalse})
	}
	roots := findRoots(records)
	if len(roots) == 0 {
		return LookupResult{}, fmt.Errorf("mapping has no primary action")
	}
	if err := a.validateGraph(records, roots, parameters); err != nil {
		return LookupResult{}, err
	}

	var primary []Action
	var entries []data.Entry
	var dependencies []DependencyCandidate
	var allDefinitionDeps []string
	certain := true
	for _, root := range roots {
		primary = append(primary, root.action)
		entry := entryForAction(root.action, root.definition, operation.Name, root.mapping)
		entry.Service = strings.ToLower(service)
		entry.Operation = operation.Name
		entries = append(entries, entry)
		allDefinitionDeps = append(allDefinitionDeps, entry.Dependencies...)
	}
	for _, record := range records {
		if !record.dependent {
			continue
		}
		if record.inapplicable {
			// Keep this occurrence: the mapper must account for an absent optional
			// dependency rather than silently dropping a raw catalog edge.
			dependencies = append(dependencies, DependencyCandidate{Action: record.action, ParameterNames: dependencyParameterNames(record.mapping), ProvenInapplicable: true})
			continue
		}
		values, state := dependencyValues(record.mapping, parameters)
		switch state {
		case dependencyFalse:
			dependencies = append(dependencies, DependencyCandidate{Action: record.action, ParameterNames: dependencyParameterNames(record.mapping), ProvenInapplicable: true})
		case dependencyUnknown:
			certain = false
			dependencies = append(dependencies, DependencyCandidate{Action: record.action, ParameterNames: dependencyParameterNames(record.mapping)})
		case dependencyTrue:
			if len(values) == 0 {
				certain = false
				dependencies = append(dependencies, DependencyCandidate{Action: record.action, ParameterNames: dependencyParameterNames(record.mapping)})
				continue
			}
			for _, value := range values {
				dependencies = append(dependencies, DependencyCandidate{Action: record.action, Resources: []string{value}, ParameterNames: dependencyParameterNames(record.mapping)})
			}
		}
	}
	entry := data.Entry{Service: strings.ToLower(service), Operation: operation.Name, Dependencies: append([]string(nil), allDefinitionDeps...)}
	if len(entries) > 0 {
		entry = entries[0]
		entry.Dependencies = append([]string(nil), allDefinitionDeps...)
	}
	return LookupResult{Entry: entry, Primary: primary, PrimaryEntries: entries, Dependencies: dependencies, DependenciesCertain: certain}, nil
}

func parseAction(value string) (Action, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(value, " \t\r\n") {
		return Action{}, false
	}
	return Action{Service: parts[0], Name: parts[1]}, true
}
func actionKey(action Action) string {
	return strings.ToLower(action.Service) + ":" + strings.ToLower(action.Name)
}
func definitionEdges(definition iamlivecatalog.ActionDefinition) []string {
	var out []string
	for _, r := range definition.Resources {
		out = append(out, r.DependentActions...)
	}
	return out
}

func findRoots(records []mappingRecord) []mappingRecord {
	possible := map[string]bool{}
	for _, r := range records {
		for _, edge := range definitionEdges(r.definition) {
			if target, ok := parseAction(edge); ok {
				possible[actionKey(target)] = true
			}
		}
	}
	var roots []mappingRecord
	for i := range records {
		// Classify the raw occurrence from graph evidence before applying its
		// condition. An inapplicable dependent occurrence still accounts for an
		// edge and must be emitted as inapplicable evidence.
		records[i].dependent = possible[actionKey(records[i].action)]
		if records[i].inapplicable {
			continue
		}
		if !records[i].dependent {
			roots = append(roots, records[i])
		}
	}
	return roots
}

// validateGraph ensures all definitions reachable from the selected primary
// records are known, acyclic, and represented by raw mapping occurrences.
func (a *Adapter) validateGraph(records []mappingRecord, roots []mappingRecord, parameters map[string]awsrequest.Value) error {
	colors := map[string]uint8{}
	var visit func(Action, iamlivecatalog.ActionDefinition) error
	visit = func(action Action, definition iamlivecatalog.ActionDefinition) error {
		key := actionKey(action)
		if colors[key] == 1 {
			return fmt.Errorf("dependent action cycle: %s", key)
		}
		if colors[key] == 2 {
			return nil
		}
		colors[key] = 1
		for _, raw := range definitionEdges(definition) {
			target, ok := parseAction(raw)
			if !ok {
				return fmt.Errorf("malformed dependent action %q", raw)
			}
			td, err := a.catalog.Action(raw)
			if err != nil || td.State != iamlivecatalog.EvidenceKnown {
				return fmt.Errorf("unknown or contradictory dependent action %q", raw)
			}
			if err := visit(target, td); err != nil {
				return err
			}
		}
		colors[key] = 2
		return nil
	}
	for _, root := range roots {
		if err := visit(root.action, root.definition); err != nil {
			return err
		}
	}

	used := map[int]bool{}
	for _, r := range records {
		if r.inapplicable {
			used[r.index] = true
		}
	}
	for _, root := range roots {
		used[root.index] = true
	}
	inactive := map[string]int{}
	for _, r := range records {
		if r.dependent && mappingInapplicable(r.mapping, parameters) {
			inactive[actionKey(r.action)]++
			used[r.index] = true
		}
	}

	var match func(Action, iamlivecatalog.ActionDefinition) error
	match = func(source Action, definition iamlivecatalog.ActionDefinition) error {
		for _, raw := range definitionEdges(definition) {
			target, ok := parseAction(raw)
			if !ok {
				return fmt.Errorf("malformed dependent action %q", raw)
			}
			var found []int
			for _, r := range records {
				if r.dependent && !used[r.index] && actionKey(r.action) == actionKey(target) && !mappingInapplicable(r.mapping, parameters) {
					found = append(found, r.index)
				}
			}
			if len(found) == 0 {
				if inactive[actionKey(target)] > 0 {
					inactive[actionKey(target)]--
					continue
				}
				return fmt.Errorf("missing dependent action mapping %s -> %s", actionKey(source), actionKey(target))
			}
			if len(found) > 1 {
				for _, i := range found {
					for _, r := range records {
						if r.index == i && !conditionalMapping(r.mapping) {
							return fmt.Errorf("dependent mapping multiplicity disagrees: %s", actionKey(target))
						}
					}
				}
			}
			for _, i := range found {
				used[i] = true
				for _, r := range records {
					if r.index == i {
						if err := match(r.action, r.definition); err != nil {
							return err
						}
						break
					}
				}
			}
		}
		return nil
	}
	for _, root := range roots {
		if err := match(root.action, root.definition); err != nil {
			return err
		}
	}
	for _, r := range records {
		if !used[r.index] {
			return fmt.Errorf("extra dependent/action mapping occurrence %s", actionKey(r.action))
		}
	}
	return nil
}

func conditionalMapping(mapping iamlivecatalog.ActionMapping) bool {
	return mapping.Condition != nil || strings.Contains(strings.ToLower(mapping.ARNOverride), "iftruthy")
}
func mappingInapplicable(mapping iamlivecatalog.ActionMapping, parameters map[string]awsrequest.Value) bool {
	_, state := dependencyValues(mapping, parameters)
	return state == dependencyFalse
}

type conditionState uint8

const (
	conditionUnknown conditionState = iota
	conditionFalse
	conditionTrue
)

func evaluateCondition(condition *iamlivecatalog.Condition, parameters map[string]awsrequest.Value) conditionState {
	if condition == nil {
		return conditionTrue
	}
	values, present, valid := pathValues(parameters, condition.LHS)
	if !valid {
		return conditionUnknown
	}
	var result bool
	switch strings.ToLower(condition.Op) {
	case "exists":
		result = present
	case "notexists":
		result = !present
	case "equals":
		result = present && anyString(values, func(v string) bool { return v == condition.RHS })
	case "notequals":
		result = !present || !anyString(values, func(v string) bool { return v == condition.RHS })
	case "contains":
		result = present && anyString(values, func(v string) bool { return strings.Contains(v, condition.RHS) })
	case "icontains":
		result = present && anyString(values, func(v string) bool { return strings.Contains(strings.ToLower(v), strings.ToLower(condition.RHS)) })
	case "startswith":
		result = present && anyString(values, func(v string) bool { return strings.HasPrefix(v, condition.RHS) })
	case "notstartswith":
		result = !present || !anyString(values, func(v string) bool { return strings.HasPrefix(v, condition.RHS) })
	default:
		return conditionUnknown
	}
	if condition.And != nil {
		right := evaluateCondition(condition.And, parameters)
		if right == conditionUnknown {
			return conditionUnknown
		}
		if right == conditionFalse || !result {
			return conditionFalse
		}
	}
	if result {
		return conditionTrue
	}
	return conditionFalse
}
func anyString(values []string, predicate func(string) bool) bool {
	for _, v := range values {
		if predicate(v) {
			return true
		}
	}
	return false
}
func pathValues(root map[string]awsrequest.Value, path string) ([]string, bool, bool) {
	if path == "" {
		return nil, false, false
	}
	current := []awsrequest.Value{{Kind: awsrequest.ValueObject, Object: root}}
	for n, part := range strings.Split(path, ".") {
		array := strings.HasSuffix(part, "[]")
		name := strings.TrimSuffix(part, "[]")
		var next []awsrequest.Value
		for _, parent := range current {
			if parent.Kind != awsrequest.ValueObject {
				return nil, false, false
			}
			for key, value := range parent.Object {
				if strings.EqualFold(key, name) {
					next = append(next, value)
				}
			}
		}
		if len(next) == 0 {
			return nil, false, true
		}
		if array {
			var expanded []awsrequest.Value
			for _, value := range next {
				if value.Kind != awsrequest.ValueArray {
					return nil, false, false
				}
				expanded = append(expanded, value.Array...)
			}
			next = expanded
		}
		if n == len(strings.Split(path, "."))-1 {
			out := []string{}
			for _, value := range next {
				if value.Kind != awsrequest.ValueString {
					return nil, false, false
				}
				out = append(out, value.String)
			}
			return out, len(out) > 0, true
		}
		current = next
	}
	return nil, false, true
}

func entryForAction(action Action, definition iamlivecatalog.ActionDefinition, operation string, mapping iamlivecatalog.ActionMapping) data.Entry {
	entry := data.Entry{Service: strings.ToLower(action.Service), Operation: operation, Action: action.Service + ":" + action.Name, Resource: "global", Scope: "known_global"}
	var named []string
	for _, resource := range definition.Resources {
		entry.Dependencies = append(entry.Dependencies, resource.DependentActions...)
		if resource.Name != "" {
			named = append(named, resource.Name)
		}
	}
	if strings.EqualFold(action.Service, "dynamodb") && operation == "BatchExecuteStatement" && mapping.Condition != nil {
		entry.Resource = "table*"
		entry.Scope = "exact"
	} else if len(named) == 1 {
		entry.Resource = named[0]
		entry.Scope = "exact"
	} else if len(named) > 1 {
		params := map[string]bool{}
		for _, resource := range mapping.Resources {
			params[strings.ToLower(resource.Parameter)] = true
		}
		for _, name := range named {
			n := strings.ToLower(strings.TrimSuffix(name, "*"))
			if n == "object" && (params["key"] || params["objectname"]) {
				entry.Resource = name
				entry.Scope = "exact"
				break
			}
			if n == "table" && params["tablename"] {
				entry.Resource = name
				entry.Scope = "exact"
				break
			}
			if n == "task-definition" && (params["taskdefinition"] || params["taskdefinitionfamilyname"]) {
				entry.Resource = name
				entry.Scope = "exact"
				break
			}
			if n == "log-stream" && (params["logstreamname"] || params["loggroupname"]) {
				entry.Resource = name
				entry.Scope = "exact"
				break
			}
		}
		if entry.Resource == "global" {
			entry.Scope = "unresolved"
		}
	}
	return entry
}

func dependencyParameterNames(mapping iamlivecatalog.ActionMapping) []string {
	var names []string
	for _, template := range append([]string{mapping.ARNOverride}, resourceTemplates(mapping)...) {
		names = append(names, templateNames(template)...)
	}
	if len(names) == 0 {
		names = []string{"Role", "RoleArn", "TaskRoleArn", "ExecutionRoleArn", "IamRoleArn"}
	}
	return uniqueStrings(names)
}
func resourceTemplates(mapping iamlivecatalog.ActionMapping) []string {
	var out []string
	for _, r := range mapping.Resources {
		out = append(out, r.Template)
	}
	for _, r := range mapping.ConditionMappings {
		out = append(out, r.Template)
	}
	return out
}
func dependencyValues(mapping iamlivecatalog.ActionMapping, parameters map[string]awsrequest.Value) ([]string, dependencyState) {
	if mapping.Condition != nil {
		state := evaluateCondition(mapping.Condition, parameters)
		if state == conditionFalse {
			return nil, dependencyFalse
		}
		if state == conditionUnknown {
			return nil, dependencyUnknown
		}
	}
	names := dependencyParameterNames(mapping)
	var values []string
	if mapping.ARNOverride != "" {
		values = templateValues(mapping.ARNOverride, parameters)
	} else {
		for _, template := range resourceTemplates(mapping) {
			values = append(values, templateValues(template, parameters)...)
		}
	}
	if strings.Contains(strings.ToLower(mapping.ARNOverride), "iftruthy") {
		if invalidNamedValue(parameters, names...) {
			return nil, dependencyUnknown
		}
		if len(Find(parameters, names...)) == 0 {
			return nil, dependencyFalse
		}
	}
	if len(values) == 0 {
		return nil, dependencyUnknown
	}
	return values, dependencyTrue
}
func dependencyParameterNamesDummy() {}

func invalidNamedValue(parameters map[string]awsrequest.Value, names ...string) bool {
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[strings.ToLower(name)] = true
	}
	var walk func(map[string]awsrequest.Value, int) bool
	walk = func(values map[string]awsrequest.Value, depth int) bool {
		if depth > 16 {
			return true
		}
		for key, value := range values {
			if wanted[strings.ToLower(key)] && value.Kind != awsrequest.ValueString {
				return true
			}
			if value.Kind == awsrequest.ValueObject && walk(value.Object, depth+1) {
				return true
			}
			if value.Kind == awsrequest.ValueArray {
				for _, item := range value.Array {
					if item.Kind == awsrequest.ValueObject && walk(item.Object, depth+1) {
						return true
					}
				}
			}
		}
		return false
	}
	return walk(parameters, 0)
}

type dependencyState uint8

const (
	dependencyUnknown dependencyState = iota
	dependencyFalse
	dependencyTrue
)

func templateValues(template string, parameters map[string]awsrequest.Value) []string {
	var out []string
	for _, name := range templateNames(template) {
		out = append(out, Find(parameters, name)...)
	}
	return out
}
func templateNames(template string) []string {
	var out []string
	for {
		i := strings.Index(template, "${")
		if i < 0 {
			break
		}
		template = template[i+2:]
		j := strings.IndexByte(template, '}')
		if j < 0 {
			break
		}
		name := template[:j]
		if k := strings.LastIndexAny(name, ".[]"); k >= 0 {
			name = name[k+1:]
		}
		if name != "" {
			out = append(out, name)
		}
		template = template[j+1:]
	}
	return uniqueStrings(out)
}
func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		key := strings.ToLower(value)
		if value != "" && !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}

func (a *Adapter) LookupOperation(service, operation string) (string, data.Entry, error) {
	result, err := a.Lookup(service, operation)
	if err != nil {
		return "", data.Entry{}, err
	}
	return result.Entry.Operation, result.Entry, nil
}
func (a *Adapter) Version() string {
	if a == nil || a.catalog == nil {
		return ""
	}
	return AdapterVersion
}
func (a *Adapter) DataVersion() string {
	if a == nil || a.catalog == nil {
		return ""
	}
	return data.AuthorizationDataVersion()
}
func (a *Adapter) Map(context.Context, *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	return nil, fmt.Errorf("iamlive adapter is metadata-only; use kordn mapper")
}

func Find(values map[string]awsrequest.Value, names ...string) []string {
	want := map[string]bool{}
	for _, name := range names {
		want[strings.ToLower(name)] = true
	}
	var out []string
	var walk func(string, awsrequest.Value, int)
	walk = func(key string, value awsrequest.Value, depth int) {
		if depth > 16 {
			return
		}
		if value.Kind == awsrequest.ValueString && want[strings.ToLower(key)] && value.String != "" {
			out = append(out, value.String)
		}
		if value.Kind == awsrequest.ValueObject {
			for k, v := range value.Object {
				walk(k, v, depth+1)
			}
		}
		if value.Kind == awsrequest.ValueArray {
			for _, item := range value.Array {
				if item.Kind == awsrequest.ValueObject {
					for k, v := range item.Object {
						walk(k, v, depth+1)
					}
				}
			}
		}
	}
	for key, value := range values {
		walk(key, value, 0)
	}
	return out
}
