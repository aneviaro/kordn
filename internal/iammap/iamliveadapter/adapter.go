package iamliveadapter

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
	"github.com/kordn-ai/kordn/internal/iammap/data"
)

// UpstreamCommit is the exact iamlive revision consumed by the adapter.
const UpstreamCommit = iamlivecatalog.UpstreamCommit

// AdapterVersion identifies the request-aware adapter contract and its exact
// upstream evidence pin.
const AdapterVersion = "iamlive-derived/v3@" + UpstreamCommit

// FailureKind identifies bounded adapter evidence failures.
type FailureKind uint8

const (
	FailureUnknownWireOperation FailureKind = iota + 1
	FailureAmbiguousWireOperation
	FailureIncompleteWireIdentity
	FailureCatalogInconsistency
	FailureUnresolvedApplicability
	FailureUnresolvedDependency
)

// Failure is a typed, bounded adapter failure. It deliberately omits service,
// operation, parameters, and catalog diagnostic text from its wire-facing
// message while retaining a cause for semantic matching by the mapper.
type Failure struct {
	Kind   FailureKind
	cause  error
	static bool
	detail string
}

func (f *Failure) Error() string {
	if f == nil {
		return "adapter failure"
	}
	if f.static {
		if f.detail != "" {
			return "static catalog validation failed: " + safeFailureDetail(f.detail)
		}
		return "static catalog validation failed"
	}
	switch f.Kind {
	case FailureUnknownWireOperation:
		return "unknown operation"
	case FailureAmbiguousWireOperation:
		return "ambiguous operation"
	case FailureIncompleteWireIdentity:
		return "incomplete wire identity"
	case FailureCatalogInconsistency:
		return "catalog inconsistency"
	case FailureUnresolvedApplicability:
		return "unresolved applicability"
	case FailureUnresolvedDependency:
		return "unresolved dependency"
	default:
		return "adapter failure"
	}
}

// SafeDetail returns a bounded static-catalog label for policy diagnostics.
// It never returns request-derived evidence.
func (f *Failure) SafeDetail() string {
	if f == nil || !f.static {
		return ""
	}
	return safeFailureDetail(f.detail)
}

func safeFailureDetail(value string) string {
	if len(value) > 96 {
		value = value[:96]
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != ':' && r != '-' && r != '_' && r != ' ' {
			return "catalog evidence"
		}
	}
	return value
}
func (f *Failure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.cause
}
func adapterFailure(kind FailureKind, cause error) error { return &Failure{Kind: kind, cause: cause} }
func adapterStaticFailure(kind FailureKind, detail string) error {
	return &Failure{Kind: kind, static: true, detail: detail}
}

type Action struct{ Service, Name string }

// catalogDependency is the immutable, narrow catalog view needed by this
// consumer. Static plans are compiled before publication and copied at the
// catalog boundary.
type catalogDependency interface {
	OperationOccurrences(string, string) []iamlivecatalog.OperationOccurrence
}

type Adapter struct{ catalog catalogDependency }

func New() (*Adapter, error) {
	c, err := iamlivecatalog.Load()
	if err != nil {
		return nil, err
	}
	return &Adapter{catalog: catalogDependency(c)}, nil
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
	return a.LookupRequestContext(context.Background(), service, operation, identity, parameters)
}

// LookupRequestContext performs bounded wire selection and request-dependent
// evaluation under the caller's context. Static plan evidence is never
// rebuilt or mutated here.
func (a *Adapter) LookupRequestContext(ctx context.Context, service, operation string, identity WireIdentity, parameters map[string]awsrequest.Value) (LookupResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return LookupResult{}, err
	}
	if a == nil || a.catalog == nil {
		return LookupResult{}, adapterFailure(FailureCatalogInconsistency, nil)
	}
	op := NormalizeOperation(operation)
	if op == "" || !identity.Protocol.Supported() || strings.TrimSpace(identity.Method) == "" || identity.Path == "" {
		return LookupResult{}, adapterFailure(FailureIncompleteWireIdentity, nil)
	}
	occurrences := a.catalog.OperationOccurrences(service, op)
	selected := make([]iamlivecatalog.OperationOccurrence, 0, len(occurrences))
	for _, occurrence := range occurrences {
		if err := ctx.Err(); err != nil {
			return LookupResult{}, err
		}
		record := occurrence.Operation
		if record.State != iamlivecatalog.EvidenceKnown {
			continue
		}
		protocol, ok := recordProtocol(occurrence.Service.Protocol, record.Route.JSONVersion)
		if !ok || protocol != identity.Protocol {
			continue
		}
		if !routeMatches(record, occurrence.Service, op, identity) {
			continue
		}
		// OperationOccurrences already deep-copies the selected evidence. Keep
		// only matching records so request work remains bounded to this bucket.
		selected = append(selected, occurrence)
	}
	if len(selected) != 1 {
		if len(selected) == 0 {
			return LookupResult{}, adapterFailure(FailureUnknownWireOperation, nil)
		}
		return LookupResult{}, adapterFailure(FailureAmbiguousWireOperation, nil)
	}
	return a.lookupOperationContext(ctx, service, selected[0].Operation, selected[0].Plan, parameters)
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

func routeMatches(record iamlivecatalog.Operation, service iamlivecatalog.WireService, operation string, id WireIdentity) bool {
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
		_, ok, err := awsrequest.MatchRESTRoute(
			record.Route.URI,
			id.Path,
			id.Query,
			record.QueryBindings,
			awsrequest.DefaultDecodeLimits(),
		)
		return err == nil && ok
	}
	return false
}

func jsonVersion(p awsrequest.AWSProtocol) string {
	if p == awsrequest.ProtocolJSON10 {
		return "1.0"
	}
	return "1.1"
}

// Lookup is retained for metadata clients. The production mapper deliberately
// does not use this name-only compatibility method.
func (a *Adapter) Lookup(service, operation string, parameters ...map[string]awsrequest.Value) (LookupResult, error) {
	if a == nil || a.catalog == nil {
		return LookupResult{}, adapterFailure(FailureCatalogInconsistency, nil)
	}
	if len(parameters) > 1 {
		return LookupResult{}, adapterFailure(FailureIncompleteWireIdentity, nil)
	}
	op := NormalizeOperation(operation)
	if op == "" {
		return LookupResult{}, adapterFailure(FailureUnknownWireOperation, nil)
	}
	occurrences := a.catalog.OperationOccurrences(service, op)
	if len(occurrences) == 0 {
		return LookupResult{}, adapterFailure(FailureUnknownWireOperation, nil)
	}
	if len(occurrences) > 1 {
		return LookupResult{}, adapterFailure(FailureAmbiguousWireOperation, nil)
	}
	var p map[string]awsrequest.Value
	if len(parameters) == 1 {
		p = parameters[0]
	}
	return a.lookupOperation(service, occurrences[0].Operation, occurrences[0].Plan, p)
}

type mappingRecord struct {
	id           uint32
	definitionID uint32
	action       Action
	definition   iamlivecatalog.ActionDefinition
	mapping      iamlivecatalog.ActionMapping
	inapplicable bool
	dependent    bool
}

func runtimePlanUsable(plan iamlivecatalog.StaticPlan) bool { return plan.Valid() }

func runtimePlanFailure(plan iamlivecatalog.StaticPlan) (FailureKind, string) {
	for _, diagnostic := range plan.Diagnostics {
		// These are structured catalog validation facts, not request text. A
		// dependency diagnostic must retain precedence over a generic plan
		// failure so policy receives the stable dependent reason.
		if diagnostic.Detail == "missing dependent action mapping occurrence" || diagnostic.RelatedAction != "" {
			return FailureUnresolvedDependency, diagnostic.Action
		}
		if diagnostic.Detail == "mapping has no primary action" {
			return FailureUnresolvedApplicability, ""
		}
	}
	return FailureCatalogInconsistency, ""
}

func (a *Adapter) lookupOperation(service string, operation iamlivecatalog.Operation, plan iamlivecatalog.StaticPlan, parameters map[string]awsrequest.Value) (LookupResult, error) {
	return a.lookupOperationContext(context.Background(), service, operation, plan, parameters)
}

func (a *Adapter) lookupOperationContext(ctx context.Context, service string, operation iamlivecatalog.Operation, plan iamlivecatalog.StaticPlan, parameters map[string]awsrequest.Value) (LookupResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return LookupResult{}, err
	}
	if !runtimePlanUsable(plan) {
		kind, detail := runtimePlanFailure(plan)
		return LookupResult{}, adapterStaticFailure(kind, detail)
	}
	if operation.State != iamlivecatalog.EvidenceKnown || operation.MappingState != iamlivecatalog.EvidenceKnown || len(plan.Mappings) == 0 {
		return LookupResult{}, adapterFailure(FailureCatalogInconsistency, nil)
	}
	records := make([]mappingRecord, 0, len(plan.Mappings))
	var roots []mappingRecord
	definitionIDs := map[string]uint32{}
	var nextDefinitionID uint32 = 1
	for index, compiled := range plan.Mappings {
		if err := ctx.Err(); err != nil {
			return LookupResult{}, err
		}
		raw := compiled.Mapping
		if compiled.Action.Service == "" || compiled.Action.Name == "" {
			return LookupResult{}, adapterFailure(FailureCatalogInconsistency, nil)
		}
		action := Action{Service: compiled.Action.Service, Name: compiled.Action.Name}
		state := conditionTrue
		if raw.Condition != nil {
			state = evaluateCondition(ctx, raw.Condition, parameters)
		}
		if state == conditionUnknown {
			return LookupResult{}, adapterFailure(FailureUnresolvedApplicability, nil)
		}
		id := compiled.Occurrence()
		if id == 0 {
			id = uint32(index + 1)
		}
		definitionKey := strings.ToLower(action.Service) + "\x00" + strings.ToLower(action.Name)
		definitionID := definitionIDs[definitionKey]
		if definitionID == 0 {
			definitionID = nextDefinitionID
			nextDefinitionID++
			definitionIDs[definitionKey] = definitionID
		}
		record := mappingRecord{id: id, definitionID: definitionID, action: action, definition: compiled.Definition, mapping: raw, inapplicable: state == conditionFalse, dependent: compiled.Dependent}
		records = append(records, record)
		if !compiled.Dependent && !record.inapplicable {
			roots = append(roots, record)
		}
	}
	if len(roots) == 0 {
		// All primary mappings were proven inapplicable for this request. This
		// is request-dependent unresolved applicability, not a static catalog
		// defect.
		return LookupResult{}, adapterFailure(FailureUnresolvedApplicability, nil)
	}

	var primaryOccurrences []PrimaryOccurrence
	var dependencyOccurrences []DependencyOccurrence
	// Static validation guarantees that every dependent mapping occurrence has
	// one corresponding definition edge. Keep a local occurrence address for
	// that edge rather than collapsing duplicate edges by action name.
	edgeIDs := map[string][]uint32{}
	var nextEdgeID uint32 = 1
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return LookupResult{}, err
		}
		for _, resource := range root.definition.Resources {
			if err := ctx.Err(); err != nil {
				return LookupResult{}, err
			}
			for _, dependency := range resource.DependentActions {
				key := strings.ToLower(dependency)
				edgeIDs[key] = append(edgeIDs[key], nextEdgeID)
				nextEdgeID++
			}
		}
	}
	edgeIndexes := map[string]int{}
	operationID := plan.Occurrence
	if operationID == 0 {
		operationID = 1
	}
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return LookupResult{}, err
		}
		entry := entryForAction(root.action, root.definition, operation.Name, root.mapping)
		entry.Service = strings.ToLower(service)
		entry.Operation = operation.Name
		primaryOccurrences = append(primaryOccurrences, PrimaryOccurrence{
			ID: root.id, OperationID: operationID, DefinitionID: root.definitionID, Operation: operation.Name, Action: root.action,
			Mapping: root.mapping.Clone(), Definition: root.definition.Clone(),
			ResourceType:           entry.Resource,
			ResourceTypeOccurrence: resourceTypeOccurrence(root.definition, entry.Resource), Scope: entry.Scope,
			DefinitionDependencies: append([]string(nil), entry.Dependencies...),
		})
	}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return LookupResult{}, err
		}
		if !record.dependent {
			continue
		}
		parameterNames := dependencyParameterNames(ctx, record.mapping)
		if err := ctx.Err(); err != nil {
			return LookupResult{}, err
		}
		dependencyKey := strings.ToLower(record.action.Service) + ":" + strings.ToLower(record.action.Name)
		edgeIndex := edgeIndexes[dependencyKey]
		var edgeID uint32
		if edgeIndex < len(edgeIDs[dependencyKey]) {
			edgeID = edgeIDs[dependencyKey][edgeIndex]
			edgeIndexes[dependencyKey] = edgeIndex + 1
		}
		if edgeID == 0 {
			// A direct test seam may provide a deliberately duplicated mapping
			// occurrence without rebuilding the compiled edge multiset. Keep its
			// identity distinct; production plans are checked by dependencies.
			edgeID = nextEdgeID
			nextEdgeID++
		}
		occurrence := DependencyOccurrence{ID: record.id, OperationID: operationID, DefinitionID: record.definitionID, DefinitionEdgeID: edgeID, MappingID: record.id, Action: record.action, ParameterNames: append([]string(nil), parameterNames...)}
		if record.inapplicable {
			// Preserve proven-inapplicable occurrences as evidence.
			occurrence.Applicability = ApplicabilityInapplicable
			dependencyOccurrences = append(dependencyOccurrences, occurrence)
			continue
		}
		values, state := dependencyValues(ctx, record.mapping, parameters)
		if err := ctx.Err(); err != nil {
			return LookupResult{}, err
		}
		switch state {
		case dependencyFalse:
			occurrence.Applicability = ApplicabilityInapplicable
		case dependencyUnknown:
			occurrence.Applicability = ApplicabilityUnknown
		case dependencyTrue:
			if len(values) == 0 {
				occurrence.Applicability = ApplicabilityUnknown
				break
			}
			occurrence.Resources = append([]string(nil), values...)
			occurrence.Applicability = ApplicabilityApplicable
		}
		dependencyOccurrences = append(dependencyOccurrences, occurrence)
	}
	return LookupResult{Operation: operation.Name, PrimaryOccurrences: primaryOccurrences, DependencyOccurrences: dependencyOccurrences}, nil
}

type conditionState uint8

const (
	conditionUnknown conditionState = iota
	conditionFalse
	conditionTrue
)

func evaluateCondition(ctx context.Context, condition *iamlivecatalog.Condition, parameters map[string]awsrequest.Value) conditionState {
	if condition == nil {
		return conditionTrue
	}
	if ctx != nil && ctx.Err() != nil {
		return conditionUnknown
	}
	values, present, valid := pathValues(ctx, parameters, condition.LHS)
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
		result = present && anyString(ctx, values, func(v string) bool { return v == condition.RHS })
	case "notequals":
		result = !present || !anyString(ctx, values, func(v string) bool { return v == condition.RHS })
	case "contains":
		result = present && anyString(ctx, values, func(v string) bool { return strings.Contains(v, condition.RHS) })
	case "icontains":
		result = present && anyString(ctx, values, func(v string) bool { return strings.Contains(strings.ToLower(v), strings.ToLower(condition.RHS)) })
	case "startswith":
		result = present && anyString(ctx, values, func(v string) bool { return strings.HasPrefix(v, condition.RHS) })
	case "notstartswith":
		result = !present || !anyString(ctx, values, func(v string) bool { return strings.HasPrefix(v, condition.RHS) })
	default:
		return conditionUnknown
	}
	if condition.And != nil {
		right := evaluateCondition(ctx, condition.And, parameters)
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
func anyString(ctx context.Context, values []string, predicate func(string) bool) bool {
	for _, v := range values {
		if ctx != nil && ctx.Err() != nil {
			return false
		}
		if predicate(v) {
			return true
		}
	}
	return false
}
func pathValues(ctx context.Context, root map[string]awsrequest.Value, path string) ([]string, bool, bool) {
	if path == "" {
		return nil, false, false
	}
	current := []awsrequest.Value{{Kind: awsrequest.ValueObject, Object: root}}
	for n, part := range strings.Split(path, ".") {
		if ctx != nil && ctx.Err() != nil {
			return nil, false, false
		}
		array := strings.HasSuffix(part, "[]")
		name := strings.TrimSuffix(part, "[]")
		var next []awsrequest.Value
		for _, parent := range current {
			if ctx != nil && ctx.Err() != nil {
				return nil, false, false
			}
			if parent.Kind != awsrequest.ValueObject {
				return nil, false, false
			}
			for key, value := range parent.Object {
				if ctx != nil && ctx.Err() != nil {
					return nil, false, false
				}
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
				if ctx != nil && ctx.Err() != nil {
					return nil, false, false
				}
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
				if ctx != nil && ctx.Err() != nil {
					return nil, false, false
				}
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
		matches := []string{}
		for _, name := range named {
			n := strings.ToLower(strings.TrimSuffix(name, "*"))
			matched := (n == "object" && (params["key"] || params["objectname"])) ||
				(n == "table" && params["tablename"]) ||
				(n == "task-definition" && (params["taskdefinition"] || params["taskdefinitionfamilyname"])) ||
				(n == "log-stream" && (params["logstreamname"] || params["loggroupname"]))
			if matched {
				matches = append(matches, name)
			}
		}
		if len(matches) == 1 {
			entry.Resource = matches[0]
			entry.Scope = "exact"
		} else {
			// Multiple matching resource types are ambiguous; absence and
			// ambiguity are both represented as unresolved, never as global.
			entry.Scope = "unresolved"
		}
	} else if len(definition.Resources) > 1 {
		// Multiple unnamed resource occurrences cannot safely be represented as
		// one known-global resource. Keep the scope unresolved instead.
		entry.Scope = "unresolved"
	}
	return entry
}

func resourceTypeOccurrence(definition iamlivecatalog.ActionDefinition, resource string) uint32 {
	want := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(resource)), "*")
	for index, candidate := range definition.Resources {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(candidate.Name)), "*")
		if want != "" && name == want {
			return uint32(index + 1)
		}
	}
	if len(definition.Resources) == 1 {
		return 1
	}
	return 0
}

func dependencyParameterNames(ctx context.Context, mapping iamlivecatalog.ActionMapping) []string {
	var names []string
	for _, template := range append([]string{mapping.ARNOverride}, resourceTemplatesContext(ctx, mapping)...) {
		if ctx != nil && ctx.Err() != nil {
			return nil
		}
		names = append(names, templateNames(ctx, template)...)
	}
	if len(names) == 0 {
		names = []string{"Role", "RoleArn", "TaskRoleArn", "ExecutionRoleArn", "IamRoleArn"}
	}
	return uniqueStringsContext(ctx, names)
}
func resourceTemplates(mapping iamlivecatalog.ActionMapping) []string {
	return resourceTemplatesContext(context.Background(), mapping)
}
func resourceTemplatesContext(ctx context.Context, mapping iamlivecatalog.ActionMapping) []string {
	var out []string
	for _, r := range mapping.Resources {
		if ctx != nil && ctx.Err() != nil {
			return nil
		}
		out = append(out, r.Template)
	}
	for _, r := range mapping.ConditionMappings {
		if ctx != nil && ctx.Err() != nil {
			return nil
		}
		out = append(out, r.Template)
	}
	return out
}
func dependencyValues(ctx context.Context, mapping iamlivecatalog.ActionMapping, parameters map[string]awsrequest.Value) ([]string, dependencyState) {
	if ctx != nil && ctx.Err() != nil {
		return nil, dependencyUnknown
	}
	if mapping.Condition != nil {
		state := evaluateCondition(ctx, mapping.Condition, parameters)
		if state == conditionFalse {
			return nil, dependencyFalse
		}
		if state == conditionUnknown {
			return nil, dependencyUnknown
		}
	}
	names := dependencyParameterNames(ctx, mapping)
	if ctx != nil && ctx.Err() != nil {
		return nil, dependencyUnknown
	}
	var values []string
	if mapping.ARNOverride != "" {
		values = templateValues(ctx, mapping.ARNOverride, parameters)
	} else {
		for _, template := range resourceTemplatesContext(ctx, mapping) {
			if ctx != nil && ctx.Err() != nil {
				return nil, dependencyUnknown
			}
			values = append(values, templateValues(ctx, template, parameters)...)
		}
	}
	if strings.Contains(strings.ToLower(mapping.ARNOverride), "iftruthy") {
		if invalidNamedValueContext(ctx, parameters, names...) {
			return nil, dependencyUnknown
		}
		if len(FindContext(ctx, parameters, names...)) == 0 {
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
	return invalidNamedValueContext(context.Background(), parameters, names...)
}

func invalidNamedValueContext(ctx context.Context, parameters map[string]awsrequest.Value, names ...string) bool {
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
			if ctx != nil && ctx.Err() != nil {
				return true
			}
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

func templateValues(ctx context.Context, template string, parameters map[string]awsrequest.Value) []string {
	var out []string
	for _, name := range templateNames(ctx, template) {
		if ctx != nil && ctx.Err() != nil {
			return nil
		}
		out = append(out, FindContext(ctx, parameters, name)...)
	}
	return out
}
func templateNames(ctx context.Context, template string) []string {
	var out []string
	for {
		if ctx != nil && ctx.Err() != nil {
			return nil
		}
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
	return uniqueStringsContext(ctx, out)
}
func uniqueStrings(values []string) []string {
	return uniqueStringsContext(context.Background(), values)
}
func uniqueStringsContext(ctx context.Context, values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if ctx != nil && ctx.Err() != nil {
			return nil
		}
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
	if len(result.PrimaryOccurrences) == 0 {
		return "", data.Entry{}, adapterFailure(FailureCatalogInconsistency, nil)
	}
	primary := result.PrimaryOccurrences[0]
	entry := entryForAction(primary.Action, primary.Definition, result.Operation, primary.Mapping)
	entry.Resource, entry.Scope = primary.ResourceType, primary.Scope
	entry.Service = strings.ToLower(service)
	return result.Operation, entry, nil
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
	return FindContext(context.Background(), values, names...)
}

// FindContext extracts only named string evidence while observing ctx.
func FindContext(ctx context.Context, values map[string]awsrequest.Value, names ...string) []string {
	want := map[string]bool{}
	for _, name := range names {
		want[strings.ToLower(name)] = true
	}
	var out []string
	var walk func(string, awsrequest.Value, int)
	walk = func(key string, value awsrequest.Value, depth int) {
		if ctx != nil && ctx.Err() != nil {
			return
		}
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
				if ctx != nil && ctx.Err() != nil {
					return
				}
				if item.Kind == awsrequest.ValueObject {
					for k, v := range item.Object {
						walk(k, v, depth+1)
					}
				}
			}
		}
	}
	for key, value := range values {
		if ctx != nil && ctx.Err() != nil {
			return nil
		}
		walk(key, value, 0)
	}
	return out
}
