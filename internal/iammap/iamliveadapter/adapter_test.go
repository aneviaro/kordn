package iamliveadapter

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

type testCatalog struct {
	occurrences []iamlivecatalog.OperationOccurrence
	actions     map[string]iamlivecatalog.ActionDefinition
}

func (c testCatalog) OperationOccurrences(string, string) []iamlivecatalog.OperationOccurrence {
	out := make([]iamlivecatalog.OperationOccurrence, len(c.occurrences))
	for i, occurrence := range c.occurrences {
		out[i] = occurrence.Clone()
		if len(out[i].Plan.Mappings) == 0 {
			edges := map[string]bool{}
			for _, definition := range c.actions {
				for _, resource := range definition.Resources {
					for _, edge := range resource.DependentActions {
						edges[strings.ToLower(edge)] = true
					}
				}
			}
			for _, mapping := range out[i].Operation.Mappings {
				parts := strings.SplitN(mapping.Action, ":", 2)
				if len(parts) != 2 {
					continue
				}
				definition := c.actions[strings.ToLower(mapping.Action)]
				out[i].Plan.Mappings = append(out[i].Plan.Mappings, iamlivecatalog.StaticMapping{Action: iamlivecatalog.ActionReference{Service: parts[0], Name: parts[1]}, Mapping: mapping.Clone(), Definition: definition.Clone(), Dependent: edges[strings.ToLower(mapping.Action)]})
			}
			out[i].Plan.Service = "test"
			out[i].Plan.Operation = out[i].Operation.Name
		}
	}
	return out
}
func (c testCatalog) Action(name string) (iamlivecatalog.ActionDefinition, error) {
	definition, ok := c.actions[strings.ToLower(name)]
	if !ok {
		return iamlivecatalog.ActionDefinition{}, fmt.Errorf("unknown action %q", name)
	}
	return definition.Clone(), nil
}

func testOccurrence(version string, mappings []iamlivecatalog.ActionMapping) iamlivecatalog.OperationOccurrence {
	return iamlivecatalog.OperationOccurrence{
		Service: iamlivecatalog.WireService{EndpointPrefix: "test", APIVersion: version, Protocol: "query"},
		Operation: iamlivecatalog.Operation{
			Name: "Describe", State: iamlivecatalog.EvidenceKnown,
			Route:    iamlivecatalog.Route{Method: "POST"},
			Mappings: mappings, MappingState: iamlivecatalog.EvidenceKnown,
		},
	}
}

func testDefinition(service, name string, dependencies ...string) iamlivecatalog.ActionDefinition {
	return iamlivecatalog.ActionDefinition{Service: service, Name: name, State: iamlivecatalog.EvidenceKnown, Resources: []iamlivecatalog.ResourceType{{DependentActions: dependencies}}}
}

func TestLookupRequestRejectsMultipleRawMatchingOccurrences(t *testing.T) {
	mapping := iamlivecatalog.ActionMapping{Action: "test:Describe", State: iamlivecatalog.EvidenceKnown}
	a := &Adapter{catalog: testCatalog{
		occurrences: []iamlivecatalog.OperationOccurrence{testOccurrence("2020", []iamlivecatalog.ActionMapping{mapping}), testOccurrence("2020", []iamlivecatalog.ActionMapping{mapping})},
		actions:     map[string]iamlivecatalog.ActionDefinition{"test:describe": testDefinition("test", "Describe")},
	}}
	_, err := a.LookupRequest("test", "Describe", WireIdentity{Protocol: awsrequest.ProtocolQuery, Method: "POST", Path: "/", Query: url.Values{"Action": {"Describe"}, "Version": {"2020"}}}, nil)
	if err == nil || !strings.Contains(err.Error(), "ambiguous operation") {
		t.Fatalf("multiple raw matching occurrences were not rejected: %v", err)
	}
}

func TestLookupRequestSelectsExactQueryAPIVersion(t *testing.T) {
	mapping := iamlivecatalog.ActionMapping{Action: "test:Describe", State: iamlivecatalog.EvidenceKnown}
	a := &Adapter{catalog: testCatalog{
		occurrences: []iamlivecatalog.OperationOccurrence{testOccurrence("2020", []iamlivecatalog.ActionMapping{mapping}), testOccurrence("2021", []iamlivecatalog.ActionMapping{mapping})},
		actions:     map[string]iamlivecatalog.ActionDefinition{"test:describe": testDefinition("test", "Describe")},
	}}
	result, err := a.LookupRequest("test", "Describe", WireIdentity{Protocol: awsrequest.ProtocolQuery, Method: "POST", Path: "/", Query: url.Values{"Action": {"Describe"}, "Version": {"2021"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation != "Describe" || len(result.PrimaryOccurrences) != 1 || result.PrimaryOccurrences[0].Action.Name != "Describe" {
		t.Fatalf("exact query API version did not select one occurrence: %+v", result)
	}
}

func TestLookupRequestResultsAndParametersAreIndependent(t *testing.T) {
	mappings := []iamlivecatalog.ActionMapping{
		{Action: "test:Describe", State: iamlivecatalog.EvidenceKnown},
		{Action: "iam:PassRole", State: iamlivecatalog.EvidenceKnown, ARNOverride: "${RoleArn}"},
	}
	a := &Adapter{catalog: testCatalog{
		occurrences: []iamlivecatalog.OperationOccurrence{testOccurrence("2020", mappings)},
		actions: map[string]iamlivecatalog.ActionDefinition{
			"test:describe": testDefinition("test", "Describe", "iam:PassRole"),
			"iam:passrole":  testDefinition("iam", "PassRole"),
		},
	}}
	identity := WireIdentity{Protocol: awsrequest.ProtocolQuery, Method: "POST", Path: "/", Query: url.Values{"Action": {"Describe"}, "Version": {"2020"}}}
	first, err := a.LookupRequest("test", "Describe", identity, map[string]awsrequest.Value{"RoleArn": {Kind: awsrequest.ValueString, String: "arn:one"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.DependencyOccurrences) != 1 || len(first.DependencyOccurrences[0].Resources) != 1 || first.DependencyOccurrences[0].Resources[0] != "arn:one" || first.DependencyOccurrences[0].Applicability != ApplicabilityApplicable {
		t.Fatalf("unexpected first dependency: %+v", first.DependencyOccurrences)
	}
	first.DependencyOccurrences[0].Resources[0] = "mutated"
	first.PrimaryOccurrences[0].Action.Name = "mutated"
	second, err := a.LookupRequest("test", "Describe", identity, map[string]awsrequest.Value{"RoleArn": {Kind: awsrequest.ValueString, String: "arn:two"}})
	if err != nil {
		t.Fatal(err)
	}
	if second.PrimaryOccurrences[0].Action.Name != "Describe" || second.DependencyOccurrences[0].Resources[0] != "arn:two" {
		t.Fatalf("lookup results or parameter evaluation leaked across calls: %+v", second)
	}
	third, err := a.LookupRequest("test", "Describe", identity, map[string]awsrequest.Value{"RoleArn": {Kind: awsrequest.ValueString, String: "arn:one"}})
	if err != nil {
		t.Fatal(err)
	}
	if third.DependencyOccurrences[0].Resources[0] != "arn:one" {
		t.Fatalf("later lookup retained mutated result state: %+v", third)
	}
}

func TestLookupUsesPinnedActionsAndInvokesDependencies(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.LookupRequest("ec2", "DescribeInstances", WireIdentity{Protocol: awsrequest.ProtocolEC2Query, Method: "POST", Path: "/", Query: map[string][]string{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.PrimaryOccurrences) != 1 || result.PrimaryOccurrences[0].Action.Name != "DescribeInstances" || len(result.DependencyOccurrences) != 0 {
		t.Fatalf("unexpected lookup result: %+v", result)
	}
}

func TestRouteMatchesModeledRESTQueryBindings(t *testing.T) {
	record := iamlivecatalog.Operation{
		Route: iamlivecatalog.Route{Method: "GET", URI: "/bucket/{key}"},
		QueryBindings: []iamlivecatalog.QueryBinding{{
			Member: "UploadId", LocationName: "uploadId", Required: true,
		}},
	}
	base := WireIdentity{Protocol: awsrequest.ProtocolRESTXML, Method: "GET", Path: "/bucket/object"}
	for name, tc := range map[string]struct {
		query url.Values
		want  bool
	}{
		"required query member":  {query: url.Values{"uploadId": {"upload"}}, want: true},
		"unknown query member":   {query: url.Values{"other": {"value"}}, want: false},
		"duplicate query member": {query: url.Values{"uploadId": {"one", "two"}}, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			identity := base
			identity.Query = tc.query
			if got := routeMatches(record, iamlivecatalog.WireService{}, "GetObject", identity); got != tc.want {
				t.Errorf("routeMatches(%q, %q) = %t, want %t", record.Route.URI, name, got, tc.want)
			}
		})
	}
}

func TestRouteMatchesRESTGreedyPathLabel(t *testing.T) {
	record := iamlivecatalog.Operation{
		Route: iamlivecatalog.Route{Method: "GET", URI: "/bucket/{key+}"},
	}
	identity := WireIdentity{
		Protocol: awsrequest.ProtocolRESTXML,
		Method:   "GET",
		Path:     "/bucket/folder/object",
	}
	if got := routeMatches(record, iamlivecatalog.WireService{}, "GetObject", identity); !got {
		t.Errorf("routeMatches(%q, %q) = %t, want true", record.Route.URI, identity.Path, got)
	}
}

func TestLookupRequestRejectsTargetOperationMismatch(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.LookupRequest("dynamodb", "GetItem", WireIdentity{Protocol: awsrequest.ProtocolJSON10, Method: "POST", Path: "/", Target: "DynamoDB_20120810.PutItem"}, nil)
	if err == nil {
		t.Fatal("target operation mismatch was accepted")
	}
}

func TestLookupRequestSelectsExactJSONAPIVersion(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.LookupRequest("dynamodb", "GetItem", WireIdentity{Protocol: awsrequest.ProtocolJSON10, Method: "POST", Path: "/", Target: "DynamoDB_20120810.GetItem"}, map[string]awsrequest.Value{"TableName": {Kind: awsrequest.ValueString, String: "events"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.PrimaryOccurrences) != 1 || result.PrimaryOccurrences[0].Action.Name != "GetItem" {
		t.Fatalf("unexpected GetItem lookup result: %+v", result)
	}
}

func TestLookupFailsClosedForAbsentAndContradictoryMappingEvidence(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		service, operation string
	}{
		{"cloudsearchdomain", "UploadDocuments"},
		{"verifiedpermissions", "IsAuthorized"},
	} {
		if _, err := a.Lookup(tc.service, tc.operation); err == nil {
			t.Fatalf("Lookup(%q, %q) accepted invalid mapping evidence", tc.service, tc.operation)
		}
	}
}

func TestAbsentOptionalDependencyRemainsInapplicableEvidence(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.LookupRequest("ecs", "RunTask", WireIdentity{Protocol: awsrequest.ProtocolJSON11, Method: "POST", Path: "/", Target: "AmazonEC2ContainerServiceV20141113.RunTask"}, map[string]awsrequest.Value{"TaskDefinition": {Kind: awsrequest.ValueString, String: "web"}})
	if err == nil || !strings.Contains(err.Error(), "static catalog validation failed") {
		t.Fatalf("invalid conditional plan was reopened at request time: %v", err)
	}
}

func TestConditionFalseDependentActionMappingRetainsOccurrences(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, duplicate := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "duplicate"}[duplicate], func(t *testing.T) {
			occurrences := a.catalog.OperationOccurrences("omics", "StartRunBatch")
			if len(occurrences) != 1 {
				t.Fatalf("expected one operation occurrence, got %d", len(occurrences))
			}
			op := occurrences[0].Operation
			plan := occurrences[0].Plan
			condition := &iamlivecatalog.Condition{LHS: "ConditionFalseDependency", Op: "Equals", RHS: "present"}
			var dependencyIndex int
			for i := range op.Mappings {
				if op.Mappings[i].Action == "iam:PassRole" {
					op.Mappings[i].Condition = condition
					plan.Mappings[i].Mapping.Condition = condition
					dependencyIndex = i
					break
				}
			}
			if op.Mappings[dependencyIndex].Action != "iam:PassRole" {
				t.Fatal("catalog operation has no PassRole dependency mapping")
			}
			if duplicate {
				op.Mappings = append(op.Mappings, op.Mappings[dependencyIndex])
				plan.Mappings = append(plan.Mappings, plan.Mappings[dependencyIndex])
			}

			result, err := a.lookupOperation("omics", op, plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if duplicate {
				want = 2
			}
			if len(result.DependencyOccurrences) != want {
				t.Fatalf("condition-false dependency occurrences were dropped: got %d, want %d", len(result.DependencyOccurrences), want)
			}
			for _, candidate := range result.DependencyOccurrences {
				if candidate.Action.Service != "iam" || candidate.Action.Name != "PassRole" || candidate.Applicability != ApplicabilityInapplicable {
					t.Fatalf("unexpected condition-false dependency occurrence: %+v", candidate)
				}
			}
		})
	}
}

func TestDependentActionsModelsPassRoleFromTypedParameters(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Lookup("lambda", "CreateFunction", map[string]awsrequest.Value{
		"Role": {Kind: awsrequest.ValueString, String: "arn:aws:iam::123456789012:role/app"},
	})
	if err == nil {
		t.Fatal("incomplete dependent-action evidence was accepted")
	}
	result, err := a.Lookup("lambda", "Invoke", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DependencyOccurrences) != 0 {
		t.Fatalf("nondependent operation was not proven empty: %+v", result)
	}
}
