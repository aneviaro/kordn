package iamliveadapter

import (
	"net/url"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

func TestLookupUsesPinnedActionsAndInvokesDependencies(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.LookupRequest("ec2", "DescribeInstances", WireIdentity{Protocol: awsrequest.ProtocolEC2Query, Method: "POST", Path: "/", Query: map[string][]string{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Primary) != 1 || result.Primary[0].Name != "DescribeInstances" || !result.DependenciesCertain {
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
			if got := routeMatches(record, iamlivecatalog.Service{}, "GetObject", identity); got != tc.want {
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
	if got := routeMatches(record, iamlivecatalog.Service{}, "GetObject", identity); !got {
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

func TestLookupRequestRejectsContradictoryOperationRecord(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.LookupRequest("dynamodb", "GetItem", WireIdentity{Protocol: awsrequest.ProtocolJSON10, Method: "POST", Path: "/", Target: "DynamoDB_20120810.GetItem"}, map[string]awsrequest.Value{"TableName": {Kind: awsrequest.ValueString, String: "events"}})
	if err == nil {
		t.Fatal("contradictory operation record was promoted")
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
	result, err := a.LookupRequest("ecs", "RunTask", WireIdentity{Protocol: awsrequest.ProtocolJSON11, Method: "POST", Path: "/", Target: "AmazonEC2ContainerServiceV20141113.RunTask"}, map[string]awsrequest.Value{"TaskDefinition": {Kind: awsrequest.ValueString, String: "web"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Dependencies) != 2 {
		t.Fatalf("dependency occurrences were dropped: %+v", result.Dependencies)
	}
	for _, candidate := range result.Dependencies {
		if !candidate.ProvenInapplicable {
			t.Fatalf("missing inapplicable proof: %+v", result.Dependencies)
		}
	}
}

func TestConditionFalseDependentActionMappingRetainsOccurrences(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, duplicate := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "duplicate"}[duplicate], func(t *testing.T) {
			op, err := a.catalog.Operation("omics", "StartRunBatch")
			if err != nil {
				t.Fatal(err)
			}
			condition := &iamlivecatalog.Condition{LHS: "ConditionFalseDependency", Op: "Equals", RHS: "present"}
			var dependencyIndex int
			for i := range op.Mappings {
				if op.Mappings[i].Action == "iam:PassRole" {
					op.Mappings[i].Condition = condition
					dependencyIndex = i
					break
				}
			}
			if op.Mappings[dependencyIndex].Action != "iam:PassRole" {
				t.Fatal("catalog operation has no PassRole dependency mapping")
			}
			if duplicate {
				op.Mappings = append(op.Mappings, op.Mappings[dependencyIndex])
			}

			result, err := a.lookupOperation("omics", op, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if duplicate {
				want = 2
			}
			if len(result.Dependencies) != want {
				t.Fatalf("condition-false dependency occurrences were dropped: got %d, want %d", len(result.Dependencies), want)
			}
			for _, candidate := range result.Dependencies {
				if candidate.Action.Service != "iam" || candidate.Action.Name != "PassRole" || !candidate.ProvenInapplicable {
					t.Fatalf("unexpected condition-false dependency candidate: %+v", candidate)
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
	if len(result.Dependencies) != 0 || !result.DependenciesCertain {
		t.Fatalf("nondependent operation was not proven empty: %+v", result)
	}
}
