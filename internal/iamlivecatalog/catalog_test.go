package iamlivecatalog

import (
	"strings"
	"testing"
)

func TestPinnedCatalogCoverageAndRepresentativeEvidence(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if UpstreamCommit != "3ec1a40e560c2f00ec82c50223add810e2567efb" || !strings.Contains(Version(), UpstreamCommit) {
		t.Fatalf("pin is not exposed: %s", Version())
	}
	if len(c.Services()) < 400 || len(c.Operations()) < 10000 {
		t.Fatalf("catalog unexpectedly incomplete: %d services, %d operations", len(c.Services()), len(c.Operations()))
	}

	checks := []struct {
		service, operation string
		mappings           int
	}{
		{"iam", "ListUsers", 1},
		{"dynamodb", "BatchExecuteStatement", 4},
		{"cloudwatch", "ListTagsForResource", 1},
		{"lambda", "CreateFunction", 2},
	}
	for _, tc := range checks {
		o, err := c.Operation(tc.service, tc.operation)
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.service, tc.operation, err)
		}
		if len(o.Mappings) != tc.mappings {
			t.Fatalf("%s/%s mappings: got %d, want %d", tc.service, tc.operation, len(o.Mappings), tc.mappings)
		}
		if o.Route.Method == "" || o.Route.URI == "" || o.Route.QueryDiscriminator == "" {
			t.Fatalf("%s/%s lost route metadata: %+v", tc.service, tc.operation, o.Route)
		}
	}

	listUsers, _ := c.Operation("IAM", "listusers")
	if listUsers.MappingState != EvidenceKnown || listUsers.Mappings[0].Action != "iam:ListUsers" {
		t.Fatalf("ListUsers evidence was not retained: %+v", listUsers)
	}
	a, err := c.Action("iam:ListUsers")
	if err != nil || len(a.Resources) == 0 {
		t.Fatalf("ListUsers should retain known-global SAR evidence: %+v, %v", a, err)
	}
	for _, r := range a.Resources {
		if r.Name != "" {
			t.Fatalf("ListUsers unexpectedly acquired a resource scope: %+v", a.Resources)
		}
	}
	batch, _ := c.Operation("dynamodb", "BatchExecuteStatement")
	if batch.Mappings[0].Condition == nil || len(batch.Mappings) < 2 {
		t.Fatalf("plural/applicability evidence was lost: %+v", batch.Mappings)
	}
	cloudwatch, _ := c.Operation("cloudwatch", "ListTagsForResource")
	if len(cloudwatch.Mappings[0].ResourceARNMappings) == 0 {
		t.Fatal("cross-service/resource ARN extraction evidence was lost")
	}
	lambda, _ := c.Operation("lambda", "CreateFunction")
	if lambda.Mappings[1].Action != "iam:PassRole" || lambda.Mappings[1].ARNOverride == "" {
		t.Fatalf("dependent action evidence was lost: %+v", lambda.Mappings)
	}
	if _, err := c.Action("verifiedpermissions:IsAuthorized"); err == nil {
		t.Fatal("case-variant duplicate action evidence must fail closed")
	}
	if _, err := c.Action("cloudsearch:upload"); err == nil {
		t.Fatal("missing IAM definition evidence must not become a permission")
	}
}

func TestCatalogPreservesAbsentAndContradictoryMappingEvidence(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var absent, contradictory, permissionless bool
	for _, o := range c.Operations() {
		if o.MappingState == EvidencePermissionless {
			permissionless = true
		}
		for _, m := range o.Mappings {
			switch m.State {
			case EvidenceAbsent:
				absent = true
			case EvidenceContradictory:
				contradictory = true
			}
		}
	}
	if !absent {
		t.Fatal("catalog dropped absent IAM action mapping evidence")
	}
	if !contradictory {
		t.Fatal("catalog dropped contradictory IAM action mapping evidence")
	}
	if !permissionless {
		t.Fatal("catalog dropped permissionless operation evidence")
	}
	var undocumented bool
	for _, a := range c.Actions() {
		if a.State == EvidenceUndocumented {
			undocumented = true
			break
		}
	}
	if !undocumented {
		t.Fatal("catalog dropped undocumented IAM action evidence")
	}

	absentOp, err := c.Operation("cloudsearchdomain", "UploadDocuments")
	if err != nil {
		t.Fatal(err)
	}
	if absentOp.MappingState != EvidenceAbsent || len(absentOp.Mappings) == 0 || absentOp.Mappings[0].State != EvidenceAbsent {
		t.Fatalf("absent mapping state was not retained: %+v", absentOp)
	}
	contradictoryOp, err := c.Operation("verifiedpermissions", "IsAuthorized")
	if err != nil {
		t.Fatal(err)
	}
	if contradictoryOp.MappingState != EvidenceContradictory {
		t.Fatalf("contradictory mapping state was not retained: %+v", contradictoryOp)
	}
	foundContradictory := false
	for _, m := range contradictoryOp.Mappings {
		if m.Action == "verifiedpermissions:IsAuthorized" && m.State == EvidenceContradictory {
			foundContradictory = true
		}
	}
	if !foundContradictory {
		t.Fatalf("contradictory action mapping was not retained: %+v", contradictoryOp.Mappings)
	}
}

func TestCatalogCopiesAreImmutableToCallers(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	s := c.Services()
	if len(s) == 0 || len(s[0].Operations) == 0 {
		t.Fatal("empty catalog")
	}
	s[0].Aliases[0] = "mutated"
	s[0].Protocols[0] = "mutated"
	s[0].Operations[0].Mappings = append(s[0].Operations[0].Mappings, ActionMapping{Action: "mutated"})
	reloaded, err := c.Service(s[0].EndpointPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Aliases[0] == "mutated" || reloaded.Protocols[0] == "mutated" {
		t.Fatal("service slices alias catalog storage")
	}

	o, err := c.Operation("lambda", "CreateFunction")
	if err != nil {
		t.Fatal(err)
	}
	o.Mappings[0].ResourceARNMappings["mutated"] = "mutated"
	o.Mappings[0].Resources = append(o.Mappings[0].Resources, ResourceMapping{Template: "mutated"})
	again, err := c.Operation("lambda", "CreateFunction")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Mappings[0].ResourceARNMappings["mutated"]; ok {
		t.Fatal("mapping map aliases catalog storage")
	}
	for _, r := range again.Mappings[0].Resources {
		if r.Template == "mutated" {
			t.Fatal("mapping slice aliases catalog storage")
		}
	}

	actions := c.Actions()
	if len(actions) == 0 {
		t.Fatal("empty action index")
	}
	actions[0].Resources = append(actions[0].Resources, ResourceType{Name: "mutated"})
	fresh := c.Actions()
	for _, a := range fresh[0].Resources {
		if a.Name == "mutated" {
			t.Fatal("action slice aliases catalog storage")
		}
	}
}

func TestCatalogIndexesEveryAPIOperation(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, s := range c.Services() {
		for _, o := range s.Operations {
			count++
			if _, err := c.Operation(s.EndpointPrefix, o.Name); err != nil {
				// Duplicate API model records are intentionally ambiguous, but
				// every record remains present in the service index.
				if o.State != EvidenceContradictory {
					t.Fatalf("unindexed %s/%s: %v", s.EndpointPrefix, o.Name, err)
				}
			}
		}
	}
	if count != len(c.Operations()) {
		t.Fatalf("operation index dropped records: service count %d, index count %d", count, len(c.Operations()))
	}
}
