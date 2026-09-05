package iamlivecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"reflect"
	"sort"
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

func TestCatalogVariedServiceContracts(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		service, operation, action, protocol string
		global                               bool
	}{
		{"kms", "ListKeys", "kms:ListKeys", "json1.1", true},
		{"sqs", "SendMessage", "sqs:SendMessage", "json1.0", false},
		{"sns", "Publish", "sns:Publish", "query", false},
		{"organizations", "ListAccounts", "organizations:ListAccounts", "json1.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.service+"/"+tc.operation, func(t *testing.T) {
			o, err := c.Operation(tc.service, tc.operation)
			if err != nil {
				t.Fatal(err)
			}
			service, err := c.Service(tc.service)
			if err != nil {
				t.Fatal(err)
			}
			modelProtocol := service.Protocol
			if strings.HasPrefix(tc.protocol, "json") {
				modelProtocol += o.Route.JSONVersion
			}
			if modelProtocol != tc.protocol {
				t.Fatalf("wire protocol = %q, want %q", modelProtocol, tc.protocol)
			}
			if o.MappingState != EvidenceKnown || len(o.Mappings) != 1 || o.Mappings[0].Action != tc.action {
				t.Fatalf("mapping evidence = %+v", o)
			}
			if o.Route.QueryDiscriminator == "" || o.Route.Method == "" || o.Route.URI == "" {
				t.Fatalf("wire evidence incomplete: %+v", o.Route)
			}
			if tc.global {
				a, err := c.Action(tc.action)
				if err != nil || len(a.Resources) != 1 || a.Resources[0].Name != "" {
					t.Fatalf("global action evidence = %+v (%v)", a, err)
				}
			}
		})
	}
}

func TestCatalogSourceHashRejectsAlteredAPIModelContent(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	apiPaths, err := fs.Glob(embeddedData, "upstream/iamlivecore/apis/*/*/api-2.json")
	if err != nil || len(apiPaths) == 0 {
		t.Fatalf("API model set unavailable: %v", err)
	}
	sort.Strings(apiPaths)
	alteredPath := apiPaths[0]
	original, err := readEmbedded(alteredPath)
	if err != nil {
		t.Fatal(err)
	}
	altered := append([]byte(nil), original...)
	altered[len(altered)/2] ^= 1
	contentHash := func(replacement []byte) string {
		h := sha256.New()
		for _, item := range []struct {
			name string
			data []byte
		}{
			{"LICENSE", mustEmbedded(t, "upstream/LICENSE")},
			{"NOTICE", mustEmbedded(t, "upstream/NOTICE")},
			{"iamlivecore/map.json", mustEmbedded(t, "upstream/iamlivecore/map.json")},
			{"iamlivecore/iam_definition.json", mustEmbedded(t, "upstream/iamlivecore/iam_definition.json")},
		} {
			h.Write([]byte(item.name))
			h.Write([]byte{0})
			h.Write(item.data)
		}
		for _, file := range apiPaths {
			data := mustEmbedded(t, file)
			if file == alteredPath && replacement != nil {
				data = replacement
			}
			h.Write([]byte(file))
			h.Write([]byte{0})
			h.Write(data)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	if got := contentHash(nil); got != c.SourceHash() {
		t.Fatalf("source hash does not match selected bytes: got %s, want %s", c.SourceHash(), got)
	}
	if got := contentHash(altered); got == c.SourceHash() {
		t.Fatal("altered API-model bytes retained the catalog content identity")
	}
}

func mustEmbedded(t *testing.T, name string) []byte {
	t.Helper()
	data, err := readEmbedded(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
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

func TestWireOccurrenceIndexPreservesCatalogCardinality(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for serviceIndex, service := range c.services {
		want += len(service.Operations)
		for operationIndex, operation := range service.Operations {
			key := operationKey(service.EndpointPrefix, operation.Name)
			positions := c.operationOccurrences[key]
			found := false
			for _, position := range positions {
				if position.serviceIndex == serviceIndex && position.operationIndex == operationIndex {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("operation %s/%s missing from occurrence index", service.EndpointPrefix, operation.Name)
			}
		}
	}
	got := 0
	for key, positions := range c.operationOccurrences {
		if len(positions) == 0 {
			t.Fatalf("occurrence index has empty bucket %q", key)
		}
		got += len(positions)
	}
	if got != want {
		t.Fatalf("occurrence index cardinality = %d, want %d", got, want)
	}
}

func TestWireOccurrenceSelectorsPreserveVersionsAndAreImmutable(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	var duplicateKey string
	var versions map[string]bool
	for key, positions := range c.operationOccurrences {
		if len(positions) < 2 {
			continue
		}
		candidateVersions := map[string]bool{}
		for _, position := range positions {
			candidateVersions[c.services[position.serviceIndex].APIVersion] = true
		}
		if len(candidateVersions) > 1 {
			duplicateKey, versions = key, candidateVersions
			break
		}
	}
	if duplicateKey == "" {
		t.Fatal("catalog has no repeated operation across API versions")
	}
	parts := strings.SplitN(duplicateKey, "\x00", 2)
	occurrences := c.OperationOccurrences(parts[0], parts[1])
	if len(occurrences) != len(c.operationOccurrences[duplicateKey]) {
		t.Fatalf("occurrence selector cardinality = %d, want %d", len(occurrences), len(c.operationOccurrences[duplicateKey]))
	}
	seenVersions := map[string]bool{}
	for _, occurrence := range occurrences {
		seenVersions[occurrence.Service.APIVersion] = true
	}
	if !reflect.DeepEqual(seenVersions, versions) {
		t.Fatalf("occurrence API versions = %v, want %v", seenVersions, versions)
	}
	if got := c.OperationOccurrences("unknown-endpoint", "unknown-operation"); len(got) != 0 {
		t.Fatalf("unknown occurrence key returned %d candidates", len(got))
	}

	wire := c.WireServices()
	if len(wire) == 0 || len(wire[0].Operations) == 0 {
		t.Fatal("wire snapshot is empty")
	}
	wireWant := wire[0].Clone()
	wire[0].Protocols = append(wire[0].Protocols, "mutated")
	wire[0].Operations[0].QueryBindings = append(wire[0].Operations[0].QueryBindings, QueryBinding{Member: "mutated"})
	wire[0].Operations = append(wire[0].Operations, WireOperation{Name: "mutated"})
	wireAgain := c.WireServices()
	if !reflect.DeepEqual(wireAgain[0], wireWant) {
		t.Fatal("wire snapshot output aliases catalog storage")
	}

	// Lambda CreateFunction has nested mapping maps and conditions in the pinned
	// catalog, making it a compact check that the selected full operation is
	// isolated at every mutable level.
	selected := c.OperationOccurrences("lambda", "CreateFunction")
	if len(selected) == 0 {
		t.Fatal("expected Lambda CreateFunction occurrence")
	}
	occurrenceWant := selected[0].Clone()
	selected[0].Service.Protocols = append(selected[0].Service.Protocols, "mutated")
	op := &selected[0].Operation
	op.QueryBindings = append(op.QueryBindings, QueryBinding{Member: "mutated"})
	for i := range op.Mappings {
		mapping := &op.Mappings[i]
		mapping.ResourceARNMappings["mutated"] = "mutated"
		mapping.ConditionMappings["mutated"] = ResourceMapping{Condition: &Condition{LHS: "mutated"}}
		mapping.Resources = append(mapping.Resources, ResourceMapping{Condition: &Condition{LHS: "mutated"}})
		if mapping.Condition != nil {
			mapping.Condition.LHS = "mutated"
			if mapping.Condition.And != nil {
				mapping.Condition.And.RHS = "mutated"
			}
		}
		for j := range mapping.Resources {
			if mapping.Resources[j].Condition != nil {
				mapping.Resources[j].Condition.RHS = "mutated"
			}
		}
		for key := range mapping.ConditionMappings {
			if mapping.ConditionMappings[key].Condition != nil {
				value := mapping.ConditionMappings[key]
				value.Condition.Op = "mutated"
				mapping.ConditionMappings[key] = value
			}
		}
	}
	fresh := c.OperationOccurrences("lambda", "CreateFunction")
	if len(fresh) != len(selected) || !reflect.DeepEqual(fresh[0], occurrenceWant) {
		t.Fatal("selected operation output aliases catalog storage")
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

	o, err := c.Operation("s3", "GetObject")
	if err != nil || len(o.QueryBindings) == 0 {
		t.Fatalf("S3 query bindings unavailable: %v", err)
	}
	o.QueryBindings[0].LocationName = "mutated"
	freshS3, err := c.Operation("s3", "GetObject")
	if err != nil || freshS3.QueryBindings[0].LocationName == "mutated" {
		t.Fatal("query binding slice aliases catalog storage")
	}

	o, err = c.Operation("lambda", "CreateFunction")
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

func TestAPIDecodeRejectsMalformedEvidenceWithContext(t *testing.T) {
	base := func(shape string) string {
		return `{"metadata":{},"operations":{"Op":{"input":{"shape":"Input"}}},"shapes":{"Input":` + shape + `,"S":{"type":"string"}}}`
	}
	cases := []struct {
		name, shape, want string
	}{
		{"duplicate member key", `{"type":"structure","members":{"X":{"shape":"S"},"X":{"shape":"S"}}}`, "shapes.Input.members"},
		{"duplicate required", `{"type":"structure","required":["X","X"],"members":{"X":{"shape":"S"}}}`, "duplicate required"},
		{"absent required member", `{"type":"structure","required":["Missing"],"members":{"X":{"shape":"S"}}}`, "absent required"},
		{"empty required member", `{"type":"structure","required":[""],"members":{}}`, "empty required"},
		{"empty query location", `{"type":"structure","members":{"X":{"shape":"S","location":"querystring","locationName":""}}}`, "empty query locationName"},
		{"duplicate query location", `{"type":"structure","members":{"X":{"shape":"S","location":"querystring","locationName":"q"},"Y":{"shape":"S","location":"querystring","locationName":"q"}}}`, "duplicate query locationName"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeAPI("malformed/api-2.json", []byte(base(tc.shape)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error lacks contextual evidence: %v", err)
			}
			if tc.name != "duplicate member key" && (!strings.Contains(err.Error(), `operation "Op"`) || !strings.Contains(err.Error(), `input shape "Input"`)) {
				t.Fatalf("error lacks operation/shape context: %v", err)
			}
		})
	}
}

func TestStrictAPIDecodeRejectsTrailingJSON(t *testing.T) {
	_, err := decodeAPI("trailing/api-2.json", []byte(`{"metadata":{},"operations":{},"shapes":{}} {}`))
	if err == nil || !strings.Contains(err.Error(), "trailing/api-2.json") || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("trailing API JSON was accepted without context: %v", err)
	}
}

func TestModeledRESTQueryBindingsDisambiguateS3(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	get, err := c.Operation("s3", "GetObject")
	if err != nil || len(get.QueryBindings) == 0 {
		t.Fatalf("GetObject query bindings missing: %+v %v", get.QueryBindings, err)
	}
	list, err := c.Operation("s3", "ListParts")
	if err != nil || len(list.QueryBindings) == 0 {
		t.Fatalf("ListParts query bindings missing: %+v %v", list.QueryBindings, err)
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
			indexed := c.operations[operationKey(s.EndpointPrefix, o.Name)]
			found := false
			for _, candidate := range indexed {
				if candidate.modelKey == s.Key && operationEquivalent(candidate.operation, o) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("unindexed %s/%s model %q", s.EndpointPrefix, o.Name, s.Key)
			}
		}
	}
	if count != len(c.Operations()) {
		t.Fatalf("operation index dropped records: service count %d, index count %d", count, len(c.Operations()))
	}
}
