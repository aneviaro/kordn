package iamlivecatalog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
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

func TestBundleRejectsMalformedDuplicateMissingOversizedAndTrailingEntries(t *testing.T) {
	valid := func(names ...string) []byte {
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		tw := tar.NewWriter(gz)
		for _, name := range names {
			data := []byte("{}")
			if name == "iamlivecore/apis/a/v/api-2.json" {
				data = []byte(`{"metadata":{},"operations":{},"shapes":{}}`)
			}
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	fixed := append([]string{}, bundleFixedEntries...)
	fixed = append(fixed, "iamlivecore/apis/a/v/api-2.json")
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"malformed gzip", []byte("not gzip"), "bundle gzip"},
		{"missing fixed entry", valid(bundleFixedEntries[0], bundleFixedEntries[1], bundleFixedEntries[2], "iamlivecore/apis/a/v/api-2.json"), "expected"},
		{"duplicate API entry", valid(append(fixed, "iamlivecore/apis/a/v/api-2.json")...), "duplicated"},
		{"trailing archive data", append(valid(fixed...), []byte("trailing")...), "trailing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := readBundleData(tc.data, func(string, []byte) error { return nil }); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	var oversized bytes.Buffer
	gz := gzip.NewWriter(&oversized)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "LICENSE", Mode: 0600, Size: maxJSONBytes + 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()
	if err := readBundleData(oversized.Bytes(), func(string, []byte) error { return nil }); err == nil || !strings.Contains(err.Error(), "exceeds parser bound") {
		t.Fatalf("oversized entry error = %v", err)
	}
}

func TestCatalogSourceHashRejectsAlteredAPIModelContent(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.SourceHash() != "43e605716ea0ccdaeb625bad52088deece0204ad38e4b6e461e6792a1dd00869" {
		t.Fatalf("source hash changed: %s", c.SourceHash())
	}
	var original []byte
	err = readBundle(func(name string, data []byte) error {
		if original == nil && strings.HasPrefix(name, "iamlivecore/apis/") {
			original = append([]byte(nil), data...)
		}
		return nil
	})
	if err != nil || len(original) == 0 {
		t.Fatalf("API model set unavailable: %v", err)
	}
	altered := append([]byte(nil), original...)
	altered[len(altered)/2] ^= 1
	contentHash := func(replacement []byte) string {
		h := sha256.New()
		firstAPI := true
		err := readBundle(func(name string, data []byte) error {
			hashName := name
			if strings.HasPrefix(name, "iamlivecore/apis/") {
				hashName = "upstream/" + name
				if firstAPI && replacement != nil {
					data = replacement
				}
				firstAPI = false
			}
			h.Write([]byte(hashName))
			h.Write([]byte{0})
			h.Write(data)
			return nil
		})
		if err != nil {
			t.Fatal(err)
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
	if len(c.store.operations) != 19543 {
		t.Fatalf("operations = %d, want 19543", len(c.store.operations))
	}
	seen := map[occurrenceID]bool{}
	for _, operation := range c.store.operations {
		if operation.occurrence == invalidOccurrenceID || seen[operation.occurrence] {
			t.Fatal("operation occurrence identity lost")
		}
		seen[operation.occurrence] = true
	}
	for key, positions := range c.store.occurrences {
		if len(positions) == 0 {
			t.Fatalf("empty occurrence bucket %q", key)
		}
		for _, position := range positions {
			if position.operation < 0 || position.operation >= len(c.store.operations) || c.store.operations[position.operation].occurrence != position.occurrence {
				t.Fatalf("corrupt occurrence %q", key)
			}
		}
	}
}

func TestWireOccurrenceSelectorsPreserveVersionsAndAreImmutable(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var key string
	for candidate, positions := range c.store.occurrences {
		if len(positions) > 1 {
			key = candidate
			break
		}
	}
	if key == "" {
		t.Fatal("no duplicate operation")
	}
	parts := strings.SplitN(key, "\x00", 2)
	got := c.OperationOccurrences(parts[0], parts[1])
	if len(got) != len(c.store.occurrences[key]) {
		t.Fatal("occurrence cardinality changed")
	}
	wire := c.WireServices()
	if len(wire) == 0 || len(wire[0].Operations) == 0 {
		t.Fatal("empty wire view")
	}
	want := wire[0].Clone()
	wire[0].Operations[0].Name = "mutated"
	if !reflect.DeepEqual(c.WireServices()[0], want) {
		t.Fatal("wire view aliases store")
	}
	selected := c.OperationOccurrences("lambda", "CreateFunction")
	if len(selected) == 0 {
		t.Fatal("missing Lambda occurrence")
	}
	wantOccurrence := selected[0].Clone()
	selected[0].Operation.Mappings[0].Action = "mutated"
	fresh := c.OperationOccurrences("lambda", "CreateFunction")
	if !reflect.DeepEqual(fresh[0], wantOccurrence) {
		t.Fatal("operation view aliases store")
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

func TestCatalogRetainsEveryEvidenceKindInSourceOrderAndInternsValues(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.MappingOccurrenceCardinality() == 0 || c.InternedStringCardinality() == 0 {
		t.Fatal("canonical evidence stores are empty")
	}
	all := c.AllMappingOccurrences()
	for i := 1; i < len(all); i++ {
		if all[i-1].occurrenceID >= all[i].occurrenceID {
			t.Fatal("mapping source order lost")
		}
	}
	resources, dependencies := 0, 0
	if err := c.ForEachResourceTypeOccurrence(func(ResourceType) error { resources++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.ForEachDependentActionOccurrence(func(string) error { dependencies++; return nil }); err != nil {
		t.Fatal(err)
	}
	if resources == 0 || dependencies == 0 {
		t.Fatal("nested evidence missing")
	}
	if c.stringIndex != nil {
		t.Fatal("build string index retained")
	}
}

func TestCatalogSpanAndOccurrenceBoundsRejectCorruption(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	probe := *c
	copied := *c.store
	copied.mappingIndex = map[string][]mappingSpan{operationKey("bad", "operation"): {{start: uint32(len(c.store.mappings)), count: 1}}}
	probe.store = &copied
	if got := probe.MappingOccurrences("bad", "operation"); got != nil {
		t.Fatal("invalid mapping span addressable")
	}
	if validMappingSpan(mappingSpan{start: 1, count: 1}, 1) || !validMappingSpan(mappingSpan{start: 0, count: 1}, 1) {
		t.Fatal("span bounds incorrect")
	}
}

func cloneCatalogForCorruption(c *Catalog) *Catalog {
	probe := *c
	store := *c.store
	store.services = append([]compactService(nil), c.store.services...)
	store.operations = append([]compactOperation(nil), c.store.operations...)
	for i := range store.operations {
		store.operations[i].mappings = append([]mappingSpan(nil), c.store.operations[i].mappings...)
	}
	store.serviceOps = make([][]compactOperationPosition, len(c.store.serviceOps))
	for i := range c.store.serviceOps {
		store.serviceOps[i] = append([]compactOperationPosition(nil), c.store.serviceOps[i]...)
	}
	store.queryRecords = append([]compactQuery(nil), c.store.queryRecords...)
	store.mappings = append([]compactMapping(nil), c.store.mappings...)
	store.mappingResources = append([]compactResourceMapping(nil), c.store.mappingResources...)
	store.mapPairs = append([]compactMapPair(nil), c.store.mapPairs...)
	store.mappingIndex = make(map[string][]mappingSpan, len(c.store.mappingIndex))
	for key, spans := range c.store.mappingIndex {
		store.mappingIndex[key] = append([]mappingSpan(nil), spans...)
	}
	store.conditions = append([]compactCondition(nil), c.store.conditions...)
	store.actions = append([]compactAction(nil), c.store.actions...)
	store.resources = append([]compactResource(nil), c.store.resources...)
	for i := range store.resources {
		store.resources[i].dependentIDs = append([]occurrenceID(nil), c.store.resources[i].dependentIDs...)
	}
	store.dependents = append([]compactDependent(nil), c.store.dependents...)
	store.actionOrder = append([]compactActionPosition(nil), c.store.actionOrder...)
	probe.store = &store
	return &probe
}

func TestCatalogRetainsOnlyCompactCanonicalStore(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.store == nil {
		t.Fatal("compact canonical store was not published")
	}
	if c.services != nil || c.mappingStore != nil || c.buildActions != nil {
		t.Fatal("full parser views remain retained after publication")
	}
}

func TestCatalogSelectorsRejectEveryCompactIDAndSpanKind(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	operation := 0
	for i, value := range c.store.operations {
		if value.queries.count > 0 {
			operation = i
			break
		}
	}
	mapping := 0
	mappingWithResource := 0
	mappingWithCondition := 0
	mappingWithConditionPair := 0
	for i, value := range c.store.mappings {
		if value.resources.count > 0 && c.store.mappingResources[value.resources.start].occurrence != invalidOccurrenceID {
			mappingWithResource = i
		}
		if value.condition >= 0 {
			mappingWithCondition = i
		}
		if value.conditionMappings.count > 0 {
			mappingWithConditionPair = i
		}
		if value.resources.count > 0 || value.condition >= 0 || value.conditionMappings.count > 0 {
			mapping = i
		}
	}
	action := 0
	for i, value := range c.store.actions {
		if value.resources.count > 0 {
			action = i
			break
		}
	}
	resource := int(c.store.actions[action].resources.start)
	dependencyResource := resource
	for i, value := range c.store.resources {
		if value.dependents.count > 0 {
			dependencyResource = i
			break
		}
	}
	cases := []struct {
		name string
		bad  func(*compactStore)
		ok   func(*Catalog) bool
	}{
		{"operation occurrence", func(s *compactStore) { s.operations[operation].occurrence = 0 }, func(p *Catalog) bool { return p.Operations() == nil }},
		{"route ID", func(s *compactStore) { s.operations[operation].route.method = stringID(len(s.strings)) }, func(p *Catalog) bool { return p.Operations() == nil }},
		{"query span", func(s *compactStore) {
			s.operations[operation].queries = stringSpan{start: uint32(len(s.queryRecords)), count: 1}
		}, func(p *Catalog) bool { return p.Operations() == nil }},
		{"query ID", func(s *compactStore) {
			s.queryRecords[s.operations[operation].queries.start].member = stringID(len(s.strings))
		}, func(p *Catalog) bool { return p.Operations() == nil }},
		{"mapping occurrence", func(s *compactStore) { s.mappings[mapping].occurrence = 0 }, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping resource span", func(s *compactStore) {
			s.mappings[mappingWithResource].resources = stringSpan{start: uint32(len(s.mappingResources)), count: 1}
		}, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping resource ID", func(s *compactStore) {
			s.mappingResources[s.mappings[mappingWithResource].resources.start].occurrence = 0
		}, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"condition ID", func(s *compactStore) {
			s.conditions[s.mappings[mappingWithCondition].condition].lhs = stringID(len(s.strings))
		}, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"condition resource index", func(s *compactStore) {
			s.mapPairs[s.mappings[mappingWithConditionPair].conditionMappings.start].resource = -1
		}, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"action occurrence", func(s *compactStore) { s.actionOrder[0].occurrence = 0 }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"action ID", func(s *compactStore) { s.actions[action].service = stringID(len(s.strings)) }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"resource span", func(s *compactStore) {
			s.actions[action].resources = stringSpan{start: uint32(len(s.resources)), count: 1}
		}, func(p *Catalog) bool { return p.Actions() == nil }},
		{"resource occurrence", func(s *compactStore) { s.resources[resource].occurrence = 0 }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"dependency span", func(s *compactStore) {
			s.resources[dependencyResource].dependents = stringSpan{start: uint32(len(s.dependents)), count: 1}
		}, func(p *Catalog) bool { return p.Actions() == nil }},
		{"dependency occurrence", func(s *compactStore) { s.resources[dependencyResource].dependentIDs[0] = 0 }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"dependency record ID", func(s *compactStore) { s.dependents[s.resources[dependencyResource].dependents.start].occurrence = 0 }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"dependency action ID", func(s *compactStore) {
			s.dependents[s.resources[dependencyResource].dependents.start].action = stringID(len(s.strings))
		}, func(p *Catalog) bool { return p.Actions() == nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := cloneCatalogForCorruption(c)
			tc.bad(probe.store)
			if !tc.ok(probe) {
				t.Fatal("corrupt compact record remained addressable")
			}
		})
	}
}

func TestCatalogCanonicalOccurrencesAreInternedOrderedAndDistinct(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.store == nil || len(c.store.strings) < 2 {
		t.Fatal("canonical string store is empty")
	}
	// Equal source values in distinct operation records must point at one
	// nonzero interned ID, rather than merely producing a small string pool.
	var repeated stringID
	var repeatedValue string
	seenOperations := map[stringID]occurrenceID{}
	for _, operation := range c.store.operations {
		if operation.service == invalidStringID || operation.service >= stringID(len(c.store.strings)) {
			continue
		}
		if prior, ok := seenOperations[operation.service]; ok && prior != operation.occurrence {
			repeated = operation.service
			repeatedValue = c.store.strings[repeated]
			break
		}
		seenOperations[operation.service] = operation.occurrence
	}
	if repeated == invalidStringID || repeatedValue == "" || c.store.strings[repeated] != repeatedValue {
		t.Fatalf("repeated operation source value was not actually interned: id=%d value=%q", repeated, repeatedValue)
	}

	increasing := func(name string, ids []occurrenceID) {
		t.Helper()
		if len(ids) == 0 {
			t.Fatalf("%s has no retained occurrences", name)
		}
		for i, id := range ids {
			if id == invalidOccurrenceID || (i > 0 && ids[i-1] >= id) {
				t.Fatalf("%s source order/identity lost at %d: %v", name, i, ids)
			}
		}
	}
	operationIDs := make([]occurrenceID, 0, len(c.store.operations))
	for _, operation := range c.store.operations {
		operationIDs = append(operationIDs, operation.occurrence)
	}
	increasing("API operations", operationIDs)
	publicOperations := c.Operations()
	if len(publicOperations) != len(operationIDs) {
		t.Fatalf("public operation count = %d, want %d", len(publicOperations), len(operationIDs))
	}
	for i := range publicOperations {
		if publicOperations[i].occurrenceID != operationIDs[i] {
			t.Fatalf("public operation %d identity = %d, want %d", i, publicOperations[i].occurrenceID, operationIDs[i])
		}
	}

	mappingIDs := make([]occurrenceID, 0, len(c.store.mappingOrder))
	unmatched := false
	for _, position := range c.store.mappingOrder {
		mapping := c.store.mappings[position.storeIndex]
		mappingIDs = append(mappingIDs, mapping.occurrence)
		if mapping.state == EvidenceAbsent {
			unmatched = true
		}
		if mapping.occurrence != position.occurrence {
			t.Fatalf("mapping order identity mismatch at store index %d", position.storeIndex)
		}
	}
	increasing("IAM mappings", mappingIDs)
	if !unmatched {
		t.Fatal("no unmatched mapping occurrence was retained before filtering")
	}
	publicMappings := c.AllMappingOccurrences()
	if len(publicMappings) != len(mappingIDs) {
		t.Fatalf("public mapping count = %d, want %d", len(publicMappings), len(mappingIDs))
	}
	for i := range publicMappings {
		if publicMappings[i].occurrenceID != mappingIDs[i] {
			t.Fatalf("public mapping %d identity = %d, want %d", i, publicMappings[i].occurrenceID, mappingIDs[i])
		}
	}

	actionIDs := make([]occurrenceID, 0, len(c.store.actionOrder))
	for _, position := range c.store.actionOrder {
		action := c.store.actions[position.action]
		actionIDs = append(actionIDs, action.occurrence)
		if action.occurrence != position.occurrence {
			t.Fatalf("action order identity mismatch at store index %d", position.action)
		}
	}
	increasing("action definitions", actionIDs)
	publicActions := c.Actions()
	if len(publicActions) != len(actionIDs) {
		t.Fatalf("public action count = %d, want %d", len(publicActions), len(actionIDs))
	}
	for i := range publicActions {
		if publicActions[i].occurrenceID != actionIDs[i] {
			t.Fatalf("public action %d identity = %d, want %d", i, publicActions[i].occurrenceID, actionIDs[i])
		}
	}

	resourceIDs := []occurrenceID{}
	for _, position := range c.store.actionOrder {
		action := c.store.actions[position.action]
		if !validSpan(action.resources, len(c.store.resources)) {
			t.Fatal("invalid resource span in retained action")
		}
		for i := uint32(0); i < action.resources.count; i++ {
			resourceIDs = append(resourceIDs, c.store.resources[action.resources.start+i].occurrence)
		}
	}
	increasing("resource types", resourceIDs)
	var publicResources []ResourceType
	if err := c.ForEachResourceTypeOccurrence(func(resource ResourceType) error {
		publicResources = append(publicResources, resource)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(publicResources) != len(resourceIDs) {
		t.Fatalf("public resource count = %d, want %d", len(publicResources), len(resourceIDs))
	}
	for i := range publicResources {
		if publicResources[i].occurrenceID != resourceIDs[i] {
			t.Fatalf("public resource %d identity = %d, want %d", i, publicResources[i].occurrenceID, resourceIDs[i])
		}
	}

	dependentIDs := make([]occurrenceID, 0, len(c.store.dependents))
	for _, dependent := range c.store.dependents {
		dependentIDs = append(dependentIDs, dependent.occurrence)
	}
	increasing("dependent actions", dependentIDs)
	var publicDependencies []string
	if err := c.ForEachDependentActionOccurrence(func(dependency string) error {
		publicDependencies = append(publicDependencies, dependency)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(publicDependencies) != len(dependentIDs) {
		t.Fatalf("public dependency count = %d, want %d", len(publicDependencies), len(dependentIDs))
	}
	for i, dependent := range c.store.dependents {
		value, ok := compactString(c.store, dependent.action)
		if !ok || publicDependencies[i] != value {
			t.Fatalf("public dependency %d = %q, want %q", i, publicDependencies[i], value)
		}
	}

	// Confirm multiplicity is not collapsed when equal values recur. Action
	// definitions use case-insensitive source keys because the pinned fixture's
	// duplicate evidence is case-variant.
	duplicateOperation := false
	operationSeen := map[[2]stringID]occurrenceID{}
	for _, operation := range c.store.operations {
		key := [2]stringID{operation.service, operation.name}
		if prior, ok := operationSeen[key]; ok && prior != operation.occurrence {
			duplicateOperation = true
			break
		}
		operationSeen[key] = operation.occurrence
	}
	duplicateMapping := false
	mappingSeen := map[stringID]occurrenceID{}
	for _, mapping := range c.store.mappings {
		if prior, ok := mappingSeen[mapping.action]; ok && prior != mapping.occurrence {
			duplicateMapping = true
			break
		}
		mappingSeen[mapping.action] = mapping.occurrence
	}
	duplicateResource := false
	resourceSeen := map[stringID]occurrenceID{}
	for _, resource := range c.store.resources {
		if resource.name != invalidStringID {
			if prior, ok := resourceSeen[resource.name]; ok && prior != resource.occurrence {
				duplicateResource = true
				break
			}
			resourceSeen[resource.name] = resource.occurrence
		}
	}
	duplicateDependent := false
	dependentSeen := map[stringID]occurrenceID{}
	for _, dependent := range c.store.dependents {
		if dependent.action != invalidStringID {
			if prior, ok := dependentSeen[dependent.action]; ok && prior != dependent.occurrence {
				duplicateDependent = true
				break
			}
			dependentSeen[dependent.action] = dependent.occurrence
		}
	}
	duplicateAction := false
	actionSeen := map[[2]string]occurrenceID{}
	for _, action := range c.store.actions {
		service, serviceOK := compactString(c.store, action.service)
		name, nameOK := compactString(c.store, action.name)
		if serviceOK && nameOK {
			key := [2]string{strings.ToLower(service), strings.ToLower(name)}
			if prior, ok := actionSeen[key]; ok && prior != action.occurrence {
				duplicateAction = true
				break
			}
			actionSeen[key] = action.occurrence
		}
	}
	if !duplicateOperation || !duplicateMapping || !duplicateResource || !duplicateDependent || !duplicateAction {
		t.Fatalf("duplicate occurrence multiplicity missing: operation=%v mapping=%v action=%v resource=%v dependent=%v", duplicateOperation, duplicateMapping, duplicateAction, duplicateResource, duplicateDependent)
	}
}

func TestCatalogSelectorsRejectOverflowAndExactEndForEveryNestedSpan(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	operation := -1
	for i, value := range c.store.operations {
		if value.queries.count > 0 && len(value.mappings) > 0 {
			operation = i
			break
		}
	}
	if operation < 0 {
		t.Fatal("fixture has no operation with query and mapping spans")
	}
	opService, ok := compactString(c.store, c.store.operations[operation].service)
	if !ok {
		t.Fatal("operation service ID is corrupt")
	}
	opName, ok := compactString(c.store, c.store.operations[operation].name)
	if !ok {
		t.Fatal("operation name ID is corrupt")
	}
	mapping := -1
	mappingWithResource, mappingWithARN, mappingWithConditionMap := -1, -1, -1
	mappingWithCondition := -1
	for i, value := range c.store.mappings {
		if value.resources.count > 0 {
			mappingWithResource = i
		}
		if value.arn.count > 0 {
			mappingWithARN = i
		}
		if value.conditionMappings.count > 0 {
			mappingWithConditionMap = i
		}
		if value.condition >= 0 {
			mappingWithCondition = i
		}
		if value.resources.count > 0 || value.arn.count > 0 || value.conditionMappings.count > 0 {
			mapping = i
		}
	}
	if mapping < 0 || mappingWithResource < 0 || mappingWithARN < 0 || mappingWithConditionMap < 0 || mappingWithCondition < 0 {
		t.Fatal("fixture lacks required nested mapping records")
	}
	mappingIndexKey := ""
	for key, spans := range c.store.mappingIndex {
		if len(spans) > 0 {
			mappingIndexKey = key
			break
		}
	}
	if mappingIndexKey == "" {
		t.Fatal("fixture lacks mapping index spans")
	}
	mappingIndexParts := strings.SplitN(mappingIndexKey, "\x00", 2)
	action := -1
	for i, value := range c.store.actions {
		if value.resources.count > 0 {
			action = i
			break
		}
	}
	if action < 0 {
		t.Fatal("fixture lacks action resources")
	}
	resource := int(c.store.actions[action].resources.start)
	resourceWithDependencies := -1
	for i, value := range c.store.resources {
		if value.dependentActions.count > 0 && len(value.dependentIDs) > 0 {
			resourceWithDependencies = i
			break
		}
	}
	if resourceWithDependencies < 0 {
		t.Fatal("fixture lacks dependent action resources")
	}

	badSpans := func(length int) []stringSpan {
		return []stringSpan{
			// A count beginning exactly at the backing-store boundary is invalid.
			{start: uint32(length), count: 1},
			// These operands deliberately wrap uint32 arithmetic.
			{start: ^uint32(0), count: ^uint32(0)},
		}
	}
	type spanCase struct {
		name   string
		length int
		set    func(*compactStore, stringSpan)
		valid  func(*Catalog) bool
	}
	cases := []spanCase{
		{"operation query span", len(c.store.queryRecords), func(s *compactStore, span stringSpan) { s.operations[operation].queries = span }, func(p *Catalog) bool { return p.OperationOccurrences(opService, opName) == nil }},
		{"operation mapping span", len(c.store.mappings), func(s *compactStore, span stringSpan) {
			s.operations[operation].mappings[0] = mappingSpan{start: span.start, count: span.count}
		}, func(p *Catalog) bool { return p.OperationOccurrences(opService, opName) == nil }},
		{"mapping index span", len(c.store.mappings), func(s *compactStore, span stringSpan) {
			s.mappingIndex[mappingIndexKey][0] = mappingSpan{start: span.start, count: span.count}
		}, func(p *Catalog) bool { return p.MappingOccurrences(mappingIndexParts[0], mappingIndexParts[1]) == nil }},
		{"mapping resource span", len(c.store.mappingResources), func(s *compactStore, span stringSpan) { s.mappings[mappingWithResource].resources = span }, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping ARN map-pair span", len(c.store.mapPairs), func(s *compactStore, span stringSpan) { s.mappings[mappingWithARN].arn = span }, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping condition map-pair span", len(c.store.mapPairs), func(s *compactStore, span stringSpan) { s.mappings[mappingWithConditionMap].conditionMappings = span }, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"action resource span", len(c.store.resources), func(s *compactStore, span stringSpan) { s.actions[action].resources = span }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"resource condition-key span", len(c.store.refs), func(s *compactStore, span stringSpan) { s.resources[resource].conditionKeys = span }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"resource dependent-action span", len(c.store.refs), func(s *compactStore, span stringSpan) { s.resources[resourceWithDependencies].dependentActions = span }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"resource dependency-record span", len(c.store.dependents), func(s *compactStore, span stringSpan) { s.resources[resourceWithDependencies].dependents = span }, func(p *Catalog) bool { return p.Actions() == nil }},
	}
	for _, tc := range cases {
		for variant, span := range badSpans(tc.length) {
			t.Run(tc.name+"/variant"+string(rune('0'+variant)), func(t *testing.T) {
				probe := cloneCatalogForCorruption(c)
				tc.set(probe.store, span)
				if !tc.valid(probe) {
					t.Fatalf("selector accepted malformed %s span %#v", tc.name, span)
				}
			})
		}
	}

	type idCase struct {
		name  string
		set   func(*compactStore)
		valid func(*Catalog) bool
	}
	invalidID := func(s *compactStore) stringID { return stringID(len(s.strings)) }
	idCases := []idCase{
		{"route method ID", func(s *compactStore) { s.operations[operation].route.method = invalidID(s) }, func(p *Catalog) bool { return p.OperationOccurrences(opService, opName) == nil }},
		{"route URI ID", func(s *compactStore) { s.operations[operation].route.uri = invalidID(s) }, func(p *Catalog) bool { return p.OperationOccurrences(opService, opName) == nil }},
		{"route discriminator ID", func(s *compactStore) { s.operations[operation].route.discriminator = invalidID(s) }, func(p *Catalog) bool { return p.OperationOccurrences(opService, opName) == nil }},
		{"route target ID", func(s *compactStore) { s.operations[operation].route.target = invalidID(s) }, func(p *Catalog) bool { return p.OperationOccurrences(opService, opName) == nil }},
		{"route JSON version ID", func(s *compactStore) { s.operations[operation].route.jsonVersion = invalidID(s) }, func(p *Catalog) bool { return p.OperationOccurrences(opService, opName) == nil }},
		{"query member ID", func(s *compactStore) { s.queryRecords[s.operations[operation].queries.start].member = invalidID(s) }, func(p *Catalog) bool { return p.OperationOccurrences(opService, opName) == nil }},
		{"query location ID", func(s *compactStore) { s.queryRecords[s.operations[operation].queries.start].location = invalidID(s) }, func(p *Catalog) bool { return p.OperationOccurrences(opService, opName) == nil }},
		{"mapping action ID", func(s *compactStore) { s.mappings[mapping].action = invalidID(s) }, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping resource ID", func(s *compactStore) {
			s.mappingResources[s.mappings[mappingWithResource].resources.start].occurrence = invalidOccurrenceID
		}, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping pair key ID", func(s *compactStore) { s.mapPairs[s.mappings[mappingWithARN].arn.start].key = invalidID(s) }, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping pair value ID", func(s *compactStore) { s.mapPairs[s.mappings[mappingWithARN].arn.start].value = invalidID(s) }, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"condition pair resource index", func(s *compactStore) {
			s.mapPairs[s.mappings[mappingWithConditionMap].conditionMappings.start].resource = len(s.mappingResources)
		}, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"condition pair value ID", func(s *compactStore) {
			s.mapPairs[s.mappings[mappingWithConditionMap].conditionMappings.start].value = invalidID(s)
		}, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping condition ID", func(s *compactStore) { s.conditions[s.mappings[mappingWithCondition].condition].lhs = invalidID(s) }, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping condition index", func(s *compactStore) { s.mappings[mappingWithCondition].condition = len(s.conditions) }, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"mapping condition cycle", func(s *compactStore) {
			s.conditions[s.mappings[mappingWithCondition].condition].and = s.mappings[mappingWithCondition].condition
		}, func(p *Catalog) bool { return p.AllMappingOccurrences() == nil }},
		{"action service ID", func(s *compactStore) { s.actions[action].service = invalidID(s) }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"resource name ID", func(s *compactStore) { s.resources[resource].name = invalidID(s) }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"dependency action ID", func(s *compactStore) {
			s.dependents[s.resources[resourceWithDependencies].dependents.start].action = invalidID(s)
		}, func(p *Catalog) bool { return p.Actions() == nil }},
		{"dependency occurrence ID", func(s *compactStore) { s.resources[resourceWithDependencies].dependentIDs[0] = invalidOccurrenceID }, func(p *Catalog) bool { return p.Actions() == nil }},
		{"dependency ID-slice boundary", func(s *compactStore) {
			s.resources[resourceWithDependencies].dependentIDs = s.resources[resourceWithDependencies].dependentIDs[:len(s.resources[resourceWithDependencies].dependentIDs)-1]
		}, func(p *Catalog) bool { return p.Actions() == nil }},
	}
	for _, tc := range idCases {
		t.Run(tc.name, func(t *testing.T) {
			probe := cloneCatalogForCorruption(c)
			tc.set(probe.store)
			if !tc.valid(probe) {
				t.Fatal("selector accepted malformed nested ID")
			}
		})
	}
}

func TestCatalogIndexesEveryAPIOperation(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, service := range c.Services() {
		for _, operation := range service.Operations {
			count++
			indexes := c.store.operationIndex[operationKey(service.EndpointPrefix, operation.Name)]
			found := false
			for _, position := range indexes {
				if position.operation >= 0 && position.operation < len(c.store.operations) && c.store.operations[position.operation].occurrence == position.occurrence {
					found = true
				}
			}
			if !found {
				t.Fatalf("unindexed %s/%s", service.EndpointPrefix, operation.Name)
			}
		}
	}
	if count != len(c.store.operations) {
		t.Fatalf("operation count %d/%d", count, len(c.store.operations))
	}
}
