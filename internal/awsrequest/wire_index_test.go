package awsrequest

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

type wireSnapshotSpy struct {
	services []iamlivecatalog.WireService
	calls    int
}

func (s *wireSnapshotSpy) WireServices() []iamlivecatalog.WireService {
	s.calls++
	return append([]iamlivecatalog.WireService(nil), s.services...)
}

func TestWireIndexSnapshotsOnceAndDecodeDoesNotEnumerate(t *testing.T) {
	spy := &wireSnapshotSpy{services: []iamlivecatalog.WireService{{
		EndpointPrefix: "sts", APIVersion: "2011-06-15", Protocol: "query",
		Operations: []iamlivecatalog.WireOperation{{Name: "GetCallerIdentity", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{Method: "POST", URI: "/"}}},
	}}}
	idx, err := buildWireIndex(spy)
	if err != nil {
		t.Fatal(err)
	}
	if spy.calls != 1 {
		t.Fatalf("snapshot calls = %d, want 1", spy.calls)
	}
	d := &Decoder{limits: DefaultDecodeLimits(), classifier: DefaultEndpointClassifier, catalog: idx}
	_, v := stsRequest(io.NopCloser(strings.NewReader("")))
	if _, err := d.Decode(context.Background(), v, v.Endpoint); err != nil {
		t.Fatal(err)
	}
	if spy.calls != 1 {
		t.Fatalf("post-init snapshot calls = %d, want 1", spy.calls)
	}
}

type selectorSpy struct {
	wireSnapshotSpy
	selectorCalls int
}

func (s *selectorSpy) ForEachWireOperation(fn func(iamlivecatalog.WireService, iamlivecatalog.WireOperation) error) error {
	s.selectorCalls++
	for _, service := range s.services {
		for _, operation := range service.Operations {
			if err := fn(service, operation); err != nil {
				return err
			}
		}
	}
	return nil
}

func TestWireIndexUsesImmutableSelectorAndCopiesPublishedCandidates(t *testing.T) {
	spy := &selectorSpy{wireSnapshotSpy: wireSnapshotSpy{services: []iamlivecatalog.WireService{{
		EndpointPrefix: "example", APIVersion: "v1", Protocol: "query",
		Operations: []iamlivecatalog.WireOperation{{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{Method: "POST", URI: "/"}, QueryBindings: []iamlivecatalog.QueryBinding{{Member: "Input", LocationName: "input"}}}},
	}}}}
	idx, err := buildWireIndex(spy)
	if err != nil {
		t.Fatal(err)
	}
	if spy.selectorCalls != 1 || spy.calls != 0 {
		t.Fatalf("selector/snapshot calls = %d/%d, want 1/0", spy.selectorCalls, spy.calls)
	}
	spy.services[0].Operations[0].QueryBindings[0].LocationName = "mutated"
	candidates := idx.query[queryIndexKey{"example", string(ProtocolQuery), "v1", "Op"}]
	if len(candidates) != 1 || candidates[0].queryBindings[0].LocationName != "input" {
		t.Fatal("published wire index aliases selector input")
	}
	if got := catalogQueryOperation(idx, "example", "v1", ProtocolQuery, "Op"); !got {
		t.Fatal("single immutable wire candidate was not addressable")
	}
}

func TestWireIndexRejectsMalformedFixedRouteQuery(t *testing.T) {
	spy := &wireSnapshotSpy{services: []iamlivecatalog.WireService{{
		EndpointPrefix: "example", Protocol: "rest-xml",
		Operations: []iamlivecatalog.WireOperation{{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{Method: "GET", URI: "/items?%zz=x"}}},
	}}}
	if _, err := buildWireIndex(spy); err == nil {
		t.Fatal("malformed fixed query accepted")
	}
}

func TestQueryExactVersionBucketsPreserveOccurrenceMultiplicity(t *testing.T) {
	services := []iamlivecatalog.WireService{
		{EndpointPrefix: "example", APIVersion: "v1", Protocol: "query", Operations: []iamlivecatalog.WireOperation{{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{Method: "POST", URI: "/"}}}},
		{EndpointPrefix: "example", APIVersion: "v2", Protocol: "query", Operations: []iamlivecatalog.WireOperation{{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{Method: "POST", URI: "/"}}}},
	}
	idx, err := buildWireIndex(&wireSnapshotSpy{services: services})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		version string
		want    bool
	}{
		{"absent exact bucket", "missing", false},
		{"one known candidate", "v1", true},
		{"different version cannot satisfy requested version", "v3", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := catalogQueryOperation(idx, "example", tc.version, ProtocolQuery, "Op"); got != tc.want {
				t.Fatalf("catalogQueryOperation version %q = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
	differentVersionOnly, err := buildWireIndex(&wireSnapshotSpy{services: []iamlivecatalog.WireService{services[1]}})
	if err != nil {
		t.Fatal(err)
	}
	if got := catalogQueryOperation(differentVersionOnly, "example", "v1", ProtocolQuery, "Op"); got {
		t.Fatal("operation from API version v2 satisfied a requested v1 bucket")
	}

	duplicateServices := append([]iamlivecatalog.WireService(nil), services[:1]...)
	duplicateServices[0].Operations = append(duplicateServices[0].Operations, duplicateServices[0].Operations[0])
	duplicateIndex, err := buildWireIndex(&wireSnapshotSpy{services: duplicateServices})
	if err != nil {
		t.Fatal(err)
	}
	if got := catalogQueryOperation(duplicateIndex, "example", "v1", ProtocolQuery, "Op"); got {
		t.Fatal("multiple same-key raw query occurrences were accepted")
	}
}

func TestTier1WireIndexPreservesExactRDSQueryVersions(t *testing.T) {
	catalog, err := iamlivecatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	idx, err := buildWireIndex(catalog)
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]bool{}
	for _, service := range catalog.WireServices() {
		if service.EndpointPrefix != "rds" || service.Protocol != "query" {
			continue
		}
		for _, operation := range service.Operations {
			if operation.Name == "DescribeDBInstances" && operation.State == iamlivecatalog.EvidenceKnown {
				versions[service.APIVersion] = true
			}
		}
	}
	if len(versions) < 2 {
		t.Fatalf("RDS repeated query model versions = %d, want at least 2", len(versions))
	}
	for version := range versions {
		key := queryIndexKey{"rds", string(ProtocolQuery), version, "DescribeDBInstances"}
		if len(idx.query[key]) == 0 {
			t.Errorf("RDS DescribeDBInstances has no exact wire bucket for API version %q", version)
		}
	}
	// An unambiguous older model remains addressable, while the pinned latest
	// model deliberately retains its repeated occurrences and therefore fails
	// closed instead of borrowing evidence from another API version.
	if !catalogQueryOperation(idx, "rds", "2013-02-12", ProtocolQuery, "DescribeDBInstances") {
		t.Fatal("RDS operation from an exact, unambiguous API version was not addressable")
	}
	latest := idx.query[queryIndexKey{"rds", string(ProtocolQuery), "2014-10-31", "DescribeDBInstances"}]
	if len(latest) < 2 || catalogQueryOperation(idx, "rds", "2014-10-31", ProtocolQuery, "DescribeDBInstances") {
		t.Fatalf("RDS repeated latest-model occurrences were collapsed or accepted: %d", len(latest))
	}
	if catalogQueryOperation(idx, "rds", "2014-10-30", ProtocolQuery, "DescribeDBInstances") {
		t.Fatal("RDS operation from an absent API version satisfied an exact query bucket")
	}
}

func TestTier1WireIndexPreservesExactJSONWireVersion(t *testing.T) {
	catalog, err := iamlivecatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	idx, err := buildWireIndex(catalog)
	if err != nil {
		t.Fatal(err)
	}
	var selected iamlivecatalog.WireService
	var operation iamlivecatalog.WireOperation
	for _, service := range catalog.WireServices() {
		if service.EndpointPrefix != "acm" || service.Protocol != "json" || service.APIVersion != "2015-12-08" {
			continue
		}
		for _, candidate := range service.Operations {
			if candidate.State == iamlivecatalog.EvidenceKnown && candidate.Route.JSONVersion == "1.1" {
				selected, operation = service, candidate
				break
			}
		}
		if operation.Name != "" {
			break
		}
	}
	if operation.Name == "" {
		t.Fatal("pinned ACM JSON 1.1 operation was not found")
	}
	target := selected.TargetPrefix + "." + operation.Name
	if got, err := targetOperationFor(target, "acm", ProtocolJSON11, idx, 128); err != nil || got != operation.Name {
		t.Fatalf("exact JSON 1.1 operation lookup failed: %q %v", got, err)
	}
	if got, err := targetOperationFor(target, "acm", ProtocolJSON10, idx, 128); err == nil {
		t.Fatalf("JSON 1.0 incorrectly satisfied a JSON 1.1 operation lookup: %q", got)
	}
}

func TestModeledWireRouteRejectsWrongHTTPMethods(t *testing.T) {
	cases := []struct {
		name     string
		protocol AWSProtocol
		targets  []string
		service  iamlivecatalog.WireService
		query    url.Values
	}{
		{
			name:     "query",
			protocol: ProtocolQuery,
			query:    url.Values{"Action": {"Op"}, "Version": {"v1"}},
			service:  iamlivecatalog.WireService{EndpointPrefix: "example", APIVersion: "v1", Protocol: "query", Operations: []iamlivecatalog.WireOperation{{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{Method: "POST", URI: "/"}}}},
		},
		{
			name:     "json",
			protocol: ProtocolJSON10,
			targets:  []string{"Target.Op"},
			service:  iamlivecatalog.WireService{EndpointPrefix: "example", TargetPrefix: "Target", Protocol: "json", Operations: []iamlivecatalog.WireOperation{{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{Method: "POST", URI: "/", TargetPrefix: "Target", JSONVersion: "1.0"}}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx, err := buildWireIndex(&wireSnapshotSpy{services: []iamlivecatalog.WireService{tc.service}})
			if err != nil {
				t.Fatal(err)
			}
			if err := validateModeledWireRoute(idx, "example", tc.protocol, "/", http.MethodGet, tc.query, tc.targets); err == nil || err.Error() != "wire route conflicts with protocol operation" {
				t.Fatalf("wrong method error = %v, want fail-closed route error", err)
			}
			if err := validateModeledWireRoute(idx, "example", tc.protocol, "/", http.MethodPost, tc.query, tc.targets); err != nil {
				t.Fatalf("correct method rejected: %v", err)
			}
		})
	}
}

func TestJSONVariantOwnershipAndRESTQueryEvidenceFailClosed(t *testing.T) {
	owned := &wireSnapshotSpy{services: []iamlivecatalog.WireService{{EndpointPrefix: "example", TargetPrefix: "TargetA", Protocol: "json", Operations: []iamlivecatalog.WireOperation{{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{TargetPrefix: "TargetA", JSONVersion: "1.0"}}}}}}
	idx, err := buildWireIndex(owned)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := targetOperationFor("TargetA.Op", "example", ProtocolJSON10, idx, 128); err != nil || got != "Op" {
		t.Fatalf("owned target rejected: %q %v", got, err)
	}
	variant := &wireSnapshotSpy{services: []iamlivecatalog.WireService{
		{EndpointPrefix: "example", TargetPrefix: "TargetA", Protocol: "json", Operations: []iamlivecatalog.WireOperation{{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{TargetPrefix: "TargetA", JSONVersion: "1.0"}}}},
		{EndpointPrefix: "example", TargetPrefix: "TargetB", Protocol: "json", Operations: []iamlivecatalog.WireOperation{{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{TargetPrefix: "TargetA", JSONVersion: "1.0"}}}},
	}}
	idx, err = buildWireIndex(variant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetOperationFor("TargetA.Op", "example", ProtocolJSON10, idx, 128); err == nil {
		t.Fatal("ambiguous variant ownership accepted")
	}
	rest := &wireSnapshotSpy{services: []iamlivecatalog.WireService{{EndpointPrefix: "example", Protocol: "rest-xml", Operations: []iamlivecatalog.WireOperation{
		{Name: "One", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{Method: "GET", URI: "/items"}, QueryBindings: []iamlivecatalog.QueryBinding{{LocationName: "kind", Required: true}}},
		{Name: "Two", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{Method: "GET", URI: "/items"}, QueryBindings: []iamlivecatalog.QueryBinding{{LocationName: "other", Required: true}}},
	}}}}
	idx, err = buildWireIndex(rest)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := restOperationFromCatalog("example", "/items", "GET", url.Values{"kind": {"x"}}, ProtocolRESTXML, idx, DefaultDecodeLimits()); err != nil || got != "One" {
		t.Fatalf("single REST binding did not disambiguate: %q %v", got, err)
	}
	if _, _, err := restOperationFromCatalog("example", "/items", "GET", url.Values{"kind": {"x"}, "other": {"y"}}, ProtocolRESTXML, idx, DefaultDecodeLimits()); err == nil {
		t.Fatal("multiple REST bindings accepted")
	}
}

func TestSharedDecoderConcurrentActualDecode(t *testing.T) {
	d := NewDecoder()
	const workers = 12
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, v := stsRequest(io.NopCloser(strings.NewReader("")))
			if _, err := d.Decode(context.Background(), v, v.Endpoint); err != nil {
				errs <- err
				return
			}
			if r.Method != http.MethodPost {
				errs <- &wireIndexTestError{"method changed"}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

var (
	allocationDecodeResult *DecodedAWSRequest
	allocationDecodeErr    error
)

func TestBenchmarkDecodeQueryAllocationCeiling(t *testing.T) {
	if defaultWireIndexOrNil() == nil {
		t.Fatal("wire index unavailable")
	}
	d, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		t.Fatal(err)
	}
	_, v := stsRequest(io.NopCloser(strings.NewReader("")))
	const ceiling = 128
	observed := testing.AllocsPerRun(20, func() {
		allocationDecodeResult, allocationDecodeErr = d.Decode(context.Background(), v, v.Endpoint)
	})
	if allocationDecodeErr != nil {
		t.Fatalf("BenchmarkDecodeQuery failed: %v (observed allocations %.0f, ceiling %d)", allocationDecodeErr, observed, ceiling)
	}
	if observed > ceiling {
		t.Fatalf("BenchmarkDecodeQuery allocations: observed %.0f, ceiling %d", observed, ceiling)
	}
}

func TestBenchmarkDecodeJSONAllocationCeiling(t *testing.T) {
	if defaultWireIndexOrNil() == nil {
		t.Fatal("wire index unavailable")
	}
	ep, err := DefaultEndpointClassifier.Classify("dynamodb.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/", strings.NewReader(`{"TableName":"events","Key":{"id":{"S":"1"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = ep.Host
	r.Header.Set("Content-Type", "application/x-amz-json-1.0")
	r.Header.Set("X-Amz-Target", "DynamoDB_20120810.GetItem")
	v := &VerifiedRequest{Request: r, Endpoint: ep, Protocol: ProtocolJSON10, SigningScheme: SigningHeaderV4, SigningRegion: ep.Region, SigningService: ep.Service, PayloadMode: PayloadHashSHA256}
	d, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		t.Fatal(err)
	}
	const ceiling = 256
	observed := testing.AllocsPerRun(20, func() {
		allocationDecodeResult, allocationDecodeErr = d.Decode(context.Background(), v, v.Endpoint)
	})
	if allocationDecodeErr != nil {
		t.Fatalf("BenchmarkDecodeJSON failed: %v (observed allocations %.0f, ceiling %d)", allocationDecodeErr, observed, ceiling)
	}
	if observed > ceiling {
		t.Fatalf("BenchmarkDecodeJSON allocations: observed %.0f, ceiling %d", observed, ceiling)
	}
}

type wireIndexTestError struct{ message string }

func (e *wireIndexTestError) Error() string { return e.message }
