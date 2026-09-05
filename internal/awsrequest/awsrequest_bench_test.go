package awsrequest

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

var (
	benchmarkDecodeResult        *DecodedAWSRequest
	benchmarkDecodeErr           error
	benchmarkWireLookupResult    bool
	benchmarkWireLookupOperation string
	benchmarkWireLookupErr       error
)

func benchmarkVerified(b *testing.B, service, host string, protocol AWSProtocol, contentType, target string, body []byte) (*VerifiedRequest, AWSEndpoint) {
	b.Helper()
	ep := AWSEndpoint{Partition: "aws", Host: host, Service: service, Region: "us-east-1", Scope: ScopeRegional}
	req, err := http.NewRequest(http.MethodPost, "https://"+host+"/", bytes.NewReader(body))
	if err != nil {
		b.Fatal(err)
	}
	req.Host = host
	req.Header.Set("Content-Type", contentType)
	if target != "" {
		req.Header.Set("X-Amz-Target", target)
	}
	return &VerifiedRequest{Request: req, Endpoint: ep, Protocol: protocol, SigningScheme: SigningHeaderV4, SigningRegion: ep.Region, SigningService: service, PayloadMode: PayloadHashSHA256}, ep
}

func BenchmarkDecodeQuery(b *testing.B) {
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	v, ep := benchmarkVerified(b, "sts", "sts.us-east-1.amazonaws.com", ProtocolQuery, "application/x-www-form-urlencoded", "", body)
	d, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkDecodeResult, benchmarkDecodeErr = d.Decode(context.Background(), v, ep)
		if benchmarkDecodeErr != nil {
			b.Fatal(benchmarkDecodeErr)
		}
	}
}

func BenchmarkDecodeJSON(b *testing.B) {
	body := []byte(`{"TableName":"events","Key":{"id":{"S":"1"}}}`)
	v, ep := benchmarkVerified(b, "dynamodb", "dynamodb.us-east-1.amazonaws.com", ProtocolJSON10, "application/x-amz-json-1.0", "DynamoDB_20120810.GetItem", body)
	d, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkDecodeResult, benchmarkDecodeErr = d.Decode(context.Background(), v, ep)
		if benchmarkDecodeErr != nil {
			b.Fatal(benchmarkDecodeErr)
		}
	}
}

func BenchmarkWireIndexLookupQueryExact(b *testing.B) {
	idx := defaultWireIndexOrNil()
	if idx == nil {
		b.Fatal("wire index unavailable")
	}
	const service, version, action = "sts", "2011-06-15", "GetCallerIdentity"
	if !catalogQueryOperation(idx, service, version, ProtocolQuery, action) {
		b.Fatal("exact query candidate is unavailable")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkWireLookupResult = catalogQueryOperation(idx, service, version, ProtocolQuery, action)
	}
}

func BenchmarkWireIndexLookupQueryNegative(b *testing.B) {
	idx := defaultWireIndexOrNil()
	if idx == nil {
		b.Fatal("wire index unavailable")
	}
	const service, version, action = "sts", "2011-06-15", "OperationAbsentFromCatalog"
	if catalogQueryOperation(idx, service, version, ProtocolQuery, action) {
		b.Fatal("negative query candidate unexpectedly exists")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkWireLookupResult = catalogQueryOperation(idx, service, version, ProtocolQuery, action)
	}
}

func BenchmarkWireIndexLookupQueryAmbiguous(b *testing.B) {
	idx, err := buildWireIndex(&wireSnapshotSpy{services: []iamlivecatalog.WireService{{
		EndpointPrefix: "bench", APIVersion: "v1", Protocol: "query",
		Operations: []iamlivecatalog.WireOperation{
			{Name: "Op", State: iamlivecatalog.EvidenceKnown},
			{Name: "Op", State: iamlivecatalog.EvidenceKnown},
		},
	}}})
	if err != nil {
		b.Fatal(err)
	}
	if catalogQueryOperation(idx, "bench", "v1", ProtocolQuery, "Op") {
		b.Fatal("ambiguous query candidate unexpectedly succeeded")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkWireLookupResult = catalogQueryOperation(idx, "bench", "v1", ProtocolQuery, "Op")
	}
}

func BenchmarkWireIndexLookupJSONExact(b *testing.B) {
	idx := defaultWireIndexOrNil()
	if idx == nil {
		b.Fatal("wire index unavailable")
	}
	const service, target = "dynamodb", "DynamoDB_20120810.GetItem"
	if operation, err := targetOperationFor(target, service, ProtocolJSON10, idx, 4096); err != nil || operation != "GetItem" {
		b.Fatalf("exact JSON candidate unavailable: %q %v", operation, err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkWireLookupOperation, benchmarkWireLookupErr = targetOperationFor(target, service, ProtocolJSON10, idx, 4096)
	}
}

func BenchmarkWireIndexLookupJSONAmbiguous(b *testing.B) {
	idx, err := buildWireIndex(&wireSnapshotSpy{services: []iamlivecatalog.WireService{{
		EndpointPrefix: "bench", TargetPrefix: "Bench", Protocol: "json",
		Operations: []iamlivecatalog.WireOperation{
			{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{TargetPrefix: "Bench", JSONVersion: "1.0"}},
			{Name: "Op", State: iamlivecatalog.EvidenceKnown, Route: iamlivecatalog.Route{TargetPrefix: "Bench", JSONVersion: "1.0"}},
		},
	}}})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := targetOperationFor("Bench.Op", "bench", ProtocolJSON10, idx, 4096); err == nil {
		b.Fatal("ambiguous JSON candidate unexpectedly succeeded")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkWireLookupOperation, benchmarkWireLookupErr = targetOperationFor("Bench.Op", "bench", ProtocolJSON10, idx, 4096)
	}
}
