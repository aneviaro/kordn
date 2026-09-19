package iammap

import (
	"context"
	"net/http"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
)

var (
	benchmarkLookupResult       iamliveadapter.LookupResult
	benchmarkLookupErr          error
	benchmarkCatalogCardinality int
	benchmarkCatalogOccurrences []iamlivecatalog.OperationOccurrence
)

func BenchmarkLookupRequest(b *testing.B) {
	adapter, err := iamliveadapter.New()
	if err != nil {
		b.Fatal(err)
	}
	identity := iamliveadapter.WireIdentity{
		Protocol: awsrequest.ProtocolJSON10,
		Method:   "POST",
		Path:     "/",
		Target:   "DynamoDB_20120810.GetItem",
	}
	parameters := map[string]awsrequest.Value{"TableName": {Kind: awsrequest.ValueString, String: "bench-table-0"}}
	tableNames := []string{"bench-table-0", "bench-table-1", "bench-table-2", "bench-table-3"}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; b.Loop(); iteration++ {
		parameters["TableName"] = awsrequest.Value{Kind: awsrequest.ValueString, String: tableNames[iteration%len(tableNames)]}
		benchmarkLookupResult, benchmarkLookupErr = adapter.LookupRequest("dynamodb", "GetItem", identity, parameters)
		if benchmarkLookupErr != nil {
			b.Fatal(benchmarkLookupErr)
		}
	}
}

func BenchmarkCatalogResidentLookup(b *testing.B) {
	catalog, err := iamlivecatalog.Load()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(catalog.InternedStringCardinality()), "interned-strings")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkCatalogCardinality = catalog.OperationCardinality("sts", "GetCallerIdentity")
		if benchmarkCatalogCardinality != 1 {
			b.Fatalf("operation cardinality = %d", benchmarkCatalogCardinality)
		}
	}
}

func BenchmarkMapping(b *testing.B) {
	mapper, err := NewMapper()
	if err != nil {
		b.Fatal(err)
	}
	protocol, _ := awsrequest.AuthoritativeProtocol("dynamodb")
	req := &awsrequest.DecodedAWSRequest{
		Partition: "aws", EndpointHost: "dynamodb.us-east-1.amazonaws.com", Service: "dynamodb", Region: "us-east-1",
		CallerAccountID: "123456789012", Protocol: protocol, Operation: "GetItem", Method: "POST", CanonicalPath: "/",
		Parameters:      map[string]awsrequest.Value{"TableName": {Kind: awsrequest.ValueString, String: "bench-table"}},
		Headers:         http.Header{"X-Amz-Target": []string{"DynamoDB_20120810.GetItem"}},
		PayloadHashMode: awsrequest.PayloadHashSHA256,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mapper.Map(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStagedMapping(b *testing.B) {
	catalog, err := iamlivecatalog.Load()
	if err != nil {
		b.Fatal(err)
	}
	adapter, err := iamliveadapter.New()
	if err != nil {
		b.Fatal(err)
	}
	mapper, err := NewMapper()
	if err != nil {
		b.Fatal(err)
	}
	identity := iamliveadapter.WireIdentity{
		Protocol: awsrequest.ProtocolJSON10,
		Method:   "POST",
		Path:     "/",
		Target:   "DynamoDB_20120810.GetItem",
	}
	parameters := map[string]awsrequest.Value{"TableName": {Kind: awsrequest.ValueString, String: "bench-table"}}
	protocol, _ := awsrequest.AuthoritativeProtocol("dynamodb")
	request := &awsrequest.DecodedAWSRequest{
		Partition: "aws", EndpointHost: "dynamodb.us-east-1.amazonaws.com", Service: "dynamodb", Region: "us-east-1",
		CallerAccountID: "123456789012", Protocol: protocol, Operation: "GetItem", Method: "POST", CanonicalPath: "/",
		Parameters: parameters, Headers: http.Header{"X-Amz-Target": []string{"DynamoDB_20120810.GetItem"}},
		PayloadHashMode: awsrequest.PayloadHashSHA256,
	}

	b.Run("catalog-select", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkCatalogOccurrences = catalog.OperationOccurrences("dynamodb", "GetItem")
			if len(benchmarkCatalogOccurrences) == 0 {
				b.Fatal("catalog operation unavailable")
			}
		}
	})
	b.Run("adapter-lookup", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkLookupResult, benchmarkLookupErr = adapter.LookupRequest("dynamodb", "GetItem", identity, parameters)
			if benchmarkLookupErr != nil {
				b.Fatal(benchmarkLookupErr)
			}
		}
	})
	b.Run("mapper", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := mapper.Map(context.Background(), request); err != nil {
				b.Fatal(err)
			}
		}
	})
}
