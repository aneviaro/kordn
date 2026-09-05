package iammap

import (
	"context"
	"net/http"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
)

var (
	benchmarkLookupResult iamliveadapter.LookupResult
	benchmarkLookupErr    error
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
