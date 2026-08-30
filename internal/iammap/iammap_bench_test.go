package iammap

import (
	"context"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

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
