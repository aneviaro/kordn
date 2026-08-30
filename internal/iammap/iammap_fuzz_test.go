package iammap

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

// FuzzMapperInput calls the production Mapper and its resource/ARN
// extraction, rather than testing a local string helper. Errors are the
// expected fail-closed result for unknown operations or malformed evidence.
func FuzzMapperInput(f *testing.F) {
	f.Add(0, "GetObject", "bucket", "key")
	f.Add(1, "GetItem", "table", "key")
	f.Add(2, "DescribeInstances", "i-12345678", "")
	f.Add(3, "GetRole", "role", "")
	mapper, err := NewMapper(MapperOptions{Timeout: time.Second})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, family int, operation, bucket, key string) {
		if len(operation) > 128 || len(bucket) > 256 || len(key) > 256 {
			return
		}
		service, host, protocol := "s3", "s3.us-east-1.amazonaws.com", awsrequest.ProtocolRESTXML
		params := map[string]awsrequest.Value{
			"Bucket": {Kind: awsrequest.ValueString, String: bucket},
			"Key":    {Kind: awsrequest.ValueString, String: key},
		}
		switch ((family % 4) + 4) % 4 {
		case 1:
			service, host, protocol, operation = "dynamodb", "dynamodb.us-east-1.amazonaws.com", awsrequest.ProtocolJSON10, "GetItem"
			params = map[string]awsrequest.Value{"TableName": {Kind: awsrequest.ValueString, String: bucket}}
		case 2:
			service, host, protocol, operation = "ec2", "ec2.us-east-1.amazonaws.com", awsrequest.ProtocolQuery, "DescribeInstances"
		case 3:
			service, host, protocol, operation = "iam", "iam.amazonaws.com", awsrequest.ProtocolQuery, "GetRole"
			params = map[string]awsrequest.Value{"RoleName": {Kind: awsrequest.ValueString, String: bucket}}
		}
		req := &awsrequest.DecodedAWSRequest{Partition: "aws", EndpointHost: host, Service: service, Region: "us-east-1", CallerAccountID: "123456789012", Protocol: protocol, Operation: operation, Method: "POST", CanonicalPath: "/", Parameters: params, PayloadHashMode: awsrequest.PayloadHashSHA256}
		before := *req
		before.Parameters = cloneValues(req.Parameters)
		first, _ := mapper.Map(context.Background(), req)
		second, _ := mapper.Map(context.Background(), req)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("mapper is not deterministic: first=%+v second=%+v", first, second)
		}
		if !reflect.DeepEqual(req, &before) {
			t.Fatal("mapper mutated decoded request")
		}
		if first != nil {
			for _, requirement := range first.Requirements {
				if requirement.ScopeKind == awsrequest.ScopeUnresolved && len(requirement.Resources) != 0 {
					t.Fatalf("unresolved scope widened into resources: %+v", requirement)
				}
			}
		}
	})
}

func cloneValues(input map[string]awsrequest.Value) map[string]awsrequest.Value {
	output := make(map[string]awsrequest.Value, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
