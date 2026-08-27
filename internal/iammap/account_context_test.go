package iammap

import (
	"context"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

func TestUnknownAccountContextOnlyResolvesKnownGlobal(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatal(err)
	}
	global := goldenRequest("ec2", "ec2.us-east-1.amazonaws.com", "us-east-1", "DescribeInstances", nil)
	global.CallerAccountID = ""
	if result, err := m.Map(context.Background(), global); err != nil || result == nil {
		t.Fatalf("known-global mapping with unknown account failed: result=%+v err=%v", result, err)
	}
	scoped := goldenRequest("dynamodb", "dynamodb.us-east-1.amazonaws.com", "us-east-1", "GetItem", map[string]awsrequest.Value{"TableName": str("events")})
	scoped.CallerAccountID = ""
	if result, err := m.Map(context.Background(), scoped); err == nil || result != nil {
		t.Fatalf("account-scoped mapping widened with unknown account: result=%+v err=%v", result, err)
	}
	global.CallerAccountID = "12345678901 "
	if result, err := m.Map(context.Background(), global); err == nil || result != nil {
		t.Fatalf("invalid account reached global mapper: result=%+v err=%v", result, err)
	}
}
