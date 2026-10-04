package iammap

import (
	"context"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

func TestS3ControlEndpointAccountBindsToDecodedContext(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatal(err)
	}
	host := "123456789012.s3-control.us-east-1.amazonaws.com"
	req := goldenRequest("s3-control", host, "us-east-1", "ListAccessPoints", map[string]awsrequest.Value{"AccountId": str("123456789012")})
	req.AccountID = "123456789012"
	req.Method = "GET"
	req.CanonicalPath = "/v20180820/accesspoint"
	endpoint, err := awsrequest.ClassifyEndpoint(host)
	if err != nil {
		t.Fatal(err)
	}
	req.SigningService = endpoint.SigningService
	req.SigningRegion = endpoint.SigningRegion
	decodedEndpoint := awsrequest.AWSEndpoint{Partition: req.Partition, Host: req.EndpointHost, Service: req.Service, SigningService: req.SigningService, SigningRegion: req.SigningRegion, Region: req.Region, Scope: req.Scope, AccountID: req.AccountID}
	if !awsrequest.SameEndpoint(endpoint, decodedEndpoint) {
		t.Fatalf("decoded S3 Control endpoint lost account evidence: classified=%+v decoded=%+v", endpoint, decodedEndpoint)
	}

	mismatched := *req
	mismatched.CallerAccountID = "210987654321"
	if result, err := m.Map(context.Background(), &mismatched); err == nil || result != nil {
		t.Fatalf("S3 Control account disagreement reached policy mapping: result=%+v err=%v", result, err)
	}
}

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
