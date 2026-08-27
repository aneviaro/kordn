// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package iammap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iammap/data"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
)

func goldenRequest(service, host, region, op string, p map[string]awsrequest.Value) *awsrequest.DecodedAWSRequest {
	protocol, _ := awsrequest.AuthoritativeProtocol(service)
	return &awsrequest.DecodedAWSRequest{Partition: "aws", EndpointHost: host, Service: service, Region: region, Protocol: protocol, Operation: op, Method: "POST", CanonicalPath: "/", Parameters: p, Headers: map[string][]string{}, PayloadHashMode: awsrequest.PayloadHashSHA256, CallerAccountID: "123456789012"}
}
func str(v string) awsrequest.Value { return awsrequest.Value{Kind: awsrequest.ValueString, String: v} }
func TestGoldenMappings(t *testing.T) {
	m, e := NewMapper()
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		s, h, r, o string
		p          map[string]awsrequest.Value
		a          string
		scope      awsrequest.ScopeKind
	}{{"ec2", "ec2.us-east-1.amazonaws.com", "us-east-1", "DescribeInstances", nil, "ec2:DescribeInstances", awsrequest.ScopeKnownGlobal}, {"ecs", "ecs.us-east-1.amazonaws.com", "us-east-1", "RunTask", map[string]awsrequest.Value{"TaskDefinition": str("web"), "TaskRoleArn": str("arn:aws:iam::123456789012:role/task")}, "ecs:RunTask", awsrequest.ScopeExact}, {"sts", "sts.us-east-1.amazonaws.com", "us-east-1", "GetCallerIdentity", nil, "sts:GetCallerIdentity", awsrequest.ScopeKnownGlobal}, {"s3", "s3.us-east-1.amazonaws.com", "us-east-1", "GetObject", map[string]awsrequest.Value{"Bucket": str("bucket"), "Key": str("key")}, "s3:GetObject", awsrequest.ScopeExact}, {"cloudwatch", "monitoring.us-east-1.amazonaws.com", "us-east-1", "PutMetricData", map[string]awsrequest.Value{"Namespace": str("App")}, "cloudwatch:PutMetricData", awsrequest.ScopeExact}, {"logs", "logs.us-east-1.amazonaws.com", "us-east-1", "CreateLogGroup", map[string]awsrequest.Value{"LogGroupName": str("app")}, "logs:CreateLogGroup", awsrequest.ScopeExact}, {"iam", "iam.amazonaws.com", "", "GetRole", map[string]awsrequest.Value{"RoleName": str("reader")}, "iam:GetRole", awsrequest.ScopeExact}, {"lambda", "lambda.us-east-1.amazonaws.com", "us-east-1", "Invoke", map[string]awsrequest.Value{"FunctionName": str("fn")}, "lambda:InvokeFunction", awsrequest.ScopeExact}, {"dynamodb", "dynamodb.us-east-1.amazonaws.com", "us-east-1", "GetItem", map[string]awsrequest.Value{"TableName": str("events")}, "dynamodb:GetItem", awsrequest.ScopeExact}}
	for _, tc := range cases {
		t.Run(tc.s, func(t *testing.T) {
			r, e := m.Map(context.Background(), goldenRequest(tc.s, tc.h, tc.r, tc.o, tc.p))
			if e != nil {
				t.Fatal(e)
			}
			if r == nil || r.Confidence != awsrequest.ConfidenceHigh || r.Requirements[0].Action != tc.a || r.Requirements[0].ScopeKind != tc.scope {
				t.Fatalf("bad mapping: %+v", r)
			}
			if r.IamLiveVersion == "" || r.AuthorizationDataVersion == "" {
				t.Fatal("missing provenance")
			}
		})
	}
}
func TestAssumeRoleUsesCrossAccountRoleARN(t *testing.T) {
	m, e := NewMapper()
	if e != nil {
		t.Fatal(e)
	}
	r := goldenRequest("sts", "sts.us-east-1.amazonaws.com", "us-east-1", "AssumeRole", map[string]awsrequest.Value{"RoleArn": str("arn:aws:iam::999999999999:role/deploy")})
	got, e := m.Map(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	want := "arn:aws:iam::999999999999:role/deploy"
	if len(got.Requirements) != 1 || got.Requirements[0].Action != "sts:AssumeRole" || len(got.Requirements[0].Resources) != 1 || got.Requirements[0].Resources[0] != want {
		t.Fatalf("unexpected AssumeRole mapping: %+v", got)
	}
}

func TestDependentPassRole(t *testing.T) {
	m, _ := NewMapper()
	r := goldenRequest("ecs", "ecs.us-east-1.amazonaws.com", "us-east-1", "CreateService", map[string]awsrequest.Value{"Cluster": str("prod"), "Service": str("api"), "TaskRoleArn": str("arn:aws:iam::123456789012:role/task")})
	x, e := m.Map(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, q := range x.Requirements {
		if q.Action == "iam:PassRole" {
			found = q.Dependent && q.ScopeKind == awsrequest.ScopeExact
		}
	}
	if !found {
		t.Fatalf("PassRole absent: %+v", x.Requirements)
	}
}
func TestUnknownFailsClosed(t *testing.T) {
	m, _ := NewMapper()
	r := goldenRequest("ec2", "ec2.us-east-1.amazonaws.com", "us-east-1", "NoSuchOperation", nil)
	x, e := m.Map(context.Background(), r)
	if e == nil || x != nil {
		t.Fatalf("unknown was forwardable: %v %+v", e, x)
	}
}
func TestNoScopeWidening(t *testing.T) {
	m, _ := NewMapper()
	r := goldenRequest("s3", "s3.us-east-1.amazonaws.com", "us-east-1", "GetObject", map[string]awsrequest.Value{"Bucket": str("bucket")})
	x, e := m.Map(context.Background(), r)
	if e == nil || x != nil || !strings.Contains(e.Error(), "unresolved primary resource") {
		t.Fatalf("unresolved was forwardable: %v %+v", e, x)
	}
	r = goldenRequest("ecs", "ecs.us-east-1.amazonaws.com", "us-east-1", "RunTask", map[string]awsrequest.Value{"TaskDefinition": str("web")})
	x, e = m.Map(context.Background(), r)
	if e == nil || x != nil || !strings.Contains(e.Error(), "dependency applicability") {
		t.Fatalf("unknown dependency was forwardable: %v %+v", e, x)
	}
}
func TestMapperPanicAndTimeoutFailClosed(t *testing.T) {
	panicMapper, e := newMapperForTest(MapperOptions{Timeout: 100 * time.Millisecond}, panicAdapter{})
	if e != nil {
		t.Fatal(e)
	}
	r := goldenRequest("ec2", "ec2.us-east-1.amazonaws.com", "us-east-1", "DescribeInstances", nil)
	if got, e := panicMapper.Map(context.Background(), r); got != nil || e == nil {
		t.Fatalf("panic was forwardable: %v %+v", e, got)
	}
	release := make(chan struct{})
	defer close(release)
	timeoutMapper, e := newMapperForTest(MapperOptions{Timeout: time.Millisecond}, blockingAdapter{release: release})
	if e != nil {
		t.Fatal(e)
	}
	if got, e := timeoutMapper.Map(context.Background(), r); got != nil || e == nil {
		t.Fatalf("timeout was forwardable: %v %+v", e, got)
	}
}

func TestStaleEndpointFailsClosed(t *testing.T) {
	m, e := NewMapper(MapperOptions{Timeout: 100 * time.Millisecond, Classifier: staleClassifier{}})
	if e != nil {
		t.Fatal(e)
	}
	r := goldenRequest("ec2", "ec2.us-east-1.amazonaws.com", "us-east-1", "DescribeInstances", nil)
	if got, e := m.Map(context.Background(), r); got != nil || e == nil {
		t.Fatalf("stale endpoint was forwardable: %v %+v", e, got)
	}
}

type staleClassifier struct{}

func (staleClassifier) Classify(string) (awsrequest.AWSEndpoint, error) {
	return awsrequest.AWSEndpoint{Partition: "aws", Host: "ec2.us-east-1.amazonaws.com", Service: "s3", Region: "us-east-1", Scope: awsrequest.ScopeRegional}, nil
}

type panicAdapter struct{}

func (panicAdapter) Lookup(string, string, ...map[string]awsrequest.Value) (iamliveadapter.LookupResult, error) {
	panic("test panic")
}
func (panicAdapter) Version() string { return iamliveadapter.AdapterVersion }

type blockingAdapter struct{ release <-chan struct{} }

func (a blockingAdapter) Lookup(string, string, ...map[string]awsrequest.Value) (iamliveadapter.LookupResult, error) {
	<-a.release
	return iamliveadapter.LookupResult{}, errors.New("test adapter released")
}
func (blockingAdapter) Version() string { return iamliveadapter.AdapterVersion }

// newMapperForTest is a same-package-only seam for fail-closed tests. Public
// constructors never accept an adapter.
func newMapperForTest(o MapperOptions, adapter mapperAdapter) (*Mapper, error) {
	if o.Timeout == 0 {
		o.Timeout = time.Second
	}
	if o.Timeout <= 0 || o.Timeout > time.Minute {
		return nil, errors.New("mapper timeout is invalid")
	}
	if o.Classifier == nil {
		o.Classifier = awsrequest.DefaultEndpointClassifier
	}
	if adapter == nil {
		var err error
		adapter, err = iamliveadapter.New()
		if err != nil {
			return nil, err
		}
	}
	return &Mapper{timeout: o.Timeout, classifier: o.Classifier, adapter: adapter}, nil
}

func TestWideningBaselineClasses(t *testing.T) {
	base, e := data.BaselineEntries()
	if e != nil {
		t.Fatal(e)
	}
	tests := []struct {
		pick   func(data.Entry) bool
		mutate func(*data.Entry)
	}{
		{func(data.Entry) bool { return true }, func(x *data.Entry) { x.Action = "x:Changed" }},
		{func(x data.Entry) bool { return x.Resource != "global" }, func(x *data.Entry) { x.Resource = "global" }},
		{func(x data.Entry) bool { return len(x.Dependencies) > 0 }, func(x *data.Entry) { x.Dependencies = nil }},
		{func(x data.Entry) bool { return x.Scope != "unresolved" }, func(x *data.Entry) { x.Scope = "unresolved" }},
	}
	for _, tc := range tests {
		i := -1
		for j, x := range base {
			if tc.pick(x) {
				i = j
				break
			}
		}
		if i < 0 {
			t.Fatal("baseline lacks mutation fixture")
		}
		candidate := append([]data.Entry(nil), base...)
		tc.mutate(&candidate[i])
		if data.CheckNoWidening(base, candidate) == nil {
			t.Fatal("widening mutation accepted")
		}
	}
}
