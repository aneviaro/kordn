package iammap

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iammap/data"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
)

func TestVariedWireToMappingContracts(t *testing.T) {
	cases := []struct {
		name, authority, target, query, body, operation, action string
		protocol                                                awsrequest.AWSProtocol
		unresolved                                              bool
		scope                                                   awsrequest.ScopeKind
	}{
		{"kms", "kms.us-east-1.amazonaws.com", "TrentService.ListKeys", "", `{}`, "ListKeys", "kms:ListKeys", awsrequest.ProtocolJSON11, false, awsrequest.ScopeKnownGlobal},
		{"sqs", "sqs.us-east-1.amazonaws.com", "AmazonSQS.SendMessage", "", `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/123456789012/orders","MessageBody":"hello"}`, "SendMessage", "sqs:SendMessage", awsrequest.ProtocolJSON10, true, awsrequest.ScopeUnresolved},
		{"sns", "sns.us-east-1.amazonaws.com", "", "Action=Publish&Version=2010-03-31&TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A123456789012%3Aorders&Message=hello", "", "Publish", "sns:Publish", awsrequest.ProtocolQuery, true, awsrequest.ScopeUnresolved},
		{"organizations", "organizations.us-east-1.amazonaws.com", "AWSOrganizationsV20161128.ListAccounts", "", `{}`, "ListAccounts", "organizations:ListAccounts", awsrequest.ProtocolJSON11, false, awsrequest.ScopeKnownGlobal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep, err := awsrequest.DefaultEndpointClassifier.Classify(tc.authority)
			if err != nil {
				t.Fatal(err)
			}
			r, err := http.NewRequest("POST", "https://"+tc.authority+"/", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = ep.Host
			r.URL.RawQuery = tc.query
			if tc.protocol == awsrequest.ProtocolQuery {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else if tc.protocol == awsrequest.ProtocolJSON10 {
				r.Header.Set("Content-Type", "application/x-amz-json-1.0")
			} else {
				r.Header.Set("Content-Type", "application/x-amz-json-1.1")
			}
			if tc.target != "" {
				r.Header.Set("X-Amz-Target", tc.target)
			}
			region := ep.Region
			if region == "" {
				region = "us-east-1"
			}
			verified := &awsrequest.VerifiedRequest{Request: r, Endpoint: ep, Protocol: tc.protocol, SigningScheme: awsrequest.SigningHeaderV4, SigningRegion: region, SigningService: ep.Service, PayloadMode: awsrequest.PayloadHashSHA256}
			decoder, err := awsrequest.NewConfiguredDecoder(awsrequest.DecoderOptions{CallerAccountID: "123456789012"})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decoder.Decode(context.Background(), verified, ep)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Protocol != tc.protocol || decoded.Operation != tc.operation {
				t.Fatalf("decoded wire identity = protocol %q operation %q, want %q %q", decoded.Protocol, decoded.Operation, tc.protocol, tc.operation)
			}
			m, err := NewMapper()
			if err != nil {
				t.Fatal(err)
			}
			mapped, err := m.Map(context.Background(), decoded)
			if tc.unresolved {
				if err == nil || mapped != nil || !strings.Contains(err.Error(), "resource") {
					t.Fatalf("unresolved resource was accepted: result=%+v err=%v", mapped, err)
				}
				return
			}
			if err != nil || mapped == nil || len(mapped.Requirements) != 1 {
				t.Fatalf("mapping = %+v, err = %v", mapped, err)
			}
			got := mapped.Requirements[0]
			if got.Action != tc.action || got.ScopeKind != tc.scope || len(got.Resources) != 1 || got.Resources[0] != "*" {
				t.Fatalf("requirement = %+v, want action %q scope %q global resource", got, tc.action, tc.scope)
			}
		})
	}
}

func TestWireToMappingGoldens(t *testing.T) {
	cases := []struct{ name, authority, protocol, target, method, path, query, body, operation, action, resource string }{
		{"ec2", "ec2.us-east-1.amazonaws.com", string(awsrequest.ProtocolEC2Query), "", "POST", "/", "Action=DescribeInstances&Version=2016-11-15", "", "DescribeInstances", "ec2:DescribeInstances", "*"},
		{"ecs", "ecs.us-east-1.amazonaws.com", string(awsrequest.ProtocolJSON11), "AmazonEC2ContainerServiceV20141113.RunTask", "POST", "/", "", `{"taskDefinition":"web","taskRoleArn":"arn:aws:iam::123456789012:role/task"}`, "RunTask", "ecs:RunTask", "arn:aws:ecs:us-east-1:123456789012:task-definition/web"},
		{"s3", "s3.us-east-1.amazonaws.com", string(awsrequest.ProtocolRESTXML), "", "GET", "/bucket/object", "", "", "GetObject", "s3:GetObject", "arn:aws:s3:::bucket/object"},
		{"logs", "logs.us-east-1.amazonaws.com", string(awsrequest.ProtocolJSON11), "Logs_20140328.PutLogEvents", "POST", "/", "", `{"logGroupName":"app","logStreamName":"stream"}`, "PutLogEvents", "logs:PutLogEvents", "arn:aws:logs:us-east-1:123456789012:log-group:app:log-stream:stream"},
		{"iam", "iam.amazonaws.com", string(awsrequest.ProtocolQuery), "", "POST", "/", "Action=GetRole&RoleName=reader&Version=2010-05-08", "", "GetRole", "iam:GetRole", "arn:aws:iam::123456789012:role/reader"},
		{"lambda", "lambda.us-east-1.amazonaws.com", string(awsrequest.ProtocolRESTJSON), "", "POST", "/2015-03-31/functions/fn/invocations", "", "{}", "Invoke", "lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123456789012:function:fn"},
		{"dynamodb", "dynamodb.us-east-1.amazonaws.com", string(awsrequest.ProtocolJSON10), "DynamoDB_20120810.BatchExecuteStatement", "POST", "/", "", `{"Statements":[{"Statement":"SELECT * FROM \"read_table\""},{"Statement":"INSERT INTO \"write_table\" VALUE {'id': '1'}"}]}`, "BatchExecuteStatement", "dynamodb:PartiQLInsert", "arn:aws:dynamodb:us-east-1:123456789012:table/write_table"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep, err := awsrequest.DefaultEndpointClassifier.Classify(tc.authority)
			if err != nil {
				t.Fatal(err)
			}
			r, err := http.NewRequest(tc.method, "https://"+tc.authority+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = ep.Host
			r.URL.RawQuery = tc.query
			switch awsrequest.AWSProtocol(tc.protocol) {
			case awsrequest.ProtocolEC2Query, awsrequest.ProtocolQuery:
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			case awsrequest.ProtocolJSON10:
				r.Header.Set("Content-Type", "application/x-amz-json-1.0")
			case awsrequest.ProtocolJSON11:
				r.Header.Set("Content-Type", "application/x-amz-json-1.1")
			case awsrequest.ProtocolRESTJSON:
				r.Header.Set("Content-Type", "application/json")
			case awsrequest.ProtocolRESTXML:
				r.Header.Set("Content-Type", "application/xml")
			}
			if tc.target != "" {
				r.Header.Set("X-Amz-Target", tc.target)
			}
			region := ep.Region
			if region == "" {
				region = "us-east-1"
			}
			v := &awsrequest.VerifiedRequest{Request: r, Endpoint: ep, Protocol: awsrequest.AWSProtocol(tc.protocol), SigningScheme: awsrequest.SigningHeaderV4, SigningRegion: region, SigningService: ep.Service, PayloadMode: awsrequest.PayloadHashSHA256}
			decoder, err := awsrequest.NewConfiguredDecoder(awsrequest.DecoderOptions{CallerAccountID: "123456789012"})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decoder.Decode(context.Background(), v, ep)
			if err != nil {
				t.Fatal(err)
			}
			m, err := NewMapper()
			if err != nil {
				t.Fatal(err)
			}
			got, err := m.Map(context.Background(), decoded)
			if err != nil {
				t.Fatal(err)
			}
			if got.Operation != tc.operation || got.Requirements[0].Action != tc.action || got.Requirements[0].Resources[0] != tc.resource {
				t.Fatalf("mapping=%+v", got)
			}
			wantRequirements := map[string][]awsrequest.IAMRequirement{
				"ec2":      {{Action: "ec2:DescribeInstances", Resources: []string{"*"}, ScopeKind: awsrequest.ScopeKnownGlobal}},
				"ecs":      {{Action: "ecs:RunTask", Resources: []string{"arn:aws:ecs:us-east-1:123456789012:task-definition/web"}, ScopeKind: awsrequest.ScopeExact}, {Action: "iam:PassRole", Resources: []string{"arn:aws:iam::123456789012:role/task"}, ScopeKind: awsrequest.ScopeExact, Dependent: true}},
				"s3":       {{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/object"}, ScopeKind: awsrequest.ScopeExact}},
				"logs":     {{Action: "logs:PutLogEvents", Resources: []string{"arn:aws:logs:us-east-1:123456789012:log-group:app:log-stream:stream"}, ScopeKind: awsrequest.ScopeExact}},
				"iam":      {{Action: "iam:GetRole", Resources: []string{"arn:aws:iam::123456789012:role/reader"}, ScopeKind: awsrequest.ScopeExact}},
				"lambda":   {{Action: "lambda:InvokeFunction", Resources: []string{"arn:aws:lambda:us-east-1:123456789012:function:fn"}, ScopeKind: awsrequest.ScopeExact}},
				"dynamodb": {{Action: "dynamodb:PartiQLInsert", Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/write_table"}, ScopeKind: awsrequest.ScopeExact}, {Action: "dynamodb:PartiQLSelect", Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/read_table"}, ScopeKind: awsrequest.ScopeExact}},
			}[tc.name]
			if !reflect.DeepEqual(got.Requirements, wantRequirements) {
				t.Fatalf("requirements=%+v, want=%+v", got.Requirements, wantRequirements)
			}
			if got.MapperVersion != MapperVersion || got.IamLiveVersion != iamliveadapter.AdapterVersion || got.AuthorizationDataVersion != data.AuthorizationDataVersion() {
				t.Fatalf("incomplete or unexpected provenance: %+v", got)
			}
		})
	}
}
