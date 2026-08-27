// Copyright 2026 Kordn AI contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/internal/awserror"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/config"
)

func testInput(t *testing.T, policy config.Policy, mapping awsrequest.MappingResult) DecisionInput {
	t.Helper()
	ep := awsrequest.AWSEndpoint{Partition: "aws", Host: "s3.us-east-1.amazonaws.com", Service: "s3", Region: "us-east-1"}
	req := &awsrequest.DecodedAWSRequest{Partition: "aws", EndpointHost: ep.Host, Service: "s3", Region: ep.Region, CallerAccountID: "123456789012", Protocol: awsrequest.ProtocolRESTXML, Operation: "GetObject", Method: "GET", CanonicalPath: "/", PayloadHashMode: awsrequest.PayloadHashSHA256}
	hash, err := config.PolicyHash(policy)
	if err != nil {
		t.Fatal(err)
	}
	return DecisionInput{RunID: "run", Endpoint: ep, Request: req, Mapping: &mapping, PolicyHash: hash, MapperVersion: mapping.MapperVersion}
}

func TestEngineAtomicAndDeterministic(t *testing.T) {
	p := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{
		{ID: "z-allow", Effect: config.EffectAllow, Actions: []string{"S3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"}},
		{ID: "a-deny", Effect: config.EffectDeny, Actions: []string{"s3:getobject"}, Resources: []string{"arn:aws:s3:::bucket/secret"}},
	}}
	e, err := NewEngine(p)
	if err != nil {
		t.Fatal(err)
	}
	mapping := awsrequest.MappingResult{Service: "s3", Operation: "GetObject", MapperVersion: "m", Confidence: awsrequest.ConfidenceHigh, Requirements: []awsrequest.IAMRequirement{{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/secret", "arn:aws:s3:::bucket/public"}, ScopeKind: awsrequest.ScopeSet}}}
	d := e.Evaluate(context.Background(), testInput(t, p, mapping))
	if d.Result != DecisionDeny || d.ReasonCode != awserror.ReasonExplicitDeny || len(d.MatchedRuleIDs) != 2 {
		t.Fatalf("unexpected decision: %#v", d)
	}
}

func TestEngineAllowsDependentRequirementFromAnotherService(t *testing.T) {
	p := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{
		{ID: "run-task", Effect: config.EffectAllow, Actions: []string{"ecs:RunTask"}, Resources: []string{"arn:aws:ecs:us-east-1:123456789012:task-definition/web"}},
		{ID: "pass-role", Effect: config.EffectAllow, Actions: []string{"iam:PassRole"}, Resources: []string{"arn:aws:iam::123456789012:role/task"}},
	}}
	e, err := NewEngine(p)
	if err != nil {
		t.Fatal(err)
	}
	mapping := awsrequest.MappingResult{Service: "ecs", Operation: "RunTask", MapperVersion: "m", Confidence: awsrequest.ConfidenceHigh, Requirements: []awsrequest.IAMRequirement{
		{Action: "ecs:RunTask", Resources: []string{"arn:aws:ecs:us-east-1:123456789012:task-definition/web"}, ScopeKind: awsrequest.ScopeExact},
		{Action: "iam:PassRole", Resources: []string{"arn:aws:iam::123456789012:role/task"}, ScopeKind: awsrequest.ScopeExact, Dependent: true},
	}}
	in := testInput(t, p, mapping)
	in.Endpoint = awsrequest.AWSEndpoint{Partition: "aws", Host: "ecs.us-east-1.amazonaws.com", Service: "ecs", Region: "us-east-1"}
	in.Request = &awsrequest.DecodedAWSRequest{Partition: "aws", EndpointHost: in.Endpoint.Host, Service: "ecs", Region: in.Endpoint.Region, CallerAccountID: "123456789012", Protocol: awsrequest.ProtocolRESTXML, Operation: "RunTask", Method: "POST", CanonicalPath: "/", PayloadHashMode: awsrequest.PayloadHashSHA256}
	d := e.Evaluate(context.Background(), in)
	if d.Result != DecisionAllow {
		t.Fatalf("dependent requirement was not evaluated: %#v", d)
	}
}

func testInputFor(t *testing.T, policy config.Policy, mapping awsrequest.MappingResult, endpoint awsrequest.AWSEndpoint) DecisionInput {
	t.Helper()
	hash, err := config.PolicyHash(policy)
	if err != nil {
		t.Fatal(err)
	}
	request := &awsrequest.DecodedAWSRequest{
		Partition: endpoint.Partition, EndpointHost: endpoint.Host, Service: endpoint.Service,
		Region: endpoint.Region, CallerAccountID: "123456789012", Protocol: awsrequest.ProtocolRESTXML,
		Operation: mapping.Operation, Method: "POST", CanonicalPath: "/", PayloadHashMode: awsrequest.PayloadHashSHA256,
	}
	return DecisionInput{RunID: "run", Endpoint: endpoint, Request: request, Mapping: &mapping,
		PolicyHash: hash, MapperVersion: mapping.MapperVersion}
}

func TestEngineARNConstraintIdentity(t *testing.T) {
	const account = "123456789012"
	regionalEndpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "ec2.us-east-1.amazonaws.com", Service: "ec2", Region: "us-east-1"}
	iamEndpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "iam.amazonaws.com", Service: "iam", Global: true}
	s3Endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "s3.us-east-1.amazonaws.com", Service: "s3", Region: "us-east-1"}
	cases := []struct {
		name     string
		action   string
		resource string
		scope    awsrequest.ScopeKind
		endpoint awsrequest.AWSEndpoint
		rule     config.Rule
		result   DecisionResult
		reason   awserror.ReasonCode
	}{
		{
			name: "iam-global-arn-does-not-inherit-region", action: "iam:GetRole",
			resource: "arn:aws:iam::" + account + ":role/reader", scope: awsrequest.ScopeExact, endpoint: iamEndpoint,
			rule:   config.Rule{ID: "iam-region", Effect: config.EffectAllow, Actions: []string{"iam:GetRole"}, Resources: []string{"arn:aws:iam::*:role/*"}, Regions: []string{"us-east-1"}},
			result: DecisionDeny, reason: awserror.ReasonPolicyNoMatchingAllow,
		},
		{
			name: "iam-global-arn-without-region-constraint", action: "iam:GetRole",
			resource: "arn:aws:iam::" + account + ":role/reader", scope: awsrequest.ScopeExact, endpoint: iamEndpoint,
			rule:   config.Rule{ID: "iam-global", Effect: config.EffectAllow, Actions: []string{"iam:GetRole"}, Resources: []string{"arn:aws:iam::*:role/*"}},
			result: DecisionAllow, reason: awserror.ReasonAllRequirementsAllowed,
		},
		{
			name: "s3-accountless-arn-does-not-inherit-account", action: "s3:GetObject",
			resource: "arn:aws:s3:::bucket/key", scope: awsrequest.ScopeExact, endpoint: s3Endpoint,
			rule:   config.Rule{ID: "s3-account", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"}, Accounts: []string{account}},
			result: DecisionDeny, reason: awserror.ReasonPolicyNoMatchingAllow,
		},
		{
			name: "s3-accountless-arn-without-account-constraint", action: "s3:GetObject",
			resource: "arn:aws:s3:::bucket/key", scope: awsrequest.ScopeExact, endpoint: s3Endpoint,
			rule:   config.Rule{ID: "s3-global", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"}},
			result: DecisionAllow, reason: awserror.ReasonAllRequirementsAllowed,
		},
		{
			name: "regional-arn-matches-its-components", action: "ec2:DescribeInstances",
			resource: "arn:aws:ec2:us-east-1:" + account + ":instance/i-1", scope: awsrequest.ScopeExact, endpoint: regionalEndpoint,
			rule:   config.Rule{ID: "regional", Effect: config.EffectAllow, Actions: []string{"ec2:DescribeInstances"}, Resources: []string{"arn:aws:ec2:*:*:instance/*"}, Regions: []string{"us-east-1"}, Accounts: []string{account}, Partitions: []string{"aws"}},
			result: DecisionAllow, reason: awserror.ReasonAllRequirementsAllowed,
		},
		{
			name: "regional-arn-does-not-cross-region", action: "ec2:DescribeInstances",
			resource: "arn:aws:ec2:us-east-1:" + account + ":instance/i-1", scope: awsrequest.ScopeExact, endpoint: regionalEndpoint,
			rule:   config.Rule{ID: "other-region", Effect: config.EffectAllow, Actions: []string{"ec2:DescribeInstances"}, Resources: []string{"arn:aws:ec2:*:*:instance/*"}, Regions: []string{"us-west-2"}},
			result: DecisionDeny, reason: awserror.ReasonPolicyNoMatchingAllow,
		},
		{
			name: "regional-arn-does-not-cross-endpoint", action: "ec2:DescribeInstances",
			resource: "arn:aws:ec2:us-east-1:" + account + ":instance/i-1", scope: awsrequest.ScopeExact,
			endpoint: awsrequest.AWSEndpoint{Partition: "aws", Host: "ec2.us-west-2.amazonaws.com", Service: "ec2", Region: "us-west-2"},
			rule:     config.Rule{ID: "east-resource", Effect: config.EffectAllow, Actions: []string{"ec2:DescribeInstances"}, Resources: []string{"arn:aws:ec2:*:*:instance/*"}, Regions: []string{"us-east-1"}},
			result:   DecisionDeny, reason: awserror.ReasonPolicyNoMatchingAllow,
		},
		{
			name: "arn-partition-is-not-request-account-context", action: "ec2:DescribeInstances",
			resource: "arn:aws:ec2:us-east-1:" + account + ":instance/i-1", scope: awsrequest.ScopeExact, endpoint: regionalEndpoint,
			rule:   config.Rule{ID: "other-partition", Effect: config.EffectAllow, Actions: []string{"ec2:DescribeInstances"}, Resources: []string{"arn:*:ec2:*:*:instance/*"}, Partitions: []string{"aws-us-gov"}},
			result: DecisionDeny, reason: awserror.ReasonPolicyNoMatchingAllow,
		},
		{
			name: "known-global-uses-explicit-request-context", action: "ec2:DescribeInstances", resource: "*", scope: awsrequest.ScopeKnownGlobal, endpoint: regionalEndpoint,
			rule:   config.Rule{ID: "global-region", Effect: config.EffectAllow, Actions: []string{"ec2:DescribeInstances"}, Resources: []string{"*"}, Regions: []string{"us-east-1"}, Accounts: []string{account}, Partitions: []string{"aws"}, AllowAWSRequiredWildcard: true},
			result: DecisionAllow, reason: awserror.ReasonAllRequirementsAllowed,
		},
		{
			name: "known-global-does-not-cross-request-region", action: "ec2:DescribeInstances", resource: "*", scope: awsrequest.ScopeKnownGlobal, endpoint: regionalEndpoint,
			rule:   config.Rule{ID: "global-other-region", Effect: config.EffectAllow, Actions: []string{"ec2:DescribeInstances"}, Resources: []string{"*"}, Regions: []string{"us-west-2"}, AllowAWSRequiredWildcard: true},
			result: DecisionDeny, reason: awserror.ReasonPolicyNoMatchingAllow,
		},
		{
			name: "non-arn-exact-with-constraint-fails-closed", action: "s3:GetObject", resource: "bucket/key", scope: awsrequest.ScopeExact, endpoint: s3Endpoint,
			rule:   config.Rule{ID: "unproven-context", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"*"}, Regions: []string{"us-east-1"}},
			result: DecisionDeny, reason: awserror.ReasonPolicyNoMatchingAllow,
		},
		{
			name: "malformed-arn-fails-closed", action: "s3:GetObject", resource: "arn:aws:s3", scope: awsrequest.ScopeExact, endpoint: s3Endpoint,
			rule:   config.Rule{ID: "malformed", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"*"}},
			result: DecisionDeny, reason: awserror.ReasonInternalFailClosed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{tc.rule}}
			e, err := NewEngine(p)
			if err != nil {
				t.Fatal(err)
			}
			mapping := awsrequest.MappingResult{Service: tc.endpoint.Service, Operation: strings.TrimPrefix(tc.action, tc.endpoint.Service+":"), MapperVersion: "m", Confidence: awsrequest.ConfidenceHigh, Requirements: []awsrequest.IAMRequirement{{Action: tc.action, Resources: []string{tc.resource}, ScopeKind: tc.scope}}}
			d := e.Evaluate(context.Background(), testInputFor(t, p, mapping, tc.endpoint))
			if d.Result != tc.result || d.ReasonCode != tc.reason {
				t.Fatalf("unexpected decision: %#v", d)
			}
		})
	}
}

func TestEngineDenyWinsRegardlessOfRuleOrder(t *testing.T) {
	p := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{
		{ID: "allow", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"}},
		{ID: "deny", Effect: config.EffectDeny, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/key"}},
	}}
	mapping := awsrequest.MappingResult{Service: "s3", Operation: "GetObject", MapperVersion: "m", Confidence: awsrequest.ConfidenceHigh, Requirements: []awsrequest.IAMRequirement{{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/key"}, ScopeKind: awsrequest.ScopeExact}}}
	left, err := NewEngine(p)
	if err != nil {
		t.Fatal(err)
	}
	reversed := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{p.Rules[1], p.Rules[0]}}
	right, err := NewEngine(reversed)
	if err != nil {
		t.Fatal(err)
	}
	leftDecision := left.Evaluate(context.Background(), testInput(t, p, mapping))
	rightDecision := right.Evaluate(context.Background(), testInput(t, reversed, mapping))
	if !reflect.DeepEqual(leftDecision, rightDecision) || leftDecision.ReasonCode != awserror.ReasonExplicitDeny {
		t.Fatalf("rule order changed complete decision: %#v %#v", leftDecision, rightDecision)
	}
	if !sort.StringsAreSorted(leftDecision.MatchedRuleIDs) {
		t.Fatalf("matched IDs are not sorted: %v", leftDecision.MatchedRuleIDs)
	}
}

func indexPermutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	result := make([][]int, 0)
	var build func([]int, []bool)
	build = func(prefix []int, used []bool) {
		if len(prefix) == n {
			result = append(result, append([]int(nil), prefix...))
			return
		}
		for i := 0; i < n; i++ {
			if used[i] {
				continue
			}
			used[i] = true
			build(append(prefix, i), used)
			used[i] = false
		}
	}
	build(nil, make([]bool, n))
	return result
}

func TestEngineAllSmallPermutations(t *testing.T) {
	basePolicy := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{
		{ID: "allow-s3", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"}},
		{ID: "allow-role", Effect: config.EffectAllow, Actions: []string{"iam:PassRole"}, Resources: []string{"arn:aws:iam::123456789012:role/task"}},
		{ID: "irrelevant-deny", Effect: config.EffectDeny, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::private/*"}},
	}}
	baseMapping := awsrequest.MappingResult{Service: "s3", Operation: "GetObject", MapperVersion: "m", Confidence: awsrequest.ConfidenceHigh, Requirements: []awsrequest.IAMRequirement{
		{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/a", "arn:aws:s3:::bucket/b"}, ScopeKind: awsrequest.ScopeSet},
		{Action: "iam:PassRole", Resources: []string{"arn:aws:iam::123456789012:role/task"}, ScopeKind: awsrequest.ScopeExact, Dependent: true},
	}}
	baseEngine, err := NewEngine(basePolicy)
	if err != nil {
		t.Fatal(err)
	}
	want := baseEngine.Evaluate(context.Background(), testInput(t, basePolicy, baseMapping))
	for _, ruleOrder := range indexPermutations(len(basePolicy.Rules)) {
		policy := cloneFuzzPolicy(basePolicy)
		for i, source := range ruleOrder {
			policy.Rules[i] = basePolicy.Rules[source]
		}
		for _, requirementOrder := range indexPermutations(len(baseMapping.Requirements)) {
			mapping := cloneFuzzMapping(baseMapping)
			for i, source := range requirementOrder {
				mapping.Requirements[i] = baseMapping.Requirements[source]
			}
			for reverseResources := 0; reverseResources < 2; reverseResources++ {
				if reverseResources != 0 {
					for i := range mapping.Requirements {
						if len(mapping.Requirements[i].Resources) > 1 {
							mapping.Requirements[i].Resources[0], mapping.Requirements[i].Resources[1] = mapping.Requirements[i].Resources[1], mapping.Requirements[i].Resources[0]
						}
					}
				}
				engine, err := NewEngine(policy)
				if err != nil {
					t.Fatal(err)
				}
				got := engine.Evaluate(context.Background(), testInput(t, policy, mapping))
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("permutation changed complete decision: %#v want %#v", got, want)
				}
				if !sort.StringsAreSorted(got.MatchedRuleIDs) {
					t.Fatalf("matched IDs are not sorted: %v", got.MatchedRuleIDs)
				}
			}
		}
	}
}

func TestEngineGlobalAcknowledgementAndCancellation(t *testing.T) {
	p := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{{ID: "global", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"*"}}}}
	e, err := NewEngine(p)
	if err != nil {
		t.Fatal(err)
	}
	mapping := awsrequest.MappingResult{Service: "s3", Operation: "GetObject", MapperVersion: "m", Confidence: awsrequest.ConfidenceHigh, Requirements: []awsrequest.IAMRequirement{{Action: "s3:GetObject", Resources: []string{"*"}, ScopeKind: awsrequest.ScopeKnownGlobal}}}
	d := e.Evaluate(context.Background(), testInput(t, p, mapping))
	if d.ReasonCode != awserror.ReasonAWSRequiredWildcardNotApproved {
		t.Fatalf("unexpected decision: %#v", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d := e.Evaluate(ctx, testInput(t, p, mapping)); d.ReasonCode != awserror.ReasonInternalFailClosed {
		t.Fatalf("cancellation was not fail closed: %#v", d)
	}
}
