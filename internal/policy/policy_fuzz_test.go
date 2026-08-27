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
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/config"
)

// permuteFuzz is a bounded Fisher-Yates permutation. It consumes the fuzz
// bytes cyclically, so an arbitrarily large fuzz input cannot cause an
// allocation or an unbounded loop in this property test.
func permuteFuzz[T any](values []T, data []byte, cursor *int) {
	for i := len(values) - 1; i > 0; i-- {
		var b byte
		if len(data) != 0 {
			b = data[*cursor%len(data)]
			(*cursor)++
		}
		j := int(b) % (i + 1)
		values[i], values[j] = values[j], values[i]
	}
}

func fuzzPolicy() config.Policy {
	return config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{
		{ID: "allow-s3", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/public/*"}},
		{ID: "allow-config", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/config"}},
		{ID: "allow-role", Effect: config.EffectAllow, Actions: []string{"iam:PassRole"}, Resources: []string{"arn:aws:iam::123456789012:role/task"}},
		{ID: "allow-table", Effect: config.EffectAllow, Actions: []string{"dynamodb:GetItem"}, Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/*"}},
		{ID: "deny-private", Effect: config.EffectDeny, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::private/*"}},
		{ID: "irrelevant", Effect: config.EffectAllow, Actions: []string{"s3:ListBucket"}, Resources: []string{"arn:aws:s3:::bucket"}},
	}}
}

func fuzzMapping() awsrequest.MappingResult {
	return awsrequest.MappingResult{
		Service: "s3", Operation: "GetObject", MapperVersion: "fuzz", Confidence: awsrequest.ConfidenceHigh,
		Requirements: []awsrequest.IAMRequirement{
			{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/public/a", "arn:aws:s3:::bucket/public/b"}, ScopeKind: awsrequest.ScopeSet},
			{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/config"}, ScopeKind: awsrequest.ScopeExact},
			{Action: "iam:PassRole", Resources: []string{"arn:aws:iam::123456789012:role/task"}, ScopeKind: awsrequest.ScopeExact, Dependent: true},
			{Action: "dynamodb:GetItem", Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/events", "arn:aws:dynamodb:us-east-1:123456789012:table/users"}, ScopeKind: awsrequest.ScopeSet, Dependent: true},
			{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/log/a", "arn:aws:s3:::bucket/log/b"}, ScopeKind: awsrequest.ScopeSet},
			{Action: "iam:PassRole", Resources: []string{"arn:aws:iam::123456789012:role/other"}, ScopeKind: awsrequest.ScopeExact, Dependent: true},
		},
	}
}

func cloneFuzzPolicy(source config.Policy) config.Policy {
	result := source
	result.Rules = make([]config.Rule, len(source.Rules))
	for i, rule := range source.Rules {
		result.Rules[i] = rule
		result.Rules[i].Actions = append([]string(nil), rule.Actions...)
		result.Rules[i].Resources = append([]string(nil), rule.Resources...)
		result.Rules[i].Regions = append([]string(nil), rule.Regions...)
		result.Rules[i].Accounts = append([]string(nil), rule.Accounts...)
		result.Rules[i].Partitions = append([]string(nil), rule.Partitions...)
	}
	return result
}

func cloneFuzzMapping(source awsrequest.MappingResult) awsrequest.MappingResult {
	result := source
	result.Requirements = make([]awsrequest.IAMRequirement, len(source.Requirements))
	for i, requirement := range source.Requirements {
		result.Requirements[i] = requirement
		result.Requirements[i].Resources = append([]string(nil), requirement.Resources...)
		if requirement.ConditionHint != nil {
			result.Requirements[i].ConditionHint = make(map[string][]string, len(requirement.ConditionHint))
			for key, values := range requirement.ConditionHint {
				result.Requirements[i].ConditionHint[key] = append([]string(nil), values...)
			}
		}
	}
	return result
}

func FuzzRuleOrderInvariant(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Add([]byte{42, 19, 200, 1, 99, 7})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Keep the property bounded even when run with externally supplied
		// corpus entries rather than the small seeds above.
		if len(data) > 64 {
			t.Skip()
		}
		basePolicy := fuzzPolicy()
		basePolicy.Rules = basePolicy.Rules[:3+byteAtFuzz(data, 0)%4]
		baseMapping := fuzzMapping()
		baseMapping.Requirements = baseMapping.Requirements[:3+byteAtFuzz(data, 1)%4]
		originalPolicy := cloneFuzzPolicy(basePolicy)
		originalMapping := cloneFuzzMapping(baseMapping)

		first, err := NewEngine(basePolicy)
		if err != nil {
			t.Fatal(err)
		}
		baselineInput := testInput(t, basePolicy, baseMapping)
		baselineMapping := cloneFuzzMapping(baseMapping)
		baseline := first.Evaluate(context.Background(), baselineInput)
		if !reflect.DeepEqual(basePolicy, originalPolicy) || !reflect.DeepEqual(baseMapping, baselineMapping) {
			t.Fatal("baseline evaluation mutated its inputs")
		}
		if !sort.StringsAreSorted(baseline.MatchedRuleIDs) {
			t.Fatalf("baseline matched IDs are not sorted: %v", baseline.MatchedRuleIDs)
		}

		permutedPolicy := cloneFuzzPolicy(basePolicy)
		cursor := 2
		permuteFuzz(permutedPolicy.Rules, data, &cursor)
		for i := range permutedPolicy.Rules {
			permuteFuzz(permutedPolicy.Rules[i].Actions, data, &cursor)
			permuteFuzz(permutedPolicy.Rules[i].Resources, data, &cursor)
		}
		permutedMapping := cloneFuzzMapping(baseMapping)
		permuteFuzz(permutedMapping.Requirements, data, &cursor)
		for i := range permutedMapping.Requirements {
			permuteFuzz(permutedMapping.Requirements[i].Resources, data, &cursor)
		}
		permutedPolicyBefore := cloneFuzzPolicy(permutedPolicy)
		second, err := NewEngine(permutedPolicy)
		if err != nil {
			t.Fatal(err)
		}
		mappingBefore := cloneFuzzMapping(permutedMapping)
		input := testInput(t, permutedPolicy, permutedMapping)
		decision := second.Evaluate(context.Background(), input)
		if !reflect.DeepEqual(decision, baseline) {
			t.Fatalf("permutation changed complete decision: %#v %#v", baseline, decision)
		}
		if !sort.StringsAreSorted(decision.MatchedRuleIDs) {
			t.Fatalf("matched IDs are not sorted: %v", decision.MatchedRuleIDs)
		}
		if !reflect.DeepEqual(permutedPolicy, permutedPolicyBefore) || !reflect.DeepEqual(permutedMapping, mappingBefore) {
			t.Fatal("permuted evaluation mutated its inputs")
		}
		if !reflect.DeepEqual(basePolicy, originalPolicy) || !reflect.DeepEqual(baseMapping, originalMapping) {
			t.Fatal("evaluation mutated the original inputs")
		}
	})
}

func byteAtFuzz(data []byte, index int) int {
	if len(data) == 0 {
		return 0
	}
	return int(data[index%len(data)])
}
