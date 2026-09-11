package iammap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
)

// dependencies evaluates occurrence-bound dependency evidence. Matching is by
// action multiplicity, never by position; inapplicable occurrences are
// retained for the count and unknown occurrences fail closed.
func dependencies(ctx context.Context, req *awsrequest.DecodedAWSRequest, expected []string, candidates []iamliveadapter.DependencyOccurrence) ([]awsrequest.IAMRequirement, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	expectedCounts := map[string]int{}
	order := []string{}
	for _, wanted := range expected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		want := canonicalAction(wanted)
		if want == "" {
			return nil, fmt.Errorf("unknown dependent permission %q", wanted)
		}
		if expectedCounts[want] == 0 {
			order = append(order, want)
		}
		expectedCounts[want]++
	}
	candidateCounts := map[string]int{}
	grouped := map[string][]iamliveadapter.DependencyOccurrence{}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		want := canonicalAction(candidate.Action.Service + ":" + candidate.Action.Name)
		if want == "" {
			return nil, errors.New("unknown dependent permission occurrence")
		}
		if candidate.Applicability == iamliveadapter.ApplicabilityUnknown {
			return nil, errors.New("uncertain dependent-action applicability")
		}
		candidateCounts[want]++
		grouped[want] = append(grouped[want], candidate)
	}
	if len(candidateCounts) != len(expectedCounts) {
		return nil, errors.New("iamlive dependency set disagrees")
	}
	for action, count := range expectedCounts {
		if candidateCounts[action] != count {
			return nil, fmt.Errorf("iamlive dependency occurrence multiplicity disagrees: %s", action)
		}
	}
	for action := range candidateCounts {
		if expectedCounts[action] == 0 {
			return nil, fmt.Errorf("extra dependent mapping %s", action)
		}
	}

	result := make([]awsrequest.IAMRequirement, 0, len(candidates))
	for _, want := range order {
		for _, candidate := range grouped[want] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if candidate.Applicability == iamliveadapter.ApplicabilityInapplicable {
				continue
			}
			names := candidate.ParameterNames
			if len(names) == 0 {
				names = []string{"Role", "RoleArn", "TaskRoleArn", "ExecutionRoleArn", "IamRoleArn"}
			}
			expectedResources := iamliveadapter.Find(req.Parameters, names...)
			actual := append([]string(nil), candidate.Resources...)
			if len(expectedResources) == 0 || len(expectedResources) != len(actual) {
				return nil, errors.New("iamlive dependency resources disagree")
			}
			for i, value := range expectedResources {
				var err error
				expectedResources[i], err = validateDependencyARN(want, value, req.Partition)
				if err != nil || expectedResources[i] == "" {
					return nil, errors.New("malformed dependent ARN")
				}
			}
			for i, value := range actual {
				var err error
				actual[i], err = validateDependencyARN(want, value, req.Partition)
				if err != nil || actual[i] == "" {
					return nil, errors.New("malformed dependent ARN")
				}
			}
			sort.Strings(expectedResources)
			sort.Strings(actual)
			if !sameStrings(expectedResources, actual) {
				return nil, errors.New("iamlive dependency resources disagree")
			}
			scope := awsrequest.ScopeExact
			if len(actual) > 1 {
				scope = awsrequest.ScopeSet
			}
			result = append(result, awsrequest.IAMRequirement{Action: want, Resources: actual, ScopeKind: scope, Dependent: true})
		}
	}
	return result, nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validateDependencyARN(action, value, partition string) (string, error) {
	if canonicalAction(action) == "iam:PassRole" {
		return validateRoleARN(value, partition)
	}
	parts := strings.SplitN(value, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != partition || parts[2] == "" || parts[5] == "" || strings.ContainsAny(value, "\x00\r\n*?\\") || !validPartition(partition) || !validResourcePart(parts[5]) {
		return "", errors.New("malformed dependent ARN")
	}
	return value, nil
}

// Retained as a narrow validation helper for test seams and callers in this
// package; non-string named evidence is never interpreted as applicability.
func invalidNamedValue(parameters map[string]awsrequest.Value, names ...string) bool {
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[strings.ToLower(name)] = true
	}
	var walk func(map[string]awsrequest.Value, int) bool
	walk = func(values map[string]awsrequest.Value, depth int) bool {
		if depth > 16 {
			return true
		}
		for key, value := range values {
			if wanted[strings.ToLower(key)] && (value.Kind != awsrequest.ValueString || value.String == "") {
				return true
			}
			if value.Kind == awsrequest.ValueObject && walk(value.Object, depth+1) {
				return true
			}
			if value.Kind == awsrequest.ValueArray {
				for _, item := range value.Array {
					if item.Kind == awsrequest.ValueObject && walk(item.Object, depth+1) {
						return true
					}
				}
			}
		}
		return false
	}
	return walk(parameters, 0)
}

func validateRoleARN(v, partition string) (string, error) {
	if len(v) > 2048 || strings.ContainsAny(v, "\x00\r\n*?\\") || !validPartition(partition) {
		return "", errors.New("malformed PassRole ARN")
	}
	parts := strings.SplitN(v, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != partition || parts[2] != "iam" || parts[3] != "" || !validAccount(parts[4]) || !strings.HasPrefix(parts[5], "role/") || len(parts[5]) == 5 || !validResourcePart(parts[5]) {
		return "", errors.New("malformed PassRole ARN")
	}
	return v, nil
}
