package iammap

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iammap/data"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
)

// dependencies accounts for raw dependency occurrences. It does not turn a
// missing or conditionally inapplicable occurrence into a wildcard grant.
func dependencies(req *awsrequest.DecodedAWSRequest, entry data.Entry, candidates []iamliveadapter.DependencyCandidate, certain bool) ([]awsrequest.IAMRequirement, error) {
	if !certain {
		return nil, errors.New("uncertain dependent-action evidence")
	}
	used := make([]bool, len(candidates))
	result := []awsrequest.IAMRequirement{}
	for _, wanted := range entry.Dependencies {
		want := canonicalAction(wanted)
		if want == "" {
			return nil, fmt.Errorf("unknown dependent permission %q", wanted)
		}
		var active, inactive []int
		for i, candidate := range candidates {
			if used[i] || canonicalAction(candidate.Action.Service+":"+candidate.Action.Name) != want {
				continue
			}
			if candidate.ProvenInapplicable {
				inactive = append(inactive, i)
			} else {
				active = append(active, i)
			}
		}
		if len(active) == 0 {
			if len(inactive) > 0 {
				for _, i := range inactive {
					used[i] = true
				}
				continue
			}
			return nil, fmt.Errorf("iamlive dependency set disagrees: missing %s", wanted)
		}
		for _, i := range inactive {
			used[i] = true
		}
		var names, actual []string
		for _, i := range active {
			used[i] = true
			names = append(names, candidates[i].ParameterNames...)
			actual = append(actual, candidates[i].Resources...)
		}
		if len(names) == 0 {
			names = []string{"Role", "RoleArn", "TaskRoleArn", "ExecutionRoleArn", "IamRoleArn"}
		}
		expected := iamliveadapter.Find(req.Parameters, names...)
		if len(expected) == 0 || len(expected) != len(actual) {
			return nil, errors.New("iamlive dependency resources disagree")
		}
		for i, value := range expected {
			expected[i], _ = validateDependencyARN(want, value, req.Partition)
			if expected[i] == "" {
				return nil, errors.New("malformed dependent ARN")
			}
		}
		for i, value := range actual {
			actual[i], _ = validateDependencyARN(want, value, req.Partition)
			if actual[i] == "" {
				return nil, errors.New("malformed dependent ARN")
			}
		}
		sort.Strings(expected)
		sort.Strings(actual)
		if !sameStrings(expected, actual) {
			return nil, errors.New("iamlive dependency resources disagree")
		}
		scope := awsrequest.ScopeExact
		if len(actual) > 1 {
			scope = awsrequest.ScopeSet
		}
		result = append(result, awsrequest.IAMRequirement{Action: want, Resources: actual, ScopeKind: scope, Dependent: true})
	}
	for i, candidate := range candidates {
		if !used[i] {
			return nil, fmt.Errorf("extra dependent mapping %s:%s", candidate.Action.Service, candidate.Action.Name)
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
