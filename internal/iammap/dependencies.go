// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
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

func dependencies(req *awsrequest.DecodedAWSRequest, entry data.Entry, candidates []iamliveadapter.DependencyCandidate, certain bool) ([]awsrequest.IAMRequirement, error) {
	if !certain {
		return nil, errors.New("uncertain dependent-action evidence")
	}
	// The adapter must account for every dependency, including the proven-empty
	// case. This prevents a Kordn dependency record from being copied merely to
	// claim that the adapter was consulted.
	expected := map[string]bool{}
	for _, action := range entry.Dependencies {
		if action != "iam:PassRole" || expected[action] {
			return nil, fmt.Errorf("unknown or duplicate dependent permission %q", action)
		}
		expected[action] = true
	}
	byAction := map[string][]string{}
	for _, candidate := range candidates {
		action := canonicalAction(candidate.Action.Service + ":" + candidate.Action.Name)
		if action == "" || !expected[action] {
			return nil, errors.New("iamlive dependency set disagrees")
		}
		if len(candidate.Resources) == 0 {
			return nil, errors.New("iamlive dependency has no candidate resources")
		}
		byAction[action] = append(byAction[action], candidate.Resources...)
	}
	if len(byAction) > len(expected) {
		return nil, errors.New("iamlive dependency set disagrees")
	}

	out := []awsrequest.IAMRequirement{}
	for _, action := range entry.Dependencies {
		roles, uncertain := roleEvidence(req, entry.Operation)
		if uncertain || len(roles) == 0 {
			return nil, errors.New("unresolved dependency applicability: iam:PassRole")
		}
		if len(byAction[action]) == 0 {
			return nil, fmt.Errorf("iamlive dependency set disagrees: missing %s", action)
		}
		expectedARNs := map[string]bool{}
		for _, role := range roles {
			arn, e := validateRoleARN(role, req.Partition)
			if e != nil {
				return nil, e
			}
			expectedARNs[arn] = true
		}
		candidateARNs := map[string]bool{}
		for _, value := range byAction[action] {
			arn, e := validateRoleARN(value, req.Partition)
			if e != nil {
				return nil, e
			}
			candidateARNs[arn] = true
		}
		if len(expectedARNs) != len(candidateARNs) {
			return nil, errors.New("iamlive dependency resources disagree")
		}
		arns := make([]string, 0, len(candidateARNs))
		for arn := range candidateARNs {
			if !expectedARNs[arn] {
				return nil, errors.New("iamlive dependency resources disagree")
			}
			arns = append(arns, arn)
		}
		sort.Strings(arns)
		scope := awsrequest.ScopeExact
		if len(arns) > 1 {
			scope = awsrequest.ScopeSet
		}
		out = append(out, awsrequest.IAMRequirement{Action: action, Resources: arns, ScopeKind: scope, Dependent: true})
	}
	return out, nil
}

// roleEvidence follows Smithy-shaped nested objects; it deliberately does not
// treat an instance-profile name/ARN as a role. That ambiguity is fail-closed.
func roleEvidence(req *awsrequest.DecodedAWSRequest, op string) ([]string, bool) {
	// The field set is deliberately closed per operation. A generic recursive
	// search for "Role" would turn unrelated nested user input into a PassRole
	// grant and would not establish dependency applicability.
	var names []string
	switch op {
	case "RunTask", "CreateService", "UpdateService":
		names = []string{"TaskRoleArn", "ExecutionRoleArn", "Role", "RoleArn"}
	case "RunInstances":
		names = []string{"RoleArn", "IamRoleArn"}
	case "CreateFunction", "UpdateFunctionConfiguration":
		names = []string{"Role", "RoleArn"}
	default:
		return nil, false
	}
	return iamliveadapter.Find(req.Parameters, names...), invalidNamedValue(req.Parameters, names...)
}

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
	p := strings.SplitN(v, ":", 6)
	if len(p) != 6 || p[0] != "arn" || p[1] != partition || p[2] != "iam" || p[3] != "" || !validAccount(p[4]) || !strings.HasPrefix(p[5], "role/") || len(p[5]) == 5 || !validResourcePart(p[5]) {
		return "", errors.New("malformed PassRole ARN")
	}
	return v, nil
}
