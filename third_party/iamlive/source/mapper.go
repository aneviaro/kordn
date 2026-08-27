// Copyright 2026 Kordn AI contributors
// Licensed under the MIT License (MIT); see ../LICENSE.
//
// Derived from github.com/iann0036/iamlive/iamlivecore/logger.go at
// 3ec1a40e560c2f00ec82c50223add810e2567efb, symbols getActions and
// getDependantActions (upstream lines 458-506). Kordn retains the upstream
// operation/action lookup and dependency-expansion shape, but narrows the
// table to the reviewed supported-operation matrix and uses typed request
// values instead of iamlive's runtime request map.
package mapper

import (
	"strings"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

// Action is an IAM action selected by the derived operation mapper.
type Action struct{ Service, Name string }

// DependencyCandidate is a modeled dependent permission and the concrete
// request values that caused it to be a candidate. Kordn validates the values
// as ARNs; this derived layer does not make an authorization decision.
type DependencyCandidate struct {
	Action    Action
	Resources []string
}

// DependencyResult distinguishes a proven empty result from an uncertain
// extraction. An uncertain result must never be treated as no dependency.
type DependencyResult struct {
	Candidates []DependencyCandidate
	Certain    bool
}

// The operation table is intentionally independent of Kordn's SAR-backed
// authorization records. It is the substantive, pinned iamlive-derived
// operation/action behavior used for the explicit Kordn support subset.
var operationActions = map[string][]Action{
	"cloudwatch\x00GetMetricData":           {{"cloudwatch", "GetMetricData"}},
	"cloudwatch\x00PutMetricData":           {{"cloudwatch", "PutMetricData"}},
	"dynamodb\x00DeleteItem":                {{"dynamodb", "DeleteItem"}},
	"dynamodb\x00DescribeTable":             {{"dynamodb", "DescribeTable"}},
	"dynamodb\x00GetItem":                   {{"dynamodb", "GetItem"}},
	"dynamodb\x00PutItem":                   {{"dynamodb", "PutItem"}},
	"ec2\x00DescribeInstances":              {{"ec2", "DescribeInstances"}},
	"ec2\x00RunInstances":                   {{"ec2", "RunInstances"}},
	"ec2\x00TerminateInstances":             {{"ec2", "TerminateInstances"}},
	"ecs\x00CreateService":                  {{"ecs", "CreateService"}},
	"ecs\x00DescribeServices":               {{"ecs", "DescribeServices"}},
	"ecs\x00RunTask":                        {{"ecs", "RunTask"}},
	"ecs\x00UpdateService":                  {{"ecs", "UpdateService"}},
	"iam\x00CreateRole":                     {{"iam", "CreateRole"}},
	"iam\x00GetRole":                        {{"iam", "GetRole"}},
	"lambda\x00CreateFunction":              {{"lambda", "CreateFunction"}},
	"lambda\x00Invoke":                      {{"lambda", "InvokeFunction"}},
	"lambda\x00UpdateFunctionConfiguration": {{"lambda", "UpdateFunctionConfiguration"}},
	"logs\x00CreateLogGroup":                {{"logs", "CreateLogGroup"}},
	"logs\x00CreateLogStream":               {{"logs", "CreateLogStream"}},
	"logs\x00PutLogEvents":                  {{"logs", "PutLogEvents"}},
	"s3\x00DeleteObject":                    {{"s3", "DeleteObject"}},
	"s3\x00GetBucketLocation":               {{"s3", "GetBucketLocation"}},
	"s3\x00GetObject":                       {{"s3", "GetObject"}},
	"s3\x00ListObjectsV2":                   {{"s3", "ListBucket"}},
	"s3\x00PutObject":                       {{"s3", "PutObject"}},
	"sts\x00AssumeRole":                     {{"sts", "AssumeRole"}},
	"sts\x00GetCallerIdentity":              {{"sts", "GetCallerIdentity"}},
}

// GetActions maps a service and wire operation using the pinned derived table.
// There is deliberately no explicit-action argument or escape hatch.
func GetActions(service, operation string) []Action {
	mapped := operationActions[strings.ToLower(strings.TrimSpace(service))+"\x00"+strings.TrimSpace(operation)]
	return append([]Action(nil), mapped...)
}

var roleParameterNames = map[string][]string{
	"ecs:CreateService":                  {"TaskRoleArn", "ExecutionRoleArn", "Role", "RoleArn"},
	"ecs:RunTask":                        {"TaskRoleArn", "ExecutionRoleArn", "Role", "RoleArn"},
	"ecs:UpdateService":                  {"TaskRoleArn", "ExecutionRoleArn", "Role", "RoleArn"},
	"ec2:RunInstances":                   {"RoleArn", "IamRoleArn"},
	"lambda:CreateFunction":              {"Role", "RoleArn"},
	"lambda:UpdateFunctionConfiguration": {"Role", "RoleArn"},
}

// DependentActions is the derived dependency expansion for one mapped primary
// action. It is called for every primary action, including actions for which
// the result is proven empty.
func DependentActions(primary Action, parameters map[string]awsrequest.Value) DependencyResult {
	key := strings.ToLower(primary.Service) + ":" + primary.Name
	names, roleBearing := roleParameterNames[key]
	if !roleBearing {
		return DependencyResult{Certain: true}
	}

	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[strings.ToLower(name)] = true
	}
	values := make([]string, 0, 2)
	seen := map[string]bool{}
	uncertain := false
	var walk func(map[string]awsrequest.Value, int)
	walk = func(in map[string]awsrequest.Value, depth int) {
		if depth > 16 {
			uncertain = true
			return
		}
		for name, value := range in {
			if wanted[strings.ToLower(name)] {
				if value.Kind != awsrequest.ValueString || value.String == "" {
					uncertain = true
				} else if !seen[value.String] {
					seen[value.String] = true
					values = append(values, value.String)
				}
			}
			switch value.Kind {
			case awsrequest.ValueObject:
				walk(value.Object, depth+1)
			case awsrequest.ValueArray:
				for _, item := range value.Array {
					if item.Kind == awsrequest.ValueObject {
						walk(item.Object, depth+1)
					}
				}
			}
		}
	}
	walk(parameters, 0)
	candidates := make([]DependencyCandidate, 0, len(values))
	for _, value := range values {
		candidates = append(candidates, DependencyCandidate{
			Action: Action{Service: "iam", Name: "PassRole"}, Resources: []string{value},
		})
	}
	return DependencyResult{Candidates: candidates, Certain: !uncertain}
}
