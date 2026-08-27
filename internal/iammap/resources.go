// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package iammap

import (
	"errors"
	"fmt"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"net/url"
	"strings"
	"unicode"
)

func resourceFor(req *awsrequest.DecodedAWSRequest, kind string) ([]string, awsrequest.ScopeKind, error) {
	if kind == "global" {
		return []string{"*"}, awsrequest.ScopeKnownGlobal, nil
	}
	switch kind {
	case "object":
		b := parameterString(req.Parameters, "Bucket")
		k := parameterString(req.Parameters, "Key")
		if b == "" || k == "" {
			b, k = s3PathParts(req.CanonicalPath)
		}
		if b == "" || k == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		a := s3ARN(req.Partition, b, k)
		if a == "" {
			return nil, awsrequest.ScopeUnresolved, errors.New("invalid S3 object ARN")
		}
		return []string{a}, awsrequest.ScopeExact, nil
	case "bucket":
		b := parameterString(req.Parameters, "Bucket")
		if b == "" {
			b, _ = s3PathParts(req.CanonicalPath)
		}
		if b == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		a := s3ARN(req.Partition, b, "")
		if a == "" {
			return nil, awsrequest.ScopeUnresolved, errors.New("invalid S3 bucket ARN")
		}
		return []string{a}, awsrequest.ScopeExact, nil
	case "service":
		if req.CallerAccountID == "" || req.Region == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		cluster := parameterString(req.Parameters, "Cluster", "ClusterArn")
		name := parameterString(req.Parameters, "Service", "ServiceName")
		if cluster == "" || name == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		a := awsARN(req.Partition, "ecs", req.Region, req.CallerAccountID, "service/"+cluster+"/"+name)
		if a == "" {
			return nil, awsrequest.ScopeUnresolved, errors.New("invalid ECS service ARN")
		}
		return []string{a}, awsrequest.ScopeExact, nil
	case "task", "task-definition":
		if req.CallerAccountID == "" || req.Region == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		name := parameterString(req.Parameters, "TaskDefinition")
		if name == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		if strings.HasPrefix(name, "arn:") {
			if !validARN(name, req.Partition, "ecs", req.Region, req.CallerAccountID, "task-definition/") {
				return nil, awsrequest.ScopeUnresolved, errors.New("invalid ECS task definition ARN")
			}
			return []string{name}, awsrequest.ScopeExact, nil
		}
		a := awsARN(req.Partition, "ecs", req.Region, req.CallerAccountID, "task-definition/"+name)
		if a == "" {
			return nil, awsrequest.ScopeUnresolved, errors.New("invalid ECS task definition")
		}
		return []string{a}, awsrequest.ScopeExact, nil
	case "instance":
		if req.CallerAccountID == "" || req.Region == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		ids := parameterStrings(req.Parameters, "InstanceIds")
		if len(ids) == 0 {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		out := []string{}
		for _, id := range ids {
			if !validID(id, "i-") {
				return nil, awsrequest.ScopeUnresolved, errors.New("invalid EC2 instance id")
			}
			a := awsARN(req.Partition, "ec2", req.Region, req.CallerAccountID, "instance/"+id)
			if a == "" {
				return nil, awsrequest.ScopeUnresolved, errors.New("invalid EC2 instance ARN")
			}
			out = append(out, a)
		}
		if len(out) == 1 {
			return out, awsrequest.ScopeExact, nil
		}
		return out, awsrequest.ScopeSet, nil
	case "function":
		if req.CallerAccountID == "" || req.Region == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		n := parameterString(req.Parameters, "FunctionName")
		if n == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		if strings.HasPrefix(n, "arn:") {
			if !validARN(n, req.Partition, "lambda", req.Region, req.CallerAccountID, "function:") {
				return nil, awsrequest.ScopeUnresolved, errors.New("invalid Lambda function ARN")
			}
			return []string{n}, awsrequest.ScopeExact, nil
		}
		a := awsARN(req.Partition, "lambda", req.Region, req.CallerAccountID, "function:"+n)
		if a == "" {
			return nil, awsrequest.ScopeUnresolved, errors.New("invalid Lambda function")
		}
		return []string{a}, awsrequest.ScopeExact, nil
	case "table":
		return namedARN(req, "dynamodb", "TableName", "table/")
	case "dataset":
		name := parameterString(req.Parameters, "DatasetId", "Namespace")
		if name == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		if req.CallerAccountID == "" || req.Region == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		a := awsARN(req.Partition, "cloudwatch", req.Region, req.CallerAccountID, "dataset/"+name)
		if a == "" {
			return nil, awsrequest.ScopeUnresolved, errors.New("invalid CloudWatch dataset ARN")
		}
		return []string{a}, awsrequest.ScopeExact, nil
	case "role":
		// STS supplies a complete, potentially cross-account RoleArn. IAM
		// role APIs instead supply a RoleName scoped to the configured caller.
		if req.Operation == "AssumeRole" {
			n := parameterString(req.Parameters, "RoleArn")
			if n == "" {
				return nil, awsrequest.ScopeUnresolved, nil
			}
			a, e := validateRoleARN(n, req.Partition)
			if e != nil {
				return nil, awsrequest.ScopeUnresolved, e
			}
			return []string{a}, awsrequest.ScopeExact, nil
		}
		if req.CallerAccountID == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		n := parameterString(req.Parameters, "RoleName")
		if n == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		a := awsARN(req.Partition, "iam", "", req.CallerAccountID, "role/"+n)
		if a == "" {
			return nil, awsrequest.ScopeUnresolved, errors.New("invalid IAM role")
		}
		return []string{a}, awsrequest.ScopeExact, nil
	case "log-group":
		return namedARN(req, "logs", "LogGroupName", "log-group:")
	case "log-stream":
		if req.CallerAccountID == "" || req.Region == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		g := parameterString(req.Parameters, "LogGroupName")
		s := parameterString(req.Parameters, "LogStreamName")
		if g == "" || s == "" {
			return nil, awsrequest.ScopeUnresolved, nil
		}
		a := awsARN(req.Partition, "logs", req.Region, req.CallerAccountID, "log-group:"+g+":log-stream:"+s)
		if a == "" {
			return nil, awsrequest.ScopeUnresolved, errors.New("invalid log stream ARN")
		}
		return []string{a}, awsrequest.ScopeExact, nil
	default:
		return nil, awsrequest.ScopeUnresolved, fmt.Errorf("unknown resource type %q", kind)
	}
}
func namedARN(req *awsrequest.DecodedAWSRequest, service, param, prefix string) ([]string, awsrequest.ScopeKind, error) {
	if req.CallerAccountID == "" || req.Region == "" {
		return nil, awsrequest.ScopeUnresolved, nil
	}
	n := parameterString(req.Parameters, param)
	if n == "" {
		return nil, awsrequest.ScopeUnresolved, nil
	}
	a := awsARN(req.Partition, service, req.Region, req.CallerAccountID, prefix+n)
	if a == "" {
		return nil, awsrequest.ScopeUnresolved, errors.New("invalid resource ARN")
	}
	return []string{a}, awsrequest.ScopeExact, nil
}
func parameterString(p map[string]awsrequest.Value, names ...string) string {
	for _, want := range names {
		found := ""
		ambiguous := false
		var walk func(map[string]awsrequest.Value, int)
		walk = func(m map[string]awsrequest.Value, d int) {
			if d > 16 || ambiguous {
				return
			}
			for k, v := range m {
				if strings.EqualFold(k, want) {
					if v.Kind != awsrequest.ValueString || v.String == "" {
						ambiguous = true
						return
					}
					if found != "" && found != v.String {
						ambiguous = true
						return
					}
					found = v.String
				}
				if v.Kind == awsrequest.ValueObject {
					walk(v.Object, d+1)
				}
			}
		}
		walk(p, 0)
		if !ambiguous && found != "" {
			return found
		}
	}
	return ""
}
func parameterStrings(p map[string]awsrequest.Value, name string) []string {
	for k, v := range p {
		if !strings.EqualFold(k, name) {
			continue
		}
		if v.Kind == awsrequest.ValueArray {
			r := []string{}
			for _, x := range v.Array {
				if x.Kind != awsrequest.ValueString {
					return nil
				}
				r = append(r, x.String)
			}
			return r
		}
		if v.Kind == awsrequest.ValueString {
			return strings.Fields(v.String)
		}
	}
	return nil
}
func validID(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) || len(s) <= len(prefix) || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && !strings.ContainsRune(".", r) {
			return false
		}
	}
	return true
}
func validResourcePart(s string) bool {
	if s == "" || len(s) > 1024 || strings.ContainsAny(s, "\x00\r\n*?") || strings.Contains(s, "arn:") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validPartition(p string) bool { return p == "aws" || p == "aws-cn" || p == "aws-us-gov" }
func validAccount(a string) bool {
	if len(a) != 12 {
		return false
	}
	for _, r := range a {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func validRegion(p, r string) bool {
	if p == "aws" && r == "" {
		return false
	}
	if p == "aws-cn" && !strings.HasPrefix(r, "cn-") {
		return false
	}
	if p == "aws-us-gov" && !strings.HasPrefix(r, "us-gov-") {
		return false
	}
	if p == "aws" && (strings.HasPrefix(r, "cn-") || strings.HasPrefix(r, "us-gov-")) {
		return false
	}
	if r == "" {
		return false
	}
	if strings.ContainsAny(r, "/:\\*") || len(r) > 32 {
		return false
	}
	for _, x := range r {
		if !(x >= 'a' && x <= 'z' || x >= '0' && x <= '9' || x == '-') {
			return false
		}
	}
	return true
}
func awsARN(partition, service, region, account, resource string) string {
	if !validPartition(partition) || service == "" || !validResourcePart(resource) || !validAccount(account) {
		return ""
	}
	if service == "iam" {
		if region != "" {
			return ""
		}
	} else if !validRegion(partition, region) {
		return ""
	}
	return "arn:" + partition + ":" + service + ":" + region + ":" + account + ":" + resource
}
func s3ARN(partition, bucket, key string) string {
	if !validPartition(partition) || !validResourcePart(bucket) || strings.ContainsAny(bucket, "/:\\") || len(bucket) > 63 || strings.ToLower(bucket) != bucket {
		return ""
	}
	for _, r := range bucket {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return ""
		}
	}
	if len(bucket) < 3 || bucket[0] == '.' || bucket[0] == '-' || bucket[len(bucket)-1] == '.' || bucket[len(bucket)-1] == '-' || strings.Contains(bucket, "..") {
		return ""
	}
	if key != "" && (!validResourcePart(key) || strings.HasPrefix(key, "/")) {
		return ""
	}
	for _, part := range strings.Split(key, "/") {
		if part == "." || part == ".." {
			return ""
		}
	}
	if key == "" {
		return "arn:" + partition + ":s3:::" + bucket
	}
	return "arn:" + partition + ":s3:::" + bucket + "/" + key
}
func validARN(value, partition, service, region, account, prefix string) bool {
	p := strings.SplitN(value, ":", 6)
	return len(p) == 6 && p[0] == "arn" && p[1] == partition && p[2] == service && p[3] == region && p[4] == account && strings.HasPrefix(p[5], prefix) && validResourcePart(p[5])
}
func s3PathParts(path string) (string, string) {
	v, e := url.PathUnescape(path)
	if e != nil {
		return "", ""
	}
	v = strings.TrimPrefix(v, "/")
	p := strings.SplitN(v, "/", 2)
	if len(p) != 2 {
		return "", ""
	}
	return p[0], p[1]
}
