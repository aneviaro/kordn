// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package awsrequest

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func parseQueryString(raw string, l DecodeLimits) (url.Values, error) {
	v := url.Values{}
	if raw == "" {
		return v, nil
	}
	if int64(len(raw)) > l.MaxBodyBytes {
		return nil, errors.New("query exceeds decoder limit")
	}
	for _, f := range strings.Split(raw, "&") {
		if f == "" {
			return nil, errors.New("empty query field")
		}
		p := strings.SplitN(f, "=", 2)
		k, e := url.QueryUnescape(p[0])
		if e != nil || k == "" {
			return nil, errors.New("malformed query key")
		}
		x := ""
		if len(p) == 2 {
			x, e = url.QueryUnescape(p[1])
			if e != nil {
				return nil, errors.New("malformed query value")
			}
		}
		if len(k) > l.MaxTokenBytes || len(x) > l.MaxTokenBytes {
			return nil, errors.New("query token exceeds limit")
		}
		if _, ok := v[k]; ok {
			return nil, fmt.Errorf("duplicate query parameter %q", k)
		}
		v[k] = []string{x}
		if len(v) > l.MaxParameters {
			return nil, errors.New("query parameter limit exceeded")
		}
	}
	return v, nil
}
func decodeQueryBody(body []byte, q url.Values, service string, protocol AWSProtocol, l DecodeLimits) (string, map[string]Value, url.Values, error) {
	b, e := parseQueryString(string(body), l)
	if e != nil {
		return "", nil, nil, e
	}
	all := url.Values{}
	for k, x := range q {
		all[k] = append([]string(nil), x...)
	}
	for k, x := range b {
		if _, ok := all[k]; ok {
			return "", nil, nil, fmt.Errorf("query/body parameter %q conflicts", k)
		}
		all[k] = x
	}
	a := all.Get("Action")
	if a == "" || !validOperation(a) {
		return "", nil, nil, errors.New("query Action is missing or malformed")
	}
	if !operationKnown(service, a) {
		return "", nil, nil, errors.New("query Action is unknown for endpoint service")
	}
	if protocol == ProtocolQuery && service == "ec2" {
		return "", nil, nil, errors.New("EC2 must use ec2-query protocol")
	}
	if protocol == ProtocolEC2Query && service != "ec2" {
		return "", nil, nil, errors.New("ec2-query is only valid for EC2")
	}
	params := map[string]Value{}
	indexed := map[int]string{}
	for k, x := range all {
		if k == "Action" {
			continue
		}
		if len(x) != 1 {
			return "", nil, nil, errors.New("duplicate query parameter")
		}
		params[k] = Value{Kind: ValueString, String: x[0]}
		if strings.HasPrefix(k, "InstanceId.") {
			n, er := strconv.Atoi(strings.TrimPrefix(k, "InstanceId."))
			if er != nil || n < 1 {
				return "", nil, nil, errors.New("malformed indexed query parameter")
			}
			indexed[n] = x[0]
		}
	}
	if len(indexed) > 0 {
		keys := make([]int, 0, len(indexed))
		for n := range indexed {
			keys = append(keys, n)
		}
		sort.Ints(keys)
		a := []Value{}
		for i, n := range keys {
			if i+1 != n {
				return "", nil, nil, errors.New("indexed query parameters are not contiguous")
			}
			a = append(a, Value{Kind: ValueString, String: indexed[n]})
		}
		params["InstanceIds"] = Value{Kind: ValueArray, Array: a}
	}
	return a, params, all, nil
}
