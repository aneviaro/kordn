package awsrequest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"
	"strings"
)

func decodeRESTJSONBody(body []byte, service, path, method string, q url.Values, l DecodeLimits) (string, map[string]Value, error) {
	p := map[string]Value{}
	if len(bytes.TrimSpace(body)) > 0 {
		d := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(body)))
		d.UseNumber()
		v, e := parseJSONValue(d, 0, l)
		if e != nil || v.Kind != ValueObject {
			return "", nil, errors.New("REST-JSON body is malformed")
		}
		var extra json.Token
		if e = d.Decode(&extra); e != io.EOF {
			return "", nil, errors.New("REST-JSON body has trailing data")
		}
		p = v.Object
	}
	op, route, e := restOperation(service, path, method, q, l)
	if e != nil {
		return "", nil, e
	}
	for k, v := range route {
		if old, ok := p[k]; ok && !reflect.DeepEqual(old, v) {
			return "", nil, errors.New("REST path/body evidence conflicts")
		}
		p[k] = v
	}
	return op, p, nil
}

// restOperation is a closed subset of the AWS service models represented by
// the SAR snapshot. Routes are matched by method, exact path shape, and the
// modeled query subresource; a merely AWS-looking path is not an operation.
func restOperation(service, path, method string, q url.Values, l DecodeLimits) (string, map[string]Value, error) {
	if len(path) > l.MaxPathBytes || !strings.HasPrefix(path, "/") {
		return "", nil, errors.New("REST path is malformed")
	}
	if e := validateRESTQuery(q, l); e != nil {
		return "", nil, e
	}
	decoded, e := url.PathUnescape(strings.TrimSuffix(path, "/"))
	if e != nil || strings.ContainsAny(decoded, "\x00\r\n") || strings.Contains(decoded, "?") {
		return "", nil, errors.New("REST path is malformed")
	}
	parts := strings.Split(strings.TrimPrefix(decoded, "/"), "/")
	for _, p := range parts {
		if p == "" || !validPathValue(p, l) {
			return "", nil, errors.New("REST path parameter is malformed")
		}
	}
	method = strings.ToUpper(method)
	switch service {
	case "lambda":
		switch {
		case len(parts) == 2 && parts[0] == "2015-03-31" && parts[1] == "functions" && method == "POST" && len(q) == 0:
			return "CreateFunction", nil, nil
		case len(parts) == 4 && parts[0] == "2015-03-31" && parts[1] == "functions" && parts[3] == "invocations" && method == "POST" && len(q) == 0:
			return "Invoke", map[string]Value{"FunctionName": {Kind: ValueString, String: parts[2]}}, nil
		case len(parts) == 4 && parts[0] == "2015-03-31" && parts[1] == "functions" && parts[3] == "configuration" && method == "PUT" && len(q) == 0:
			return "UpdateFunctionConfiguration", map[string]Value{"FunctionName": {Kind: ValueString, String: parts[2]}}, nil
		}
	case "s3":
		if len(parts) == 1 {
			if method == "GET" && restQueryIs(q, map[string]string{"list-type": "2"}) {
				return "ListObjectsV2", map[string]Value{"Bucket": {Kind: ValueString, String: parts[0]}}, nil
			}
			if method == "GET" && restQueryIs(q, map[string]string{"location": ""}) {
				return "GetBucketLocation", map[string]Value{"Bucket": {Kind: ValueString, String: parts[0]}}, nil
			}
			return "", nil, errors.New("ambiguous or unsupported S3 bucket operation")
		}
		if len(parts) >= 2 {
			key := strings.Join(parts[1:], "/")
			var op string
			switch method {
			case "GET":
				op = "GetObject"
			case "PUT":
				op = "PutObject"
			case "DELETE":
				op = "DeleteObject"
			default:
				return "", nil, errors.New("unsupported S3 object method")
			}
			if len(q) != 0 && !restQueryIs(q, map[string]string{"x-id": op}) {
				return "", nil, errors.New("unsupported S3 object subresource")
			}
			return op, map[string]Value{"Bucket": {Kind: ValueString, String: parts[0]}, "Key": {Kind: ValueString, String: key}}, nil
		}
	}
	return "", nil, errors.New("unknown REST-JSON operation")
}

func validateRESTQuery(q url.Values, l DecodeLimits) error {
	if len(q) > l.MaxParameters {
		return errors.New("REST query parameter limit exceeded")
	}
	for key, values := range q {
		if key == "" || len(key) > l.MaxTokenBytes || len(values) != 1 || len(values[0]) > l.MaxTokenBytes {
			return errors.New("malformed REST query parameter")
		}
	}
	return nil
}

func restQueryIs(q url.Values, allowed ...map[string]string) bool {
	if len(q) != len(allowed) {
		return false
	}
	for _, pair := range allowed {
		for key, want := range pair {
			values, ok := q[key]
			if !ok || len(values) != 1 || values[0] != want {
				return false
			}
		}
	}
	return true
}

func validPathValue(v string, l DecodeLimits) bool {
	return v != "" && len(v) <= l.MaxTokenBytes && !strings.ContainsAny(v, "\x00\r\n*?")
}
