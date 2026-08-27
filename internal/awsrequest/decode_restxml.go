// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package awsrequest

import (
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"reflect"
	"strings"
)

func decodeRESTXMLBody(body []byte, service, path, method string, q url.Values, l DecodeLimits) (string, map[string]Value, error) {
	op, p, e := restXMLOperation(service, path, method, q, l)
	if e != nil {
		return "", nil, e
	}
	if len(body) == 0 || op == "PutObject" {
		return op, p, nil
	}
	x, e := parseXMLParameters(body, l)
	if e != nil {
		return "", nil, e
	}
	for k, v := range x {
		if old, ok := p[k]; ok && !reflect.DeepEqual(old, v) {
			return "", nil, errors.New("REST-XML path/body evidence conflicts")
		}
		p[k] = v
	}
	return op, p, nil
}
func restXMLOperation(service, path, method string, q url.Values, l DecodeLimits) (string, map[string]Value, error) {
	if service != "s3" {
		return "", nil, errors.New("unsupported REST-XML service")
	}
	if len(path) > l.MaxPathBytes || !strings.HasPrefix(path, "/") {
		return "", nil, errors.New("REST-XML path is malformed")
	}
	if e := validateRESTQuery(q, l); e != nil {
		return "", nil, e
	}
	d, e := url.PathUnescape(strings.TrimSuffix(path, "/"))
	if e != nil || strings.ContainsAny(d, "\x00\r\n") {
		return "", nil, errors.New("REST-XML path is malformed")
	}
	parts := strings.Split(strings.TrimPrefix(d, "/"), "/")
	for _, p := range parts {
		if p == "" || !validPathValue(p, l) {
			return "", nil, errors.New("S3 path is malformed")
		}
	}
	p := map[string]Value{"Bucket": {Kind: ValueString, String: parts[0]}}
	if len(parts) > 1 {
		p["Key"] = Value{Kind: ValueString, String: strings.Join(parts[1:], "/")}
	}
	method = strings.ToUpper(method)
	switch {
	case method == "GET" && len(parts) == 1 && restQueryIs(q, map[string]string{"list-type": "2"}):
		return "ListObjectsV2", p, nil
	case method == "GET" && len(parts) == 1 && restQueryIs(q, map[string]string{"location": ""}):
		return "GetBucketLocation", p, nil
	case method == "GET" && len(parts) == 1:
		return "", nil, errors.New("ambiguous or unsupported S3 bucket operation")
	case method == "GET" && len(parts) > 1 && (len(q) == 0 || restQueryIs(q, map[string]string{"x-id": "GetObject"})):
		return "GetObject", p, nil
	case method == "PUT" && len(parts) > 1 && (len(q) == 0 || restQueryIs(q, map[string]string{"x-id": "PutObject"})):
		return "PutObject", p, nil
	case method == "DELETE" && len(parts) > 1 && (len(q) == 0 || restQueryIs(q, map[string]string{"x-id": "DeleteObject"})):
		return "DeleteObject", p, nil
	case len(parts) > 1:
		return "", nil, errors.New("unsupported S3 object subresource")
	}
	return "", nil, errors.New("unknown REST-XML operation")
}
func parseXMLParameters(body []byte, l DecodeLimits) (map[string]Value, error) {
	d := xml.NewDecoder(strings.NewReader(string(body)))
	d.Strict = true
	out := map[string]Value{}
	stack := 0
	tokens := 0
	var current string
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("malformed REST-XML body")
		}
		tokens++
		if tokens > 8192 || tokens > l.MaxParameters*4 {
			return nil, errors.New("REST-XML token limit exceeded")
		}
		switch x := t.(type) {
		case xml.StartElement:
			stack++
			if stack > l.MaxDepth {
				return nil, errors.New("REST-XML nesting exceeds limit")
			}
			current = x.Name.Local
		case xml.EndElement:
			stack--
		case xml.CharData:
			s := strings.TrimSpace(string(x))
			if s != "" {
				if len(s) > l.MaxTokenBytes {
					return nil, errors.New("REST-XML value exceeds limit")
				}
				out[current] = Value{Kind: ValueString, String: s}
			}
		case xml.ProcInst, xml.Directive:
			return nil, errors.New("REST-XML declaration is unsupported")
		}
	}
	if stack != 0 {
		return nil, errors.New("malformed REST-XML body")
	}
	return out, nil
}
