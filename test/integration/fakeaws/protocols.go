// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package fakeaws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
)

// Protocol is the wire protocol understood by the deterministic fake. It is
// deliberately the same closed set used by the request decoder.
type Protocol string

const (
	JSON10   Protocol = "json1.0"
	JSON11   Protocol = "json1.1"
	Query    Protocol = "query"
	EC2Query Protocol = "ec2-query"
	RESTJSON Protocol = "rest-json"
	RESTXML  Protocol = "rest-xml"
)

// Response is an AWS-shaped response fixture. Body is fixture data, not a
// copy of an incoming request.
type Response struct {
	Status  int
	Headers http.Header
	Body    []byte
}

func JSONResponse(protocol Protocol, status int, requestID string, value any) Response {
	body, _ := json.Marshal(value)
	contentType := "application/x-amz-json-1.1"
	if protocol == JSON10 {
		contentType = "application/x-amz-json-1.0"
	}
	return Response{Status: status, Headers: http.Header{"Content-Type": {contentType}, "X-Amzn-Requestid": {requestID}}, Body: body}
}

func QueryResponse(status int, requestID, code, message string) Response {
	// Query responses are consumed by real AWS CLI/SDK decoders, so keep the
	// envelope well-formed even when fixture text contains XML metacharacters.
	escape := func(value string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(value))
		return b.String()
	}
	body := fmt.Sprintf("<Response><RequestId>%s</RequestId><%sResponse><%sResult><%s>%s</%s></%sResult></%sResponse></Response>", escape(requestID), code, code, code, escape(message), code, code, code)
	return Response{Status: status, Headers: http.Header{"Content-Type": {"text/xml"}, "X-Amzn-Requestid": {requestID}}, Body: []byte(body)}
}

func RESTJSONResponse(status int, requestID string, value any) Response {
	return JSONResponse(RESTJSON, status, requestID, value)
}

func RESTXMLResponse(status int, requestID, root, value string) Response {
	body, _ := xml.Marshal(struct {
		XMLName xml.Name
		Value   string `xml:",chardata"`
	}{XMLName: xml.Name{Local: root}, Value: value})
	return Response{Status: status, Headers: http.Header{"Content-Type": {"application/xml"}, "X-Amzn-Requestid": {requestID}}, Body: body}
}

func errorResponse(protocol Protocol, status int, requestID, code, message string) Response {
	if code == "" {
		code = http.StatusText(status)
	}
	if protocol == Query || protocol == EC2Query || protocol == RESTXML {
		return QueryResponse(status, requestID, code, message)
	}
	return JSONResponse(protocol, status, requestID, map[string]string{"__type": code, "message": message})
}

func protocolFromRequest(req *http.Request, bodies ...[]byte) Protocol {
	if req == nil {
		return JSON11
	}
	if target := req.Header.Get("X-Amz-Target"); strings.Contains(target, "Json10") {
		return JSON10
	}
	if target := req.Header.Get("X-Amz-Target"); target != "" {
		return JSON11
	}
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	if strings.Contains(ct, "json") {
		return RESTJSON
	}
	if strings.Contains(ct, "xml") {
		return RESTXML
	}
	if strings.Contains(ct, "x-www-form-urlencoded") {
		if len(bodies) > 0 && strings.Contains(string(bodies[0]), "Version=2016-11-15") {
			return EC2Query
		}
		return Query
	}
	return Query
}

func actionFromRequest(req *http.Request, body []byte) string {
	if req == nil {
		return ""
	}
	if target := req.Header.Get("X-Amz-Target"); target != "" {
		if i := strings.LastIndexByte(target, '.'); i >= 0 {
			return target[i+1:]
		}
		return target
	}
	for _, part := range strings.Split(string(body), "&") {
		if strings.HasPrefix(part, "Action=") {
			return strings.TrimPrefix(part, "Action=")
		}
	}
	return ""
}
