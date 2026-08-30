// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package awsrequest

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// FuzzAWSRequestConfiguredDecoder drives the same configured decoder used by
// the proxy over every supported wire family. Malformed data is expected to
// fail closed; panics, mutation, and unbounded input handling are not.
func FuzzAWSRequestConfiguredDecoder(f *testing.F) {
	f.Add(0, "Action=GetCallerIdentity&Version=2011-06-15")
	f.Add(1, "Action=DescribeInstances&Version=2016-11-15")
	f.Add(2, `{"TableName":"events","Key":{"id":{"S":"1"}}}`)
	f.Add(3, `{"TableName":"events","Key":{"id":{"S":"1"}}}`)
	f.Add(4, `<GetObject xmlns="https://s3.amazonaws.com/doc/2006-03-01/"><Key>x</Key></GetObject>`)
	f.Fuzz(func(t *testing.T, family int, input string) {
		if len(input) > 4096 {
			return
		}
		decoder, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: "123456789012"})
		if err != nil {
			t.Fatal(err)
		}
		protocol := ProtocolQuery
		service, host, contentType, target := "sts", "sts.us-east-1.amazonaws.com", "application/x-www-form-urlencoded", ""
		body := []byte(input)
		switch ((family % 5) + 5) % 5 {
		case 1:
			protocol, service, host = ProtocolEC2Query, "ec2", "ec2.us-east-1.amazonaws.com"
		case 2:
			protocol, service, host, contentType, target = ProtocolJSON10, "dynamodb", "dynamodb.us-east-1.amazonaws.com", "application/x-amz-json-1.0", "DynamoDB_20120810.GetItem"
		case 3:
			protocol, service, host, contentType, target = ProtocolRESTJSON, "s3", "s3.us-east-1.amazonaws.com", "application/json", ""
		case 4:
			protocol, service, host, contentType, target = ProtocolRESTXML, "s3", "s3.us-east-1.amazonaws.com", "application/xml", ""
		}
		if protocol == ProtocolQuery && !strings.Contains(string(body), "Action=") {
			body = append([]byte("Action=GetCallerIdentity&Version=2011-06-15&data="), []byte(input)...)
		}
		req, err := http.NewRequest(http.MethodPost, "https://"+host+"/bucket/key", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Host = host
		req.Header.Set("Content-Type", contentType)
		if target != "" {
			req.Header.Set("X-Amz-Target", target)
		}
		before := append([]byte(nil), body...)
		endpoint := AWSEndpoint{Partition: "aws", Host: host, Service: service, Region: "us-east-1", Scope: ScopeRegional}
		verified := &VerifiedRequest{Request: req, Endpoint: endpoint, Protocol: protocol, SigningScheme: SigningHeaderV4, SigningRegion: endpoint.Region, SigningService: service, PayloadMode: PayloadHashSHA256}
		_, _ = decoder.Decode(context.Background(), verified, endpoint)
		if got, readErr := io.ReadAll(req.Body); readErr != nil || !bytes.Equal(got, before) {
			t.Fatalf("decoder mutated request body: err=%v got=%q want=%q", readErr, got, before)
		}
	})
}
