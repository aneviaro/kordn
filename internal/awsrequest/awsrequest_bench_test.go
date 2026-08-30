// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package awsrequest

import (
	"bytes"
	"context"
	"net/http"
	"testing"
)

func benchmarkVerified(b *testing.B, service, host string, protocol AWSProtocol, contentType, target string, body []byte) (*VerifiedRequest, AWSEndpoint) {
	b.Helper()
	ep := AWSEndpoint{Partition: "aws", Host: host, Service: service, Region: "us-east-1", Scope: ScopeRegional}
	req, err := http.NewRequest(http.MethodPost, "https://"+host+"/", bytes.NewReader(body))
	if err != nil {
		b.Fatal(err)
	}
	req.Host = host
	req.Header.Set("Content-Type", contentType)
	if target != "" {
		req.Header.Set("X-Amz-Target", target)
	}
	return &VerifiedRequest{Request: req, Endpoint: ep, Protocol: protocol, SigningScheme: SigningHeaderV4, SigningRegion: ep.Region, SigningService: service, PayloadMode: PayloadHashSHA256}, ep
}

func BenchmarkDecodeQuery(b *testing.B) {
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	v, ep := benchmarkVerified(b, "sts", "sts.us-east-1.amazonaws.com", ProtocolQuery, "application/x-www-form-urlencoded", "", body)
	d, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := d.Decode(context.Background(), v, ep); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeJSON(b *testing.B) {
	body := []byte(`{"TableName":"events","Key":{"id":{"S":"1"}}}`)
	v, ep := benchmarkVerified(b, "dynamodb", "dynamodb.us-east-1.amazonaws.com", ProtocolJSON10, "application/x-amz-json-1.0", "DynamoDB_20120810.GetItem", body)
	d, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := d.Decode(context.Background(), v, ep); err != nil {
			b.Fatal(err)
		}
	}
}
