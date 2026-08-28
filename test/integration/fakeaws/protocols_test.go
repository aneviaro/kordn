// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package fakeaws

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func TestVerifyKnownSignatureAllowsSecondBoundaryTransit(t *testing.T) {
	signedAt := time.Date(2026, 8, 27, 12, 0, 0, 900*int(time.Millisecond), time.UTC)
	verifiedAt := signedAt.Add(200 * time.Millisecond)
	creds := aws.Credentials{AccessKeyID: "FAKEAWSACCESSKEY01", SecretAccessKey: "fakeaws-secret", SessionToken: "fakeaws-token"}
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	req, err := http.NewRequest(http.MethodPost, "https://"+Host, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	payloadHash := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, hex.EncodeToString(payloadHash[:]), Service, Region, signedAt); err != nil {
		t.Fatal(err)
	}
	if !verifyKnownSignatureFor(req, body, creds, verifiedAt, Service, Region) {
		t.Fatal("valid signature was rejected after transit crossed a wall-clock second")
	}
}

func TestProtocolAndIndependentSignatureTable(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	creds := aws.Credentials{AccessKeyID: "FAKEAWSACCESSKEY01", SecretAccessKey: "fakeaws-secret", SessionToken: "fakeaws-token"}
	server := NewWithConfig(Config{Credentials: creds, Clock: func() time.Time { return clock }, LedgerCapacity: 32})
	defer server.Close()
	cases := []struct {
		name, contentType, target, body string
		want                            Protocol
	}{
		{"json10", "application/x-amz-json-1.0", "AmazonDynamoDBv2.Json10.GetItem", `{"TableName":"fixture"}`, JSON10},
		{"json11", "application/x-amz-json-1.1", "AmazonDynamoDBv2.GetItem", `{"TableName":"fixture"}`, JSON11},
		{"query", "application/x-www-form-urlencoded", "", "Action=GetItem&Version=2011-06-15", Query},
		{"ec2-query", "application/x-www-form-urlencoded", "", "Action=DescribeInstances&Version=2016-11-15", EC2Query},
		{"rest-json", "application/json", "", `{"TableName":"fixture"}`, RESTJSON},
		{"rest-xml", "application/xml", "", "<Request/>", RESTXML},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := signedFixtureRequest(t, server, creds, clock, tc.contentType, tc.target, []byte(tc.body), Service, Region)
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status=%d", response.StatusCode)
			}
		})
	}
	ledger := server.Ledger()
	if len(ledger) != len(cases) {
		t.Fatalf("ledger entries=%d want=%d", len(ledger), len(cases))
	}
	for i, tc := range cases {
		if ledger[i].Protocol != tc.want {
			t.Errorf("%s protocol=%q want=%q", tc.name, ledger[i].Protocol, tc.want)
		}
	}

	stale := signedFixtureRequest(t, server, creds, clock.Add(-6*time.Minute), "application/x-www-form-urlencoded", "", []byte("Action=GetItem"), Service, Region)
	stale.Body.Close()
	if stale.StatusCode != http.StatusForbidden {
		t.Fatalf("stale valid signature status=%d", stale.StatusCode)
	}
	wrongScope := signedFixtureRequest(t, server, creds, clock, "application/x-www-form-urlencoded", "", []byte("Action=GetItem"), "s3", Region)
	wrongScope.Body.Close()
	if wrongScope.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong service scope status=%d", wrongScope.StatusCode)
	}
}

func signedFixtureRequest(t *testing.T, server *Server, creds aws.Credentials, signingTime time.Time, contentType, target string, body []byte, service, region string) *http.Response {
	t.Helper()
	response, err := signedFixtureRequestResult(server, creds, signingTime, contentType, target, body, service, region)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func signedFixtureRequestResult(server *Server, creds aws.Credentials, signingTime time.Time, contentType, target string, body []byte, service, region string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, "https://"+server.Host+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = server.Host
	req.Header.Set("Content-Type", contentType)
	if target != "" {
		req.Header.Set("X-Amz-Target", target)
	}
	req.Header.Set("X-Amz-Date", signingTime.Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", hash)
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, hash, service, region, signingTime); err != nil {
		return nil, err
	}
	base := server.Client().Transport.(*http.Transport)
	tlsConfig := base.TLSClientConfig.Clone()
	tlsConfig.ServerName = "127.0.0.1"
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	client := &http.Client{Transport: transport}
	response, err := client.Do(req)
	transport.CloseIdleConnections()
	return response, err
}

func TestQueryFixtureXMLIsWellFormed(t *testing.T) {
	response := QueryResponse(http.StatusBadRequest, "request<&", "FixtureError", "message <&>")
	var document struct {
		RequestID string `xml:"RequestId"`
	}
	if err := xml.Unmarshal(response.Body, &document); err != nil {
		t.Fatalf("query fixture XML is invalid: %v (%s)", err, response.Body)
	}
	if document.RequestID != "request<&" {
		t.Fatalf("request ID=%q", document.RequestID)
	}
}

func TestFaultResponsesAreCopiedAndStreamed(t *testing.T) {
	clock := time.Now().UTC()
	creds := aws.Credentials{AccessKeyID: "FAULTACCESSKEY0001", SecretAccessKey: "fault-secret", SessionToken: "fault-token"}
	server := NewWithConfig(Config{Credentials: creds, Clock: func() time.Time { return clock }})
	defer server.Close()
	body := []byte("streamed-fault-body")
	server.Failures().Set("GetItem", Failure{Latency: 20 * time.Millisecond, Status: http.StatusTooManyRequests, RetryAfter: "1", Body: body, Streaming: true, StreamingChunk: 3, StreamingDelay: 5 * time.Millisecond})
	started := time.Now()
	response := signedFixtureRequest(t, server, creds, clock, "application/x-www-form-urlencoded", "", []byte("Action=GetItem"), Service, Region)
	if elapsed := time.Since(started); elapsed < 25*time.Millisecond {
		t.Fatalf("fault latency/stream delay=%s, want at least 25ms", elapsed)
	}
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusTooManyRequests || string(got) != string(body) || response.Header.Get("Retry-After") != "1" {
		t.Fatalf("fault response=%d %q retry=%q", response.StatusCode, got, response.Header.Get("Retry-After"))
	}
	body[0] = 'X'
	if string(server.Ledger()[0].BodySHA256) == "" {
		t.Fatal("fault request was not ledgered")
	}
}

func TestFaultDisconnectIsAnObservableFailedAttempt(t *testing.T) {
	clock := time.Now().UTC()
	creds := aws.Credentials{AccessKeyID: "DISCONNECTACCESS01", SecretAccessKey: "disconnect-secret", SessionToken: "disconnect-token"}
	server := NewWithConfig(Config{Credentials: creds, Clock: func() time.Time { return clock }})
	defer server.Close()
	server.Failures().Set("GetItem", Failure{Disconnect: true})
	response, err := signedFixtureRequestResult(server, creds, clock, "application/x-www-form-urlencoded", "", []byte("Action=GetItem"), Service, Region)
	if err == nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		t.Fatal("disconnect fault returned a response")
	}
	ledger := server.Ledger()
	if len(ledger) != 1 || ledger[0].Status != 0 || ledger[0].Action != "GetItem" {
		t.Fatalf("disconnect ledger=%+v", ledger)
	}
}
