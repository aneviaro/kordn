// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package sigv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/credentials"
)

func TestCanonicalAWSVectors(t *testing.T) {
	cases := []struct {
		name, target, host, contentType, rangeValue, contentHash, date, signed, want string
	}{
		{"iam", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", "iam.amazonaws.com", "application/x-www-form-urlencoded; charset=utf-8", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "20150830T123600Z", "content-type;host;x-amz-date", "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"},
		{"s3", "https://examplebucket.s3.amazonaws.com/test.txt", "examplebucket.s3.amazonaws.com", "", "bytes=0-9", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "20130524T000000Z", "host;range;x-amz-content-sha256;x-amz-date", "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = tc.host
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.rangeValue != "" {
				req.Header.Set("Range", tc.rangeValue)
			}
			req.Header.Set("X-Amz-Date", tc.date)
			req.Header.Set("X-Amz-Content-Sha256", tc.contentHash)
			canonical, err := BuildCanonicalRequest(req, strings.Split(tc.signed, ";"), tc.contentHash)
			if err != nil {
				t.Fatal(err)
			}
			if canonical.Hash != tc.want {
				t.Fatalf("canonical hash = %s, want %s\n%s", canonical.Hash, tc.want, canonical.Request)
			}
		})
	}
}

func TestVerifierAndResigner(t *testing.T) {
	fake := credentials.FakeCredential{AccessKeyID: "KORDN-test-access-key", SecretAccessKey: "fake-secret", SessionToken: "fake-token"}
	endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "sts.us-east-1.amazonaws.com", Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	req, err := http.NewRequest(http.MethodPost, "https://"+endpoint.Host+"/", bytes.NewBufferString("Action=GetCallerIdentity&Version=2011-06-15"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = endpoint.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", clock.Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Security-Token", fake.SessionToken)
	payload := sha256.Sum256([]byte("Action=GetCallerIdentity&Version=2011-06-15"))
	payloadHash := hex.EncodeToString(payload[:])
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: fake.AccessKeyID, SecretAccessKey: fake.SecretAccessKey, SessionToken: fake.SessionToken}, req, payloadHash, endpoint.Service, endpoint.Region, clock); err != nil {
		t.Fatal(err)
	}
	// SignHTTP strips the default port and produces the exact header list used
	// by the verifier; preserve a deliberately fake proxy header for resign.
	req.Header.Set("Proxy-Authorization", "Basic not-forwarded")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	verified, err := VerifyRequest(context.Background(), req, endpoint, fake, WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	if verified.PayloadMode != awsrequest.PayloadHashSHA256 || BodyFromRequest(req) == nil {
		t.Fatalf("unexpected verification result: %#v", verified)
	}
	real := aws.Credentials{AccessKeyID: "AKIDREAL", SecretAccessKey: "real-secret", SessionToken: "real-token"}
	resigned, err := ReSign(context.Background(), req, endpoint, aws.NewCredentialsCache(staticProvider{value: real}), WithResignClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	defer CloseBody(req)
	defer CloseBody(resigned)
	if resigned == req || resigned.Header.Get("Authorization") == req.Header.Get("Authorization") || strings.Contains(resigned.Header.Get("Authorization"), fake.AccessKeyID) {
		t.Fatal("inbound authorization leaked into re-signed request")
	}
	if resigned.Header.Get("X-Amz-Security-Token") != real.SessionToken || resigned.Header.Get("Proxy-Authorization") != "" || resigned.Header.Get("X-Forwarded-For") != "" {
		t.Fatalf("sensitive forwarding headers survived: %v", resigned.Header)
	}
	body, err := io.ReadAll(resigned.Body)
	if err != nil || string(body) != "Action=GetCallerIdentity&Version=2011-06-15" {
		t.Fatalf("re-signed body changed: %q (%v)", body, err)
	}
}

type staticProvider struct{ value aws.Credentials }

func (p staticProvider) Retrieve(context.Context) (aws.Credentials, error) { return p.value, nil }

func TestResignerPreservesEncodedTarget(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "sts.us-east-1.amazonaws.com", Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}
	real := aws.Credentials{AccessKeyID: "REALACCESSKEY0001", SecretAccessKey: "real-secret", SessionToken: "real-token"}
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	req, err := http.NewRequest(http.MethodPost, "https://"+endpoint.Host+"/a%2Fb?z=+&a=&a=%2F&X-Amz-Signature=discard", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = endpoint.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	originalQuery := req.URL.RawQuery
	resigned, err := ReSign(context.Background(), req, endpoint, staticProvider{value: real}, WithResignClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	defer CloseBody(resigned)
	if req.URL.RawQuery != originalQuery || req.URL.RawPath != "/a%2Fb" {
		t.Fatalf("inbound target was mutated: path=%q query=%q", req.URL.RawPath, req.URL.RawQuery)
	}
	if resigned.URL.RawPath != "/a%2Fb" || resigned.URL.RawQuery != "a=&a=%2F&z=%2B" {
		t.Fatalf("resigned target changed: path=%q query=%q", resigned.URL.RawPath, resigned.URL.RawQuery)
	}
	fake := credentials.FakeCredential{AccessKeyID: real.AccessKeyID, SecretAccessKey: real.SecretAccessKey, SessionToken: real.SessionToken}
	if _, err := VerifyRequest(context.Background(), resigned, endpoint, fake, WithClock(func() time.Time { return clock })); err != nil {
		t.Fatalf("resigned encoded target did not verify: %v", err)
	}
}

func TestBodySpoolPermissionsAndCleanup(t *testing.T) {
	dir := t.TempDir()
	body, err := NewBody(bytes.NewReader(bytes.Repeat([]byte("x"), 32)), BodyOptions{MaxInMemoryBytes: 8, MaxSpoolBytes: 64, TempDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	path := body.SpoolPath()
	if path == "" {
		t.Fatal("body did not spool")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("spool stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("spool permissions = %v", info.Mode().Perm())
	}
	reader, err := body.Reader()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if closer, ok := reader.(io.Closer); ok {
		_ = closer.Close()
	}
	if err != nil || len(got) != 32 {
		t.Fatalf("spool read = %d, err=%v", len(got), err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Clean(path)); !os.IsNotExist(err) {
		t.Fatalf("spool survived cleanup: %v", err)
	}
}

func TestCanonicalQueryPreservesPlusAndEncodedSlash(t *testing.T) {
	req := &http.Request{URL: &url.URL{Path: "/a/b", RawPath: "/a%2Fb", RawQuery: "z=+&a=&a=%2F"}, Method: http.MethodGet, Host: "example.com"}
	query, err := CanonicalQuery(req)
	if err != nil {
		t.Fatal(err)
	}
	if query != "a=&a=%2F&z=%2B" {
		t.Fatalf("canonical query = %q", query)
	}
	path, err := CanonicalURI(req)
	if err != nil || path != "/a%2Fb" {
		t.Fatalf("canonical path = %q, err=%v", path, err)
	}
}

func signedTestRequest(t *testing.T, endpoint awsrequest.AWSEndpoint, fake credentials.FakeCredential, when time.Time, method, target string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "https://"+endpoint.Host+target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = endpoint.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Amz-Date", when.UTC().Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Security-Token", fake.SessionToken)
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: fake.AccessKeyID, SecretAccessKey: fake.SecretAccessKey, SessionToken: fake.SessionToken,
	}, req, payloadHash, endpoint.Service, signingTestRegion(endpoint), when); err != nil {
		t.Fatal(err)
	}
	return req
}

func signingTestRegion(endpoint awsrequest.AWSEndpoint) string {
	if endpoint.IsGlobal() {
		region, _ := globalSigningRegion(endpoint.Service)
		return region
	}
	return endpoint.Region
}

func replaceAuthorizationField(t *testing.T, req *http.Request, field, value string) {
	t.Helper()
	authorization := req.Header.Get("Authorization")
	parts := strings.Split(authorization, ", ")
	prefix := field + "="
	for i, part := range parts {
		if at := strings.Index(part, prefix); at >= 0 {
			parts[i] = part[:at] + prefix + value
			req.Header.Set("Authorization", strings.Join(parts, ", "))
			return
		}
	}
	t.Fatalf("authorization field %q not found", field)
}

func authorizationField(t *testing.T, req *http.Request, field string) string {
	t.Helper()
	prefix := field + "="
	for _, part := range strings.Split(req.Header.Get("Authorization"), ", ") {
		if at := strings.Index(part, prefix); at >= 0 {
			return part[at+len(prefix):]
		}
	}
	t.Fatalf("authorization field %q not found", field)
	return ""
}

func replaceCredentialScope(t *testing.T, req *http.Request, region, service string) {
	t.Helper()
	parts := strings.Split(authorizationField(t, req, "Credential"), "/")
	if len(parts) != 5 {
		t.Fatalf("unexpected credential scope %q", strings.Join(parts, "/"))
	}
	parts[2], parts[3] = region, service
	replaceAuthorizationField(t, req, "Credential", strings.Join(parts, "/"))
}

func requireVerificationCode(t *testing.T, req *http.Request, endpoint awsrequest.AWSEndpoint, fake credentials.FakeCredential, want Code, secrets ...string) {
	t.Helper()
	_, err := VerifyRequest(context.Background(), req, endpoint, fake, WithClock(func() time.Time {
		return time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	}))
	if err == nil {
		t.Fatalf("verification succeeded, want %s", want)
	}
	if got := CodeOf(err); got != want {
		t.Fatalf("verification code = %q, want %q (err=%v)", got, want, err)
	}
	for _, secret := range secrets {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("verification error exposed secret %q: %v", secret, err)
		}
	}
}

func TestVerifierRejectsTamperedRequestAndCredentials(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "sts.us-east-1.amazonaws.com", Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}
	fake := credentials.FakeCredential{AccessKeyID: "KORDNFAKEACCESS01", SecretAccessKey: "fake-secret-value", SessionToken: "fake-session-token"}
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")

	tests := []struct {
		name   string
		mutate func(*http.Request)
		want   Code
	}{
		{"final signature", func(req *http.Request) { replaceAuthorizationField(t, req, "Signature", strings.Repeat("0", 64)) }, CodeInvalidSignature},
		{"method", func(req *http.Request) { req.Method = http.MethodPut }, CodeInvalidSignature},
		{"path", func(req *http.Request) { req.URL.Path = "/tampered"; req.URL.RawPath = "" }, CodeInvalidSignature},
		{"query", func(req *http.Request) { req.URL.RawQuery = "tampered=value" }, CodeInvalidSignature},
		{"body", func(req *http.Request) {
			_ = req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader([]byte("tampered-body")))
			req.GetBody = nil
			req.ContentLength = int64(len("tampered-body"))
		}, CodeInvalidSignature},
		{"fake access key", func(req *http.Request) {
			replaceCredentialScope(t, req, "us-east-1", "sts")
			replaceAuthorizationField(t, req, "Credential", "OTHERACCESSKEY0001/20260827/us-east-1/sts/aws4_request")
		}, CodeInvalidCredential},
		{"fake session token", func(req *http.Request) { req.Header.Set("X-Amz-Security-Token", "wrong-session-token") }, CodeInvalidCredential},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/", body)
			test.mutate(req)
			requireVerificationCode(t, req, endpoint, fake, test.want, fake.AccessKeyID, fake.SecretAccessKey, fake.SessionToken)
		})
	}
}

func TestVerifierRejectsMalformedSignedHeaderSets(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "sts.us-east-1.amazonaws.com", Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}
	fake := credentials.FakeCredential{AccessKeyID: "KORDNFAKEACCESS01", SecretAccessKey: "fake-secret-value", SessionToken: "fake-session-token"}
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	cases := []struct {
		name   string
		mutate func(*http.Request)
		want   Code
	}{
		{"missing host", func(req *http.Request) {
			replaceAuthorizationField(t, req, "SignedHeaders", "content-type;x-amz-content-sha256;x-amz-date;x-amz-security-token")
		}, CodeMalformedAuthorization},
		{"duplicate host", func(req *http.Request) {
			replaceAuthorizationField(t, req, "SignedHeaders", "content-type;host;host;x-amz-content-sha256;x-amz-date;x-amz-security-token")
		}, CodeMalformedAuthorization},
		{"uppercase name", func(req *http.Request) {
			replaceAuthorizationField(t, req, "SignedHeaders", "Content-Type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token")
		}, CodeMalformedAuthorization},
		{"signed header absent", func(req *http.Request) { req.Header.Del("Content-Type") }, CodeMalformedRequest},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			req := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/", body)
			test.mutate(req)
			requireVerificationCode(t, req, endpoint, fake, test.want, fake.SecretAccessKey, fake.SessionToken)
		})
	}
}

func TestVerifierRejectsTimestampAndScopeMismatches(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "sts.us-east-1.amazonaws.com", Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}
	fake := credentials.FakeCredential{AccessKeyID: "KORDNFAKEACCESS01", SecretAccessKey: "fake-secret-value", SessionToken: "fake-session-token"}
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")

	stale := signedTestRequest(t, endpoint, fake, clock.Add(-time.Hour), http.MethodPost, "/", body)
	requireVerificationCode(t, stale, endpoint, fake, CodeStaleTimestamp, fake.SecretAccessKey)
	future := signedTestRequest(t, endpoint, fake, clock.Add(time.Hour), http.MethodPost, "/", body)
	requireVerificationCode(t, future, endpoint, fake, CodeStaleTimestamp, fake.SecretAccessKey)
	dateMismatch := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/", body)
	dateMismatch.Header.Set("X-Amz-Date", "20260828T120000Z")
	requireVerificationCode(t, dateMismatch, endpoint, fake, CodeMalformedCredential, fake.SecretAccessKey)

	wrongRegion := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/", body)
	replaceCredentialScope(t, wrongRegion, "us-west-2", "sts")
	requireVerificationCode(t, wrongRegion, endpoint, fake, CodeEndpointMismatch, fake.SecretAccessKey)
	wrongService := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/", body)
	replaceCredentialScope(t, wrongService, "us-east-1", "iam")
	requireVerificationCode(t, wrongService, endpoint, fake, CodeEndpointMismatch, fake.SecretAccessKey)

	globalEndpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "iam.amazonaws.com", Service: "iam", Region: "us-west-2", Scope: awsrequest.ScopeGlobal}
	global := signedTestRequest(t, globalEndpoint, fake, clock, http.MethodPost, "/", body)
	verified, err := VerifyRequest(context.Background(), global, globalEndpoint, fake, WithClock(func() time.Time { return clock }))
	if err != nil || verified == nil {
		t.Fatalf("modeled global request rejected: %v", err)
	}
	defer CloseBody(global)
	globalMismatch := signedTestRequest(t, globalEndpoint, fake, clock, http.MethodPost, "/", body)
	replaceCredentialScope(t, globalMismatch, "us-west-2", "iam")
	requireVerificationCode(t, globalMismatch, globalEndpoint, fake, CodeEndpointMismatch, fake.SecretAccessKey)
}

func TestVerifierRejectsUnsupportedSigningAndPayloadModes(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "sts.us-east-1.amazonaws.com", Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}
	fake := credentials.FakeCredential{AccessKeyID: "KORDNFAKEACCESS01", SecretAccessKey: "fake-secret-value", SessionToken: "fake-session-token"}
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")

	anonymous, err := http.NewRequest(http.MethodGet, "https://"+endpoint.Host+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Host = endpoint.Host
	requireVerificationCode(t, anonymous, endpoint, fake, CodeUnsupportedSigning, fake.SecretAccessKey, fake.SessionToken)
	unrecognized := anonymous.Clone(anonymous.Context())
	unrecognized.Header = http.Header{"Authorization": {"Bearer bearer-secret"}}
	requireVerificationCode(t, unrecognized, endpoint, fake, CodeUnsupportedSigning, "bearer-secret", fake.SecretAccessKey)

	queryNoHeader := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=discard", body)
	queryNoHeader.Header.Del("Authorization")
	requireVerificationCode(t, queryNoHeader, endpoint, fake, CodeUnsupportedSigning, fake.AccessKeyID, fake.SessionToken)
	queryWithHeader := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/?X-Amz-Signature=discard", body)
	requireVerificationCode(t, queryWithHeader, endpoint, fake, CodeUnsupportedSigning, fake.SecretAccessKey)

	sigv4a := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/", body)
	sigv4a.Header.Set("Authorization", strings.Replace(sigv4a.Header.Get("Authorization"), "AWS4-HMAC-SHA256", "AWS4-ECDSA-P256-SHA256", 1))
	requireVerificationCode(t, sigv4a, endpoint, fake, CodeUnsupportedSigning, fake.SecretAccessKey)

	for _, mode := range []string{
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
		"AWS4-HMAC-SHA256-PAYLOAD",
		"AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
	} {
		t.Run(mode, func(t *testing.T) {
			req := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/", body)
			req.Header.Set("X-Amz-Content-Sha256", mode)
			requireVerificationCode(t, req, endpoint, fake, CodeUnsupportedPayload, fake.SecretAccessKey)
		})
	}
	eventStream := signedTestRequest(t, endpoint, fake, clock, http.MethodPost, "/", body)
	eventStream.Header.Set("Content-Type", "application/vnd.amazon.eventstream")
	requireVerificationCode(t, eventStream, endpoint, fake, CodeUnsupportedPayload, fake.SecretAccessKey)
}

type errorAfterReader struct {
	data []byte
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, errors.New("fixture body source failed")
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestBodyRejectsOversizeAndCleansPartialSpools(t *testing.T) {
	dir := t.TempDir()
	_, err := NewBody(bytes.NewReader(bytes.Repeat([]byte("x"), 17)), BodyOptions{MaxInMemoryBytes: 8, MaxSpoolBytes: 16, TempDir: dir})
	if CodeOf(err) != CodeOversizedBody {
		t.Fatalf("oversized body code = %q, err=%v", CodeOf(err), err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("partial oversized spool remains: entries=%v err=%v", entries, readErr)
	}

	_, err = NewBody(&errorAfterReader{data: bytes.Repeat([]byte("x"), 17)}, BodyOptions{MaxInMemoryBytes: 8, MaxSpoolBytes: 32, TempDir: dir})
	if CodeOf(err) != CodeBodyReadFailure {
		t.Fatalf("failed body code = %q, err=%v", CodeOf(err), err)
	}
	entries, readErr = os.ReadDir(dir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("failed partial spool remains: entries=%v err=%v", entries, readErr)
	}
}

func TestResignScrubsAllProxyAndSigningMaterial(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "sts.us-east-1.amazonaws.com", Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}
	fake := credentials.FakeCredential{AccessKeyID: "KORDNFAKEACCESS01", SecretAccessKey: "fake-secret-value", SessionToken: "fake-session-token"}
	real := aws.Credentials{AccessKeyID: "REALACCESSKEY0001", SecretAccessKey: "real-secret-value", SessionToken: "real-session-token"}
	req, err := http.NewRequest(http.MethodPost, "https://"+endpoint.Host+"/?keep=1&z=+&X-Amz-Algorithm=fake&x-amz-credential=fake&x-amz-signature=fake&x-amz-signedheaders=fake&x-amz-expires=1&x-amz-date=fake&x-amz-security-token=fake", bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = endpoint.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, key := range []string{
		"Proxy-Authorization", "Proxy-Authenticate", "Proxy-Connection", "Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Via", "Forwarded", "X-Real-IP", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "Date", "Host",
		"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Signature", "X-Amz-SignedHeaders", "X-Amz-Expires", "X-Amz-Date",
	} {
		req.Header.Set(key, "fake-material")
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 fake-material")
	req.Header.Set("X-Amz-Security-Token", fake.SessionToken)
	req.Header.Set("X-Nominated", "fake-material")
	req.Header.Set("Connection", "X-Nominated, X-Another-Nominated")
	req.Header.Set("X-Another-Nominated", "fake-material")

	resigned, err := ReSign(context.Background(), req, endpoint, staticProvider{value: real}, WithResignClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	defer CloseBody(resigned)
	for _, key := range []string{
		"Proxy-Authorization", "Proxy-Authenticate", "Proxy-Connection", "Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Via", "Forwarded", "X-Real-IP", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "Date", "Host", "X-Nominated", "X-Another-Nominated",
	} {
		if value := resigned.Header.Get(key); value != "" {
			t.Errorf("scrubbed header %s survived: %q", key, value)
		}
	}
	if strings.Contains(resigned.Header.Get("Authorization"), fake.AccessKeyID) || strings.Contains(resigned.Header.Get("Authorization"), fake.SecretAccessKey) || resigned.Header.Get("X-Amz-Security-Token") != real.SessionToken {
		t.Fatalf("fake signing material survived: %v", resigned.Header)
	}
	for _, key := range []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Signature", "X-Amz-SignedHeaders", "X-Amz-Expires"} {
		if value := resigned.Header.Get(key); value != "" {
			t.Errorf("old signing header %s survived: %q", key, value)
		}
	}
	if resigned.URL.RawQuery != "keep=1&z=%2B" {
		t.Fatalf("signing query material survived: %q", resigned.URL.RawQuery)
	}
}
