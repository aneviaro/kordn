// Copyright 2026 Kordn AI contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigv4

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/credentials"
)

// Code is a stable, non-secret reason class for a verification failure.
type Code string

const (
	CodeMalformedRequest       Code = "malformed_request"
	CodeMalformedAuthorization Code = "malformed_authorization"
	CodeMalformedCredential    Code = "malformed_credential"
	CodeInvalidCredential      Code = "invalid_credential"
	CodeInvalidSignature       Code = "invalid_signature"
	CodeUnsupportedSigning     Code = "unsupported_signing_scheme"
	CodeUnsupportedPayload     Code = "unsupported_payload"
	CodeInvalidTimestamp       Code = "invalid_timestamp"
	CodeStaleTimestamp         Code = "stale_timestamp"
	CodeEndpointMismatch       Code = "endpoint_mismatch"
	CodeOversizedBody          Code = "oversized_body"
	CodeBodyReadFailure        Code = "body_read_failure"
)

// Error is deliberately sanitized. detail is selected from fixed strings and
// never contains an access key, token, signature, URL, header value, or SDK
// error text.
type Error struct {
	Code   Code
	detail string
}

func (e *Error) Error() string {
	if e == nil {
		return "sigv4 verification failed"
	}
	if e.detail == "" {
		return "sigv4: " + string(e.Code)
	}
	return "sigv4: " + string(e.Code) + ": " + e.detail
}

func (e *Error) Reason() Code {
	if e == nil {
		return ""
	}
	return e.Code
}

func newError(code Code, detail string) error { return &Error{Code: code, detail: detail} }

// CodeOf returns the stable class of an error, including wrapped errors.
func CodeOf(err error) Code {
	var typed *Error
	if errors.As(err, &typed) && typed != nil {
		return typed.Code
	}
	return ""
}

// VerifyOptions controls the intentionally narrow V0.1 verifier. Zero values
// select the documented defaults.
type VerifyOptions struct {
	Clock                func() time.Time
	MaxClockSkew         time.Duration
	MaxInMemoryBodyBytes int64
	MaxSpoolBodyBytes    int64
	TempDir              string
	AllowUnsignedPayload bool
}

type VerifyOption func(*VerifyOptions)

func WithClock(clock func() time.Time) VerifyOption {
	return func(options *VerifyOptions) { options.Clock = clock }
}
func WithClockSkew(skew time.Duration) VerifyOption {
	return func(options *VerifyOptions) { options.MaxClockSkew = skew }
}
func WithBodyLimits(memory, spool int64) VerifyOption {
	return func(options *VerifyOptions) {
		options.MaxInMemoryBodyBytes = memory
		options.MaxSpoolBodyBytes = spool
	}
}
func WithTempDir(dir string) VerifyOption {
	return func(options *VerifyOptions) { options.TempDir = dir }
}
func WithUnsignedPayload() VerifyOption {
	return func(options *VerifyOptions) { options.AllowUnsignedPayload = true }
}
func WithAllowUnsignedPayload(allow bool) VerifyOption {
	return func(options *VerifyOptions) { options.AllowUnsignedPayload = allow }
}

const (
	defaultClockSkew  = 5 * time.Minute
	defaultBodyMemory = int64(8 << 20)
	defaultBodySpool  = int64(64 << 20)
)

// Verifier authenticates only a run's fake credential. The fake value is kept
// in this object and is never included in an error or returned contract.
type Verifier struct {
	fake    credentials.FakeCredential
	options VerifyOptions
}

// NewVerifier validates the shape of the fake credential before any request
// can reach the verifier. It accepts option functions so callers can inject a
// deterministic clock and private body limits in tests.
func NewVerifier(fake credentials.FakeCredential, options ...VerifyOption) (*Verifier, error) {
	selected := VerifyOptions{MaxClockSkew: defaultClockSkew, MaxInMemoryBodyBytes: defaultBodyMemory, MaxSpoolBodyBytes: defaultBodySpool}
	for _, option := range options {
		if option != nil {
			option(&selected)
		}
	}
	if selected.Clock == nil {
		selected.Clock = func() time.Time { return time.Now().UTC() }
	}
	if err := validateFakeCredential(fake); err != nil {
		return nil, err
	}
	if selected.MaxClockSkew <= 0 || selected.MaxClockSkew > 24*time.Hour {
		return nil, newError(CodeMalformedRequest, "clock skew limit is invalid")
	}
	if selected.MaxInMemoryBodyBytes <= 0 || selected.MaxSpoolBodyBytes <= 0 || selected.MaxInMemoryBodyBytes > selected.MaxSpoolBodyBytes {
		return nil, newError(CodeMalformedRequest, "body limits are invalid")
	}
	return &Verifier{fake: fake, options: selected}, nil
}

// Verify implements awsrequest.InboundAuthenticator. A successfully verified
// request owns a reusable bounded body through its request context; callers
// should call CloseBody when the request has completed.
func (v *Verifier) Verify(ctx context.Context, req *http.Request, endpoint awsrequest.AWSEndpoint) (*awsrequest.VerifiedRequest, error) {
	if v == nil {
		return nil, newError(CodeMalformedRequest, "verifier is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	verified := false
	if req != nil {
		defer func() {
			if !verified {
				// Release both an original body reader and a body captured by an
				// earlier inspection attempt. Authentication failures must not
				// leave a socket or a private spool owned by the verifier.
				closeRequestBody(req)
			}
		}()
	}
	if err := ctx.Err(); err != nil {
		return nil, newError(CodeMalformedRequest, "verification was cancelled")
	}
	if req == nil || req.URL == nil {
		return nil, newError(CodeMalformedRequest, "request URL is unavailable")
	}
	if err := endpoint.Validate(); err != nil {
		return nil, newError(CodeEndpointMismatch, "endpoint metadata is invalid")
	}
	if err := verifyRequestEndpoint(req, endpoint); err != nil {
		return nil, err
	}

	queryScheme, queryErr := querySigningPresent(req.URL.RawQuery)
	if queryErr != nil {
		return nil, newError(CodeMalformedRequest, "request query is malformed")
	}
	if queryScheme {
		return nil, newError(CodeUnsupportedSigning, "query presigning is unsupported")
	}
	authorization, present, duplicate := requestHeader(req.Header, "authorization")
	if duplicate {
		return nil, newError(CodeMalformedAuthorization, "authorization is duplicated")
	}
	if !present || authorization == "" {
		return nil, newError(CodeUnsupportedSigning, "request authentication is unsupported")
	}
	if firstSpace := strings.IndexByte(authorization, ' '); firstSpace > 0 && authorization[:firstSpace] != "AWS4-HMAC-SHA256" {
		return nil, newError(CodeUnsupportedSigning, "request signing algorithm is unsupported")
	} else if firstSpace < 0 && !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256") {
		return nil, newError(CodeUnsupportedSigning, "request signing algorithm is unsupported")
	}
	algorithm, credentialText, signedText, signature, err := parseAuthorization(authorization)
	if err != nil {
		return nil, err
	}
	if algorithm != "AWS4-HMAC-SHA256" {
		return nil, newError(CodeUnsupportedSigning, "request signing algorithm is unsupported")
	}
	accessKey, scopeDate, scopeRegion, scopeService, err := parseCredential(credentialText)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(accessKey), []byte(v.fake.AccessKeyID)) != 1 {
		return nil, newError(CodeInvalidCredential, "fake access key is invalid")
	}
	token, tokenPresent, tokenDuplicate := requestHeader(req.Header, "x-amz-security-token")
	if tokenDuplicate || !tokenPresent || token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(v.fake.SessionToken)) != 1 {
		return nil, newError(CodeInvalidCredential, "fake session token is invalid")
	}
	if !validScopeRegion(scopeRegion) || !validScopeService(scopeService) {
		return nil, newError(CodeMalformedCredential, "credential scope is malformed")
	}
	if err := verifySigningScope(endpoint, scopeRegion, scopeService); err != nil {
		return nil, err
	}

	signedHeaders, err := parseSignedHeaders(signedText)
	if err != nil {
		return nil, err
	}
	dateName, signingTime, err := requestSigningTime(req.Header, signedHeaders)
	if err != nil {
		return nil, err
	}
	if signingTime.UTC().Format("20060102") != scopeDate {
		return nil, newError(CodeMalformedCredential, "credential date does not match request date")
	}
	now := v.options.Clock().UTC()
	if now.IsZero() {
		return nil, newError(CodeInvalidTimestamp, "verification clock is invalid")
	}
	if delta := now.Sub(signingTime.UTC()); delta > v.options.MaxClockSkew || delta < -v.options.MaxClockSkew {
		return nil, newError(CodeStaleTimestamp, "request timestamp is outside the allowed skew")
	}
	if !containsString(signedHeaders, dateName) {
		return nil, newError(CodeMalformedAuthorization, "request date is not signed")
	}
	if !containsString(signedHeaders, "x-amz-security-token") {
		return nil, newError(CodeMalformedAuthorization, "session token is not signed")
	}

	if err := verifySignedHost(req, signedHeaders, endpoint); err != nil {
		return nil, err
	}
	body, payloadHash, payloadMode, err := v.payload(req)
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return nil, err
	}
	_ = body // body is retained by req's context for verification and resigning.
	canonical, err := BuildCanonicalRequest(req, signedHeaders, payloadHash)
	if err != nil {
		_ = body.Close()
		return nil, err
	}
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		signingTime.UTC().Format("20060102T150405Z"),
		scopeDate + "/" + scopeRegion + "/" + scopeService + "/aws4_request",
		canonical.Hash,
	}, "\n")
	expected := signingKey(v.fake.SecretAccessKey, scopeDate, scopeRegion, scopeService, stringToSign)
	provided, err := hex.DecodeString(signature)
	if err != nil || len(provided) != sha256.Size || subtle.ConstantTimeCompare(expected, provided) != 1 {
		_ = body.Close()
		return nil, newError(CodeInvalidSignature, "request signature is invalid")
	}
	setPayloadMode(req, payloadMode)
	verified = true
	return &awsrequest.VerifiedRequest{
		Request: req, Endpoint: endpoint, Protocol: inferProtocol(req, endpoint),
		SigningScheme: awsrequest.SigningHeaderV4, SigningRegion: scopeRegion,
		SigningService: scopeService, PayloadMode: payloadMode,
	}, nil
}

// VerifyRequest is a convenient functional form for compositions that do not
// need to retain a Verifier value.
func VerifyRequest(ctx context.Context, req *http.Request, endpoint awsrequest.AWSEndpoint, fake credentials.FakeCredential, options ...VerifyOption) (*awsrequest.VerifiedRequest, error) {
	verifier, err := NewVerifier(fake, options...)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(ctx, req, endpoint)
}

// Verify is an alias with the package-level verb used by small callers.
func Verify(ctx context.Context, req *http.Request, endpoint awsrequest.AWSEndpoint, fake credentials.FakeCredential, options ...VerifyOption) (*awsrequest.VerifiedRequest, error) {
	return VerifyRequest(ctx, req, endpoint, fake, options...)
}

func validateFakeCredential(fake credentials.FakeCredential) error {
	if len(fake.AccessKeyID) < 16 || len(fake.AccessKeyID) > 128 || strings.ContainsAny(fake.AccessKeyID, "\x00\r\n /") {
		return newError(CodeMalformedCredential, "fake access key is malformed")
	}
	if fake.SecretAccessKey == "" || len(fake.SecretAccessKey) > 512 || strings.ContainsAny(fake.SecretAccessKey, "\x00\r\n") {
		return newError(CodeMalformedCredential, "fake secret is malformed")
	}
	if fake.SessionToken == "" || len(fake.SessionToken) > 4096 || strings.ContainsAny(fake.SessionToken, "\x00\r\n") {
		return newError(CodeMalformedCredential, "fake session token is malformed")
	}
	return nil
}

func requestHeader(header http.Header, name string) (value string, present, duplicate bool) {
	for key, values := range header {
		if !strings.EqualFold(key, name) {
			continue
		}
		if present || len(values) != 1 {
			return "", true, true
		}
		present = true
		value = values[0]
	}
	return value, present, false
}

func parseAuthorization(value string) (algorithm, credential, signedHeaders, signature string, err error) {
	space := strings.IndexByte(value, ' ')
	if space <= 0 || space == len(value)-1 {
		return "", "", "", "", newError(CodeMalformedAuthorization, "authorization grammar is invalid")
	}
	algorithm, rest := value[:space], value[space+1:]
	parts := strings.Split(rest, ", ")
	if len(parts) != 3 {
		return "", "", "", "", newError(CodeMalformedAuthorization, "authorization grammar is invalid")
	}
	values := make([]string, 3)
	for i, part := range parts {
		key, item, ok := strings.Cut(part, "=")
		if !ok || item == "" || strings.Contains(item, "=") {
			return "", "", "", "", newError(CodeMalformedAuthorization, "authorization grammar is invalid")
		}
		switch i {
		case 0:
			if key != "Credential" {
				return "", "", "", "", newError(CodeMalformedAuthorization, "authorization grammar is invalid")
			}
		case 1:
			if key != "SignedHeaders" {
				return "", "", "", "", newError(CodeMalformedAuthorization, "authorization grammar is invalid")
			}
		case 2:
			if key != "Signature" {
				return "", "", "", "", newError(CodeMalformedAuthorization, "authorization grammar is invalid")
			}
		}
		values[i] = item
	}
	if len(values[2]) != sha256.Size*2 {
		return "", "", "", "", newError(CodeMalformedAuthorization, "signature encoding is invalid")
	}
	for i := range values[2] {
		if hexValue(values[2][i]) < 0 {
			return "", "", "", "", newError(CodeMalformedAuthorization, "signature encoding is invalid")
		}
	}
	return algorithm, values[0], values[1], values[2], nil
}

func parseCredential(value string) (accessKey, date, region, service string, err error) {
	parts := strings.Split(value, "/")
	if len(parts) != 5 || parts[0] == "" || parts[4] != "aws4_request" {
		return "", "", "", "", newError(CodeMalformedCredential, "credential scope is malformed")
	}
	if len(parts[1]) != 8 {
		return "", "", "", "", newError(CodeMalformedCredential, "credential date is malformed")
	}
	for i := range parts[1] {
		if parts[1][i] < '0' || parts[1][i] > '9' {
			return "", "", "", "", newError(CodeMalformedCredential, "credential date is malformed")
		}
	}
	return parts[0], parts[1], parts[2], parts[3], nil
}

func parseSignedHeaders(value string) ([]string, error) {
	if value == "" || strings.Contains(value, " ") {
		return nil, newError(CodeMalformedAuthorization, "signed headers grammar is invalid")
	}
	parts := strings.Split(value, ";")
	if len(parts) == 0 {
		return nil, newError(CodeMalformedAuthorization, "signed headers are empty")
	}
	for i, part := range parts {
		if !validHeaderName(part) || part != strings.ToLower(part) || (i > 0 && part <= parts[i-1]) {
			return nil, newError(CodeMalformedAuthorization, "signed headers are not sorted")
		}
	}
	if !containsString(parts, "host") {
		return nil, newError(CodeMalformedAuthorization, "signed host header is missing")
	}
	return parts, nil
}

func requestSigningTime(header http.Header, signed []string) (string, time.Time, error) {
	if value, present, duplicate := requestHeader(header, "x-amz-date"); duplicate {
		return "", time.Time{}, newError(CodeInvalidTimestamp, "x-amz-date is duplicated")
	} else if present {
		if value == "" {
			return "", time.Time{}, newError(CodeInvalidTimestamp, "x-amz-date is empty")
		}
		parsed, err := time.Parse("20060102T150405Z", strings.TrimSpace(value))
		if err != nil {
			return "", time.Time{}, newError(CodeInvalidTimestamp, "x-amz-date is malformed")
		}
		return "x-amz-date", parsed.UTC(), nil
	}
	value, present, duplicate := requestHeader(header, "date")
	if duplicate || !present || value == "" {
		return "", time.Time{}, newError(CodeInvalidTimestamp, "request date is unavailable")
	}
	parsed, err := http.ParseTime(strings.TrimSpace(value))
	if err != nil {
		return "", time.Time{}, newError(CodeInvalidTimestamp, "request date is malformed")
	}
	return "date", parsed.UTC(), nil
}

func verifyRequestEndpoint(req *http.Request, endpoint awsrequest.AWSEndpoint) error {
	if req == nil || req.URL == nil {
		return newError(CodeEndpointMismatch, "request authority is unavailable")
	}
	if req.URL.User != nil {
		return newError(CodeEndpointMismatch, "request authority contains user information")
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		return newError(CodeEndpointMismatch, "request host is unavailable")
	}
	name, port, err := awsrequest.NormalizeEndpointHost(host)
	if err != nil || port != 443 || name != endpoint.Host {
		return newError(CodeEndpointMismatch, "request host does not match endpoint")
	}
	if req.Host != "" && req.URL.Host != "" {
		urlName, urlPort, urlErr := awsrequest.NormalizeEndpointHost(req.URL.Host)
		if urlErr != nil || urlName != name || urlPort != port {
			return newError(CodeEndpointMismatch, "request URL authority does not match host")
		}
	}
	return nil
}

func verifySignedHost(req *http.Request, signed []string, endpoint awsrequest.AWSEndpoint) error {
	if !containsString(signed, "host") {
		return newError(CodeMalformedAuthorization, "signed host header is missing")
	}
	value, err := signedHeaderValue(req, "host")
	if err != nil {
		return err
	}
	name, port, normalizeErr := awsrequest.NormalizeEndpointHost(value)
	if normalizeErr != nil || port != 443 || name != endpoint.Host {
		return newError(CodeEndpointMismatch, "signed host does not match endpoint")
	}
	return nil
}

func verifySigningScope(endpoint awsrequest.AWSEndpoint, region, service string) error {
	if service != endpoint.Service {
		return newError(CodeEndpointMismatch, "credential service does not match endpoint")
	}
	if endpoint.IsGlobal() {
		if expected, ok := globalSigningRegion(endpoint.Service); !ok || region != expected {
			return newError(CodeEndpointMismatch, "global endpoint signing region is invalid")
		}
		return nil
	}
	if region != endpoint.Region {
		return newError(CodeEndpointMismatch, "credential region does not match endpoint")
	}
	return nil
}

// globalSigningRegion is intentionally an explicit table. A global endpoint
// never inherits a caller-selected Region and an unlisted global service is
// rejected rather than guessed.
func globalSigningRegion(service string) (string, bool) {
	switch service {
	case "iam", "organizations", "route53", "s3", "sts":
		return "us-east-1", true
	default:
		return "", false
	}
}

func validScopeRegion(region string) bool {
	if region == "" || len(region) > 64 || strings.ContainsAny(region, "/\x00\r\n ") {
		return false
	}
	for _, c := range region {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validScopeService(service string) bool {
	if service == "" || len(service) > 64 {
		return false
	}
	for _, c := range service {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func signingKey(secret, date, region, service, stringToSign string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	regionKey := hmacSHA256(dateKey, []byte(region))
	serviceKey := hmacSHA256(regionKey, []byte(service))
	requestKey := hmacSHA256(serviceKey, []byte("aws4_request"))
	return hmacSHA256(requestKey, []byte(stringToSign))
}

func hmacSHA256(key, value []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(value)
	return h.Sum(nil)
}

func querySigningPresent(raw string) (bool, error) {
	if raw == "" {
		return false, nil
	}
	for _, part := range strings.Split(raw, "&") {
		key := part
		if at := strings.IndexByte(key, '='); at >= 0 {
			key = key[:at]
		}
		decoded, err := percentDecodeQuery(key)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(string(decoded)) {
		case "x-amz-algorithm", "x-amz-credential", "x-amz-signature", "x-amz-signedheaders", "x-amz-expires", "x-amz-date", "x-amz-security-token":
			return true, nil
		}
	}
	return false, nil
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func (v *Verifier) payload(req *http.Request) (*Body, string, awsrequest.PayloadHashMode, error) {
	if req == nil {
		return nil, "", awsrequest.PayloadHashUnsupported, newError(CodeMalformedRequest, "request is unavailable")
	}
	if contentType, present, duplicate := requestHeader(req.Header, "content-type"); duplicate {
		closeRequestBody(req)
		return nil, "", awsrequest.PayloadHashUnsupported, newError(CodeMalformedRequest, "content type is duplicated")
	} else if present && isEventStreamContentType(contentType) {
		closeRequestBody(req)
		return nil, "", awsrequest.PayloadHashEventStream, newError(CodeUnsupportedPayload, "event stream payloads are unsupported")
	}
	value, present, duplicate := requestHeader(req.Header, "x-amz-content-sha256")
	if duplicate {
		closeRequestBody(req)
		return nil, "", awsrequest.PayloadHashUnsupported, newError(CodeMalformedRequest, "payload hash header is duplicated")
	}
	value = strings.TrimSpace(value)
	if present {
		switch value {
		case "UNSIGNED-PAYLOAD":
			if !v.options.AllowUnsignedPayload {
				closeRequestBody(req)
				return nil, value, awsrequest.PayloadHashUnsigned, newError(CodeUnsupportedPayload, "unsigned payloads are disabled")
			}
		case "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", "AWS4-HMAC-SHA256-PAYLOAD", "AWS4-HMAC-SHA256-PAYLOAD-TRAILER":
			closeRequestBody(req)
			return nil, value, awsrequest.PayloadHashStreaming, newError(CodeUnsupportedPayload, "streaming payloads are unsupported")
		case "":
			closeRequestBody(req)
			return nil, value, awsrequest.PayloadHashUnsupported, newError(CodeUnsupportedPayload, "payload hash is empty")
		default:
			if !validPayloadHash(value) {
				closeRequestBody(req)
				return nil, value, awsrequest.PayloadHashUnsupported, newError(CodeUnsupportedPayload, "payload hash encoding is unsupported")
			}
		}
	}
	body, err := CaptureRequestBody(req, BodyOptions{
		MaxInMemoryBytes: v.options.MaxInMemoryBodyBytes,
		MaxSpoolBytes:    v.options.MaxSpoolBodyBytes,
		TempDir:          v.options.TempDir,
	})
	if err != nil {
		return nil, "", awsrequest.PayloadHashUnsupported, err
	}
	if value == "UNSIGNED-PAYLOAD" {
		return body, value, awsrequest.PayloadHashUnsigned, nil
	}
	actual := body.SHA256()
	if value == "" {
		value = actual
	}
	provided, decodeErr := hex.DecodeString(value)
	actualBytes, actualErr := hex.DecodeString(actual)
	if decodeErr != nil || actualErr != nil || len(provided) != sha256.Size || len(actualBytes) != sha256.Size || subtle.ConstantTimeCompare(provided, actualBytes) != 1 {
		return body, value, awsrequest.PayloadHashSHA256, newError(CodeInvalidSignature, "payload hash does not match request body")
	}
	mode := awsrequest.PayloadHashSHA256
	if body.Size() == 0 && strings.EqualFold(value, emptyPayloadHash) {
		mode = awsrequest.PayloadHashEmpty
	}
	return body, value, mode, nil
}

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func isEventStreamContentType(value string) bool {
	value = strings.TrimSpace(strings.SplitN(value, ";", 2)[0])
	return strings.EqualFold(value, "application/vnd.amazon.eventstream") || strings.EqualFold(value, "application/x-amz-event-stream")
}

func inferProtocol(req *http.Request, endpoint awsrequest.AWSEndpoint) awsrequest.AWSProtocol {
	_ = endpoint
	if req == nil {
		return awsrequest.ProtocolRESTJSON
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.SplitN(req.Header.Get("Content-Type"), ";", 2)[0]))
	switch contentType {
	case "application/x-amz-json-1.0":
		return awsrequest.ProtocolJSON10
	case "application/x-amz-json-1.1":
		return awsrequest.ProtocolJSON11
	case "application/x-www-form-urlencoded":
		return awsrequest.ProtocolQuery
	case "application/xml", "text/xml":
		return awsrequest.ProtocolRESTXML
	default:
		return awsrequest.ProtocolRESTJSON
	}
}
