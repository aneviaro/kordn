package sigv4

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/kordn-ai/kordn/internal/awsrequest"
)

// ResignOptions controls upstream signing. The provider is deliberately
// injected: production passes the memoized credentials.Provider and tests use
// a known local credential provider.
type ResignOptions struct {
	Clock                func() time.Time
	Signer               v4.HTTPSigner
	MaxInMemoryBodyBytes int64
	MaxSpoolBodyBytes    int64
	TempDir              string
	AllowUnsignedPayload bool
}

type ResignOption func(*ResignOptions)

func WithResignClock(clock func() time.Time) ResignOption {
	return func(options *ResignOptions) { options.Clock = clock }
}
func WithResignSigner(signer v4.HTTPSigner) ResignOption {
	return func(options *ResignOptions) { options.Signer = signer }
}
func WithResignBodyLimits(memory, spool int64) ResignOption {
	return func(options *ResignOptions) {
		options.MaxInMemoryBodyBytes = memory
		options.MaxSpoolBodyBytes = spool
	}
}
func WithResignTempDir(dir string) ResignOption {
	return func(options *ResignOptions) { options.TempDir = dir }
}
func WithResignUnsignedPayload(allow bool) ResignOption {
	return func(options *ResignOptions) { options.AllowUnsignedPayload = allow }
}

// Resigner creates a fresh request and signs it with current credentials. It
// never mutates the inbound request, and it does not own transport retries.
type Resigner struct {
	provider aws.CredentialsProvider
	options  ResignOptions
}

func NewResigner(provider aws.CredentialsProvider, options ...ResignOption) (*Resigner, error) {
	if provider == nil {
		return nil, newError(CodeMalformedRequest, "upstream credential provider is unavailable")
	}
	selected := ResignOptions{
		Clock: func() time.Time { return time.Now().UTC() },
		Signer: v4.NewSigner(func(options *v4.SignerOptions) {
			options.DisableHeaderHoisting = true
			options.DisableURIPathEscaping = true
		}),
		MaxInMemoryBodyBytes: defaultBodyMemory,
		MaxSpoolBodyBytes:    defaultBodySpool,
	}
	for _, option := range options {
		if option != nil {
			option(&selected)
		}
	}
	if selected.Clock == nil {
		selected.Clock = func() time.Time { return time.Now().UTC() }
	}
	if selected.Signer == nil {
		return nil, newError(CodeMalformedRequest, "upstream signer is unavailable")
	}
	if selected.MaxInMemoryBodyBytes <= 0 || selected.MaxSpoolBodyBytes <= 0 || selected.MaxInMemoryBodyBytes > selected.MaxSpoolBodyBytes {
		return nil, newError(CodeMalformedRequest, "body limits are invalid")
	}
	return &Resigner{provider: provider, options: selected}, nil
}

// Resign clones, scrubs, and signs req for endpoint. The returned request is
// suitable for a single RoundTrip. Reusing it for an application retry is the
// caller's responsibility and is intentionally not done here.
func (r *Resigner) Resign(ctx context.Context, req *http.Request, endpoint awsrequest.AWSEndpoint) (*http.Request, error) {
	if r == nil || r.provider == nil {
		return nil, newError(CodeMalformedRequest, "resigner is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if req == nil || req.URL == nil {
		return nil, newError(CodeMalformedRequest, "request URL is unavailable")
	}
	capturedBody := bodyFromRequest(req)
	resigned := false
	defer func() {
		if !resigned && capturedBody != nil {
			_ = capturedBody.Close()
		}
	}()
	if err := endpoint.Validate(); err != nil {
		return nil, newError(CodeEndpointMismatch, "endpoint metadata is invalid")
	}
	if err := verifyRequestEndpoint(req, endpoint); err != nil {
		return nil, err
	}
	region, ok := endpointSigningRegion(endpoint)
	if !ok {
		return nil, newError(CodeEndpointMismatch, "endpoint signing region is unavailable")
	}
	canonicalQuery, err := scrubAndCanonicalizeQuery(req.URL.RawQuery)
	if err != nil {
		return nil, err
	}

	allowUnsigned := r.options.AllowUnsignedPayload || payloadModeFromRequest(req) == awsrequest.PayloadHashUnsigned
	if err := validateResignPayloadHeaders(req, allowUnsigned); err != nil {
		return nil, err
	}
	body := capturedBody
	bodyOptions := BodyOptions{
		MaxInMemoryBytes: r.options.MaxInMemoryBodyBytes,
		MaxSpoolBytes:    r.options.MaxSpoolBodyBytes,
		TempDir:          r.options.TempDir,
	}
	if body != nil {
		if err := validateBodyAvailable(body); err != nil {
			return nil, err
		}
	} else {
		var err error
		body, err = captureBodyForResign(req, bodyOptions)
		if err != nil {
			return nil, err
		}
	}
	payloadHash, err := resignPayloadHash(req, body, allowUnsigned)
	if err != nil {
		_ = body.Close()
		return nil, err
	}

	outgoing := req.Clone(ctx)
	if outgoing.URL == nil {
		_ = body.Close()
		return nil, newError(CodeMalformedRequest, "request URL is unavailable")
	}
	outgoing.RequestURI = ""
	outgoing.URL.Scheme = "https"
	outgoing.URL.Host = endpoint.Host
	if outgoing.Header == nil {
		outgoing.Header = make(http.Header)
	}
	outgoing.URL.User = nil
	outgoing.Host = endpoint.Host
	outgoing.URL.RawQuery = canonicalQuery
	scrubForwardingHeaders(outgoing.Header)
	attachBody(outgoing, body)
	// A request with an unknown inbound length is now replayable within the
	// private signed request because the body has a known bounded size. This
	// does not authorize an application retry: the no-replay transport still
	// sends this request at most once.

	creds, err := retrieveCredentials(ctx, r.provider)
	if err != nil {
		_ = body.Close()
		return nil, err
	}
	signingTime := r.options.Clock().UTC()
	if signingTime.IsZero() {
		_ = body.Close()
		return nil, newError(CodeInvalidTimestamp, "signing clock is invalid")
	}
	if err := r.options.Signer.SignHTTP(ctx, creds, outgoing, payloadHash, endpoint.Service, region, signingTime, func(options *v4.SignerOptions) {
		options.DisableHeaderHoisting = true
		options.DisableURIPathEscaping = true
	}); err != nil {
		_ = body.Close()
		return nil, newError(CodeInvalidSignature, "upstream signing failed")
	}
	resigned = true
	return outgoing, nil
}

// ReSign is the functional form used by small compositions.
func ReSign(ctx context.Context, req *http.Request, endpoint awsrequest.AWSEndpoint, provider aws.CredentialsProvider, options ...ResignOption) (*http.Request, error) {
	resigner, err := NewResigner(provider, options...)
	if err != nil {
		return nil, err
	}
	return resigner.Resign(ctx, req, endpoint)
}

func retrieveCredentials(ctx context.Context, provider aws.CredentialsProvider) (value aws.Credentials, err error) {
	if provider == nil {
		return aws.Credentials{}, newError(CodeMalformedRequest, "upstream credential provider is unavailable")
	}
	defer func() {
		if recover() != nil {
			value = aws.Credentials{}
			err = newError(CodeMalformedCredential, "upstream credentials are unavailable")
		}
	}()
	value, err = provider.Retrieve(ctx)
	if err != nil || value.AccessKeyID == "" || value.SecretAccessKey == "" || strings.ContainsAny(value.AccessKeyID+value.SecretAccessKey+value.SessionToken, "\x00\r\n") {
		return aws.Credentials{}, newError(CodeMalformedCredential, "upstream credentials are unavailable")
	}
	return value, nil
}

func endpointSigningRegion(endpoint awsrequest.AWSEndpoint) (string, bool) {
	if !endpoint.IsGlobal() {
		return endpoint.Region, endpoint.Region != ""
	}
	return globalSigningRegion(endpoint.Service)
}

func validateResignPayloadHeaders(req *http.Request, allowUnsigned bool) error {
	contentType, contentTypePresent, contentTypeDuplicate := requestHeader(req.Header, "content-type")
	if contentTypeDuplicate {
		return newError(CodeMalformedRequest, "content type is duplicated")
	}
	if contentTypePresent && isEventStreamContentType(contentType) {
		return newError(CodeUnsupportedPayload, "event stream payloads are unsupported")
	}
	value, present, duplicate := requestHeader(req.Header, "x-amz-content-sha256")
	if duplicate {
		return newError(CodeMalformedRequest, "payload hash header is duplicated")
	}
	if !present {
		return nil
	}
	value = strings.TrimSpace(value)
	switch value {
	case "UNSIGNED-PAYLOAD":
		if !allowUnsigned {
			return newError(CodeUnsupportedPayload, "unsigned payloads are disabled")
		}
	case "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", "AWS4-HMAC-SHA256-PAYLOAD", "AWS4-HMAC-SHA256-PAYLOAD-TRAILER":
		return newError(CodeUnsupportedPayload, "streaming payloads are unsupported")
	case "":
		return newError(CodeUnsupportedPayload, "payload hash is empty")
	default:
		if !validPayloadHash(value) {
			return newError(CodeUnsupportedPayload, "payload hash encoding is unsupported")
		}
	}
	return nil
}

func resignPayloadHash(req *http.Request, body *Body, allowUnsigned bool) (string, error) {
	contentType, contentTypePresent, contentTypeDuplicate := requestHeader(req.Header, "content-type")
	if contentTypeDuplicate {
		return "", newError(CodeMalformedRequest, "content type is duplicated")
	}
	if contentTypePresent && isEventStreamContentType(contentType) {
		return "", newError(CodeUnsupportedPayload, "event stream payloads are unsupported")
	}
	value, present, duplicate := requestHeader(req.Header, "x-amz-content-sha256")
	if duplicate {
		return "", newError(CodeMalformedRequest, "payload hash header is duplicated")
	}
	value = strings.TrimSpace(value)
	if present && value == "UNSIGNED-PAYLOAD" {
		if !allowUnsigned {
			return "", newError(CodeUnsupportedPayload, "unsigned payloads are disabled")
		}
		return value, nil
	}
	if present && !validPayloadHash(value) {
		return "", newError(CodeUnsupportedPayload, "payload hash encoding is unsupported")
	}
	if body == nil {
		return "", newError(CodeMalformedRequest, "request body is unavailable")
	}
	actual := body.SHA256()
	if present {
		provided, err := hexDecode(value)
		actualBytes, actualErr := hexDecode(actual)
		if err != nil || actualErr != nil || len(provided) != len(actualBytes) || subtleCompare(provided, actualBytes) != 1 {
			return "", newError(CodeInvalidSignature, "payload hash does not match request body")
		}
		return value, nil
	}
	return actual, nil
}

func hexDecode(value string) ([]byte, error) {
	decoded := make([]byte, len(value)/2)
	for i := range decoded {
		hi, lo := hexDigit(value[i*2]), hexDigit(value[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, errors.New("invalid hash")
		}
		decoded[i] = byte(hi<<4 | lo)
	}
	return decoded, nil
}

func hexDigit(value byte) int {
	switch {
	case value >= '0' && value <= '9':
		return int(value - '0')
	case value >= 'a' && value <= 'f':
		return int(value-'a') + 10
	case value >= 'A' && value <= 'F':
		return int(value-'A') + 10
	default:
		return -1
	}
}

func subtleCompare(left, right []byte) int {
	if len(left) != len(right) {
		return 0
	}
	var result byte
	for i := range left {
		result |= left[i] ^ right[i]
	}
	if result == 0 {
		return 1
	}
	return 0
}

func scrubForwardingHeaders(header http.Header) {
	if header == nil {
		return
	}
	// Connection names are request-controlled header names and must be
	// removed before the fixed proxy/hop list.
	var nominated []string
	for key, values := range header {
		if strings.EqualFold(key, "connection") {
			for _, value := range values {
				for _, name := range strings.Split(value, ",") {
					name = strings.TrimSpace(name)
					if name != "" {
						nominated = append(nominated, name)
					}
				}
			}
		}
	}
	for _, name := range nominated {
		deleteHeaderFold(header, name)
	}
	for key := range header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-forwarded-") || lower == "forwarded" {
			deleteHeaderFold(header, key)
		}
	}
	for _, key := range []string{"authorization", "proxy-authorization", "proxy-authenticate", "proxy-connection", "connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "via", "host", "x-amz-algorithm", "x-amz-credential", "x-amz-signature", "x-amz-signedheaders", "x-amz-expires", "x-amz-date", "x-amz-security-token", "date", "x-real-ip"} {
		deleteHeaderFold(header, key)
	}
}

func deleteHeaderFold(header http.Header, name string) {
	for key := range header {
		if strings.EqualFold(key, name) {
			delete(header, key)
		}
	}
}

func scrubAndCanonicalizeQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	parts := strings.Split(raw, "&")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		key := part
		if at := strings.IndexByte(part, '='); at >= 0 {
			key = part[:at]
		}
		decoded, err := percentDecodeQuery(key)
		if err != nil {
			return "", newError(CodeMalformedRequest, "request query contains an invalid escape")
		}
		if isSigningQueryKey(string(decoded)) {
			continue
		}
		kept = append(kept, part)
	}
	return canonicalRawQuery(strings.Join(kept, "&"))
}

func isSigningQueryKey(value string) bool {
	switch strings.ToLower(value) {
	case "x-amz-algorithm", "x-amz-credential", "x-amz-signature", "x-amz-signedheaders", "x-amz-expires", "x-amz-date", "x-amz-security-token":
		return true
	default:
		return false
	}
}

func validateBodyAvailable(body *Body) error {
	reader, err := body.Reader()
	if err != nil {
		return newError(CodeBodyReadFailure, "request body is unavailable")
	}
	if closer, ok := reader.(io.Closer); ok {
		_ = closer.Close()
	}
	return nil
}

// captureBodyForResign prefers Request.GetBody so signing a caller-owned
// request does not consume or replace its one-shot body. Incoming server
// requests generally have no GetBody; that path restores an equivalent body
// view after the unavoidable single read.
func captureBodyForResign(req *http.Request, options BodyOptions) (*Body, error) {
	if req == nil {
		return nil, newError(CodeMalformedRequest, "request is unavailable")
	}
	if req.Body == nil || req.Body == http.NoBody {
		return NewBody(http.NoBody, options)
	}
	if req.GetBody != nil {
		reader, err := req.GetBody()
		if err != nil || reader == nil {
			return nil, newError(CodeBodyReadFailure, "request body is unavailable")
		}
		body, captureErr := NewBody(reader, options)
		_ = reader.Close()
		return body, captureErr
	}
	originalBody := req.Body
	body, err := NewBody(originalBody, options)
	_ = originalBody.Close()
	req.Body = http.NoBody
	if err != nil {
		return nil, err
	}
	// Preserve the caller-visible request payload after consuming its
	// non-rewindable source. The original ContentLength and GetBody contract
	// remain unchanged; only the exhausted Body stream is replaced.
	req.Body = body.newReader()
	*req = *req.WithContext(contextWithBody(req.Context(), body))
	return body, nil
}

func attachBody(req *http.Request, body *Body) {
	if req == nil || body == nil {
		return
	}
	*req = *req.WithContext(contextWithBody(req.Context(), body))
	req.Body = body.newReader()
	req.GetBody = func() (io.ReadCloser, error) { return body.newReader(), nil }
	req.ContentLength = body.Size()
}

func payloadModeFromRequest(req *http.Request) awsrequest.PayloadHashMode {
	if req == nil {
		return awsrequest.PayloadHashUnsupported
	}
	if value, ok := req.Context().Value(payloadModeContextKey{}).(awsrequest.PayloadHashMode); ok {
		return value
	}
	return awsrequest.PayloadHashUnsupported
}

type payloadModeContextKey struct{}

func setPayloadMode(req *http.Request, mode awsrequest.PayloadHashMode) {
	if req == nil {
		return
	}
	*req = *req.WithContext(context.WithValue(req.Context(), payloadModeContextKey{}, mode))
}
