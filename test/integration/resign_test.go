package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/credentials"
	"github.com/kordn-ai/kordn/internal/proxy"
	"github.com/kordn-ai/kordn/internal/sigv4"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

func TestVerificationFailureDoesNotReachFakeAWS(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	real := aws.Credentials{AccessKeyID: "REALACCESSKEY0001", SecretAccessKey: "real-secret", SessionToken: "real-token"}
	upstream := fakeaws.New(real, func() time.Time { return clock })
	defer upstream.Close()
	endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: fakeaws.Host, Service: fakeaws.Service, Region: fakeaws.Region, Scope: awsrequest.ScopeRegional}
	fake := credentials.FakeCredential{AccessKeyID: "KORDNFAKEACCESS01", SecretAccessKey: "fake-secret", SessionToken: "fake-token"}
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	request, err := http.NewRequest(http.MethodPost, "https://"+fakeaws.Host+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = fakeaws.Host
	request.Header.Set("X-Amz-Date", clock.Format("20060102T150405Z"))
	request.Header.Set("X-Amz-Security-Token", fake.SessionToken)
	payloadHash := sha256Hex(body)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: fake.AccessKeyID, SecretAccessKey: fake.SecretAccessKey, SessionToken: fake.SessionToken}, request, payloadHash, endpoint.Service, endpoint.Region, clock); err != nil {
		t.Fatal(err)
	}
	authorization := request.Header.Get("Authorization")
	at := strings.Index(authorization, "Signature=") + len("Signature=")
	mutated := []byte(authorization)
	if at < len(mutated) {
		if mutated[at] == '0' {
			mutated[at] = '1'
		} else {
			mutated[at] = '0'
		}
	}
	request.Header.Set("Authorization", string(mutated))
	_, err = sigv4.VerifyRequest(context.Background(), request, endpoint, fake, sigv4.WithClock(func() time.Time { return clock }))
	if got := sigv4.CodeOf(err); got != sigv4.CodeInvalidSignature {
		t.Fatalf("invalid request code = %q, err=%v", got, err)
	}
	if err != nil && (strings.Contains(err.Error(), fake.AccessKeyID) || strings.Contains(err.Error(), fake.SecretAccessKey) || strings.Contains(err.Error(), fake.SessionToken)) {
		t.Fatalf("verification error exposed fake credential: %v", err)
	}
	if got := upstream.RequestCount(); got != 0 {
		t.Fatalf("verification failure reached fake AWS %d times", got)
	}
}

func TestResignAcceptedByIndependentFakeAWS(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	real := aws.Credentials{AccessKeyID: "REALACCESSKEY0001", SecretAccessKey: "real-secret", SessionToken: "real-token"}
	upstream := fakeaws.New(real, func() time.Time { return clock })
	defer upstream.Close()
	endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: fakeaws.Host, Service: fakeaws.Service, Region: fakeaws.Region, Scope: awsrequest.ScopeRegional}
	fake := credentials.FakeCredential{AccessKeyID: "KORDNFAKEACCESS01", SecretAccessKey: "fake-secret", SessionToken: "fake-token"}
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	request, err := http.NewRequest(http.MethodPost, "https://"+fakeaws.Host+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = fakeaws.Host
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	request.Header.Set("X-Amz-Security-Token", fake.SessionToken)
	request.Header.Set("X-Amz-Date", clock.Format("20060102T150405Z"))
	request.Header.Set("Proxy-Authorization", "Basic local-only")
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	payloadHash := sha256Hex(body)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: fake.AccessKeyID, SecretAccessKey: fake.SecretAccessKey, SessionToken: fake.SessionToken}, request, payloadHash, endpoint.Service, endpoint.Region, clock); err != nil {
		t.Fatal(err)
	}
	verified, err := sigv4.VerifyRequest(context.Background(), request, endpoint, fake, sigv4.WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	if verified == nil {
		t.Fatal("verification returned no result")
	}
	defer sigv4.CloseBody(request)
	resigned, err := sigv4.ReSign(context.Background(), request, endpoint, staticCredentials{value: real}, sigv4.WithResignClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	defer sigv4.CloseBody(resigned)
	if strings.Contains(resigned.Header.Get("Authorization"), fake.AccessKeyID) || resigned.Header.Get("X-Amz-Security-Token") != real.SessionToken {
		t.Fatalf("fake signing material leaked: %v", resigned.Header)
	}
	if resigned.Header.Get("Proxy-Authorization") != "" || resigned.Header.Get("X-Forwarded-For") != "" {
		t.Fatal("proxy forwarding headers survived resign")
	}

	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, ServerName: "127.0.0.1"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	defer transport.CloseIdleConnections()
	response, err := proxy.NewNoReplayRoundTripper(transport).RoundTrip(resigned)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(responseBody) != `{"ok":true}` {
		t.Fatalf("fake upstream response = %d %q", response.StatusCode, responseBody)
	}
	if response.Header.Get("x-amzn-requestid") != "fixture-request-id" || upstream.RequestCount() != 1 {
		t.Fatalf("upstream response/request count mismatch: id=%q count=%d", response.Header.Get("x-amzn-requestid"), upstream.RequestCount())
	}
}

type staticCredentials struct{ value aws.Credentials }

func (p staticCredentials) Retrieve(context.Context) (aws.Credentials, error) { return p.value, nil }

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestNoReplayRejectsStaleReusedGETRetry(t *testing.T) {
	var requests atomic.Int32
	firstIdle := make(chan struct{}, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			switch requests.Add(1) {
			case 1:
				writer.Header().Set("Content-Length", "5")
				_, _ = io.WriteString(writer, "prime")
			case 2:
				// The request was parsed from the reused connection, so application
				// bytes have already crossed the wire. Close without a response.
				hijacker, ok := writer.(http.Hijacker)
				if ok {
					conn, _, hijackErr := hijacker.Hijack()
					if hijackErr == nil {
						_ = conn.Close()
					}
				}
			case 3:
				writer.Header().Set("Content-Length", "5")
				_, _ = io.WriteString(writer, "retry")
			}
		}),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateIdle {
				select {
				case firstIdle <- struct{}{}:
				default:
				}
			}
		},
	}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	url := "http://" + listener.Addr().String() + "/"
	prime, err := transport.RoundTrip(mustIntegrationRequest(t, http.MethodGet, url, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got, readErr := io.ReadAll(prime.Body); readErr != nil || string(got) != "prime" {
		t.Fatalf("prime response = %q, err=%v", got, readErr)
	}
	_ = prime.Body.Close()
	select {
	case <-firstIdle:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not make the prime connection idle")
	}

	replayable := mustIntegrationRequest(t, http.MethodGet, url, nil)
	replayable.Header.Set("Idempotency-Key", "request-key")
	response, err := transport.RoundTrip(replayable)
	if err != nil {
		t.Fatalf("standard transport did not demonstrate its reused-GET retry: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "retry" {
		t.Fatalf("retried response = %q, err=%v", body, err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("standard transport application request count = %d, want 3 (prime, stale, retry)", got)
	}
}

func TestNoReplayBodylessGETSendsOnceAndReturnsFailure(t *testing.T) {
	var requests atomic.Int32
	var observedIdempotencyKey atomic.Value
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		observedIdempotencyKey.Store(req.Header.Get("Idempotency-Key"))
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, hijackErr := hijacker.Hijack()
		if hijackErr == nil {
			_ = conn.Close()
		}
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	base := &http.Transport{Proxy: nil}
	defer base.CloseIdleConnections()
	wrapped := proxy.NewNoReplayRoundTripper(base)
	req := mustIntegrationRequest(t, http.MethodGet, "http://"+listener.Addr().String()+"/ambiguous", nil)
	req.Header.Set("Idempotency-Key", "request-key")
	if response, err := wrapped.RoundTrip(req); err == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		t.Fatal("no-replay transport returned success after a response-less write")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("no-replay application request count = %d, want 1", got)
	}
	if got := observedIdempotencyKey.Load(); got != "request-key" {
		t.Fatalf("legitimate idempotency key changed: %v", got)
	}

	unsafe := proxy.NewNoReplayRoundTripper(testRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe arbitrary RoundTripper was invoked")
		return nil, nil
	}))
	if _, err := unsafe.RoundTrip(req); err == nil {
		t.Fatal("arbitrary RoundTripper was not rejected fail-closed")
	}
}

func TestNoReplayStreamsSuccessfulPOSTResponse(t *testing.T) {
	var requests atomic.Int32
	requestRead := make(chan string, 1)
	firstChunk := make(chan struct{})
	release := make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			return
		}
		requestRead <- string(body)
		writer.Header().Set("Content-Type", "text/plain")
		flusher, ok := writer.(http.Flusher)
		if !ok {
			return
		}
		_, _ = io.WriteString(writer, "first")
		flusher.Flush()
		close(firstChunk)
		<-release
		_, _ = io.WriteString(writer, "second")
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	base := &http.Transport{Proxy: nil}
	defer base.CloseIdleConnections()
	wrapped := proxy.NewNoReplayRoundTripper(base)
	req := mustIntegrationRequest(t, http.MethodPost, "http://"+listener.Addr().String()+"/stream", bytes.NewReader([]byte("request-body")))
	response, err := wrapped.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	select {
	case <-firstChunk:
	case <-time.After(5 * time.Second):
		t.Fatal("streaming response did not reach its first chunk")
	}
	first := make([]byte, len("first"))
	if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "first" {
		t.Fatalf("first response chunk = %q, err=%v", first, err)
	}
	close(release)
	rest, err := io.ReadAll(response.Body)
	if err != nil || string(rest) != "second" {
		t.Fatalf("remaining response body = %q, err=%v", rest, err)
	}
	select {
	case got := <-requestRead:
		if got != "request-body" {
			t.Fatalf("upstream request body = %q", got)
		}
	default:
		t.Fatal("upstream request body was not observed")
	}
	if requests.Load() != 1 {
		t.Fatalf("streaming upstream request count = %d, want 1", requests.Load())
	}
}

func mustIntegrationRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
