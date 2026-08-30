// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	sdkcredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/kordn-ai/kordn/internal/audit"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/cache"
	"github.com/kordn-ai/kordn/internal/credentials"
	"github.com/kordn-ai/kordn/internal/policy"
	"github.com/kordn-ai/kordn/internal/proxy"
	runtimepkg "github.com/kordn-ai/kordn/internal/runtime"
	"github.com/kordn-ai/kordn/internal/sigv4"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

func TestFakeAWSFailureScriptAndLedgerAreBoundedAndNonSecret(t *testing.T) {
	clock := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	upstream := fakeaws.NewWithConfig(fakeaws.Config{Credentials: aws.Credentials{AccessKeyID: "KNOWNACCESSKEY0001", SecretAccessKey: "known-secret", SessionToken: "known-token"}, Clock: func() time.Time { return clock }, LedgerCapacity: 2})
	defer upstream.Close()
	upstream.Failures().Set("PutItem", fakeaws.Failure{Status: http.StatusTooManyRequests, RetryAfter: "2", Body: []byte(`{"__type":"ThrottlingException","message":"try again"}`)})
	for _, action := range []string{"PutItem", "GetItem", "GetItem"} {
		response, err := sendFixtureRequest(t, upstream, action, clock)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if action == "PutItem" && (response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "2") {
			t.Fatalf("failure fixture = %d/%q", response.StatusCode, response.Header.Get("Retry-After"))
		}
	}
	ledger := upstream.Ledger()
	if len(ledger) != 2 {
		t.Fatalf("ledger length = %d, want bounded length 2", len(ledger))
	}
	for _, entry := range ledger {
		if entry.BodySHA256 == "" || entry.Action == "" || len(entry.HeaderNames) == 0 || entry.RequestID == "" {
			t.Fatalf("incomplete ledger entry: %+v", entry)
		}
		serialized := entry.Action + entry.Query + strings.Join(entry.HeaderNames, ",")
		for _, secret := range []string{"known-secret", "known-token", "KNOWNACCESSKEY0001", "Authorization"} {
			if strings.Contains(serialized, secret) {
				t.Fatalf("secret or header value in ledger: %q", secret)
			}
		}
	}
	copyOfLedger := upstream.Snapshot()
	copyOfLedger[0].HeaderNames[0] = "mutated"
	if upstream.Ledger()[0].HeaderNames[0] == "mutated" {
		t.Fatal("ledger snapshot was not deep copied")
	}
}

func TestSequentialABCAuditContractDoesNotClaimRollback(t *testing.T) {
	state := fakeaws.NewState()
	sequence := fakeaws.Sequence{ReadID: "A", WriteID: "B", DerivedValue: "derived-from-A"}
	if err := state.ApplySequence(sequence, "A", true); err != nil {
		t.Fatal(err)
	}
	if err := state.ApplySequence(sequence, "B", true); err != nil {
		t.Fatal(err)
	}
	if err := state.ApplySequence(sequence, "C", false); err == nil {
		t.Fatal("denied C operation was accepted")
	}
	resources := state.Snapshot()
	if _, ok := resources["A"]; !ok {
		t.Fatal("A was not completed")
	}
	if got, ok := resources["B"]; !ok || got.Value != "derived-from-A" {
		t.Fatalf("B state = %+v", got)
	}
	// A denied request is not a rollback operation. It is absent from the
	// upstream fixture ledger when the policy boundary rejects it.
	t.Log("A and B complete; C denied locally; no rollback is claimed")
}

func TestDirectConnectAndOriginalCredentialReadAreDocumentedOutOfScope(t *testing.T) {
	// These checks deliberately demonstrate the limitation instead of calling
	// it a passing containment test: a same-user process can ignore proxy env.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, e := listener.Accept()
		if e == nil {
			_, _ = conn.Write([]byte("direct"))
			_ = conn.Close()
		}
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	value, err := io.ReadAll(conn)
	if err != nil || string(value) != "direct" {
		t.Fatalf("direct bypass demonstration = %q, %v", value, err)
	}
	t.Log("OUT-OF-SCOPE limitation: direct connections and same-user reads of original credential files are not contained")
}

func sendFixtureRequest(t *testing.T, upstream *fakeaws.Server, action string, clock time.Time) (*http.Response, error) {
	t.Helper()
	body := []byte("Action=" + action + "&Version=2011-06-15")
	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = fakeaws.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Amz-Date", clock.Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Security-Token", upstream.Credentials.SessionToken)
	hash := sha256.Sum256(body)
	payload := hex.EncodeToString(hash[:])
	req.Header.Set("X-Amz-Content-Sha256", payload)
	if err := v4.NewSigner().SignHTTP(context.Background(), upstream.Credentials, req, payload, fakeaws.Service, fakeaws.Region, clock); err != nil {
		return nil, err
	}
	base := upstream.Client().Transport.(*http.Transport)
	transport := &http.Transport{TLSClientConfig: base.TLSClientConfig.Clone(), DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()
	return client.Do(req)
}

// securityHarness is the shared integration composition root. Lifecycle tests
// use this same real CONNECT/TLS/pipeline path rather than invoking a handler
// or a fake pipeline directly.
type securityHarness struct {
	upstream *fakeaws.Server
	proxy    *proxy.Server
	client   *http.Client
	fake     aws.Credentials
	audit    *securityAudit
	caches   *cache.RunCaches
	clock    time.Time
	host     string
	service  string
	region   string
}

type securityAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *securityAudit) Write(_ context.Context, e audit.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
	return nil
}
func (a *securityAudit) Flush(context.Context) error { return nil }
func (a *securityAudit) Events() []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Event(nil), a.events...)
}

type securityMapper struct{}

func (securityMapper) Map(_ context.Context, r *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	resource := "*"
	scope := awsrequest.ScopeKnownGlobal
	if r.Service == "dynamodb" {
		if table, ok := r.Parameters["TableName"]; ok && table.Kind == awsrequest.ValueString && table.String != "" {
			resource = "arn:aws:dynamodb:" + r.Region + ":" + r.CallerAccountID + ":table/" + table.String
			scope = awsrequest.ScopeExact
		}
	}
	return &awsrequest.MappingResult{Service: r.Service, Operation: r.Operation, MapperVersion: "integration-v1", Confidence: awsrequest.ConfidenceHigh, Requirements: []awsrequest.IAMRequirement{{Action: r.Service + ":" + r.Operation, Resources: []string{resource}, ScopeKind: scope}}}, nil
}

type securityPolicy struct {
	deny          bool
	denyOperation string
}

func (p securityPolicy) Evaluate(_ context.Context, in policy.DecisionInput) policy.Decision {
	if p.deny || (p.denyOperation != "" && in.Request.Operation == p.denyOperation) {
		return policy.Decision{Result: policy.DecisionDeny, ReasonCode: "policy_no_matching_allow", MatchedRuleIDs: []string{"integration-deny"}}
	}
	return policy.Decision{Result: policy.DecisionAllow, ReasonCode: "all_requirements_allowed", MatchedRuleIDs: []string{"integration-allow"}}
}

func newSecurityHarness(t *testing.T, deny bool) *securityHarness {
	t.Helper()
	return newSecurityHarnessWithPolicy(t, securityPolicy{deny: deny}, nil)
}

func newSecurityHarnessWithAudit(t *testing.T, deny bool, writer audit.AuditWriter) *securityHarness {
	return newSecurityHarnessWithPolicy(t, securityPolicy{deny: deny}, writer)
}

func newSecurityHarnessWithPolicy(t *testing.T, selectedPolicy securityPolicy, writer audit.AuditWriter) *securityHarness {
	return newSecurityHarnessForEndpointWithDialHook(t, selectedPolicy, writer, fakeaws.Host, fakeaws.Service, fakeaws.Region, nil)
}

func newSecurityHarnessWithOutboundDialHook(t *testing.T, selectedPolicy securityPolicy, writer audit.AuditWriter, hook func()) *securityHarness {
	return newSecurityHarnessForEndpointWithDialHookAndWrapper(t, selectedPolicy, writer, fakeaws.Host, fakeaws.Service, fakeaws.Region, hook, nil, nil)
}

func newSecurityHarnessWithTimedOutboundDial(t *testing.T, selectedPolicy securityPolicy, writer audit.AuditWriter, hook func(), wrap func(context.Context, time.Time, net.Conn) net.Conn, upstreamWrap func(http.RoundTripper) http.RoundTripper) *securityHarness {
	return newSecurityHarnessForEndpointWithDialHookAndWrapper(t, selectedPolicy, writer, fakeaws.Host, fakeaws.Service, fakeaws.Region, hook, wrap, upstreamWrap)
}

func newSecurityHarnessForEndpoint(t *testing.T, selectedPolicy securityPolicy, writer audit.AuditWriter, host, service, region string) *securityHarness {
	return newSecurityHarnessForEndpointWithDialHook(t, selectedPolicy, writer, host, service, region, nil)
}

func newSecurityHarnessForEndpointWithDialHook(t *testing.T, selectedPolicy securityPolicy, writer audit.AuditWriter, host, service, region string, hook func()) *securityHarness {
	return newSecurityHarnessForEndpointWithDialHookAndWrapper(t, selectedPolicy, writer, host, service, region, hook, nil, nil)
}

func newSecurityHarnessForEndpointWithDialHookAndWrapper(t *testing.T, selectedPolicy securityPolicy, writer audit.AuditWriter, host, service, region string, hook func(), wrap func(context.Context, time.Time, net.Conn) net.Conn, upstreamWrap func(http.RoundTripper) http.RoundTripper) *securityHarness {
	t.Helper()
	clock := time.Now().UTC()
	fake := aws.Credentials{AccessKeyID: "KORDNSECURITYACCESS01", SecretAccessKey: "security-fake-secret", SessionToken: "security-fake-token"}
	real := aws.Credentials{AccessKeyID: "SECURITYUPSTREAM01", SecretAccessKey: "security-upstream-secret", SessionToken: "security-upstream-token"}
	upstream := fakeaws.NewWithConfig(fakeaws.Config{Credentials: real, Host: host, Service: service, Region: region, Clock: func() time.Time { return clock }})
	upstream.SetResponse("GetCallerIdentity", fakeaws.Response{Status: http.StatusOK, Body: []byte(`{"ok":true}`)})
	t.Cleanup(upstream.Close)
	verifier, err := sigv4.NewVerifier(credentials.FakeCredential{AccessKeyID: fake.AccessKeyID, SecretAccessKey: fake.SecretAccessKey, SessionToken: fake.SessionToken}, sigv4.WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := awsrequest.NewConfiguredDecoder(awsrequest.DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		t.Fatal(err)
	}
	resigner, err := sigv4.NewResigner(sdkcredentials.NewStaticCredentialsProvider(real.AccessKeyID, real.SecretAccessKey, real.SessionToken), sigv4.WithResignClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	dialer := proxy.DialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	})
	if hook != nil || wrap != nil {
		baseDialer := dialer
		dialer = proxy.DialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if hook != nil {
				hook()
			}
			dialStart := time.Now()
			conn, err := baseDialer.DialContext(ctx, network, address)
			if err == nil && wrap != nil {
				conn = wrap(ctx, dialStart, conn)
			}
			return conn, err
		})
	}
	out := proxy.NewOutboundTransport(runtimeProxySettingsForIntegration(), proxy.TransportConfig{Dialer: dialer, RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs})
	out.TLSClientConfig.ServerName = "127.0.0.1"
	aud := &securityAudit{}
	if writer == nil {
		writer = aud
	}
	caches := mustIntegrationCaches(t)
	upstreamTransport := proxy.NewNoReplayRoundTripper(out)
	if upstreamWrap != nil {
		upstreamTransport = upstreamWrap(upstreamTransport)
	}
	p, err := proxy.NewServer(proxy.Config{ListenAddr: "127.0.0.1:0", Username: "integration-user", Password: "integration-password", RunID: "integration-run", PolicyHash: "sha256:" + strings.Repeat("0", 64), InboundAuthenticator: verifier, Decoder: decoder, Mapper: securityMapper{}, Policy: selectedPolicy, Audit: writer, LogResourceARNs: true, Resigner: resigner, Upstream: upstreamTransport, Caches: caches})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	proxyURL, _ := url.Parse("http://integration-user:integration-password@" + p.Addr())
	tlsConfig := tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.CA().CertPool(), ServerName: host}
	ct := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tlsConfig, DisableKeepAlives: true}
	t.Cleanup(ct.CloseIdleConnections)
	return &securityHarness{upstream: upstream, proxy: p, client: &http.Client{Transport: ct}, fake: fake, audit: aud, caches: caches, clock: clock, host: host, service: service, region: region}
}

// RunCaches returns the exact run-scoped cache set installed in the proxy.
// Integration resource tests intentionally inspect this instance rather than
// constructing a helper-only cache that the proxy never uses.
func (h *securityHarness) RunCaches() *cache.RunCaches {
	if h == nil {
		return nil
	}
	return h.caches
}

type failingSecurityAudit struct{ events *securityAudit }

func (a failingSecurityAudit) Write(_ context.Context, event audit.Event) error {
	if a.events != nil {
		_ = a.events.Write(context.Background(), event)
	}
	return errors.New("simulated audit writer failure")
}
func (failingSecurityAudit) Flush(context.Context) error { return nil }
func runtimeProxySettingsForIntegration() runtimepkg.CapturedProxySettings {
	return runtimepkg.CapturedProxySettings{}
}
func mustIntegrationCaches(t *testing.T) *cache.RunCaches {
	c, err := cache.NewRunCaches(cache.CacheOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (h *securityHarness) call(t *testing.T, creds aws.Credentials, when time.Time, action string) *http.Response {
	t.Helper()
	return h.callWithClient(t, h.client, creds, when, action)
}

func (h *securityHarness) callWithClient(t *testing.T, client *http.Client, creds aws.Credentials, when time.Time, action string) *http.Response {
	return h.callWithClientContext(t, context.Background(), client, creds, when, action)
}

func (h *securityHarness) callWithClientContext(t *testing.T, ctx context.Context, client *http.Client, creds aws.Credentials, when time.Time, action string) *http.Response {
	t.Helper()
	if h.service == "dynamodb" {
		return h.callDynamoDBWithClientContext(t, ctx, client, creds, when, action, dynamoDBBody(action, "A", "derived-from-A"))
	}
	return h.callRequestWithClientContext(t, ctx, client, creds, when, "application/x-www-form-urlencoded", "", []byte("Action="+action+"&Version=2011-06-15"))
}

func (h *securityHarness) callDynamoDB(t *testing.T, creds aws.Credentials, when time.Time, action string, body []byte) *http.Response {
	t.Helper()
	return h.callDynamoDBWithClient(t, h.client, creds, when, action, body)
}

func (h *securityHarness) callDynamoDBWithClient(t *testing.T, client *http.Client, creds aws.Credentials, when time.Time, action string, body []byte) *http.Response {
	return h.callDynamoDBWithClientContext(t, context.Background(), client, creds, when, action, body)
}

func (h *securityHarness) callDynamoDBWithClientContext(t *testing.T, ctx context.Context, client *http.Client, creds aws.Credentials, when time.Time, action string, body []byte) *http.Response {
	t.Helper()
	target := "DynamoDB_20120810." + action
	return h.callRequestWithClientContext(t, ctx, client, creds, when, "application/x-amz-json-1.0", target, body)
}

func (h *securityHarness) callRequest(t *testing.T, creds aws.Credentials, when time.Time, contentType, target string, body []byte) *http.Response {
	t.Helper()
	return h.callRequestWithClient(t, h.client, creds, when, contentType, target, body)
}

func (h *securityHarness) callRequestWithClient(t *testing.T, client *http.Client, creds aws.Credentials, when time.Time, contentType, target string, body []byte) *http.Response {
	return h.callRequestWithClientContext(t, context.Background(), client, creds, when, contentType, target, body)
}

func (h *securityHarness) callRequestWithClientContext(t *testing.T, ctx context.Context, client *http.Client, creds aws.Credentials, when time.Time, contentType, target string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+h.host+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = h.host
	if worker, ok := ctx.Value("kordn-performance-worker").(int); ok {
		req.Header.Set("X-Kordn-Performance-Worker", strconv.Itoa(worker))
	}
	req.Header.Set("Content-Type", contentType)
	if target != "" {
		req.Header.Set("X-Amz-Target", target)
	}
	req.Header.Set("X-Amz-Date", when.Format("20060102T150405Z"))
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", hash)
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hash, h.service, h.region, when); err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func dynamoDBBody(action, id, value string) []byte {
	switch action {
	case "GetItem", "DeleteItem":
		return []byte(`{"TableName":"fixture","Key":{"id":{"S":"` + id + `"}}}`)
	case "PutItem":
		return []byte(`{"TableName":"fixture","Item":{"id":{"S":"` + id + `"},"value":{"S":"` + value + `"}}}`)
	default:
		return []byte(`{"TableName":"fixture"}`)
	}
}

func TestSecurityRealProxyRejectsBadStaleAndForwardsAllowed(t *testing.T) {
	h := newSecurityHarness(t, false)
	response := h.call(t, h.fake, h.clock, "GetCallerIdentity")
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("allowed status=%d", response.StatusCode)
	}
	before := len(h.upstream.Ledger())
	bad := h.fake
	bad.SecretAccessKey = "wrong-secret"
	response = h.call(t, bad, h.clock, "GetCallerIdentity")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("bad auth status=%d", response.StatusCode)
	}
	// The real upstream fixture key is not a credential accepted by Kordn's
	// inbound boundary. Knowing an upstream secret must not create a bypass.
	realKey := h.upstream.Credentials
	response = h.call(t, realKey, h.clock, "GetCallerIdentity")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("real upstream key auth status=%d", response.StatusCode)
	}
	stale := h.clock.Add(-6 * time.Minute)
	response = h.call(t, h.fake, stale, "GetCallerIdentity")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("stale auth status=%d", response.StatusCode)
	}
	if len(h.upstream.Ledger()) != before {
		t.Fatalf("rejected requests reached upstream: %+v", h.upstream.Ledger())
	}
	seenDecision := false
	for _, e := range h.audit.Events() {
		if e.EventType == audit.RequestDecision {
			seenDecision = true
		}
	}
	if !seenDecision {
		t.Fatal("allowed request had no audit decision")
	}
}

func TestSecurityRealProxyDeniesBeforeUpstreamAndRecordsAudit(t *testing.T) {
	h := newSecurityHarness(t, true)
	response := h.call(t, h.fake, h.clock, "GetCallerIdentity")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("deny status=%d", response.StatusCode)
	}
	if len(h.upstream.Ledger()) != 0 {
		t.Fatal("denied operation crossed upstream")
	}
	if len(h.audit.Events()) == 0 {
		t.Fatal("denied operation had no audit record")
	}
}

func TestSecurityABCLedgerAndAuditUseTheRealProxyHarness(t *testing.T) {
	h := newSecurityHarnessForEndpoint(t, securityPolicy{denyOperation: "DeleteItem"}, nil, "dynamodb.us-east-1.amazonaws.com", "dynamodb", "us-east-1")
	// A is a real DynamoDB JSON 1.0 read. The fake upstream owns the initial
	// state and returns it in the response; B must use that runtime value.
	h.upstream.State().Put("A", "source-from-A")
	response := h.callDynamoDB(t, h.fake, h.clock, "GetItem", dynamoDBBody("GetItem", "A", ""))
	var read struct {
		Item map[string]struct {
			S string `json:"S"`
		} `json:"Item"`
	}
	if err := json.NewDecoder(response.Body).Decode(&read); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || read.Item["value"].S != "source-from-A" {
		t.Fatalf("A response=%d item=%+v audit=%+v ledger=%+v", response.StatusCode, read.Item, h.audit.Events(), h.upstream.Ledger())
	}
	derived := read.Item["value"].S + "-derived"

	response = h.callDynamoDB(t, h.fake, h.clock, "PutItem", dynamoDBBody("PutItem", "B", derived))
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("B status=%d", response.StatusCode)
	}

	response = h.callDynamoDB(t, h.fake, h.clock, "DeleteItem", dynamoDBBody("DeleteItem", "B", ""))
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("C status=%d", response.StatusCode)
	}

	ledger := h.upstream.Ledger()
	if len(ledger) != 2 || ledger[0].Action != "GetItem" || ledger[1].Action != "PutItem" || ledger[0].Status != http.StatusOK || ledger[1].Status != http.StatusOK {
		t.Fatalf("A/B/C upstream ledger=%+v", ledger)
	}
	var allows, denies int
	for _, event := range h.audit.Events() {
		if event.EventType != audit.RequestDecision || event.Decision == nil || event.Request == nil {
			continue
		}
		switch event.Decision.Result {
		case "allow":
			allows++
		case "deny":
			denies++
		}
		if len(event.IAMRequirements) != 1 || event.IAMRequirements[0].Resources[0] != "arn:aws:dynamodb:us-east-1:123456789012:table/fixture" {
			t.Fatalf("%s audit resource is inaccurate: %+v", event.Request.Operation, event)
		}
		if event.Request.Operation == "DeleteItem" && event.Decision.Result != "deny" {
			t.Fatalf("C audit outcome is inaccurate: %+v", event)
		}
	}
	if allows != 2 || denies != 1 {
		t.Fatalf("A/B/C audit decisions allow=%d deny=%d events=%+v", allows, denies, h.audit.Events())
	}
	if resources := h.upstream.State().Snapshot(); resources["B"].Value != derived || resources["A"].Value != "source-from-A" {
		t.Fatalf("incomplete derived state=%+v", resources)
	}
}

func TestSecurityAuditWriterFailureStopsForwarding(t *testing.T) {
	collector := &securityAudit{}
	h := newSecurityHarnessWithAudit(t, false, failingSecurityAudit{events: collector})
	response := h.call(t, h.fake, h.clock, "GetCallerIdentity")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("writer failure status=%d", response.StatusCode)
	}
	if len(h.upstream.Ledger()) != 0 {
		t.Fatal("request crossed upstream after audit writer failure")
	}
	if h.proxy.MetricsSnapshot().Counters["audit_writer_failures"] == 0 {
		t.Fatal("audit writer failure was not measured")
	}
}

func TestSecurityRealProxyFailsClosedOnUpstreamDisconnect(t *testing.T) {
	h := newSecurityHarness(t, false)
	h.upstream.Failures().Set("GetCallerIdentity", fakeaws.Failure{Disconnect: true})
	response := h.call(t, h.fake, h.clock, "GetCallerIdentity")
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("disconnect status=%d", response.StatusCode)
	}
	if len(h.upstream.Ledger()) != 1 || h.upstream.RequestCount() != 0 {
		t.Fatalf("disconnect was not recorded as a failed upstream attempt: ledger=%+v count=%d", h.upstream.Ledger(), h.upstream.RequestCount())
	}
	var forwardError bool
	for _, event := range h.audit.Events() {
		if event.EventType == audit.ForwardError {
			forwardError = true
		}
	}
	if !forwardError {
		t.Fatal("upstream disconnect had no forward-error audit")
	}
}
func TestSecurityAdversarialProxyBoundary(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamCalls++; _, _ = io.Copy(w, r.Body) }))
	defer upstream.Close()
	_, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	server, err := proxy.NewServer(proxy.Config{Username: "run-user", Password: "run-secret",
		Resolver: proxy.ResolverFunc(func(_ context.Context, _, host string) ([]net.IP, error) {
			if host == "opaque.lookalike.test" {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, fmt.Errorf("unexpected lookup")
		}),
		TargetAllow: func(host string, ip net.IP) bool { return host == "opaque.lookalike.test" && ip.IsLoopback() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	address := server.Addr()
	defer server.Close()

	// Guessed Basic/token credentials are rejected before resolver or dialer
	// work. This is a real CONNECT, not an authenticator-only unit assertion.
	for _, auth := range []string{"Basic cnVuLXVzZXI6d3Jvbmc=", "Bearer guessed-token", "Basic YWRtaW46YWRtaW4="} {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "CONNECT opaque.lookalike.test:%s HTTP/1.1\r\nHost: opaque.lookalike.test:%s\r\nProxy-Authorization: %s\r\n\r\n", port, port, auth)
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if response.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("guessed proxy credential status=%d, want 407", response.StatusCode)
		}
	}
	if upstreamCalls != 0 {
		t.Fatal("guessed proxy credentials reached upstream")
	}

	// An endpoint lookalike is deliberately not AWS-classified. Its TLS
	// certificate and bytes remain opaque rather than being sent to a fake
	// AWS handler.
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "CONNECT opaque.lookalike.test:%s HTTP/1.1\r\nHost: opaque.lookalike.test:%s\r\nProxy-Authorization: Basic cnVuLXVzZXI6cnVuLXNlY3JldA==\r\n\r\n", port, port)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("lookalike CONNECT=%v err=%v", response, err)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "opaque.lookalike.test"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("opaque-\x00-bytes-\xff")
	fmt.Fprintf(tlsConn, "POST /opaque HTTP/1.1\r\nHost: opaque.lookalike.test\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(payload))
	if _, err := tlsConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	response, err = http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = tlsConn.Close()
	if !bytes.Equal(body, payload) || upstreamCalls != 1 {
		t.Fatalf("opaque request changed: body=%q calls=%d", body, upstreamCalls)
	}

	// Termination is fail-closed for new clients. Direct-connect is tested
	// separately below as an explicit, documented non-containment limitation.
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.Dial("tcp", address); err == nil {
		_ = conn.Close()
		t.Fatal("killed proxy accepted a new connection")
	}
}

func TestSecurityExplicitDirectAndCredentialFileLimitations(t *testing.T) {
	// These tests intentionally demonstrate what V0.1 does not contain: a
	// process may unset its proxy, and a child may read an ordinary file.
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")
	file := filepath.Join(t.TempDir(), "original-credentials")
	secret := []byte("real-access-key\nreal-secret\n")
	if err := os.WriteFile(file, secret, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("explicit credential-file limitation failed: %v", err)
	}
	if strings.Contains(string(got), "KORDN") {
		t.Fatal("fixture unexpectedly contained fake credentials")
	}
}
