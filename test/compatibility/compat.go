//go:build compat

// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package compatibility

import (
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
	"os/exec"
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

type compatibilityClient struct {
	Version    string `json:"version"`
	Executable string `json:"executable"`
}

type versionMatrix struct {
	Clients       map[string]compatibilityClient `json:"clients"`
	OS            []string                       `json:"os"`
	Architectures []string                       `json:"architectures"`
}

// UnmarshalJSON accepts the compact matrix used by the correction-cycle CI
// files as well as the expanded schema used by older local checkouts. Keeping
// normalization here makes every external prerequisite check use one table.
func (m *versionMatrix) UnmarshalJSON(data []byte) error {
	var expanded struct {
		Clients       map[string]compatibilityClient `json:"clients"`
		OS            []string                       `json:"os"`
		Architectures []string                       `json:"architectures"`
	}
	if err := json.Unmarshal(data, &expanded); err != nil {
		return err
	}
	if len(expanded.Clients) > 0 {
		m.Clients = expanded.Clients
		m.OS, m.Architectures = expanded.OS, expanded.Architectures
		return nil
	}
	var compact map[string]string
	if err := json.Unmarshal(data, &compact); err != nil {
		return err
	}
	m.Clients = make(map[string]compatibilityClient)
	executables := map[string]string{"awscli": "aws", "terraform": "terraform", "terraform_aws_provider": "terraform", "python": "python3", "boto3": "python3", "botocore": "python3", "claude_code": "claude", "codex": "codex", "go": "go"}
	for key, version := range compact {
		if executable, ok := executables[key]; ok {
			m.Clients[key] = compatibilityClient{Version: version, Executable: executable}
		}
	}
	return nil
}

func loadMatrix(t *testing.T) versionMatrix {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "..", "versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var matrix versionMatrix
	if err := json.Unmarshal(data, &matrix); err != nil {
		t.Fatal(err)
	}
	return matrix
}

// requirePinnedExecutable is intentionally strict in external mode. Pure mode
// never substitutes a host tool and therefore remains hermetic.
func requirePinnedExecutable(t *testing.T, key string, args ...string) string {
	t.Helper()
	matrix := loadMatrix(t)
	client, ok := matrix.Clients[key]
	if !ok {
		t.Fatalf("client %q is absent from versions.json", key)
	}
	path, err := exec.LookPath(client.Executable)
	if err != nil {
		reason := fmt.Sprintf("compatibility client %s (%s) is missing; install pinned version %s from versions.json", client.Executable, key, client.Version)
		if failure := requiredCompatibilityFailure(compatibilityExternalRequired(), reason); failure != nil {
			t.Fatal(failure)
		}
		t.Skip(reason)
	}
	checkArgs := args
	if len(checkArgs) == 0 {
		checkArgs = []string{"--version"}
	}
	output, err := exec.Command(path, checkArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s version command failed: %v", client.Executable, err)
	}
	if !strings.Contains(string(output), client.Version) {
		reason := fmt.Sprintf("%s version mismatch: got %q, want pinned %s", client.Executable, strings.TrimSpace(string(output)), client.Version)
		if failure := requiredCompatibilityFailure(compatibilityExternalRequired(), reason); failure != nil {
			t.Fatal(failure)
		}
		t.Skip(reason)
	}
	return path
}

func requirePinnedPythonModule(t *testing.T, key string) {
	t.Helper()
	matrix := loadMatrix(t)
	client, ok := matrix.Clients[key]
	if !ok {
		t.Fatalf("client %q is absent from versions.json", key)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		reason := fmt.Sprintf("Python module %s is missing; install pinned version %s", key, client.Version)
		if failure := requiredCompatibilityFailure(compatibilityExternalRequired(), reason); failure != nil {
			t.Fatal(failure)
		}
		t.Skip(reason)
	}
	output, err := exec.Command(python, "-c", fmt.Sprintf("import %s; print(getattr(%s, '__version__', ''))", key, key)).CombinedOutput()
	if err != nil || !strings.Contains(string(output), client.Version) {
		reason := fmt.Sprintf("Python module %s is not pinned to %s: %v (%s)", key, client.Version, err, output)
		if failure := requiredCompatibilityFailure(compatibilityExternalRequired(), reason); failure != nil {
			t.Fatal(failure)
		}
		t.Skip(reason)
	}
}

// requiredCompatibilityFailure is the policy boundary for tool-required
// cases: local mode lets the caller report a skip, while external mode turns
// the same missing or mismatched prerequisite into a hard failure.
func compatibilityExternalRequired() bool {
	return os.Getenv("KORDN_COMPAT_EXTERNAL") == "1" || os.Getenv("KORDN_EXTERNAL_REQUIRED") == "1"
}

func requiredCompatibilityFailure(external bool, reason string) error {
	if !external {
		return nil
	}
	return errors.New(reason)
}

// compatEnvironment replaces inherited proxy and credential variables rather
// than appending duplicate keys. This makes the local harness deterministic on
// hosts and runners that already export a corporate proxy.
func compatEnvironment(overrides ...string) []string {
	replaced := make(map[string]struct{}, len(overrides))
	for _, item := range overrides {
		if key, _, ok := strings.Cut(item, "="); ok {
			replaced[key] = struct{}{}
		}
	}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, item := range os.Environ() {
		key, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		if _, replace := replaced[key]; !replace {
			env = append(env, item)
		}
	}
	return append(env, overrides...)
}

func fixtureScript(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("fixtures", name)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	return path
}

const compatHost = fakeaws.Host

var compatClock = time.Now().UTC()

type compatAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *compatAudit) Write(_ context.Context, event audit.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	a.events = append(a.events, event)
	a.mu.Unlock()
	return nil
}
func (a *compatAudit) Flush(context.Context) error { return nil }
func (a *compatAudit) snapshot() []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Event(nil), a.events...)
}

type compatMapper struct{}

func (compatMapper) Map(_ context.Context, req *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	return &awsrequest.MappingResult{Service: req.Service, Operation: req.Operation, MapperVersion: "compat-v1", Confidence: awsrequest.ConfidenceHigh, Requirements: []awsrequest.IAMRequirement{{Action: req.Service + ":" + req.Operation, Resources: []string{"*"}, ScopeKind: awsrequest.ScopeKnownGlobal}}}, nil
}

type compatPolicy struct{ deny bool }

func (p compatPolicy) Evaluate(_ context.Context, in policy.DecisionInput) policy.Decision {
	if p.deny || in.Request.Operation == "Denied" {
		return policy.Decision{Result: policy.DecisionDeny, ReasonCode: "policy_no_matching_allow", MatchedRuleIDs: []string{"compat-deny"}}
	}
	return policy.Decision{Result: policy.DecisionAllow, ReasonCode: "all_requirements_allowed", MatchedRuleIDs: []string{"compat-allow"}}
}

type compatHarness struct {
	upstream *fakeaws.Server
	server   *proxy.Server
	client   *http.Client
	fake     aws.Credentials
	audit    *compatAudit
	root     string
	clock    func() time.Time
}

func newCompatHarness(t *testing.T, deny bool) *compatHarness {
	return newCompatHarnessWithClock(t, deny, func() time.Time { return compatClock })
}

func newCompatHarnessWithClock(t *testing.T, deny bool, clock func() time.Time) *compatHarness {
	return newCompatHarnessWithParentAndDialHook(t, deny, clock, "", nil)
}

func newCompatHarnessWithOutboundDialHook(t *testing.T, deny bool, clock func() time.Time, hook func()) *compatHarness {
	return newCompatHarnessWithParentAndDialHookAndWrapper(t, deny, clock, "", hook, nil, nil)
}

func newCompatHarnessWithTimedOutboundDial(t *testing.T, deny bool, clock func() time.Time, hook func(), wrap func(context.Context, time.Time, net.Conn) net.Conn, upstreamWrap func(http.RoundTripper) http.RoundTripper) *compatHarness {
	return newCompatHarnessWithParentAndDialHookAndWrapper(t, deny, clock, "", hook, wrap, upstreamWrap)
}

func newCompatHarnessWithParent(t *testing.T, deny bool, clock func() time.Time, parentURL string) *compatHarness {
	return newCompatHarnessWithParentAndDialHook(t, deny, clock, parentURL, nil)
}

func newCompatHarnessWithParentAndDialHook(t *testing.T, deny bool, clock func() time.Time, parentURL string, hook func()) *compatHarness {
	return newCompatHarnessWithParentAndDialHookAndWrapper(t, deny, clock, parentURL, hook, nil, nil)
}

func newCompatHarnessWithParentAndDialHookAndWrapper(t *testing.T, deny bool, clock func() time.Time, parentURL string, hook func(), wrap func(context.Context, time.Time, net.Conn) net.Conn, upstreamWrap func(http.RoundTripper) http.RoundTripper) *compatHarness {
	t.Helper()
	fake := aws.Credentials{AccessKeyID: "KORDNCOMPATACCESS01", SecretAccessKey: "compat-secret-key", SessionToken: "compat-session-token", CanExpire: true, Expires: clock().Add(time.Hour)}
	real := aws.Credentials{AccessKeyID: "COMPATUPSTREAM01", SecretAccessKey: "upstream-secret-key", SessionToken: "upstream-session-token"}
	upstream := fakeaws.NewWithConfig(fakeaws.Config{Credentials: real, Clock: clock})
	upstream.SetResponse("GetCallerIdentity", fakeaws.Response{Status: http.StatusOK, Body: []byte(`{"UserId":"compat","Account":"123456789012","Arn":"arn:aws:iam::123456789012:role/compat"}`)})
	t.Cleanup(upstream.Close)
	var parent *httptest.Server
	if parentURL == "__fixture__" {
		parent = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodConnect {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if req.Header.Get("Proxy-Authorization") == "" {
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			client, buffered, err := hijacker.Hijack()
			if err != nil {
				return
			}
			upstreamConn, err := net.Dial("tcp", upstream.Listener.Addr().String())
			if err != nil {
				_ = client.Close()
				return
			}
			_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = buffered.Flush()
			go func() {
				defer client.Close()
				defer upstreamConn.Close()
				copyDone := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstreamConn, buffered)
					close(copyDone)
				}()
				_, _ = io.Copy(client, upstreamConn)
				_ = upstreamConn.Close()
				<-copyDone
			}()
		}))
		t.Cleanup(parent.Close)
		parentURL = parent.URL
	}
	parentSettings := runtimeProxySettings()
	if parentURL != "" {
		parsedParent, err := url.Parse(parentURL)
		if err != nil {
			t.Fatal(err)
		}
		parentSettings.HTTPProxy = "http://corp-user:corp-password@" + parsedParent.Host
		parentSettings.HTTPSProxy = parentSettings.HTTPProxy
	}
	verifier, err := sigv4.NewVerifier(credentials.FakeCredential{AccessKeyID: fake.AccessKeyID, SecretAccessKey: fake.SecretAccessKey, SessionToken: fake.SessionToken}, sigv4.WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := awsrequest.NewConfiguredDecoder(awsrequest.DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		t.Fatal(err)
	}
	resigner, err := sigv4.NewResigner(sdkcredentials.NewStaticCredentialsProvider(real.AccessKeyID, real.SecretAccessKey, real.SessionToken), sigv4.WithResignClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	dialer := proxy.DialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if parentURL != "" {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
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
	transport := proxy.NewOutboundTransport(parentSettings, proxy.TransportConfig{Dialer: dialer, RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs})
	// httptest's certificate is issued for its loopback listener address. The
	// request Host remains the real AWS name, while this explicit local dial
	// keeps TLS verification pinned to the fixture certificate.
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	aud := &compatAudit{}
	upstreamTransport := proxy.NewNoReplayRoundTripper(transport)
	if upstreamWrap != nil {
		upstreamTransport = upstreamWrap(upstreamTransport)
	}
	server, err := proxy.NewServer(proxy.Config{ListenAddr: "127.0.0.1:0", Username: "compat-user", Password: "compat-password", RunID: "compat-run", PolicyHash: "sha256:" + strings.Repeat("0", 64), InboundAuthenticator: verifier, Decoder: decoder, Mapper: compatMapper{}, Policy: compatPolicy{deny: deny}, Audit: aud, Resigner: resigner, Upstream: upstreamTransport, Caches: mustCompatCaches(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse("http://compat-user:compat-password@" + server.Addr())
	tlsConfig := tlsConfigFor(server)
	clientTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tlsConfig, DisableKeepAlives: true}
	client := &http.Client{Transport: clientTransport}
	t.Cleanup(clientTransport.CloseIdleConnections)
	return &compatHarness{upstream: upstream, server: server, client: client, fake: fake, audit: aud, clock: clock}
}

// Kept as a function to make it impossible for a compatibility child to read
// ambient proxy variables while constructing the upstream transport.
func runtimeProxySettings() runtimepkg.CapturedProxySettings {
	return runtimepkg.CapturedProxySettings{}
}
func mustCompatCaches(t *testing.T) *cache.RunCaches {
	c, err := cache.NewRunCaches(cache.CacheOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func tlsConfigFor(server *proxy.Server) tls.Config {
	return tls.Config{MinVersion: tls.VersionTLS12, RootCAs: server.CA().CertPool(), ServerName: compatHost}
}

func (h *compatHarness) call(t *testing.T, operation string) *http.Response {
	return h.callWithClient(t, h.client, operation)
}

func (h *compatHarness) callWithClient(t *testing.T, client *http.Client, operation string) *http.Response {
	return h.callWithClientContext(t, context.Background(), client, operation)
}

func (h *compatHarness) callWithClientContext(t *testing.T, ctx context.Context, client *http.Client, operation string) *http.Response {
	t.Helper()
	body := []byte("Action=" + operation + "&Version=2011-06-15")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+compatHost+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = compatHost
	if worker, ok := ctx.Value("kordn-performance-worker").(int); ok {
		req.Header.Set("X-Kordn-Performance-Worker", strconv.Itoa(worker))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Amz-Date", h.clock().Format("20060102T150405Z"))
	hash := sha256.Sum256(body)
	payload := hex.EncodeToString(hash[:])
	req.Header.Set("X-Amz-Content-Sha256", payload)
	if err := v4.NewSigner().SignHTTP(ctx, h.fake, req, payload, fakeaws.Service, fakeaws.Region, h.clock()); err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertForwarded(t *testing.T, h *compatHarness, operation string, wantStatus int) {
	t.Helper()
	response := h.call(t, operation)
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != wantStatus {
		t.Fatalf("operation %s status=%d want=%d", operation, response.StatusCode, wantStatus)
	}
	ledger := h.upstream.Ledger()
	if wantStatus == http.StatusOK && len(ledger) == 0 {
		t.Fatal("allowed request did not reach fake AWS")
	}
	for _, e := range h.audit.snapshot() {
		if e.EventType == audit.RequestDecision && e.Request != nil && e.Request.Operation == operation {
			return
		}
	}
	t.Fatalf("operation %s has no decision audit event", operation)
}
