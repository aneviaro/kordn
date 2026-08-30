//go:build compat

package compatibility

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/kordn-ai/kordn/internal/audit"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/credentials"
	"github.com/kordn-ai/kordn/internal/policy"
	"github.com/kordn-ai/kordn/internal/proxy"
	"github.com/kordn-ai/kordn/internal/sigv4"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

const fixtureHost = "fixture.sts.kordn.test"

func TestVersionMatrixAndDocumentation(t *testing.T) {
	matrix := loadMatrix(t)
	for _, key := range []string{"awscli", "terraform", "terraform_aws_provider", "python", "boto3", "botocore", "claude_code", "codex", "go"} {
		client, ok := matrix.Clients[key]
		if !ok || client.Version == "" || client.Executable == "" {
			t.Fatalf("versions.json missing usable client %q: %+v", key, client)
		}
	}
	docs, err := os.ReadFile(filepath.Join("..", "..", "docs", "compatibility.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"AWS CLI", "Terraform", "boto3", "Claude Code", "Codex", "Corporate", "Adversarial"} {
		if !strings.Contains(string(docs), marker) {
			t.Fatalf("compatibility documentation missing %q", marker)
		}
	}
}

type fixtureClassifier struct{}

func (fixtureClassifier) Classify(host string) (awsrequest.AWSEndpoint, error) {
	if host != fixtureHost {
		return awsrequest.AWSEndpoint{}, fmt.Errorf("unknown fixture host")
	}
	return awsrequest.AWSEndpoint{Partition: "aws", Host: fixtureHost, Service: "sts", Region: "us-east-1", Scope: awsrequest.ScopeRegional}, nil
}

type fixtureDecoder struct{}

func (fixtureDecoder) Decode(_ context.Context, verified *awsrequest.VerifiedRequest, endpoint awsrequest.AWSEndpoint) (*awsrequest.DecodedAWSRequest, error) {
	body, err := io.ReadAll(verified.Request.Body)
	if err != nil {
		return nil, err
	}
	verified.Request.Body = io.NopCloser(strings.NewReader(string(body)))
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	operation := values.Get("Action")
	if operation == "" {
		operation = "Unknown"
	}
	return &awsrequest.DecodedAWSRequest{Partition: endpoint.Partition, EndpointHost: endpoint.Host, Service: endpoint.Service, Region: endpoint.Region, CallerAccountID: "123456789012", Protocol: awsrequest.ProtocolQuery, Operation: operation, Method: verified.Request.Method, CanonicalPath: "/", CanonicalQuery: url.Values{}, Headers: verified.Request.Header.Clone(), Parameters: map[string]awsrequest.Value{}, PayloadHashMode: awsrequest.PayloadHashSHA256, PayloadBytes: int64(len(body))}, nil
}

type fixtureMapper struct{}

func (fixtureMapper) Map(_ context.Context, request *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	return &awsrequest.MappingResult{Service: "sts", Operation: request.Operation, MapperVersion: "fixture-mapper", Confidence: awsrequest.ConfidenceHigh,
		Requirements: []awsrequest.IAMRequirement{{Action: "sts:" + request.Operation, Resources: []string{"*"}, ScopeKind: awsrequest.ScopeKnownGlobal}}}, nil
}

type fixturePolicy struct{ deny map[string]bool }

func (p fixturePolicy) Evaluate(_ context.Context, input policy.DecisionInput) policy.Decision {
	if p.deny[input.Request.Operation] {
		return policy.Decision{Result: policy.DecisionDeny, ReasonCode: "policy_no_matching_allow", MatchedRuleIDs: []string{"fixture-deny"}}
	}
	return policy.Decision{Result: policy.DecisionAllow, ReasonCode: "all_requirements_allowed", MatchedRuleIDs: []string{"fixture-allow"}}
}

type eventLog struct {
	mu     sync.Mutex
	events []audit.Event
}

func (l *eventLog) Write(_ context.Context, e audit.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	return nil
}
func (l *eventLog) Flush(context.Context) error { return nil }
func (l *eventLog) snapshot() []audit.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]audit.Event(nil), l.events...)
}

type fixtureRun struct {
	fake     *fakeaws.ProtocolServer
	server   *proxy.Server
	log      *eventLog
	env      []string
	fakeCred credentials.FakeCredential
}

func TestFixtureHarnessRealProxyLedgerAndLocalDeny(t *testing.T) {
	run := newFixtureRun(t, "DeleteThing")
	proxyURL, err := url.Parse("http://fixture-user:fixture-password@" + run.server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: run.server.CA().CertPool(), ServerName: fixtureHost}}
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)
	call := func(operation string) *http.Response {
		t.Helper()
		body := []byte("Action=" + operation + "&Version=2011-06-15")
		req, err := http.NewRequest(http.MethodPost, "https://"+fixtureHost+"/", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = fixtureHost
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		now := time.Now().UTC()
		req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		req.Header.Set("X-Amz-Content-Sha256", hash)
		creds := aws.Credentials{AccessKeyID: run.fakeCred.AccessKeyID, SecretAccessKey: run.fakeCred.SecretAccessKey, SessionToken: run.fakeCred.SessionToken}
		if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, hash, "sts", "us-east-1", now); err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := call("GetCallerIdentity")
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("allowed fixture status=%d", response.StatusCode)
	}
	response = call("DeleteThing")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("denied fixture status=%d", response.StatusCode)
	}
	run.assertLedger(t, "GetCallerIdentity", 1)
	run.assertLedger(t, "DeleteThing", 0)
	run.assertAudit(t, "GetCallerIdentity", "allow")
	run.assertAudit(t, "DeleteThing", "deny")
}

func newFixtureRun(t *testing.T, denied ...string) *fixtureRun {
	t.Helper()
	upstreamCred := aws.Credentials{AccessKeyID: "UPSTREAMFIXTURE01", SecretAccessKey: "fixture-upstream-secret", SessionToken: "fixture-upstream-token"}
	refreshedCred := aws.Credentials{AccessKeyID: "UPSTREAMFIXTURE02", SecretAccessKey: "fixture-upstream-secret-2", SessionToken: "fixture-upstream-token-2"}
	fake := fakeaws.NewProtocolServer(fakeaws.ProtocolOptions{Host: fixtureHost, Service: "sts", Region: "us-east-1", Credentials: upstreamCred, CredentialGenerations: []aws.Credentials{upstreamCred, refreshedCred}})
	t.Cleanup(fake.Close)
	fakeCred := credentials.FakeCredential{AccessKeyID: "KORDNfixture-access", SecretAccessKey: "KORDNfixture-secret", SessionToken: "KORDNfixture-token", CreatedAt: time.Now().UTC()}
	verifier, err := sigv4.NewVerifier(fakeCred)
	if err != nil {
		t.Fatal(err)
	}
	provider := &rotatingProvider{credentials: []aws.Credentials{upstreamCred, refreshedCred}}
	resigner, err := sigv4.NewResigner(provider)
	if err != nil {
		t.Fatal(err)
	}
	dec := fixtureDecoder{}
	log := &eventLog{}
	deny := make(map[string]bool, len(denied))
	for _, operation := range denied {
		deny[operation] = true
	}
	server, err := proxy.NewServer(proxy.Config{
		ListenAddr: "127.0.0.1:0", Username: "fixture-user", Password: "fixture-password", RunID: "run-compatibility", PolicyHash: "sha256:" + strings.Repeat("0", 64),
		Classifier: fixtureClassifier{}, Resolver: proxy.ResolverFunc(func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}),
		// The loopback exception is limited to this local fixture harness. It
		// permits the opaque agent API test to use its httptest TLS endpoint;
		// production leaves TargetAllow unset and never admits arbitrary
		// loopback destinations.
		TargetAllow: func(host string, ip net.IP) bool {
			return ip.IsLoopback() && (host == fixtureHost || net.ParseIP(host) != nil)
		},
		InboundAuthenticator: verifier, Decoder: dec, Mapper: fixtureMapper{}, Policy: fixturePolicy{deny: deny}, Audit: log, Resigner: resigner, Upstream: fake.RoundTripper(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL := "http://fixture-user:fixture-password@" + server.Addr()
	env := []string{
		"AWS_ACCESS_KEY_ID=" + fakeCred.AccessKeyID, "AWS_SECRET_ACCESS_KEY=" + fakeCred.SecretAccessKey, "AWS_SESSION_TOKEN=" + fakeCred.SessionToken,
		"AWS_DEFAULT_REGION=us-east-1", "AWS_REGION=us-east-1", "AWS_CA_BUNDLE=" + server.CAPEMPath(),
		"HTTP_PROXY=" + proxyURL, "HTTPS_PROXY=" + proxyURL, "http_proxy=" + proxyURL, "https_proxy=" + proxyURL,
		"NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1", "AWS_EC2_METADATA_DISABLED=true",
	}
	return &fixtureRun{fake: fake, server: server, log: log, env: env, fakeCred: fakeCred}
}

type staticProvider struct{ credentials aws.Credentials }

func (p staticProvider) Retrieve(context.Context) (aws.Credentials, error) { return p.credentials, nil }

type rotatingProvider struct {
	credentials []aws.Credentials
	calls       atomic.Uint64
}

func (p *rotatingProvider) Retrieve(context.Context) (aws.Credentials, error) {
	n := p.calls.Add(1)
	return p.credentials[(n-1)%uint64(len(p.credentials))], nil
}

func (r *fixtureRun) command(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	limit := 15 * time.Second
	if os.Getenv("KORDN_BOTO_LONG_RUN") == "1" {
		// Leave enough time for the three-minute loop to finish its final
		// request, sleep, and emit the JSON summary before cancellation.
		limit = 4 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), r.env...)
	return cmd
}
func (r *fixtureRun) endpoint() string { return "https://" + fixtureHost }
func (r *fixtureRun) assertLedger(t *testing.T, operation string, want int) {
	t.Helper()
	got := r.ledgerCount(operation)
	if got != want {
		t.Fatalf("fakeAWS ledger operation %s=%d, want %d (ledger=%+v)", operation, got, want, r.fake.Ledger())
	}
}

func (r *fixtureRun) ledgerCount(operation string) int {
	got := 0
	for _, request := range r.fake.Ledger() {
		if request.Operation == operation {
			got++
		}
	}
	return got
}

func (r *fixtureRun) assertLedgerAtLeast(t *testing.T, operation string, want int) {
	t.Helper()
	if got := r.ledgerCount(operation); got < want {
		t.Fatalf("fakeAWS ledger operation %s=%d, want at least %d (ledger=%+v)", operation, got, want, r.fake.Ledger())
	}
}
func (r *fixtureRun) assertAudit(t *testing.T, operation string, result string) {
	t.Helper()
	for _, event := range r.log.snapshot() {
		if event.Request != nil && event.Request.Operation == operation {
			if event.Decision == nil || event.Decision.Result != result {
				t.Fatalf("audit %s decision=%+v", operation, event.Decision)
			}
			return
		}
	}
	t.Fatalf("no audit event for %s", operation)
}

func (r *fixtureRun) assertLastAudit(t *testing.T, operation string, result string) {
	t.Helper()
	events := r.log.snapshot()
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Request != nil && event.Request.Operation == operation {
			if event.Decision == nil || event.Decision.Result != result {
				t.Fatalf("latest audit %s decision=%+v", operation, event.Decision)
			}
			return
		}
	}
	t.Fatalf("no audit event for %s", operation)
}

func externalRequired(t *testing.T, binary string) string {
	t.Helper()
	if os.Getenv("KORDN_EXTERNAL_TESTS") != "1" {
		t.Skipf("external producer gate is opt-in; set KORDN_EXTERNAL_TESTS=1 (and KORDN_EXTERNAL_REQUIRED=1 in CI)")
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		if os.Getenv("KORDN_EXTERNAL_REQUIRED") == "1" {
			t.Fatalf("required external producer %q is not installed: %v", binary, err)
		}
		t.Skipf("external producer %q is not installed (set KORDN_EXTERNAL_REQUIRED=1 in the external job)", binary)
	}
	return path
}
func runOutput(t *testing.T, cmd *exec.Cmd) ([]byte, error) { t.Helper(); return cmd.CombinedOutput() }
func writeTemp(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Keep these imports and helper assertions tied to actual transport behavior;
// compatibility tests must not grow fake producer shims.
var _ = tls.VersionTLS12
var _ = http.MethodPost
