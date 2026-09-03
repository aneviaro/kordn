//go:build compat

package compatibility

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/kordn-ai/kordn/internal/audit"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/cache"
	"github.com/kordn-ai/kordn/internal/config"
	"github.com/kordn-ai/kordn/internal/credentials"
	"github.com/kordn-ai/kordn/internal/iammap"
	"github.com/kordn-ai/kordn/internal/policy"
	"github.com/kordn-ai/kordn/internal/proxy"
	"github.com/kordn-ai/kordn/internal/sigv4"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

func TestAWSCLIListUsers(t *testing.T) {
	awsCLI := requirePinnedExecutable(t, "awscli")
	const host = "iam.amazonaws.com"
	endpoint := "https://" + host

	allowPolicy := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{{
		ID:                       "allow-list-users",
		Effect:                   config.EffectAllow,
		Actions:                  []string{"iam:ListUsers"},
		Resources:                []string{"*"},
		AllowAWSRequiredWildcard: true,
	}}}
	allowed := newCatalogCLIRun(t, host, "iam", allowPolicy)
	output, err := runOutput(t, allowed.command(t, awsCLI, "iam", "list-users", "--endpoint-url", endpoint, "--output", "json"))
	if err != nil {
		t.Fatalf("aws iam list-users allow failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "Users") {
		t.Fatalf("aws iam list-users output = %q, want Users response", output)
	}
	allowed.assertLedger(t, "ListUsers", 1)
	allowed.assertAudit(t, "ListUsers", "allow")

	denyPolicy := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{{
		ID:        "deny-list-users",
		Effect:    config.EffectDeny,
		Actions:   []string{"iam:ListUsers"},
		Resources: []string{"*"},
	}}}
	denied := newCatalogCLIRun(t, host, "iam", denyPolicy)
	output, err = runOutput(t, denied.command(t, awsCLI, "iam", "list-users", "--endpoint-url", endpoint, "--output", "json"))
	if err == nil || !strings.Contains(string(output), "AccessDenied") {
		t.Fatalf("aws iam list-users denial error = %v, output = %q, want parseable AccessDenied", err, output)
	}
	if strings.Contains(strings.ToLower(string(output)), "invalid xml") {
		t.Fatalf("aws iam list-users denial output = %q, must not report invalid XML", output)
	}
	denied.assertLedger(t, "ListUsers", 0)
	decision := catalogCLIDecision(t, denied, "ListUsers")
	if decision.Decision == nil || decision.Decision.Result != "deny" || decision.Decision.ReasonCode != "explicit_deny" {
		t.Fatalf("aws iam list-users audit decision = %+v, want explicit deny", decision.Decision)
	}
	if !strings.Contains(string(output), decision.EventID) {
		t.Fatalf("aws iam list-users denial output = %q, want correlated event ID %q", output, decision.EventID)
	}
}

func TestAWSCLIGeneratedOperation(t *testing.T) {
	awsCLI := requirePinnedExecutable(t, "awscli")
	const host = "dynamodb.us-east-1.amazonaws.com"
	selected := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{{
		ID:        "allow-get-item",
		Effect:    config.EffectAllow,
		Actions:   []string{"dynamodb:GetItem"},
		Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/fixture"},
	}}}
	run := newCatalogCLIRun(t, host, "dynamodb", selected)
	output, err := runOutput(t, run.command(
		t,
		awsCLI,
		"dynamodb",
		"get-item",
		"--table-name",
		"fixture",
		"--key",
		`{"id":{"S":"A"}}`,
		"--endpoint-url",
		"https://"+host,
		"--output",
		"json",
	))
	if err != nil {
		t.Fatalf("aws dynamodb get-item failed: %v\n%s", err, output)
	}
	run.assertLedger(t, "GetItem", 1)
	run.assertAudit(t, "GetItem", "allow")
}

func newCatalogCLIRun(t *testing.T, host, service string, selected config.Policy) *fixtureRun {
	t.Helper()
	clock := time.Now().UTC()
	inbound := credentials.FakeCredential{
		AccessKeyID:     "KORDNcatalog-cli-access",
		SecretAccessKey: "KORDNcatalog-cli-secret",
		SessionToken:    "KORDNcatalog-cli-token",
		CreatedAt:       clock,
	}
	upstreamCredentials := aws.Credentials{
		AccessKeyID:     "CATALOGCLIUPSTREAM1",
		SecretAccessKey: "catalog-cli-upstream-secret",
		SessionToken:    "catalog-cli-upstream-token",
	}
	fake := fakeaws.NewProtocolServer(fakeaws.ProtocolOptions{
		Host:        host,
		Service:     service,
		Region:      "us-east-1",
		Credentials: upstreamCredentials,
		Clock:       func() time.Time { return clock },
	})
	t.Cleanup(fake.Close)
	verifier, err := sigv4.NewVerifier(inbound, sigv4.WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := awsrequest.NewConfiguredDecoder(awsrequest.DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		t.Fatal(err)
	}
	mapper, err := iammap.NewMapper()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewEngine(selected)
	if err != nil {
		t.Fatal(err)
	}
	resigner, err := sigv4.NewResigner(staticProvider{credentials: upstreamCredentials}, sigv4.WithResignClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	caches, err := cache.NewRunCaches(cache.CacheOptions{})
	if err != nil {
		t.Fatal(err)
	}
	log := &eventLog{}
	server, err := proxy.NewServer(proxy.Config{
		ListenAddr:           "127.0.0.1:0",
		Username:             "catalog-cli-user",
		Password:             "catalog-cli-password",
		RunID:                "run-catalog-cli",
		PolicyHash:           engine.PolicyHash(),
		InboundAuthenticator: verifier,
		Decoder:              decoder,
		Mapper:               mapper,
		Policy:               engine,
		Audit:                log,
		Resigner:             resigner,
		Upstream:             fake.RoundTripper(),
		Caches:               caches,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL := "http://catalog-cli-user:catalog-cli-password@" + server.Addr()
	env := []string{
		"AWS_ACCESS_KEY_ID=" + inbound.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + inbound.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + inbound.SessionToken,
		"AWS_DEFAULT_REGION=us-east-1",
		"AWS_REGION=us-east-1",
		"AWS_CA_BUNDLE=" + server.CAPEMPath(),
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
		"AWS_EC2_METADATA_DISABLED=true",
	}
	return &fixtureRun{fake: fake, server: server, log: log, env: env, fakeCred: inbound}
}

func catalogCLIDecision(t *testing.T, run *fixtureRun, operation string) audit.Event {
	t.Helper()
	var matches []audit.Event
	for _, event := range run.log.snapshot() {
		if event.EventType == audit.RequestDecision && event.Request != nil && event.Request.Operation == operation {
			matches = append(matches, event)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("catalog CLI audit decisions for %q = %d, want 1: %+v", operation, len(matches), run.log.snapshot())
	}
	return matches[0]
}

func TestAWSCLIActualSubprocessScenarios(t *testing.T) {
	aws := requirePinnedExecutable(t, "awscli")
	// Keep the successful mutation on an allow-only fixture. A separate
	// immutable deny fixture below proves that a denied mutation is not treated
	// as a successful producer request.
	run := newFixtureRun(t)
	endpoint := run.endpoint()

	read := run.command(t, aws, "sts", "get-caller-identity", "--endpoint-url", endpoint, "--output", "json")
	t.Logf("running AWS CLI read through %s", endpoint)
	output, err := runOutput(t, read)
	if err != nil {
		t.Fatalf("AWS CLI read failed: %v\n%s ledger=%+v metrics=%+v", err, output, run.fake.Ledger(), run.server.MetricsSnapshot())
	}
	if !strings.Contains(string(output), "123456789012") {
		t.Fatalf("read did not return fakeAWS identity: %s", output)
	}
	run.assertLedger(t, "GetCallerIdentity", 1)
	run.assertAudit(t, "GetCallerIdentity", "allow")

	mutation := run.command(t, aws, "sts", "get-session-token", "--duration-seconds", "900", "--endpoint-url", endpoint, "--output", "json")
	output, err = runOutput(t, mutation)
	if err != nil {
		t.Fatalf("AWS CLI mutation failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "fixture-access") {
		t.Fatalf("mutation response was not preserved: %s", output)
	}
	run.assertLedger(t, "GetSessionToken", 1)
	run.assertAudit(t, "GetSessionToken", "allow")

	deniedRun := newFixtureRun(t, "GetSessionToken")
	deniedEndpoint := deniedRun.endpoint()
	deniedMutation := deniedRun.command(t, aws, "sts", "get-session-token", "--duration-seconds", "900", "--endpoint-url", deniedEndpoint, "--output", "json")
	deniedOutput, deniedErr := runOutput(t, deniedMutation)
	if deniedErr == nil || !strings.Contains(string(deniedOutput), "AccessDenied") {
		t.Fatalf("denied AWS CLI mutation was not a recognizable local denial: err=%v output=%s", deniedErr, deniedOutput)
	}
	deniedRun.assertLedger(t, "GetSessionToken", 0)
	deniedRun.assertAudit(t, "GetSessionToken", "deny")

	run.fake.SetFailure("GetCallerIdentity", fakeFailure())
	// The normal AWS CLI error summary omits response metadata. Debug output
	// includes the upstream request ID header so preservation can be asserted.
	upstreamError := run.command(t, aws, "sts", "get-caller-identity", "--endpoint-url", endpoint, "--output", "json", "--debug")
	output, err = runOutput(t, upstreamError)
	if err == nil {
		t.Fatal("AWS CLI accepted injected upstream error")
	}
	text := string(output)
	for _, marker := range []string{"FixtureThrottled", "upstream-request-42"} {
		if !strings.Contains(text, marker) {
			t.Fatalf("upstream error lost %q: %s", marker, text)
		}
	}
	run.assertLedger(t, "GetCallerIdentity", 2)
	run.assertAudit(t, "GetCallerIdentity", "allow")

	run.fake.SetFailure("GetCallerIdentity", fakeawsFailureUnknown())
	unknown := run.command(t, aws, "sts", "get-caller-identity", "--endpoint-url", endpoint)
	output, err = runOutput(t, unknown)
	if err == nil || !strings.Contains(string(output), "UnknownOperationException") {
		t.Fatalf("unknown operation response not surfaced: err=%v output=%s", err, output)
	}
}

// Kept as functions so the scenario remains local and deterministic while the
// producer remains the pinned AWS CLI binary, not a replacement executable.
func fakeFailure() fakeaws.Failure {
	// Use a non-retryable status so this scenario tests error preservation
	// rather than the producer's retry policy.
	return fakeaws.Failure{Status: 400, Code: "FixtureThrottled", RequestID: "upstream-request-42", Body: []byte(`<ErrorResponse><Error><Code>FixtureThrottled</Code><Message>retry fixture</Message></Error><RequestId>upstream-request-42</RequestId></ErrorResponse>`)}
}
func fakeawsFailureUnknown() fakeaws.Failure {
	return fakeaws.Failure{Status: 400, Code: "UnknownOperationException", RequestID: "unknown-operation-42", Body: []byte(`<ErrorResponse><Error><Code>UnknownOperationException</Code><Message>unknown operation</Message></Error><RequestId>unknown-operation-42</RequestId></ErrorResponse>`)}
}
