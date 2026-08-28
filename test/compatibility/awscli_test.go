//go:build compat

// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package compatibility

import (
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

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
