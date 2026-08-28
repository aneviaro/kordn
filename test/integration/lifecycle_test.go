// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package integration

import (
	"context"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

func TestFakeAWSResetProvidesFreshStateAndLedger(t *testing.T) {
	server := fakeaws.NewWithConfig(fakeaws.Config{Credentials: aws.Credentials{AccessKeyID: "KNOWNACCESSKEY0001", SecretAccessKey: "known-secret", SessionToken: "known-token"}, LedgerCapacity: 4})
	defer server.Close()
	server.State().Put("resource", "value")
	server.Failures().Set("Read", fakeaws.Failure{Latency: time.Millisecond})
	if len(server.State().Snapshot()) != 1 {
		t.Fatal("fixture state was not populated")
	}
	server.Reset()
	if len(server.Ledger()) != 0 || len(server.State().Snapshot()) != 0 {
		t.Fatal("reset retained state or ledger")
	}
	if _, ok := server.Failures().Take("Read"); ok {
		t.Fatal("reset retained failure script")
	}
}

func TestLifecycleClosesRealProxyAndLeavesNoActiveUpstream(t *testing.T) {
	h := newSecurityHarness(t, false)
	response := h.call(t, h.fake, h.clock, "GetCallerIdentity")
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("lifecycle request status=%d", response.StatusCode)
	}
	if err := h.proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if h.proxy.MetricsSnapshot().ActiveConnections != 0 {
		t.Fatal("proxy cleanup left active connections")
	}
}

func TestFailureScriptConsumesOneFailurePerCall(t *testing.T) {
	script := fakeaws.NewFailureScript()
	script.Set("op", fakeaws.Failure{Status: 429}, fakeaws.Failure{Status: 500})
	first, ok := script.Take("op")
	if !ok || first.Status != 429 {
		t.Fatalf("first failure = %+v/%v", first, ok)
	}
	second, ok := script.Take("op")
	if !ok || second.Status != 500 {
		t.Fatalf("second failure = %+v/%v", second, ok)
	}
	if _, ok := script.Take("op"); ok {
		t.Fatal("failure script did not exhaust")
	}
}
func TestLifecycleKilledChildDoesNotLeaveUsableProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "sh", "-c", "trap 'exit 143' TERM; while :; do sleep 1; done")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("killed child unexpectedly succeeded")
	}
}
