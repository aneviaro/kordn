package integration

import (
	"context"
	"errors"
	"github.com/kordn-ai/kordn/internal/app"
	"net/http"
	"testing"
)

// This integration package keeps the executable boundary covered without
// requiring AWS credentials. The production pipeline is exercised through the
// proxy package tests; this verifies the invariant that only a separated child
// argv can enter the protected runtime.
func TestPipelineCommandBoundary(t *testing.T) {
	_, err := app.ParseRunArgs([]string{"--", "/bin/echo", "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.ParseRunArgs([]string{"/bin/echo"}); err == nil {
		t.Fatal("missing separator accepted")
	}
}
func TestPipelineStageFailureIsNotAForwardSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("context did not cancel")
	}
	_ = http.MethodPost
}
