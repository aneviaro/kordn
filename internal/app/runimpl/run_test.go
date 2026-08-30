package runimpl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	runtimepkg "github.com/kordn-ai/kordn/internal/runtime"
)

func TestRunCancellationKillsShellGrandchildBeforeCleanup(t *testing.T) {
	pidPath := t.TempDir() + "/grandchild.pid"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanupChecked := false
	cleanup := func() error {
		cleanupChecked = true
		data, err := os.ReadFile(pidPath)
		if err != nil {
			return err
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return err
		}
		for i := 0; i < 20; i++ {
			err = syscall.Kill(pid, 0)
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			time.Sleep(10 * time.Millisecond)
		}
		return fmt.Errorf("shell grandchild %d survived process-group cancellation", pid)
	}
	spec := runtimepkg.ChildSpec{
		Argv: []string{"/bin/sh", "-c", "sleep 30 & echo $! > \"$KORDN_TEST_PID\"; wait"},
		Env:  append(os.Environ(), "KORDN_TEST_PID="+pidPath), Stdout: io.Discard, Stderr: io.Discard,
	}
	started := time.Now()
	for time.Since(started) < time.Second {
		if _, err := os.Stat(pidPath); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Start in a goroutine so cancellation occurs only after the direct child
	// has published its grandchild PID. The supervisor owns process-group kill.
	resultCh := make(chan struct {
		result runtimepkg.ChildResult
		err    error
	}, 1)
	go func() {
		result, err := runtimepkg.RunChild(ctx, spec, runtimepkg.SupervisorOptions{Hooks: runtimepkg.LifecycleHooks{Cleanup: cleanup}})
		resultCh <- struct {
			result runtimepkg.ChildResult
			err    error
		}{result, err}
	}()
	deadline := time.After(time.Second)
	for {
		if _, err := os.Stat(pidPath); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("child did not publish grandchild PID")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	select {
	case outcome := <-resultCh:
		if outcome.err == nil || !outcome.result.SafetyFailure || outcome.result.ExitCode != runtimepkg.ExitSafety {
			t.Fatalf("cancellation outcome=%+v err=%v", outcome.result, outcome.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not finish")
	}
	if !cleanupChecked {
		t.Fatal("cleanup hook was not called")
	}
}

func TestRunChildHealthyExitStillRunsCleanup(t *testing.T) {
	called := false
	result, err := runtimepkg.RunChild(context.Background(), runtimepkg.ChildSpec{Argv: []string{"/bin/sh", "-c", "exit 0"}, Stdout: io.Discard, Stderr: io.Discard}, runtimepkg.SupervisorOptions{Hooks: runtimepkg.LifecycleHooks{Cleanup: func() error { called = true; return nil }}})
	if err != nil || result.ExitCode != 0 || result.SafetyFailure {
		t.Fatalf("healthy outcome=%+v err=%v", result, err)
	}
	if !called {
		t.Fatal("healthy exit skipped cleanup")
	}
}
