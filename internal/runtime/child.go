// Copyright 2026 Kordn AI contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runtime

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	ExitStartup = 78
	ExitSafety  = 70
	ExitExec    = 126

	defaultDrainTimeout   = 2 * time.Second
	defaultCleanupTimeout = 2 * time.Second
	defaultKillGrace      = 500 * time.Millisecond
)

// ChildSpec is a direct argv invocation. Argv is never joined into a shell
// command and is copied before execution.
type ChildSpec struct {
	Argv   []string
	Env    []string
	Dir    string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// LifecycleHooks are composition seams for the proxy/audit pipeline. All
// prelaunch hooks run before exec.Cmd.Start. Safety reports a fatal
// post-launch Kordn error. Nil hooks are no-ops.
type LifecycleHooks struct {
	Prelaunch []func() error
	Start     func() error
	Safety    <-chan error
	Drain     func(context.Context) error
	Cleanup   func() error
}

// SupervisorOptions configures bounded shutdown behavior. CleanupTimeout is
// optional; when zero it uses DrainTimeout or the conservative default.
type SupervisorOptions struct {
	Hooks          LifecycleHooks
	DrainTimeout   time.Duration
	KillGrace      time.Duration
	CleanupTimeout time.Duration
}

// ChildResult preserves normal child status and records whether Kordn had to
// replace it with a lifecycle failure. Signal-terminated children use the
// conventional 128+signal exit value for os.Exit compatibility.
type ChildResult struct {
	ExitCode      int
	Signal        os.Signal
	Started       bool
	SafetyFailure bool
}

// RunChild starts and supervises a direct child process. Hook failures before
// Start return 78 and do not invoke exec.Cmd.Start. A fatal Safety event kills
// the complete POSIX process group and returns 70.
func RunChild(ctx context.Context, spec ChildSpec, options SupervisorOptions) (ChildResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(spec.Argv) == 0 || spec.Argv[0] == "" {
		return ChildResult{ExitCode: ExitStartup}, errors.New("child command is required")
	}
	if err := ctx.Err(); err != nil {
		cleanupBeforeLaunch(options.Hooks.Cleanup, options)
		return ChildResult{ExitCode: ExitStartup}, errors.New("protected startup was cancelled")
	}
	for _, hook := range options.Hooks.Prelaunch {
		if hook == nil {
			continue
		}
		if err := invokeHook(hook); err != nil {
			cleanupBeforeLaunch(options.Hooks.Cleanup, options)
			return ChildResult{ExitCode: ExitStartup}, errors.New("protected startup failed")
		}
	}
	if options.Hooks.Start != nil {
		if err := invokeHook(options.Hooks.Start); err != nil {
			cleanupBeforeLaunch(options.Hooks.Cleanup, options)
			return ChildResult{ExitCode: ExitStartup}, errors.New("protected runtime start failed")
		}
	}
	// A hook may take long enough for cancellation to arrive. Recheck before
	// exec so cancellation during setup still guarantees no child launch.
	if err := ctx.Err(); err != nil {
		cleanupBeforeLaunch(options.Hooks.Cleanup, options)
		return ChildResult{ExitCode: ExitStartup}, errors.New("protected startup was cancelled")
	}

	argv := append([]string(nil), spec.Argv...)
	command := exec.Command(argv[0], argv[1:]...)
	if spec.Env != nil {
		command.Env = append([]string(nil), spec.Env...)
	}
	if spec.Dir != "" {
		command.Dir = spec.Dir
	}
	command.Stdin = spec.Stdin
	command.Stdout = spec.Stdout
	command.Stderr = spec.Stderr
	if command.Stdin == nil {
		command.Stdin = os.Stdin
	}
	if command.Stdout == nil {
		command.Stdout = os.Stdout
	}
	if command.Stderr == nil {
		command.Stderr = os.Stderr
	}
	terminal := prepareTerminal(command.Stdin, command.Stdout, command.Stderr)
	configureProcessGroup(command)
	if terminal != nil {
		terminal.configure(command)
	}
	// Install forwarding before Start so a termination arriving in the small
	// exec window cannot terminate Kordn while leaving a child un-supervised.
	signals, stopSignals := newSignalForwarder()
	defer stopSignals()
	if err := command.Start(); err != nil {
		// Foreground handoff can fail in Start (for example if the terminal was
		// taken away between probing and exec). Restore before any cleanup output.
		terminal.restore()
		cleanupBeforeLaunch(options.Hooks.Cleanup, options)
		return ChildResult{ExitCode: ExitExec}, errors.New("child exec failed")
	}

	result := ChildResult{Started: true}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	safety := options.Hooks.Safety
	for {
		select {
		case err, ok := <-safety:
			if !ok || err == nil {
				// A closed channel means the safety monitor completed normally;
				// no future failure can be reported.
				safety = nil
				continue
			}
			terminateProcessGroup(command.Process.Pid)
			waitForChild(wait, command.Process.Pid, options.KillGrace)
			// Wait only accounts for the root child. Ensure descendants in the
			// dedicated group cannot survive a fatal Kordn safety failure.
			forceKillProcessGroup(command.Process.Pid)
			result.ExitCode = ExitSafety
			result.SafetyFailure = true
			return finishChild(result, terminal, options, errors.New("post-launch safety failure"))
		case sig, ok := <-signals:
			if !ok {
				signals = nil
				continue
			}
			if sig != nil {
				_ = forwardToProcessGroup(command.Process.Pid, sig)
			}
		case <-ctx.Done():
			terminateProcessGroup(command.Process.Pid)
			waitForChild(wait, command.Process.Pid, options.KillGrace)
			// Wait only accounts for the root child. Ensure descendants in the
			// dedicated group cannot survive cancellation.
			forceKillProcessGroup(command.Process.Pid)
			result.ExitCode = ExitSafety
			result.SafetyFailure = true
			return finishChild(result, terminal, options, errors.New("child context cancelled"))
		case err := <-wait:
			result = statusResult(result, err)
			return finishChild(result, terminal, options, nil)
		}
	}
}

func Execute(ctx context.Context, spec ChildSpec, options SupervisorOptions) int {
	result, _ := RunChild(ctx, spec, options)
	return result.ExitCode
}

func statusResult(result ChildResult, err error) ChildResult {
	if err == nil {
		result.ExitCode = 0
		return result
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ProcessState == nil {
		result.ExitCode = ExitSafety
		result.SafetyFailure = true
		return result
	}
	status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		result.ExitCode = ExitSafety
		result.SafetyFailure = true
		return result
	}
	if status.Exited() {
		result.ExitCode = status.ExitStatus()
		return result
	}
	if status.Signaled() {
		result.Signal = status.Signal()
		result.ExitCode = 128 + int(status.Signal())
		return result
	}
	result.ExitCode = ExitSafety
	result.SafetyFailure = true
	return result
}

func finishChild(result ChildResult, terminal *terminalState, options SupervisorOptions, cause error) (ChildResult, error) {
	// The child is gone before this function is called. Restore first so drain,
	// cleanup, and any caller summary output run with Kordn back in the
	// terminal's foreground process group.
	terminal.restore()

	drainTimeout := options.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = defaultDrainTimeout
	}
	if options.Hooks.Drain != nil {
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		drainResult := make(chan error, 1)
		go func() { drainResult <- invokeHook(func() error { return options.Hooks.Drain(ctx) }) }()
		var err error
		select {
		case err = <-drainResult:
		case <-ctx.Done():
			err = ctx.Err()
		}
		cancel()
		if err != nil && !result.SafetyFailure {
			result.ExitCode = ExitSafety
			result.SafetyFailure = true
			cause = errors.New("runtime drain failed")
		}
	}
	cleanupTimeout := options.CleanupTimeout
	if cleanupTimeout <= 0 {
		cleanupTimeout = drainTimeout
	}
	if options.Hooks.Cleanup != nil {
		if err := runBounded(options.Hooks.Cleanup, cleanupTimeout); err != nil && !result.SafetyFailure {
			result.ExitCode = ExitSafety
			result.SafetyFailure = true
			cause = errors.New("runtime cleanup failed")
		}
	}
	return result, cause
}

func cleanupBeforeLaunch(cleanup func() error, options SupervisorOptions) {
	if cleanup == nil {
		return
	}
	timeout := options.CleanupTimeout
	if timeout <= 0 {
		timeout = options.DrainTimeout
	}
	if timeout <= 0 {
		timeout = defaultCleanupTimeout
	}
	_ = runBounded(cleanup, timeout)
}

func invokeHook(fn func() error) (err error) {
	if fn == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = errors.New("runtime hook failed")
		}
	}()
	return fn()
}

func runBounded(fn func() error, timeout time.Duration) error {
	if fn == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = defaultCleanupTimeout
	}
	result := make(chan error, 1)
	go func() { result <- invokeHook(fn) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func waitForChild(wait <-chan error, pid int, grace time.Duration) {
	if grace <= 0 {
		grace = defaultKillGrace
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-wait:
		return
	case <-timer.C:
		forceKillProcessGroup(pid)
	}
	// The wait channel is buffered, so a late Wait cannot strand the child
	// goroutine. Keep this second wait bounded as well.
	timer.Reset(grace)
	select {
	case <-wait:
	case <-timer.C:
	}
}
