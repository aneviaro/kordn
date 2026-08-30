package runtime

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	sdkconfig "github.com/aws/aws-sdk-go-v2/config"
)

// TestRuntimeHelperProcess is a deterministic long-lived child fixture. It is
// selected only in a subprocess and emits hashes/labels, never credentials.
func TestRuntimeHelperProcess(t *testing.T) {
	if os.Getenv("KORDN_HELPER") != "1" {
		return
	}
	args := helperArguments()
	if len(args) == 0 {
		os.Exit(3)
	}
	switch args[0] {
	case "stable":
		runStableCredentialHelper()
	case "no-real":
		runNoRealCredentialHelper()
	case "argv":
		if _, err := fmt.Fprintln(os.Stdout, strings.Join(args[1:], "|")); err != nil {
			os.Exit(3)
		}
		os.Exit(17)
	case "signal":
		runSignalHelper()
	case "block":
		_, _ = fmt.Fprintln(os.Stdout, "started")
		select {}
	case "self-term":
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			os.Exit(3)
		}
		select {}
	case "tty":
		runTTYHelper()
	default:
		os.Exit(3)
	}
}

func helperArguments() []string {
	if mode := os.Getenv("KORDN_HELPER_MODE"); mode != "" {
		for i, arg := range os.Args {
			if arg == mode {
				return os.Args[i:]
			}
		}
		return []string{mode}
	}
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			return os.Args[i+1:]
		}
	}
	return nil
}

func helperEnv(mode string) []string {
	return []string{"KORDN_HELPER=1", "KORDN_HELPER_MODE=" + mode}
}

func runStableCredentialHelper() {
	// Use the standard SDK chain exactly as a long-lived child would. The
	// caller compares only access IDs; no secret is written to output.
	cfg, err := sdkconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		os.Exit(3)
	}
	first, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		os.Exit(3)
	}
	second, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		os.Exit(3)
	}
	_, _ = fmt.Fprintf(os.Stdout, "%s\n%s\n", first.AccessKeyID, second.AccessKeyID)
	os.Exit(0)
}

func runNoRealCredentialHelper() {
	const marker = "parent-only-placeholder"
	for _, value := range os.Environ() {
		if strings.Contains(value, marker) || strings.Contains(value, "parent-profile") {
			os.Exit(4)
		}
	}
	for _, key := range []string{"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN"} {
		if _, ok := os.LookupEnv(key); ok {
			os.Exit(4)
		}
	}
	for _, key := range []string{"AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"} {
		data, err := os.ReadFile(os.Getenv(key))
		if err != nil || bytes.Contains(data, []byte(marker)) || bytes.Contains(data, []byte("parent-profile")) {
			os.Exit(5)
		}
	}
	cfg, err := sdkconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		os.Exit(6)
	}
	value, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil || value.AccessKeyID != os.Getenv("AWS_ACCESS_KEY_ID") {
		os.Exit(7)
	}
	_, _ = fmt.Fprintln(os.Stdout, "safe")
	os.Exit(0)
}

func helperCommand(arguments ...string) []string {
	result := []string{os.Args[0], "-test.run=TestRuntimeHelperProcess", "--"}
	return append(result, arguments...)
}

func TestChild_StableFakeCredential(t *testing.T) {
	session, fake, files := testFiles(t)
	defer session.Cleanup()
	env, err := BuildChildEnvironment(EnvironmentInput{
		ParentEnv: os.Environ(),
		Fake:      fake,
		Files:     files,
		ProxyURL:  "http://kordn:proxy-placeholder@127.0.0.1:43123",
		RunID:     session.RunID,
	})
	if err != nil {
		t.Fatal(err)
	}
	env = append(env, helperEnv("stable")...)
	var output bytes.Buffer
	result, runErr := RunChild(context.Background(), ChildSpec{Argv: helperCommand("stable"), Env: env, Stdout: &output, Stderr: &output}, SupervisorOptions{})
	if runErr != nil || result.ExitCode != 0 {
		t.Fatalf("stable helper result = %+v, err=%v, output=%s", result, runErr, output.String())
	}
	lines := strings.Fields(output.String())
	if len(lines) != 2 || lines[0] != fake.AccessKeyID || lines[1] != fake.AccessKeyID {
		t.Fatalf("child did not retain one stable fake access ID: %q", output.String())
	}
}

func TestChild_NoRealCredential(t *testing.T) {
	session, fake, files := testFiles(t)
	defer session.Cleanup()
	parent := []string{
		"PATH=" + os.Getenv("PATH"),
		"AWS_ACCESS_KEY_ID=parent-only-placeholder",
		"AWS_SECRET_ACCESS_KEY=parent-only-placeholder",
		"AWS_SESSION_TOKEN=parent-only-placeholder",
		"AWS_PROFILE=parent-profile",
		"AWS_WEB_IDENTITY_TOKEN_FILE=/parent-only-placeholder",
		"AWS_ROLE_ARN=arn:aws:iam::123456789012:role/parent",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=http://parent-only-placeholder",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN=parent-only-placeholder",
	}
	env, err := BuildChildEnvironment(EnvironmentInput{ParentEnv: parent, Fake: fake, Files: files, ProxyURL: "http://kordn:proxy-placeholder@127.0.0.1:43123", RunID: session.RunID})
	if err != nil {
		t.Fatal(err)
	}
	env = append(env, helperEnv("no-real")...)
	var output bytes.Buffer
	result, runErr := RunChild(context.Background(), ChildSpec{Argv: helperCommand("no-real"), Env: env, Stdout: &output, Stderr: &output}, SupervisorOptions{})
	if runErr != nil || result.ExitCode != 0 {
		t.Fatalf("credential isolation result = %+v, err=%v, output=%s", result, runErr, output.String())
	}
	if strings.TrimSpace(output.String()) != "safe" {
		t.Fatalf("unexpected isolation helper output: %q", output.String())
	}
}

func TestChild_ArgvAndExitPropagation(t *testing.T) {
	var output bytes.Buffer
	result, runErr := RunChild(context.Background(), ChildSpec{
		Argv:   helperCommand("argv", "first value", "--literal", "$HOME"),
		Env:    helperEnv("argv"),
		Stdout: &output,
		Stderr: &output,
	}, SupervisorOptions{})
	if runErr != nil || result.ExitCode != 17 {
		t.Fatalf("argv result = %+v, err=%v, output=%s", result, runErr, output.String())
	}
	if strings.TrimSpace(output.String()) != "first value|--literal|$HOME" {
		t.Fatalf("argv was not passed directly: %q", output.String())
	}
	result, runErr = RunChild(context.Background(), ChildSpec{Argv: helperCommand("self-term"), Env: helperEnv("self-term")}, SupervisorOptions{})
	if runErr != nil || result.ExitCode != 128+int(syscall.SIGTERM) || result.Signal != syscall.SIGTERM {
		t.Fatalf("signal exit result = %+v, err=%v", result, runErr)
	}
}

func TestChild_SignalForwarding(t *testing.T) {
	reader, writer := io.Pipe()
	resultChannel := make(chan ChildResult, 1)
	errChannel := make(chan error, 1)
	go func() {
		result, err := RunChild(context.Background(), ChildSpec{Argv: helperCommand("signal"), Env: helperEnv("signal"), Stdout: writer, Stderr: writer}, SupervisorOptions{})
		resultChannel <- result
		errChannel <- err
	}()
	readLineWithDeadline(t, reader, "ready")
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	readLineWithDeadline(t, reader, "got")
	select {
	case result := <-resultChannel:
		if result.ExitCode != 0 || result.SafetyFailure {
			t.Fatalf("forwarded signal result = %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for forwarded signal child")
	}
	if err := <-errChannel; err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	_ = reader.Close()
}

func runTTYHelper() {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		os.Exit(3)
	}
	defer tty.Close()
	foreground, err := terminalForegroundPGID(int(tty.Fd()))
	if err != nil {
		os.Exit(3)
	}
	_, _ = fmt.Fprintf(os.Stdout, "TTY_CHILD_READY pid=%d pgid=%d foreground=%d\n", os.Getpid(), syscall.Getpgrp(), foreground)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT)
	defer signal.Stop(signals)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		os.Exit(3)
	}
	_, _ = fmt.Fprintf(os.Stdout, "TTY_CHILD_INPUT=%s", line)
	if <-signals != syscall.SIGINT {
		os.Exit(3)
	}
	_, _ = fmt.Fprintln(os.Stdout, "TTY_CHILD_SIGINT=handled")
}

func runSignalHelper() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	_, _ = fmt.Fprintln(os.Stdout, "ready")
	sig := <-signals
	if sig == syscall.SIGINT || sig == syscall.SIGTERM {
		_, _ = fmt.Fprintln(os.Stdout, "got")
		os.Exit(0)
	}
	os.Exit(3)
}

func TestTerminal_CustomStreamsUseIsolatedFallback(t *testing.T) {
	if terminal := prepareTerminal(strings.NewReader("input"), io.Discard, io.Discard); terminal != nil {
		terminal.restore()
		t.Fatal("custom streams unexpectedly enabled terminal handoff")
	}
	file, err := os.CreateTemp(t.TempDir(), "redirected-stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if terminal := prepareTerminal(file, file, file); terminal != nil {
		terminal.restore()
		t.Fatal("redirected streams unexpectedly enabled terminal handoff")
	}
}

func TestChild_TTYHarness(t *testing.T) {
	if os.Getenv("KORDN_PTY_HARNESS") == "1" {
		runTTYHarnessChild(t)
		return
	}

	master, slave := openTestPTY(t)
	command := exec.Command(os.Args[0], "-test.run=^TestChild_TTYHarness$")
	command.Env = append(os.Environ(), "KORDN_PTY_HARNESS=1")
	command.Stdin = slave
	command.Stdout = slave
	command.Stderr = slave
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		if command.Process != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	_ = slave.Close()
	output := bufio.NewReader(master)
	ready := readPTYLine(t, master, output, "TTY_CHILD_READY")
	var childPID, childPGID, childForeground int
	if _, err := fmt.Sscanf(ready, "TTY_CHILD_READY pid=%d pgid=%d foreground=%d", &childPID, &childPGID, &childForeground); err != nil {
		t.Fatalf("invalid PTY foreground report %q: %v", ready, err)
	}
	if childPID != childPGID || childPGID != childForeground {
		t.Fatalf("child did not own the PTY foreground: %q", ready)
	}
	if _, err := master.Write([]byte("input-from-pty\n")); err != nil {
		t.Fatal(err)
	}
	readPTYLine(t, master, output, "TTY_CHILD_INPUT=input-from-pty")
	if _, err := master.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	readPTYLine(t, master, output, "TTY_CHILD_SIGINT=handled")
	readPTYLine(t, master, output, "TTY_PARENT_RESTORED=")
	_ = master.Close()
	if err := command.Wait(); err != nil {
		t.Fatalf("PTY harness failed: %v", err)
	}
}

func runTTYHarnessChild(t *testing.T) {
	original, err := terminalForegroundPGID(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatalf("harness has no controlling PTY: %v", err)
	}
	var restored int
	result, runErr := RunChild(context.Background(), ChildSpec{Argv: helperCommand("tty"), Env: helperEnv("tty")}, SupervisorOptions{Hooks: LifecycleHooks{
		Drain: func(context.Context) error {
			var err error
			restored, err = terminalForegroundPGID(int(os.Stdin.Fd()))
			if err == nil {
				_, _ = fmt.Fprintf(os.Stdout, "TTY_PARENT_RESTORED=%d\n", restored)
			}
			return err
		},
	}})
	if runErr != nil || result.ExitCode != 0 || restored != original {
		t.Fatalf("PTY child result=%+v err=%v restored=%d original=%d", result, runErr, restored, original)
	}
}

func readPTYLine(t *testing.T, master *os.File, reader *bufio.Reader, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_ = master.SetReadDeadline(deadline)
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading PTY output for %q: %v", want, err)
		}
		if strings.Contains(line, want) {
			return line
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for PTY output %q (last line %q)", want, line)
		}
	}
}

func TestChild_PrelaunchFailureDoesNotSpawnAndExecFailureIs126(t *testing.T) {
	called := false
	result, err := RunChild(context.Background(), ChildSpec{Argv: helperCommand("argv", "must-not-run")}, SupervisorOptions{Hooks: LifecycleHooks{Prelaunch: []func() error{func() error {
		called = true
		return fmt.Errorf("synthetic startup failure")
	}}}})
	if err == nil || result.Started || result.ExitCode != ExitStartup || !called {
		t.Fatalf("prelaunch failure result = %+v, err=%v", result, err)
	}
	result, err = RunChild(context.Background(), ChildSpec{Argv: []string{"/definitely/not/a/kordn-child"}}, SupervisorOptions{})
	if err == nil || result.Started || result.ExitCode != ExitExec {
		t.Fatalf("exec failure result = %+v, err=%v", result, err)
	}
}

func TestChild_PostlaunchSafetyKillsGroupAndCleanupIsBounded(t *testing.T) {
	reader, writer := io.Pipe()
	safety := make(chan error, 1)
	resultChannel := make(chan ChildResult, 1)
	errChannel := make(chan error, 1)
	go func() {
		result, err := RunChild(context.Background(), ChildSpec{Argv: helperCommand("block"), Env: helperEnv("block"), Stdout: writer, Stderr: writer}, SupervisorOptions{KillGrace: 100 * time.Millisecond, Hooks: LifecycleHooks{Safety: safety}})
		resultChannel <- result
		errChannel <- err
	}()
	readLineWithDeadline(t, reader, "started")
	safety <- fmt.Errorf("proxy safety failure")
	select {
	case result := <-resultChannel:
		if result.ExitCode != ExitSafety || !result.SafetyFailure {
			t.Fatalf("safety result = %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for safety shutdown")
	}
	if err := <-errChannel; err == nil {
		t.Fatal("safety failure did not return an error")
	}
	_ = writer.Close()
	_ = reader.Close()

	release := make(chan struct{})
	started := time.Now()
	result, err := RunChild(context.Background(), ChildSpec{Argv: []string{"/usr/bin/true"}}, SupervisorOptions{DrainTimeout: 20 * time.Millisecond, Hooks: LifecycleHooks{Drain: func(context.Context) error {
		<-release
		return nil
	}}})
	close(release)
	if err == nil || result.ExitCode != ExitSafety || time.Since(started) > time.Second {
		t.Fatalf("bounded drain result = %+v, err=%v", result, err)
	}
}

func TestChild_ContextCancellationIsStartupFailureBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := RunChild(ctx, ChildSpec{Argv: helperCommand("block")}, SupervisorOptions{})
	if err == nil || result.ExitCode != ExitStartup || result.Started {
		t.Fatalf("cancelled startup result = %+v, err=%v", result, err)
	}
}

func readLineWithDeadline(t *testing.T, reader *io.PipeReader, want string) {
	t.Helper()
	lineChannel := make(chan string, 1)
	errChannel := make(chan error, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(reader, int64(len(want)+1)))
		if err != nil {
			errChannel <- err
			return
		}
		lineChannel <- strings.TrimSpace(string(data))
	}()
	select {
	case line := <-lineChannel:
		if line != want {
			t.Fatalf("child synchronization line = %q, want %q", line, want)
		}
	case err := <-errChannel:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for child line %q", want)
	}
}
