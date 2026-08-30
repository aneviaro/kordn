package app

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kordn-ai/kordn/internal/config"
	"github.com/kordn-ai/kordn/internal/credentials"
)

func TestVersionJSONIsDeterministicAndCarriesProvenance(t *testing.T) {
	first, err := json.Marshal(buildVersionInfo())
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(buildVersionInfo())
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("version metadata is not deterministic")
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"target", "go", "mapper", "iamlive", "authorization_data", "direct_dependencies"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("version JSON omitted %q", key)
		}
	}
}

func TestIdentityParserAcceptsBothOrdersAndRejectsAmbiguity(t *testing.T) {
	for _, args := range [][]string{
		{"--config", "policy.yaml", "--profile", "one"},
		{"--profile=one", "--config=policy.yaml"},
	} {
		path, profile, err := parseIdentityArgs(args)
		if err != nil || path != "policy.yaml" || profile != "one" {
			t.Fatalf("parse %v = %q, %q, %v", args, path, profile, err)
		}
	}
	for _, args := range [][]string{
		{"--config", "a", "--config", "b"}, {"--profile", "a", "--profile", "b"},
		{"--unknown", "value"}, {"--config"}, {"--profile", "--config", "a"}, {"--config=", "x"},
	} {
		if _, _, err := parseIdentityArgs(args); err == nil {
			t.Errorf("accepted invalid identity args %v", args)
		}
	}
}

func TestCLIParseRunArgsRequiresSeparatorAndPreservesChild(t *testing.T) {
	if _, err := ParseRunArgs([]string{"echo"}); err == nil {
		t.Fatal("accepted run without separator")
	}
	inv, err := ParseRunArgs([]string{"--quiet", "--config", "policy.yaml", "--", "echo", "--config", "value"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Argv) != 3 || inv.Argv[1] != "--config" {
		t.Fatalf("child argv not preserved: %#v", inv.Argv)
	}
}
func TestAtomicInitFailureLeavesNoPartialFinal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "config.yaml")
	if err := atomicPrivateConfig(path, []byte("incomplete")); err == nil {
		t.Fatal("atomic write unexpectedly succeeded in missing directory")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("failed init left a final file: %v", err)
	}
}

func TestCLIInitDoesNotOverwrite(t *testing.T) {
	home := t.TempDir()
	old, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	_ = old
	t.Setenv("HOME", home)
	if code := initCommand(nil); code != 0 {
		t.Fatalf("init=%d", code)
	}
	p := filepath.Join(home, ".kordn", "config.yaml")
	before, _ := os.ReadFile(p)
	if code := initCommand(nil); code == 0 {
		t.Fatal("second init overwrote config")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("config changed")
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestCLIInitConcurrentPublicationIsCompleteAndPrivate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	codes := make(chan int, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- initCommand(nil)
		}()
	}
	wg.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == 0 {
			successes++
		} else if code != 73 {
			t.Fatalf("concurrent init returned %d", code)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent init successes=%d, want 1", successes)
	}
	path := filepath.Join(home, ".kordn", "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatalf("published config is partial: %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("published config mode: %v (%v)", info, err)
	}
}

func TestIdentityProfileOverrideReachesInjectedPreflightWithoutSecretOutput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if code := initCommand(nil); code != 0 {
		t.Fatalf("init=%d", code)
	}
	var selected config.Upstream
	oldLoader := identityConfigLoader
	identityConfigLoader = func(string) (*config.Config, error) {
		return &config.Config{Upstream: config.Upstream{Profile: "configured", Region: "us-east-1"}}, nil
	}
	defer func() { identityConfigLoader = oldLoader }()
	oldLookup := identityLookup
	identityLookup = func(_ context.Context, upstream config.Upstream) (credentials.UpstreamIdentity, error) {
		selected = upstream
		return credentials.UpstreamIdentity{Profile: upstream.Profile, ARN: "arn:aws:iam::123456789012:role/public"}, nil
	}
	defer func() { identityLookup = oldLookup }()

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = write
	code := identityCommand([]string{"--profile", "override", "--config", filepath.Join(home, ".kordn", "config.yaml")})
	_ = write.Close()
	os.Stdout = oldStdout
	output, _ := io.ReadAll(read)
	_ = read.Close()
	if code != 0 {
		t.Fatalf("identity=%d", code)
	}
	if selected.Profile != "override" {
		t.Fatalf("profile override did not reach preflight: %q", selected.Profile)
	}
	want := "profile: override\nprincipal: arn:aws:iam::123456789012:role/public\n"
	if string(output) != want {
		t.Fatalf("unexpected identity output: %q", output)
	}
	if string(output) == "secret-token" {
		t.Fatal("identity output leaked secret material")
	}
}
