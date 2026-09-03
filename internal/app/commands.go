// Package app contains the command surface and the sole runtime composition
// root. Parsing the child boundary here prevents a second shell-based path.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kordn-ai/kordn/internal/audit"
	"github.com/kordn-ai/kordn/internal/config"
	"github.com/kordn-ai/kordn/internal/credentials"
	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
	"github.com/kordn-ai/kordn/internal/iammap"
	"github.com/kordn-ai/kordn/internal/iammap/data"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
)

const usage = `Usage:
  kordn version
  kordn init
  kordn policy validate [--config PATH]
  kordn identity [--profile NAME]
  kordn audit [--run RUN_ID] [--json]
  kordn run [flags] -- <command> [args...]
`

// Main executes the bootstrap command tree. Until the authenticated proxy and
// CA pipeline exists, run intentionally fails closed rather than launching a
// child with only partial protection.
func Main(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		return 2
	}

	switch args[0] {
	case "help", "--help", "-h":
		_, _ = fmt.Fprint(os.Stdout, usage)
		return 0
	case "version", "--version":
		return versionCommand(args[1:])
	case "run":
		return runCommand(args[1:])
	case "init":
		return initCommand(args[1:])
	case "identity":
		return identityCommand(args[1:])
	case "audit":
		return auditCommand(args[1:])
	case "policy":
		if len(args) > 1 && args[1] == "validate" {
			return validatePolicyCommand(args[2:])
		}
	}

	_, _ = fmt.Fprintf(os.Stderr, "kordn: unknown command\n\n%s", usage)
	return 2
}

// RunInvocation is the parsed, direct child argv boundary. The runtime must
// consume Argv as-is; it must never turn it into a shell command.
type RunInvocation struct {
	ConfigPath string
	AuditPath  string
	Listen     string
	Quiet      bool
	Verbose    bool
	Argv       []string
}

// ParseRunArgs parses only Kordn flags before the mandatory --. Everything
// after that marker belongs to the child, including values that look like
// flags. Profile and role overrides are deliberately not accepted here: the
// immutable configuration owns the upstream authority ceiling.
func ParseRunArgs(args []string) (RunInvocation, error) {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return RunInvocation{}, fmt.Errorf("the '--' separator and a child command are required")
	}
	if separator == len(args)-1 || args[separator+1] == "" {
		return RunInvocation{}, fmt.Errorf("a child command is required after '--'")
	}
	var invocation RunInvocation
	for i := 0; i < separator; i++ {
		arg := args[i]
		switch {
		case arg == "--quiet":
			invocation.Quiet = true
		case arg == "--verbose":
			invocation.Verbose = true
		case arg == "--config":
			if i+1 >= separator || args[i+1] == "" {
				return RunInvocation{}, fmt.Errorf("--config requires a path")
			}
			invocation.ConfigPath = args[i+1]
			i++
		case len(arg) > len("--config=") && arg[:len("--config=")] == "--config=":
			invocation.ConfigPath = arg[len("--config="):]
			if invocation.ConfigPath == "" {
				return RunInvocation{}, fmt.Errorf("--config requires a path")
			}
		case arg == "--audit-path" || arg == "--listen":
			if i+1 >= separator || args[i+1] == "" {
				return RunInvocation{}, fmt.Errorf("%s requires a value", arg)
			}
			if arg == "--audit-path" {
				invocation.AuditPath = args[i+1]
			} else {
				invocation.Listen = args[i+1]
			}
			i++
		case strings.HasPrefix(arg, "--audit-path="):
			invocation.AuditPath = strings.TrimPrefix(arg, "--audit-path=")
			if invocation.AuditPath == "" {
				return RunInvocation{}, fmt.Errorf("--audit-path requires a value")
			}
		case strings.HasPrefix(arg, "--listen="):
			invocation.Listen = strings.TrimPrefix(arg, "--listen=")
			if invocation.Listen == "" {
				return RunInvocation{}, fmt.Errorf("--listen requires a value")
			}
		default:
			// Do not echo arbitrary flag text: callers may accidentally place
			// credential-like material in a malformed option.
			return RunInvocation{}, fmt.Errorf("unsupported run flag")
		}
	}
	invocation.Argv = append([]string(nil), args[separator+1:]...)
	return invocation, nil
}

func runCommand(args []string) int {
	inv, err := ParseRunArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kordn run: %v\n", err)
		return 2
	}
	return Run(context.Background(), inv)
}

func homePath(parts ...string) string {
	h, e := os.UserHomeDir()
	if e != nil {
		return ""
	}
	return filepath.Join(append([]string{h, ".kordn"}, parts...)...)
}
func initCommand(args []string) int {
	if len(args) > 0 {
		return 2
	}
	root := homePath()
	if root == "" {
		return 78
	}
	if info, err := os.Lstat(root); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return 78
		}
	} else if !os.IsNotExist(err) {
		return 78
	}
	if err := os.MkdirAll(filepath.Join(root, "audit"), 0700); err != nil {
		return 78
	}
	if err := os.Chmod(root, 0700); err != nil {
		return 78
	}
	p := filepath.Join(root, "config.yaml")
	doc := fmt.Sprintf(`apiVersion: kordn.dev/v1alpha1
kind: LocalRunPolicy
upstream:
  profile: kordn-prod-ceiling
  roleSessionName: kordn-local
  durationSeconds: 3600
  region: us-east-1
proxy:
  listen: 127.0.0.1:0
  nonAwsTraffic: tunnel
  upstreamProxy: inherit
  maxInMemoryBodyBytes: 8388608
  maxSpoolBodyBytes: 67108864
policy:
  default: deny
  rules: []
audit:
  path: %s
  fsync: batch
  failureMode: deny
  logResourceArns: false
  hashResourceNames: true
`, filepath.Join(root, "audit", "events.jsonl"))
	if err := atomicPrivateConfig(p, []byte(doc)); err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintln(os.Stderr, "kordn init: config already exists")
			return 73
		}
		return 78
	}
	fmt.Println(p)
	return 0
}

// atomicPrivateConfig writes and validates the complete private document
// before publishing it. Link is atomic and, unlike rename, never replaces a
// file created by a concurrent initializer.
func atomicPrivateConfig(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config.yaml.tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Link(tmpName, path); err != nil {
		return err
	}
	// The link is the publication point. Persist the directory entry before
	// reporting success; failure is still safe because the final file is
	// complete and mode-checked.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func configArg(args []string) string {
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--config=") {
			return strings.TrimPrefix(a, "--config=")
		}
	}
	return homePath("config.yaml")
}
func validatePolicyCommand(args []string) int {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--config" {
			if i+1 >= len(args) || args[i+1] == "" {
				fmt.Fprintln(os.Stderr, "kordn policy validate: --config requires a path")
				return 2
			}
			i++
		} else if strings.HasPrefix(arg, "--config=") {
			if strings.TrimPrefix(arg, "--config=") == "" {
				return 2
			}
		} else {
			fmt.Fprintln(os.Stderr, "kordn policy validate: unsupported flag")
			return 2
		}
	}
	cfg, err := config.Load(configArg(args))
	if err != nil {
		fmt.Fprintf(os.Stderr, "kordn policy validate: invalid configuration %v\n", err)
		return 2
	}
	fmt.Printf("valid policy %s\n", cfg.PolicyHash)
	return 0
}

// identityLookup is the protected identity-preflight seam. Production uses
// credentials.NewProvider; keeping the seam here lets command tests inject a
// non-network preflight without weakening the command's output contract.
var identityLookup = func(ctx context.Context, upstream config.Upstream) (credentials.UpstreamIdentity, error) {
	provider, err := credentials.NewProvider(ctx, upstream)
	if err != nil {
		return credentials.UpstreamIdentity{}, err
	}
	return provider.Identity(), nil
}

var identityConfigLoader = config.Load

func identityCommand(args []string) int {
	path, profile, err := parseIdentityArgs(args)
	if err != nil {
		return 2
	}
	cfg, err := identityConfigLoader(path)
	if err != nil {
		return 78
	}
	// Keep the loaded snapshot immutable. The profile flag is an explicit
	// diagnostic selection only; role, region, and every other ceiling remain
	// exactly those from the configuration.
	selected := cloneConfig(cfg)
	if profile != "" {
		selected.Upstream.Profile = profile
	}
	x, err := identityLookup(context.Background(), selected.Upstream)
	if err != nil {
		return 78
	}
	// Identity output is intentionally limited to non-secret values.
	fmt.Printf("profile: %s\nprincipal: %s\n", x.Profile, x.ARN)
	return 0
}

func parseIdentityArgs(args []string) (path, profile string, err error) {
	path = homePath("config.yaml")
	seenConfig, seenProfile := false, false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := "", "", false
		switch {
		case arg == "--config", arg == "--profile":
			name = strings.TrimPrefix(arg, "--")
			if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "--") {
				return "", "", fmt.Errorf("%s requires a value", arg)
			}
			value, hasValue = args[i+1], true
			i++
		case strings.HasPrefix(arg, "--config="):
			name, value, hasValue = "config", strings.TrimPrefix(arg, "--config="), true
		case strings.HasPrefix(arg, "--profile="):
			name, value, hasValue = "profile", strings.TrimPrefix(arg, "--profile="), true
		default:
			return "", "", fmt.Errorf("unsupported identity flag")
		}
		if !hasValue || value == "" {
			return "", "", fmt.Errorf("--%s requires a value", name)
		}
		switch name {
		case "config":
			if seenConfig {
				return "", "", fmt.Errorf("duplicate --config")
			}
			seenConfig = true
			path = value
		case "profile":
			if seenProfile {
				return "", "", fmt.Errorf("duplicate --profile")
			}
			seenProfile = true
			profile = value
		}
	}
	return path, profile, nil
}

func cloneConfig(in *config.Config) *config.Config {
	if in == nil {
		return nil
	}
	out := *in
	out.Policy.Rules = append([]config.Rule(nil), in.Policy.Rules...)
	for i := range out.Policy.Rules {
		out.Policy.Rules[i].Actions = append([]string(nil), in.Policy.Rules[i].Actions...)
		out.Policy.Rules[i].Resources = append([]string(nil), in.Policy.Rules[i].Resources...)
		out.Policy.Rules[i].Regions = append([]string(nil), in.Policy.Rules[i].Regions...)
		out.Policy.Rules[i].Accounts = append([]string(nil), in.Policy.Rules[i].Accounts...)
		out.Policy.Rules[i].Partitions = append([]string(nil), in.Policy.Rules[i].Partitions...)
	}
	return &out
}
func auditCommand(args []string) int {
	path := homePath("audit", "events.jsonl")
	run := ""
	jsonOut := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--run", "--path":
			if i+1 >= len(args) || args[i+1] == "" {
				return 2
			}
			if args[i] == "--run" {
				run = args[i+1]
			} else {
				path = args[i+1]
			}
			i++
		case "--json":
			jsonOut = true
		case "--run=", "--path=":
			return 2
		default:
			if strings.HasPrefix(args[i], "--run=") {
				run = strings.TrimPrefix(args[i], "--run=")
			} else if strings.HasPrefix(args[i], "--path=") {
				path = strings.TrimPrefix(args[i], "--path=")
			} else {
				return 2
			}
		}
	}
	events, err := audit.Query(path, run)
	if err != nil {
		return 78
	}
	s := audit.Summarize(events)
	if jsonOut {
		b, _ := json.Marshal(s)
		fmt.Println(string(b))
	} else {
		fmt.Printf("audit events: %d allowed: %d denied: %d\n", s.Total, s.Allowed, s.Denied)
	}
	return 0
}

type versionDependency struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum,omitempty"`
}

type versionInfo struct {
	Binary             string              `json:"binary"`
	Version            string              `json:"version"`
	Commit             string              `json:"commit,omitempty"`
	Target             string              `json:"target"`
	Go                 string              `json:"go"`
	Config             string              `json:"config"`
	Audit              string              `json:"audit"`
	Mapper             string              `json:"mapper"`
	IamLive            string              `json:"iamlive"`
	AuthorizationData  string              `json:"authorization_data"`
	UpstreamCommit     string              `json:"upstream_commit"`
	SelectedContentSHA string              `json:"selected_content_sha256"`
	CatalogSchema      string              `json:"catalog_schema"`
	CatalogVersion     string              `json:"catalog_version"`
	MapperVersion      string              `json:"mapper_version"`
	AdapterVersion     string              `json:"adapter_version"`
	DirectDependencies []versionDependency `json:"direct_dependencies"`
}

func buildVersionInfo() versionInfo {
	info := versionInfo{
		Binary: "kordn", Version: "0.1.0", Target: runtime.GOOS + "/" + runtime.GOARCH,
		Go: runtime.Version(), Config: "kordn.dev/v1alpha1", Audit: audit.SchemaVersion,
		Mapper: iammap.MapperVersion, IamLive: iamliveadapter.AdapterVersion,
		AuthorizationData: data.AuthorizationDataVersion(), UpstreamCommit: iamlivecatalog.UpstreamCommit,
		CatalogSchema: iamlivecatalog.CatalogSchemaVersion, MapperVersion: iammap.MapperVersion,
		AdapterVersion: iamliveadapter.AdapterVersion, DirectDependencies: directDependencies(),
		CatalogVersion: iamlivecatalog.Version(),
	}
	if catalog, err := iamlivecatalog.Load(); err == nil {
		info.SelectedContentSHA = catalog.SourceHash()
		info.CatalogVersion = catalog.Version()
	}
	if build, ok := debug.ReadBuildInfo(); ok {
		if build.Main.Version != "" && build.Main.Version != "(devel)" {
			info.Version = build.Main.Version
		}
		for _, setting := range build.Settings {
			if setting.Key == "vcs.revision" {
				info.Commit = setting.Value
			}
		}
	}
	return info
}

// directDependencies is intentionally a checked-in projection of go.mod's
// direct require block. BuildInfo does not expose Go's direct/indirect marker,
// and recording this explicit list keeps version --json deterministic.
func directDependencies() []versionDependency {
	return []versionDependency{
		{Path: "github.com/aws/aws-sdk-go-v2", Version: "v1.37.2"},
		{Path: "github.com/aws/aws-sdk-go-v2/config", Version: "v1.29.3"},
		{Path: "github.com/aws/aws-sdk-go-v2/credentials", Version: "v1.17.56"},
		{Path: "github.com/aws/aws-sdk-go-v2/service/sts", Version: "v1.36.0"},
		{Path: "github.com/santhosh-tekuri/jsonschema/v6", Version: "v6.0.3"},
		{Path: "go.yaml.in/yaml/v3", Version: "v3.0.4"},
		{Path: "golang.org/x/net", Version: "v0.21.0"},
	}
}

func versionCommand(args []string) int {
	jsonOut := false
	for _, a := range args {
		if a == "--json" {
			jsonOut = true
		} else {
			return 2
		}
	}
	info := buildVersionInfo()
	if jsonOut {
		b, err := json.Marshal(info)
		if err != nil {
			return 70
		}
		fmt.Println(string(b))
	} else {
		fmt.Printf("%s %s (%s)\n", info.Binary, info.Version, info.Target)
	}
	return 0
}

func notReady(command string) int {
	_, _ = fmt.Fprintf(os.Stderr, "kordn %s: command is reserved for the protected runtime\n", command)
	return 78
}

var _ io.Writer = os.Stdout
