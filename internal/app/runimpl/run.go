package runimpl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/kordn-ai/kordn/internal/app"
	"github.com/kordn-ai/kordn/internal/audit"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/cache"
	"github.com/kordn-ai/kordn/internal/config"
	"github.com/kordn-ai/kordn/internal/credentials"
	"github.com/kordn-ai/kordn/internal/iammap"
	"github.com/kordn-ai/kordn/internal/observe"
	"github.com/kordn-ai/kordn/internal/pki"
	"github.com/kordn-ai/kordn/internal/policy"
	"github.com/kordn-ai/kordn/internal/proxy"
	runtimepkg "github.com/kordn-ai/kordn/internal/runtime"
	"github.com/kordn-ai/kordn/internal/sigv4"
)

type providerAdapter struct{ p *credentials.Provider }

func (p providerAdapter) Retrieve(ctx context.Context) (aws.Credentials, error) {
	value, err := p.p.Retrieve(ctx)
	if err == nil {
		audit.RegisterSensitiveValues(value.AccessKeyID, value.SecretAccessKey, value.SessionToken)
	}
	return value, err
}

// Run assembles the only protected child path. Setup is intentionally linear:
// config/policy, identity, run secrets/CA, audit/proxy, environment, exec.
func Run(ctx context.Context, inv app.RunInvocation) int {
	if len(inv.Argv) == 0 || inv.Argv[0] == "" {
		return 2
	}
	if ctx == nil {
		ctx = context.Background()
	}
	path := inv.ConfigPath
	if path == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return 78
		}
		path = home + string(os.PathSeparator) + ".kordn" + string(os.PathSeparator) + "config.yaml"
	}
	cfg, err := config.Load(path)
	if err != nil {
		return startupError(inv, err)
	}
	eng, err := policy.NewEngine(cfg.Policy)
	if err != nil {
		return startupError(inv, err)
	}
	upstream, err := credentials.NewProvider(ctx, cfg.Upstream)
	if err != nil {
		return startupError(inv, err)
	}
	secrets, err := credentials.GenerateRunSecrets()
	if err != nil {
		return startupError(inv, err)
	}
	// Run credentials are used in child files, proxy authentication, and
	// request signing. Register every value before any audit or diagnostic
	// path can observe the run.
	audit.RegisterSensitiveValues(secrets.Fake.AccessKeyID, secrets.Fake.SecretAccessKey, secrets.Fake.SessionToken, secrets.ProxySecret, cfg.Upstream.ExternalID, cfg.Upstream.SourceIdentity)
	sess, err := os.MkdirTemp("", "kordn-run-")
	if err != nil {
		return startupError(inv, err)
	}
	_ = os.Chmod(sess, 0700)
	defer os.RemoveAll(sess)
	caDir := sess + string(os.PathSeparator) + "ca"
	if err = os.MkdirAll(caDir, 0700); err != nil {
		return startupError(inv, err)
	}
	ca, err := newCA(caDir)
	if err != nil {
		return startupError(inv, err)
	}
	defer ca.Cleanup()
	auditPath := cfg.Audit.Path
	if inv.AuditPath != "" {
		auditPath = inv.AuditPath
	}
	aw, err := audit.NewWriter(auditPath, audit.Options{Fsync: audit.FsyncMode(cfg.Audit.Fsync)})
	if err != nil {
		return startupError(inv, err)
	}
	defer aw.Close()
	started := audit.NewEvent(secrets.RunID, audit.RunStarted)
	started.RootProcess = &audit.RootProcess{PID: os.Getpid(), Argv0: filepath.Base(inv.Argv[0]), CommandHash: commandHash(inv.Argv)}
	started.Upstream = &audit.UpstreamInfo{Profile: upstream.Identity().Profile, PrincipalARN: upstream.Identity().ARN}
	if err = aw.Write(ctx, started); err != nil {
		return startupError(inv, err)
	}
	fakeVerifier, err := sigv4.NewVerifier(secrets.Fake, sigv4.WithBodyLimits(cfg.Proxy.MaxInMemoryBodyBytes, cfg.Proxy.MaxSpoolBodyBytes))
	if err != nil {
		return startupError(inv, err)
	}
	dec, err := awsrequest.NewConfiguredDecoder(awsrequest.DecoderOptions{Limits: awsrequest.DecodeLimits{MaxBodyBytes: cfg.Proxy.MaxSpoolBodyBytes}, CallerAccountID: upstream.Identity().AccountID})
	if err != nil {
		return startupError(inv, err)
	}
	mapper, err := iammap.NewMapper(iammap.MapperOptions{Timeout: time.Second})
	if err != nil {
		return startupError(inv, err)
	}
	resigner, err := sigv4.NewResigner(providerAdapter{upstream}, sigv4.WithResignBodyLimits(cfg.Proxy.MaxInMemoryBodyBytes, cfg.Proxy.MaxSpoolBodyBytes))
	if err != nil {
		return startupError(inv, err)
	}
	parentProxy := runtimepkg.CurrentProxySettings()
	transport := proxy.NewOutboundTransport(parentProxy)
	runCaches, err := cache.NewRunCaches(cache.CacheOptions{})
	if err != nil {
		return startupError(inv, err)
	}
	listenAddr := cfg.Proxy.Listen
	if inv.Listen != "" {
		listenAddr = inv.Listen
	}
	server, err := proxy.NewServer(proxy.Config{ListenAddr: listenAddr, Username: secrets.ProxyUsername, Password: secrets.ProxySecret, CA: ca, InboundAuthenticator: fakeVerifier, Decoder: dec, Mapper: mapper, Policy: eng, PolicyHash: cfg.PolicyHash, Audit: aw, Resigner: resigner, Upstream: proxy.NewNoReplayRoundTripper(transport), RunID: secrets.RunID, ParentProxy: parentProxy, Caches: runCaches, LogResourceARNs: cfg.Audit.LogResourceARNs, HashResourceNames: cfg.Audit.HashResourceNames})
	if err != nil {
		return startupError(inv, err)
	}
	if err = server.Listen(); err != nil {
		_ = server.Close()
		return startupError(inv, err)
	}
	proxyURL := "http://" + secrets.ProxyUsername + ":" + secrets.ProxySecret + "@" + server.Addr()
	files, err := writeSyntheticFiles(sess, secrets.Fake, cfg.Upstream.Region, server.CAPEMPath())
	if err != nil {
		server.Close()
		return startupError(inv, err)
	}
	env, err := runtimepkg.BuildChildEnvironment(runtimepkg.EnvironmentInput{
		ParentEnv: os.Environ(), Fake: secrets.Fake,
		Files:    runtimepkg.AWSFiles{CredentialsPath: files.CredentialsPath, ConfigPath: files.ConfigPath, CABundlePath: files.CABundlePath},
		ProxyURL: proxyURL, RunID: secrets.RunID,
	})
	if err != nil {
		server.Close()
		return startupError(inv, err)
	}
	if !inv.Quiet {
		identity := upstream.Identity()
		fmt.Fprintf(os.Stderr, "Kordn run %s\n  proxy:         active on %s\n  upstream:      %s\n  principal:     %s\n",
			audit.RedactString(secrets.RunID), audit.RedactString(server.Addr()), audit.RedactString(identity.Profile), audit.RedactString(identity.ARN))
	}
	if err = server.Start(); err != nil {
		return startupError(inv, err)
	}
	result, runErr := runLocalChild(ctx, inv.Argv, env, server, aw)
	server.IncMetric("child_exit")
	if runErr != nil {
		server.IncMetric("child_supervision_failures")
	}
	ended := audit.NewEvent(secrets.RunID, audit.RunEnded)
	ended.RootProcess = started.RootProcess
	ended.ExitCode = &result.ExitCode
	metrics := server.MetricsSnapshot()
	ended.Metrics = &audit.MetricsSnapshot{Counters: metrics.Counters, ActiveConnections: metrics.ActiveConnections, PeakConnections: metrics.PeakConnections, ActiveRequests: metrics.ActiveRequests, PeakRequests: metrics.PeakRequests}
	ended.Metrics.Histograms = make(map[string]audit.Histogram, len(metrics.Histograms))
	for name, histogram := range metrics.Histograms {
		ended.Metrics.Histograms[name] = audit.Histogram{Count: histogram.Count, P50: histogram.P50, P95: histogram.P95, P99: histogram.P99}
	}
	if result.SafetyFailure {
		ended.Status = "safety_failure"
	} else {
		ended.Status = "completed"
	}
	_ = aw.Write(context.Background(), ended)
	_ = aw.Flush(context.Background())
	if !inv.Quiet {
		fmt.Fprintf(os.Stderr, "Kordn summary %s\n  child exit:    %d\n  audit:         %s\n", audit.RedactString(secrets.RunID), result.ExitCode, audit.RedactString(aw.Path()))
		printConciseMetrics(os.Stderr, metrics)
		if inv.Verbose {
			printVerboseMetrics(os.Stderr, metrics)
		}
	}
	return result.ExitCode
}
func printConciseMetrics(w io.Writer, metrics observe.Snapshot) {
	c := metrics.Counters
	local, upstream := metrics.Histograms[observe.LocalLatency], metrics.Histograms[observe.UpstreamLatency]
	fmt.Fprintf(w, "  requests:      allowed=%d denied=%d upstream-errors=%d\n", c[observe.Allowed], c[observe.Denied], c[observe.UpstreamErrors])
	fmt.Fprintf(w, "  latency (ms):  local p50=%.2f p95=%.2f upstream p50=%.2f p95=%.2f\n", local.P50, local.P95, upstream.P50, upstream.P95)
	fmt.Fprintf(w, "  cache/audit:   hits=%d misses=%d audit-failures=%d\n", c[observe.CacheEndpointHits]+c[observe.CacheMappingHits]+c[observe.CacheDecisionHits], c[observe.CacheEndpointMisses]+c[observe.CacheMappingMisses]+c[observe.CacheDecisionMisses], c[observe.AuditFailures])
	fmt.Fprintf(w, "  connections:   active=%d peak=%d requests-active=%d requests-peak=%d\n", metrics.ActiveConnections, metrics.PeakConnections, metrics.ActiveRequests, metrics.PeakRequests)
}

func printVerboseMetrics(w io.Writer, metrics observe.Snapshot) {
	keys := make([]string, 0, len(metrics.Counters))
	for key := range metrics.Counters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(w, "  metric %-28s %d\n", audit.RedactString(key), metrics.Counters[key])
	}
	histograms := make([]string, 0, len(metrics.Histograms))
	for key := range metrics.Histograms {
		histograms = append(histograms, key)
	}
	sort.Strings(histograms)
	for _, key := range histograms {
		h := metrics.Histograms[key]
		fmt.Fprintf(w, "  histogram %-24s count=%d p50=%.2f p95=%.2f p99=%.2f\n", audit.RedactString(key), h.Count, h.P50, h.P95, h.P99)
	}
	fmt.Fprintf(w, "  gauge active_connections=%d peak_connections=%d active_requests=%d peak_requests=%d\n", metrics.ActiveConnections, metrics.PeakConnections, metrics.ActiveRequests, metrics.PeakRequests)
}

func startupError(inv app.RunInvocation, err error) int {
	if !inv.Quiet {
		fmt.Fprintln(os.Stderr, "kordn: startup failed")
	}
	return 78
}
func commandHash(argv []string) string {
	h := sha256.New()
	for _, v := range argv {
		h.Write([]byte{0})
		h.Write([]byte(v))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func newCA(dir string) (*pki.CA, error) { return pki.NewCA(dir) }

type childResult struct {
	ExitCode      int
	SafetyFailure bool
}

func runLocalChild(ctx context.Context, argv, env []string, server *proxy.Server, aw *audit.Writer) (childResult, error) {
	_ = aw
	result, err := runtimepkg.RunChild(ctx, runtimepkg.ChildSpec{
		Argv: argv, Env: env, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	}, runtimepkg.SupervisorOptions{Hooks: runtimepkg.LifecycleHooks{Cleanup: func() error { return server.Close() }}})
	return childResult{ExitCode: result.ExitCode, SafetyFailure: result.SafetyFailure}, err
}
func writeSyntheticFiles(dir string, fake credentials.FakeCredential, region, ca string) (runtimeFiles, error) {
	cred := filepath.Join(dir, "credentials")
	conf := filepath.Join(dir, "config")
	if err := os.WriteFile(cred, []byte("[kordn]\naws_access_key_id = "+fake.AccessKeyID+"\naws_secret_access_key = "+fake.SecretAccessKey+"\naws_session_token = "+fake.SessionToken+"\n"), 0600); err != nil {
		return runtimeFiles{}, err
	}
	if err := os.WriteFile(conf, []byte("[profile kordn]\nregion = "+region+"\nca_bundle = "+ca+"\n"), 0600); err != nil {
		return runtimeFiles{}, err
	}
	return runtimeFiles{CredentialsPath: cred, ConfigPath: conf, CABundlePath: ca}, nil
}

type runtimeFiles struct{ CredentialsPath, ConfigPath, CABundlePath string }
