// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package runtime

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kordn-ai/kordn/internal/app"
	"github.com/kordn-ai/kordn/internal/credentials"
)

func envValues(values []string) map[string]string {
	result := make(map[string]string)
	for _, value := range values {
		key, item, ok := strings.Cut(value, "=")
		if ok {
			result[key] = item
		}
	}
	return result
}

func testFiles(t *testing.T) (*SessionDir, credentials.FakeCredential, AWSFiles) {
	t.Helper()
	secrets, err := credentials.GenerateRunSecrets()
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSessionDir(t.TempDir(), secrets.RunID)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(session.Path, "ca.pem")
	if err := writeTestCABundle(caPath); err != nil {
		t.Fatal(err)
	}
	files, err := session.WriteSyntheticAWSFiles(secrets.Fake, "us-east-1", caPath)
	if err != nil {
		t.Fatal(err)
	}
	return session, secrets.Fake, files
}

func writeTestCABundle(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Kordn test CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
}

func TestSessionDir_PrivateFilesAndCleanup(t *testing.T) {
	session, fake, files := testFiles(t)
	if info, err := os.Stat(session.Path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("run directory mode = %o, want 700", info.Mode().Perm())
	}
	for _, path := range []string{files.CredentialsPath, files.ConfigPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("synthetic file %q mode = %o, want 600", path, info.Mode().Perm())
		}
	}
	credentialData, err := os.ReadFile(files.CredentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(credentialData) != "[kordn]\naws_access_key_id = "+fake.AccessKeyID+"\naws_secret_access_key = "+fake.SecretAccessKey+"\naws_session_token = "+fake.SessionToken+"\n" {
		t.Fatal("synthetic credentials contain unexpected data")
	}
	configData, err := os.ReadFile(files.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(configData) != "[profile kordn]\nregion = us-east-1\nca_bundle = "+files.CABundlePath+"\n" {
		t.Fatal("synthetic config contains unexpected data")
	}
	if err := session.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(session.Path); !os.IsNotExist(err) {
		t.Fatalf("run directory was not removed: %v", err)
	}
	if err := session.Cleanup(); err != nil {
		t.Fatalf("cleanup was not idempotent: %v", err)
	}
}

func TestSessionDir_StaleCleanupSymlinkSafety(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	marker := filepath.Join(outside, "must-survive")
	if err := os.WriteFile(marker, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(root, "run-old")
	if err := os.Mkdir(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "data"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "run-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(root, "other")
	if err := os.Mkdir(keep, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(old, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStaleAt(root, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Fatalf("old run was not removed: %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink entry was removed or followed: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("outside marker was affected: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal(err)
	}
	if err := CleanupStale(root, time.Minute); err == nil {
		t.Fatal("stale cleanup accepted an unsafe duration")
	}
}

func TestEnvironment_ClearsFallbacksAndKeepsProxyParityWithoutMutation(t *testing.T) {
	session, fake, files := testFiles(t)
	defer session.Cleanup()
	parent := []string{
		"PATH=/usr/bin",
		"KEEP_ME=unchanged",
		"AWS_ACCESS_KEY_ID=parent-access-placeholder",
		"AWS_SECRET_ACCESS_KEY=parent-secret-placeholder",
		"AWS_SESSION_TOKEN=parent-token-placeholder",
		"AWS_PROFILE=parent-profile",
		"AWS_WEB_IDENTITY_TOKEN_FILE=/private/parent/token",
		"AWS_ROLE_ARN=arn:aws:iam::123456789012:role/parent",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1/parent",
		"HTTP_PROXY=http://corporate.example:8080",
		"http_proxy=http://lower.example:8080",
		"HTTPS_PROXY=http://corporate.example:8080",
		"ALL_PROXY=http://all.example:8080",
		"NO_PROXY=internal.example",
		"KORDN_ACTIVE=old",
	}
	before := append([]string(nil), parent...)
	child, err := BuildChildEnvironment(EnvironmentInput{
		ParentEnv: parent,
		Fake:      fake,
		Files:     files,
		ProxyURL:  "http://kordn:proxy-placeholder@127.0.0.1:43123",
		RunID:     session.RunID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parent, before) {
		t.Fatal("child environment construction mutated its input")
	}
	values := envValues(child)
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_EC2_METADATA_DISABLED", "AWS_EC2_METADATA_V1_DISABLED", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SDK_LOAD_CONFIG", "AWS_CA_BUNDLE", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy", "KORDN_RUN_ID", "KORDN_ACTIVE"} {
		if _, ok := values[key]; !ok {
			t.Fatalf("required child environment key %q missing", key)
		}
	}
	if values["AWS_ACCESS_KEY_ID"] != fake.AccessKeyID || values["AWS_SECRET_ACCESS_KEY"] != fake.SecretAccessKey || values["AWS_SESSION_TOKEN"] != fake.SessionToken {
		t.Fatal("child received a credential other than the stable fake")
	}
	if values["HTTP_PROXY"] != values["HTTPS_PROXY"] || values["HTTP_PROXY"] != values["http_proxy"] || values["HTTP_PROXY"] != values["https_proxy"] {
		t.Fatal("proxy variable spellings are not identical")
	}
	if values["NO_PROXY"] != "localhost,127.0.0.1,::1" || values["no_proxy"] != values["NO_PROXY"] {
		t.Fatal("local no-proxy policy was not enforced")
	}
	for key := range values {
		if strings.HasPrefix(strings.ToUpper(key), "AWS_") && key != "AWS_ACCESS_KEY_ID" && key != "AWS_SECRET_ACCESS_KEY" && key != "AWS_SESSION_TOKEN" && key != "AWS_EC2_METADATA_DISABLED" && key != "AWS_EC2_METADATA_V1_DISABLED" && key != "AWS_SHARED_CREDENTIALS_FILE" && key != "AWS_CONFIG_FILE" && key != "AWS_PROFILE" && key != "AWS_DEFAULT_PROFILE" && key != "AWS_SDK_LOAD_CONFIG" && key != "AWS_CA_BUNDLE" {
			t.Fatalf("unexpected AWS fallback in child environment: %s", key)
		}
	}
	for _, key := range []string{"ALL_PROXY", "all_proxy", "FTP_PROXY", "ftp_proxy", "RSYNC_PROXY", "rsync_proxy"} {
		if _, ok := values[key]; ok {
			t.Fatalf("uncontrolled proxy fallback %q was inherited", key)
		}
	}
}

func TestEnvironment_CapturesParentProxyAndUsesExplicitOutboundTransport(t *testing.T) {
	settings := CaptureProxySettings([]string{
		"HTTP_PROXY=http://upper-http.example:8080",
		"http_proxy=http://lower-http.example:8080",
		"HTTPS_PROXY=http://upper-https.example:8080",
		"NO_PROXY=localhost,example.internal",
	})
	if settings.HTTPProxy != "http://upper-http.example:8080" || settings.HTTPSProxy != "http://upper-https.example:8080" {
		t.Fatalf("uppercase proxy precedence failed: %+v", settings)
	}
	proxy := settings.ProxyFunc()
	req, _ := httpNewRequestForRuntime("https://aws.example")
	if got, err := proxy(req); err != nil || got == nil || got.Host != "upper-https.example:8080" {
		t.Fatalf("captured HTTPS proxy = %v, %v", got, err)
	}
	local, _ := httpNewRequestForRuntime("http://localhost:8080")
	if got, err := proxy(local); err != nil || got != nil {
		t.Fatalf("NO_PROXY localhost was not honored: %v, %v", got, err)
	}
	transport := settings.NewOutboundTransport()
	if transport.Proxy == nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("outbound transport did not retain explicit proxy/public TLS defaults")
	}
	transport.CloseIdleConnections()
}

func httpNewRequestForRuntime(rawURL string) (*http.Request, error) {
	return http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
}

func TestEnvironment_RejectsUnprotectedChildProxyAndInjection(t *testing.T) {
	_, fake, files := testFiles(t)
	cases := []string{
		"http://user:password@10.0.0.1:1234",
		"http://user:password@127.0.0.1",
		"http://user@127.0.0.1:1234",
		"http://user:password@127.0.0.1:1234/path",
	}
	for _, proxy := range cases {
		if _, err := BuildChildEnvironment(EnvironmentInput{ParentEnv: nil, Fake: fake, Files: files, ProxyURL: proxy, RunID: "run-test"}); err == nil {
			t.Errorf("accepted unsafe child proxy %q", proxy)
		}
	}
	if _, err := BuildChildEnvironment(EnvironmentInput{Fake: fake, Files: files, ProxyURL: "http://user:password@127.0.0.1:1234", RunID: "run\nforged"}); err == nil {
		t.Fatal("accepted newline in run identity")
	}
}

func TestApp_ParseRunArgsMandatorySeparatorAndDirectArgv(t *testing.T) {
	invocation, err := app.ParseRunArgs([]string{"--config", "policy.yaml", "--quiet", "--verbose", "--", "python", "--profile", "literal"})
	if err != nil {
		t.Fatal(err)
	}
	if invocation.ConfigPath != "policy.yaml" || !invocation.Quiet || !invocation.Verbose || !reflect.DeepEqual(invocation.Argv, []string{"python", "--profile", "literal"}) {
		t.Fatalf("unexpected invocation: %+v", invocation)
	}
	for _, args := range [][]string{{"--config", "x"}, {"--", ""}, {"--profile", "user", "--", "cmd"}, {"--config=" + "", "--", "cmd"}} {
		if _, err := app.ParseRunArgs(args); err == nil {
			t.Fatalf("accepted invalid run argv: %#v", args)
		}
	}
	if code := app.Main([]string{"run", "--", "echo", "protected"}); code != ExitStartup {
		t.Fatalf("bootstrap run code = %d, want %d", code, ExitStartup)
	}
}
