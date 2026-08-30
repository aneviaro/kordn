package runtime

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kordn-ai/kordn/internal/credentials"
)

const localNoProxy = "localhost,127.0.0.1,::1"

// EnvironmentInput is immutable input for BuildChildEnvironment. ParentEnv is
// copied; it is never modified in place and no process-global environment API
// is used.
type EnvironmentInput struct {
	ParentEnv []string
	Fake      credentials.FakeCredential
	Files     AWSFiles
	ProxyURL  string
	RunID     string
}

// CapturedProxySettings records parent proxy choices before the child
// environment is constructed. Kordn's own transport receives this value and
// never consults the child-facing local proxy variables.
type CapturedProxySettings struct {
	HTTPProxy  string
	HTTPSProxy string
	NoProxy    string

	HTTPProxyUpper  string
	HTTPProxyLower  string
	HTTPSProxyUpper string
	HTTPSProxyLower string
	NoProxyUpper    string
	NoProxyLower    string
	AllProxy        string
	AllProxyUpper   string
	AllProxyLower   string
}

// CaptureProxySettings captures standard upper/lower-case proxy variables.
// Presence is tracked internally so an explicitly empty uppercase value does
// not unexpectedly fall through to a lower-case value.
func CaptureProxySettings(env []string) CapturedProxySettings {
	var settings CapturedProxySettings
	var httpUpper, httpsUpper, noProxyUpper, allUpper bool
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		switch key {
		case "HTTP_PROXY":
			settings.HTTPProxyUpper, httpUpper = value, true
		case "http_proxy":
			settings.HTTPProxyLower = value
		case "HTTPS_PROXY":
			settings.HTTPSProxyUpper, httpsUpper = value, true
		case "https_proxy":
			settings.HTTPSProxyLower = value
		case "NO_PROXY":
			settings.NoProxyUpper, noProxyUpper = value, true
		case "no_proxy":
			settings.NoProxyLower = value
		case "ALL_PROXY":
			settings.AllProxyUpper, allUpper = value, true
		case "all_proxy":
			settings.AllProxyLower = value
		}
	}
	if httpUpper {
		settings.HTTPProxy = settings.HTTPProxyUpper
	} else {
		settings.HTTPProxy = settings.HTTPProxyLower
	}
	if httpsUpper {
		settings.HTTPSProxy = settings.HTTPSProxyUpper
	} else {
		settings.HTTPSProxy = settings.HTTPSProxyLower
	}
	if noProxyUpper {
		settings.NoProxy = settings.NoProxyUpper
	} else {
		settings.NoProxy = settings.NoProxyLower
	}
	if allUpper {
		settings.AllProxy = settings.AllProxyUpper
	} else {
		settings.AllProxy = settings.AllProxyLower
	}
	return settings
}

func CurrentProxySettings() CapturedProxySettings { return CaptureProxySettings(environ()) }

// ProxyFunc returns a proxy function backed only by captured parent values.
// Malformed proxy URLs are errors instead of being silently ignored.
func (p CapturedProxySettings) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return nil, errors.New("proxy request is nil")
		}
		if proxyExcluded(req.URL.Hostname(), p.NoProxy) {
			return nil, nil
		}
		value := p.HTTPProxy
		if strings.EqualFold(req.URL.Scheme, "https") {
			value = p.HTTPSProxy
		}
		if value == "" {
			value = p.AllProxy
		}
		if value == "" {
			return nil, nil
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("captured outbound proxy is invalid")
		}
		if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
			return nil, errors.New("captured outbound proxy uses an unsupported scheme")
		}
		return parsed, nil
	}
}

// NewOutboundTransport creates Kordn's explicitly configured transport. It
// uses the captured corporate proxy and the normal public root pool; it never
// reads HTTP(S)_PROXY from the process environment and never disables TLS
// verification.
func (p CapturedProxySettings) NewOutboundTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 p.ProxyFunc(),
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// NewOutboundClient pairs an explicit transport with a bounded request
// timeout. Callers may use the transport directly when streaming is required.
func (p CapturedProxySettings) NewOutboundClient() *http.Client {
	return &http.Client{Transport: p.NewOutboundTransport()}
}

func BuildChildEnvironment(input EnvironmentInput) ([]string, error) {
	if !safeEnvValue(input.RunID) || strings.TrimSpace(input.RunID) == "" {
		return nil, errors.New("run identity is required")
	}
	if !safeEnvValue(input.Fake.AccessKeyID) || !safeEnvValue(input.Fake.SecretAccessKey) || !safeEnvValue(input.Fake.SessionToken) {
		return nil, errors.New("fake credential is incomplete")
	}
	if !safeEnvValue(input.Files.CredentialsPath) || !safeEnvValue(input.Files.ConfigPath) || !safeEnvValue(input.Files.CABundlePath) {
		return nil, errors.New("synthetic AWS files are incomplete")
	}
	proxyURL, err := validateChildProxyURL(input.ProxyURL)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(input.ParentEnv)+24)
	for _, item := range input.ParentEnv {
		key, _, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			continue
		}
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "AWS_") || isReplacedChildKey(upper) {
			continue
		}
		result = append(result, item)
	}
	set := func(key, value string) { result = append(result, key+"="+value) }
	set("AWS_ACCESS_KEY_ID", input.Fake.AccessKeyID)
	set("AWS_SECRET_ACCESS_KEY", input.Fake.SecretAccessKey)
	set("AWS_SESSION_TOKEN", input.Fake.SessionToken)
	set("AWS_EC2_METADATA_DISABLED", "true")
	set("AWS_EC2_METADATA_V1_DISABLED", "true")
	set("AWS_SHARED_CREDENTIALS_FILE", input.Files.CredentialsPath)
	set("AWS_CONFIG_FILE", input.Files.ConfigPath)
	set("AWS_PROFILE", "kordn")
	set("AWS_DEFAULT_PROFILE", "kordn")
	set("AWS_SDK_LOAD_CONFIG", "1")
	set("AWS_CA_BUNDLE", input.Files.CABundlePath)
	set("HTTP_PROXY", proxyURL)
	set("HTTPS_PROXY", proxyURL)
	set("http_proxy", proxyURL)
	set("https_proxy", proxyURL)
	set("NO_PROXY", localNoProxy)
	set("no_proxy", localNoProxy)
	set("KORDN_RUN_ID", input.RunID)
	set("KORDN_ACTIVE", "1")
	return result, nil
}

func BuildChildEnv(parent []string, fake credentials.FakeCredential, files AWSFiles, proxyURL, runID string) ([]string, error) {
	return BuildChildEnvironment(EnvironmentInput{ParentEnv: parent, Fake: fake, Files: files, ProxyURL: proxyURL, RunID: runID})
}

func validateChildProxyURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User == nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("authenticated local proxy URL is required")
	}
	if !strings.EqualFold(parsed.Scheme, "http") {
		return "", errors.New("local proxy must use HTTP proxy URL")
	}
	if parsed.User.Username() == "" {
		return "", errors.New("local proxy username is required")
	}
	password, ok := parsed.User.Password()
	if !ok || password == "" || strings.ContainsAny(password, "\x00\r\n") {
		return "", errors.New("local proxy password is required")
	}
	host := parsed.Hostname()
	if net.ParseIP(host) == nil || (host != "127.0.0.1" && host != "::1") {
		return "", errors.New("local proxy must be loopback")
	}
	port := parsed.Port()
	if port == "" {
		return "", errors.New("local proxy port is required")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("local proxy port is invalid")
	}
	return parsed.String(), nil
}

func isReplacedChildKey(key string) bool {
	switch strings.ToUpper(key) {
	case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
		"FTP_PROXY", "RSYNC_PROXY", "KORDN_RUN_ID", "KORDN_ACTIVE":
		return true
	default:
		return false
	}
}

func proxyExcluded(host, list string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" {
		return false
	}
	for _, raw := range strings.Split(list, ",") {
		entry := strings.TrimSpace(strings.ToLower(raw))
		if entry == "" {
			continue
		}
		// A no_proxy entry may include a port. Ignore malformed port suffixes
		// rather than accidentally treating arbitrary text as a hostname.
		if parsed, err := neturlForNoProxy(entry); err == nil {
			entry = parsed
		}
		entry = strings.Trim(entry, "[]")
		entry = strings.TrimSuffix(entry, ".")
		if entry == "*" || entry == host || strings.TrimPrefix(entry, ".") == host || strings.HasSuffix(host, "."+strings.TrimPrefix(entry, ".")) {
			return true
		}
	}
	return false
}

func neturlForNoProxy(entry string) (string, error) {
	if strings.HasPrefix(entry, "[") {
		end := strings.IndexByte(entry, ']')
		if end < 0 {
			return "", errors.New("malformed no_proxy entry")
		}
		return entry[:end+1], nil
	}
	if strings.Count(entry, ":") == 1 {
		host, port, ok := strings.Cut(entry, ":")
		if ok && host != "" {
			if _, err := strconv.Atoi(port); err == nil {
				return host, nil
			}
		}
	}
	return entry, nil
}

func safeEnvValue(value string) bool { return value != "" && !strings.ContainsAny(value, "\x00\r\n") }

var environ = os.Environ
