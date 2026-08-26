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

// Package credentials resolves Kordn's upstream authority before a child is
// created. It does not alter process-global environment variables.
package credentials

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kordn-ai/kordn/internal/config"
)

// ConfigLoader is injectable so resolution tests do not read user AWS files or
// start an external credential process. The production loader is the SDK's
// shared-config loader, which supports SSO, MFA, and credential_process.
type ConfigLoader func(context.Context, ...func(*sdkconfig.LoadOptions) error) (aws.Config, error)

// STSClient is the minimal STS surface used for the fixed role step and the
// mandatory identity preflight. It is intentionally injectable.
type STSClient interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// MFATokenProvider supplies an MFA token to the SDK shared-profile role
// provider. It is called only when a selected profile's role chain requires
// MFA.
type MFATokenProvider func() (string, error)

// ProviderOptions controls dependency injection at AWS boundaries. A
// production caller should leave all fields nil; production uses the SDK's
// shared-profile loader and its synchronized stdin MFA prompt.
type ProviderOptions struct {
	LoadConfig       ConfigLoader
	NewSTS           func(aws.Config) STSClient
	MFATokenProvider MFATokenProvider
}

// Provider is a memoized upstream credentials provider and its non-secret
// preflight identity. It exposes no child-facing credential API.
type Provider struct {
	provider aws.CredentialsProvider
	identity UpstreamIdentity
}

// NewProvider resolves, refreshes, and identity-preflights the configured
// authority. No child process should be started until this returns nil error.
func NewProvider(ctx context.Context, upstream config.Upstream) (*Provider, error) {
	return NewProviderWithOptions(ctx, upstream, ProviderOptions{})
}

// NewProviderWithOptions is NewProvider with AWS config and STS injection for
// deterministic tests.
func NewProviderWithOptions(ctx context.Context, upstream config.Upstream, options ProviderOptions) (*Provider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateProviderInput(upstream); err != nil {
		return nil, err
	}
	loader := options.LoadConfig
	if loader == nil {
		loader = ConfigLoader(sdkconfig.LoadDefaultConfig)
	}
	tokenProvider := options.MFATokenProvider
	if tokenProvider == nil {
		tokenProvider = defaultMFATokenProvider
	}
	// The SDK protects one loaded provider with a credentials cache, but the
	// process can have more than one resolver. Serialize prompts at this seam
	// as well so concurrent startup or refresh cannot interleave stdin input.
	tokenProvider = serializedTokenProvider(tokenProvider)
	loaded, err := loadConfigSafely(ctx, loader, upstream, tokenProvider)
	if err != nil {
		// SDK errors can contain details returned by credential_process. Do not
		// put those details in a Kordn error or log line.
		return nil, errors.New("upstream credential configuration unavailable")
	}
	if loaded.Credentials == nil {
		return nil, errors.New("upstream credential provider unavailable")
	}

	newSTS := options.NewSTS
	if newSTS == nil {
		newSTS = defaultSTSFactory
	}
	// Cache the shared-config provider before constructing STS. This keeps
	// identity and fixed-role refreshes on the same serialized source provider
	// rather than letting an STS client retrieve directly from an uncached
	// loader result.
	sourceProvider := aws.NewCredentialsCache(loaded.Credentials)
	sourceConfig := loaded
	sourceConfig.Credentials = sourceProvider
	sourceSTS, err := newSTSSafely(newSTS, sourceConfig)
	if err != nil || sourceSTS == nil {
		return nil, errors.New("upstream STS client unavailable")
	}

	provider := aws.CredentialsProvider(sourceProvider)
	if upstream.AssumeRoleARN != "" {
		// This is the sole fixed role step. stscreds refreshes the role from
		// the source provider, but has no input from a request or child.
		provider = assumeRole(stscreds.AssumeRoleAPIClient(sourceSTS), upstream)
	}
	// CredentialsCache serializes refreshes and memoizes values through their
	// expiration. The source cache is reused directly without a second layer;
	// the optional role provider gets its own cache below.
	if upstream.AssumeRoleARN != "" {
		provider = aws.NewCredentialsCache(provider)
	}
	if value, err := retrieveSafely(ctx, provider); err != nil || !usableCredentials(value) {
		return nil, errors.New("upstream credentials unavailable")
	}

	// If a role was selected, GetCallerIdentity must use the effective role,
	// not the source profile. A separate client avoids accidentally making the
	// source client the authority ceiling.
	identityClient := sourceSTS
	if upstream.AssumeRoleARN != "" {
		effective := loaded
		effective.Credentials = provider
		identityClient, err = newSTSSafely(newSTS, effective)
		if err != nil || identityClient == nil {
			return nil, errors.New("upstream STS client unavailable")
		}
	}
	identity, err := PreflightIdentity(ctx, identityClient, provider, upstream.Profile, upstream.AssumeRoleARN)
	if err != nil {
		return nil, err
	}
	return &Provider{provider: provider, identity: identity}, nil
}

// Retrieve returns the current upstream value to Kordn's signer. Callers must
// never place the returned value in logs, errors, arguments, or child files.
func (p *Provider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if p == nil || p.provider == nil {
		return aws.Credentials{}, errors.New("upstream credentials unavailable")
	}
	value, err := retrieveSafely(ctx, p.provider)
	if err != nil || !usableCredentials(value) {
		return aws.Credentials{}, errors.New("upstream credentials unavailable")
	}
	return value, nil
}

// Identity returns only non-secret identity metadata captured during startup.
func (p *Provider) Identity() UpstreamIdentity {
	if p == nil {
		return UpstreamIdentity{}
	}
	return p.identity
}

var (
	providerProfilePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	providerRegionPattern   = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$`)
	providerRoleARNPattern  = regexp.MustCompile(`^arn:(?:[A-Za-z0-9-]+):iam::[0-9]{12}:role/[^\x00\r\n]+$`)
	providerSessionPattern  = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]+$`)
	providerExternalPattern = regexp.MustCompile(`^[A-Za-z0-9_+=,.@:/-]+$`)
)

func validateProviderInput(upstream config.Upstream) error {
	if !providerProfilePattern.MatchString(upstream.Profile) || strings.EqualFold(upstream.Profile, "default") {
		return errors.New("upstream profile is invalid")
	}
	if !providerRegionPattern.MatchString(upstream.Region) || len(upstream.Region) > 64 {
		return errors.New("upstream Region is invalid")
	}
	if upstream.AssumeRoleARN == "" && (upstream.ExternalID != "" || upstream.SourceIdentity != "") {
		return errors.New("fixed role options require an assume role ARN")
	}
	if upstream.AssumeRoleARN == "" {
		return nil
	}
	if len(upstream.AssumeRoleARN) > 2048 || !providerRoleARNPattern.MatchString(upstream.AssumeRoleARN) || !supportedRolePartition(upstream.AssumeRoleARN) {
		return errors.New("fixed assume role ARN is invalid")
	}
	if len(upstream.RoleSessionName) < 2 || len(upstream.RoleSessionName) > 64 || !providerSessionPattern.MatchString(upstream.RoleSessionName) {
		return errors.New("fixed role session name is invalid")
	}
	if upstream.DurationSeconds < 900 || upstream.DurationSeconds > 43200 {
		return errors.New("fixed role duration is outside STS limits")
	}
	if upstream.ExternalID != "" && (len(upstream.ExternalID) < 2 || len(upstream.ExternalID) > 1224 || !providerExternalPattern.MatchString(upstream.ExternalID)) {
		return errors.New("fixed external ID is invalid")
	}
	if upstream.SourceIdentity != "" && (len(upstream.SourceIdentity) < 2 || len(upstream.SourceIdentity) > 64 || !providerSessionPattern.MatchString(upstream.SourceIdentity)) {
		return errors.New("fixed source identity is invalid")
	}
	return nil
}

func loadConfigSafely(ctx context.Context, loader ConfigLoader, upstream config.Upstream, tokenProvider MFATokenProvider) (cfg aws.Config, err error) {
	defer func() {
		if recover() != nil {
			cfg = aws.Config{}
			err = errors.New("upstream credential configuration unavailable")
		}
	}()
	return loader(ctx,
		sdkconfig.WithSharedConfigProfile(upstream.Profile),
		sdkconfig.WithRegion(upstream.Region),
		sdkconfig.WithAssumeRoleCredentialOptions(func(options *stscreds.AssumeRoleOptions) {
			if options != nil {
				options.TokenProvider = tokenProvider
			}
		}),
	)
}

func newSTSSafely(factory func(aws.Config) STSClient, cfg aws.Config) (client STSClient, err error) {
	defer func() {
		if recover() != nil {
			client = nil
			err = errors.New("upstream STS client unavailable")
		}
	}()
	return factory(cfg), nil
}

func supportedRolePartition(roleARN string) bool {
	parts := strings.SplitN(roleARN, ":", 6)
	if len(parts) != 6 {
		return false
	}
	switch parts[1] {
	case "aws", "aws-us-gov", "aws-cn", "aws-iso", "aws-iso-b", "aws-iso-f":
		return true
	default:
		return false
	}
}

func usableCredentials(value aws.Credentials) bool {
	return value.AccessKeyID != "" && value.SecretAccessKey != ""
}

func retrieveSafely(ctx context.Context, provider aws.CredentialsProvider) (credentials aws.Credentials, err error) {
	if provider == nil {
		return aws.Credentials{}, errors.New("upstream credentials unavailable")
	}
	defer func() {
		if recover() != nil {
			credentials = aws.Credentials{}
			err = errors.New("upstream credentials unavailable")
		}
	}()
	return provider.Retrieve(ctx)
}

var stdinTokenProviderMu sync.Mutex

// defaultMFATokenProvider is deliberately the SDK's supported interactive
// seam. The mutex covers all Kordn production resolvers because the SDK's
// StdinTokenProvider does not synchronize concurrent prompts itself.
func defaultMFATokenProvider() (string, error) {
	stdinTokenProviderMu.Lock()
	defer stdinTokenProviderMu.Unlock()
	return stscreds.StdinTokenProvider()
}

func serializedTokenProvider(provider MFATokenProvider) MFATokenProvider {
	var mu sync.Mutex
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return provider()
	}
}

// Compile-time checks keep the injected surface aligned with the SDK client.
var _ STSClient = (*sts.Client)(nil)
