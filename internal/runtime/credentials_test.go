// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package runtime

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/kordn-ai/kordn/internal/config"
	kcredentials "github.com/kordn-ai/kordn/internal/credentials"
)

type countingProvider struct {
	mu     sync.Mutex
	value  aws.Credentials
	calls  int
	events *[]string
}

func (p *countingProvider) Retrieve(context.Context) (aws.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.events != nil {
		*p.events = append(*p.events, "retrieve")
	}
	return p.value, nil
}

func (p *countingProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type fakeSTSForRuntime struct {
	mu             sync.Mutex
	assumeCalls    int
	identityCalls  int
	lastAssume     *sts.AssumeRoleInput
	identityOutput *sts.GetCallerIdentityOutput
	sourceProvider aws.CredentialsProvider
	events         *[]string
}

func (s *fakeSTSForRuntime) AssumeRole(_ context.Context, input *sts.AssumeRoleInput, options ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	var sdkOptions sts.Options
	for _, option := range options {
		option(&sdkOptions)
	}
	if s.sourceProvider != nil {
		if _, err := s.sourceProvider.Retrieve(context.Background()); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	s.assumeCalls++
	s.lastAssume = input
	if s.events != nil {
		*s.events = append(*s.events, "assume")
	}
	s.mu.Unlock()
	return &sts.AssumeRoleOutput{Credentials: &types.Credentials{
		AccessKeyId:     aws.String("ASIAKORDNROLE12345"),
		SecretAccessKey: aws.String("role-secret-value-for-test"),
		SessionToken:    aws.String("role-token-value-for-test"),
		Expiration:      aws.Time(time.Now().Add(time.Hour)),
	}}, nil
}

func (s *fakeSTSForRuntime) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, options ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	var sdkOptions sts.Options
	for _, option := range options {
		option(&sdkOptions)
	}
	s.mu.Lock()
	s.identityCalls++
	if s.events != nil {
		*s.events = append(*s.events, "identity")
	}
	output := s.identityOutput
	s.mu.Unlock()
	if output == nil {
		output = &sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:iam::123456789012:user/kordn-test"),
			UserId:  aws.String("AIDAKORDNTEST"),
		}
	}
	return output, nil
}

func testUpstream(role bool) config.Upstream {
	upstream := config.Upstream{Profile: "operator", Region: "us-east-1", RoleSessionName: "kordn-test", DurationSeconds: 900}
	if role {
		upstream.AssumeRoleARN = "arn:aws:iam::123456789012:role/KordnTest"
		upstream.ExternalID = "external-test-id"
		upstream.SourceIdentity = "source-test"
	}
	return upstream
}

func TestProvider_RetrieveAndIdentityPreflightOrder(t *testing.T) {
	var events []string
	source := &countingProvider{value: aws.Credentials{AccessKeyID: "AKIAPARENTTEST", SecretAccessKey: "source-secret", SessionToken: "source-token"}, events: &events}
	identity := &fakeSTSForRuntime{events: &events}
	loaded := false
	provider, err := kcredentials.NewProviderWithOptions(context.Background(), testUpstream(false), kcredentials.ProviderOptions{
		LoadConfig: func(_ context.Context, _ ...func(*sdkconfig.LoadOptions) error) (aws.Config, error) {
			loaded = true
			return aws.Config{Region: "us-east-1", Credentials: source}, nil
		},
		NewSTS: func(aws.Config) kcredentials.STSClient { return identity },
	})
	if err != nil {
		t.Fatalf("provider setup: %v", err)
	}
	if !loaded {
		t.Fatal("shared-config loader was not called")
	}
	if got, want := strings.Join(events, ","), "retrieve,identity"; got != want {
		t.Fatalf("preflight order = %q, want %q", got, want)
	}
	if identity.identityCalls != 1 {
		t.Fatalf("GetCallerIdentity calls = %d, want one", identity.identityCalls)
	}
	if source.count() != 1 {
		t.Fatalf("cached source Retrieve calls = %d, want one", source.count())
	}
	if got := provider.Identity(); got.AccountID != "123456789012" || got.Profile != "operator" {
		t.Fatalf("unexpected non-secret identity: %+v", got)
	}
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("cached provider retrieve: %v", err)
	}
	if source.count() != 1 {
		t.Fatalf("refresh unexpectedly repeated source Retrieve: %d", source.count())
	}
}

func TestProvider_AssumeRoleFixedOptionsAndMemoizedRefresh(t *testing.T) {
	var events []string
	source := &countingProvider{value: aws.Credentials{AccessKeyID: "AKIAPARENTTEST", SecretAccessKey: "source-secret"}, events: &events}
	sourceSTS := &fakeSTSForRuntime{events: &events, sourceProvider: source}
	effectiveSTS := &fakeSTSForRuntime{events: &events}
	var clients []*fakeSTSForRuntime
	provider, err := kcredentials.NewProviderWithOptions(context.Background(), testUpstream(true), kcredentials.ProviderOptions{
		LoadConfig: func(_ context.Context, _ ...func(*sdkconfig.LoadOptions) error) (aws.Config, error) {
			return aws.Config{Region: "us-east-1", Credentials: source}, nil
		},
		NewSTS: func(cfg aws.Config) kcredentials.STSClient {
			// The source STS client is built with the memoized source provider;
			// the second client is the effective assumed-role client.
			if len(clients) == 0 {
				clients = append(clients, sourceSTS)
			} else {
				clients = append(clients, effectiveSTS)
			}
			return clients[len(clients)-1]
		},
	})
	if err != nil {
		t.Fatalf("role provider setup: %v", err)
	}
	if sourceSTS.assumeCalls != 1 {
		t.Fatalf("AssumeRole calls = %d, want one", sourceSTS.assumeCalls)
	}
	if effectiveSTS.identityCalls != 1 {
		t.Fatalf("effective identity calls = %d, want one", effectiveSTS.identityCalls)
	}
	if source.count() != 1 {
		t.Fatalf("source refresh calls = %d, want one", source.count())
	}
	if sourceSTS.lastAssume == nil || sourceSTS.lastAssume.RoleArn == nil || *sourceSTS.lastAssume.RoleArn != testUpstream(true).AssumeRoleARN {
		t.Fatalf("fixed AssumeRole ARN was not sent")
	}
	if sourceSTS.lastAssume.RoleSessionName == nil || *sourceSTS.lastAssume.RoleSessionName != "kordn-test" {
		t.Fatalf("fixed role session name was not sent")
	}
	if sourceSTS.lastAssume.ExternalId == nil || *sourceSTS.lastAssume.ExternalId != "external-test-id" {
		t.Fatalf("fixed external ID was not sent")
	}
	if sourceSTS.lastAssume.SourceIdentity == nil || *sourceSTS.lastAssume.SourceIdentity != "source-test" {
		t.Fatalf("fixed source identity was not sent")
	}
	first, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.AccessKeyID != second.AccessKeyID || first.SecretAccessKey != second.SecretAccessKey {
		t.Fatal("memoized assumed credentials changed during their validity window")
	}
	if sourceSTS.assumeCalls != 1 {
		t.Fatalf("AssumeRole was repeated by cached Retrieve: %d", sourceSTS.assumeCalls)
	}
}

func TestFakeCredential_LengthsRandomnessStabilityAndRedaction(t *testing.T) {
	first, err := kcredentials.GenerateRunSecrets()
	if err != nil {
		t.Fatal(err)
	}
	second, err := kcredentials.GenerateRunSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(first.RunID) != len("run-")+43 || len(first.Fake.AccessKeyID) != len("KORDN")+43 || len(first.Fake.SecretAccessKey) != 43 || len(first.Fake.SessionToken) != 43 || len(first.ProxySecret) != 43 {
		t.Fatalf("unexpected credential lengths: run=%d access=%d secret=%d token=%d proxy=%d", len(first.RunID), len(first.Fake.AccessKeyID), len(first.Fake.SecretAccessKey), len(first.Fake.SessionToken), len(first.ProxySecret))
	}
	if !strings.HasPrefix(first.Fake.AccessKeyID, "KORDN") || first == second {
		t.Fatal("run credentials were not independently random")
	}
	for name, value := range map[string]string{
		"run ID":        strings.TrimPrefix(first.RunID, "run-"),
		"access suffix": strings.TrimPrefix(first.Fake.AccessKeyID, "KORDN"),
		"secret":        first.Fake.SecretAccessKey,
		"session token": first.Fake.SessionToken,
		"proxy secret":  first.ProxySecret,
	} {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 || len(value) != 43 {
			t.Errorf("%s does not encode exactly 256 bits with unpadded URL-safe base64: encoded=%d decoded=%d err=%v", name, len(value), len(decoded), err)
		}
		for _, char := range value {
			if !(char >= 'A' && char <= 'Z') && !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' && char != '_' {
				t.Errorf("%s contains a character outside the environment/SigV4-safe alphabet: %q", name, char)
			}
		}
	}
	if len(first.Fake.AccessKeyID) < 16 || len(first.Fake.AccessKeyID) > 128 {
		t.Fatalf("Kordn access key length = %d, want AWS-compatible range [16, 128]", len(first.Fake.AccessKeyID))
	}
	if got := fmt.Sprint(first.Fake); strings.Contains(got, first.Fake.AccessKeyID) || strings.Contains(got, first.Fake.SecretAccessKey) || strings.Contains(got, first.Fake.SessionToken) {
		t.Fatalf("fake String leaked credential material: %s", got)
	}
	if got := fmt.Sprint(first); strings.Contains(got, first.Fake.AccessKeyID) || strings.Contains(got, first.ProxySecret) || strings.Contains(got, first.Fake.SecretAccessKey) || strings.Contains(got, first.Fake.SessionToken) {
		t.Fatalf("run String leaked credential material: %s", got)
	}
	if got := fmt.Sprintf("%#v", first.Fake); strings.Contains(got, first.Fake.SecretAccessKey) {
		t.Fatalf("fake GoString leaked secret material: %s", got)
	}
}

func TestProvider_ProductionSharedProfileMFAOptionFailsBeforeChildLaunch(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config")
	credentialsPath := filepath.Join(directory, "credentials")
	if err := os.WriteFile(configPath, []byte(`[profile operator]
role_arn = arn:aws:iam::123456789012:role/Operator
source_profile = base
mfa_serial = arn:aws:iam::123456789012:mfa/operator
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialsPath, []byte(`[base]
aws_access_key_id = AKIABASETEST
aws_secret_access_key = base-secret-placeholder
`), 0o600); err != nil {
		t.Fatal(err)
	}

	const tokenErrorSecret = "mfa-token-provider-secret"
	tokenCalls := 0
	loader := func(ctx context.Context, options ...func(*sdkconfig.LoadOptions) error) (aws.Config, error) {
		// This is the real SDK shared-profile loader. The two file options keep
		// the test hermetic while the resolver's own profile/region/options are
		// passed through unchanged.
		options = append(options,
			sdkconfig.WithSharedConfigFiles([]string{configPath}),
			sdkconfig.WithSharedCredentialsFiles([]string{credentialsPath}),
		)
		return sdkconfig.LoadDefaultConfig(ctx, options...)
	}
	preflight := func() error {
		_, err := kcredentials.NewProviderWithOptions(context.Background(), testUpstream(false), kcredentials.ProviderOptions{
			LoadConfig: loader,
			MFATokenProvider: func() (string, error) {
				tokenCalls++
				return "", errors.New(tokenErrorSecret)
			},
		})
		return err
	}
	result, runErr := RunChild(context.Background(), ChildSpec{Argv: []string{"/bin/true"}}, SupervisorOptions{Hooks: LifecycleHooks{Prelaunch: []func() error{preflight}}})
	if runErr == nil || result.Started || result.ExitCode != ExitStartup {
		t.Fatalf("MFA startup result = %+v, err=%v", result, runErr)
	}
	if tokenCalls != 1 {
		t.Fatalf("MFA token provider calls = %d, want one before launch", tokenCalls)
	}
	if strings.Contains(runErr.Error(), tokenErrorSecret) {
		t.Fatal("MFA token-provider error leaked secret material")
	}
}
