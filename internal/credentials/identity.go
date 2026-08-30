package credentials

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// UpstreamIdentity is safe to retain and display: it contains no credential
// material. RoleARN is the configured fixed ceiling, when one was selected.
type UpstreamIdentity struct {
	AccountID string
	ARN       string
	UserID    string
	Profile   string
	RoleARN   string
}

type IdentityClient interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// PreflightIdentity forces credential retrieval and then calls the mandatory
// GetCallerIdentity operation. SDK errors are deliberately not returned: an
// error from an external credential process may contain credential material.
func PreflightIdentity(ctx context.Context, client IdentityClient, provider aws.CredentialsProvider, profile, roleARN string) (UpstreamIdentity, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil || provider == nil {
		return UpstreamIdentity{}, errors.New("identity preflight unavailable")
	}
	if value, err := retrieveSafely(ctx, provider); err != nil || !usableCredentials(value) {
		return UpstreamIdentity{}, errors.New("upstream credentials unavailable")
	}
	output, err := callerIdentitySafely(ctx, client)
	if err != nil || output == nil || output.Account == nil || output.Arn == nil || output.UserId == nil {
		return UpstreamIdentity{}, errors.New("upstream identity preflight failed")
	}
	values := []string{*output.Account, *output.Arn, *output.UserId, profile, roleARN}
	for _, value := range values {
		if strings.ContainsAny(value, "\x00\r\n") {
			return UpstreamIdentity{}, errors.New("upstream identity preflight returned unsafe metadata")
		}
	}
	return UpstreamIdentity{
		AccountID: *output.Account,
		ARN:       *output.Arn,
		UserID:    *output.UserId,
		Profile:   profile,
		RoleARN:   roleARN,
	}, nil
}

func callerIdentitySafely(ctx context.Context, client IdentityClient) (output *sts.GetCallerIdentityOutput, err error) {
	defer func() {
		if recover() != nil {
			output = nil
			err = errors.New("upstream identity preflight failed")
		}
	}()
	return client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
}
