package credentials

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kordn-ai/kordn/internal/config"
)

// assumeRole creates the sole optional, immutable role step. Keeping it in a
// small function makes it difficult for a request handler to add per-request
// role selection accidentally.
func assumeRole(client stscreds.AssumeRoleAPIClient, upstream config.Upstream) aws.CredentialsProvider {
	return stscreds.NewAssumeRoleProvider(client, upstream.AssumeRoleARN, func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = upstream.RoleSessionName
		options.Duration = time.Duration(upstream.DurationSeconds) * time.Second
		if upstream.ExternalID != "" {
			value := upstream.ExternalID
			options.ExternalID = &value
		}
		if upstream.SourceIdentity != "" {
			value := upstream.SourceIdentity
			options.SourceIdentity = &value
		}
	})
}

func defaultSTSFactory(cfg aws.Config) STSClient { return sts.NewFromConfig(cfg) }
