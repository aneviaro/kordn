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
