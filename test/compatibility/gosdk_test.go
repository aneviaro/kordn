//go:build compat

package compatibility

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	sdkcredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

func TestGoSDKV2StableClientFixture(t *testing.T) {
	// This is one real SDK client and one real local proxy path. The fake
	// upstream consumes the first 429, so only the SDK retry creates the second
	// incoming request; Kordn forwards each incoming attempt exactly once.
	h := newCompatHarness(t, false)
	h.upstream.Failures().Set("GetCallerIdentity", fakeaws.Failure{Status: 429, Body: []byte(`<ErrorResponse><Error><Code>Throttling</Code><Message>retry</Message></Error></ErrorResponse>`)})
	endpoint := "https://" + compatHost
	cfg := aws.Config{Region: "us-east-1", Credentials: sdkcredentials.NewStaticCredentialsProvider(h.fake.AccessKeyID, h.fake.SecretAccessKey, h.fake.SessionToken), HTTPClient: h.client, Retryer: func() aws.Retryer { return retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 2 }) }, RetryMaxAttempts: 2}
	client := sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = &endpoint })
	if _, err := client.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatalf("%v audit=%+v ledger=%+v", err, h.audit.snapshot(), h.upstream.Ledger())
	}
	if got := h.upstream.RequestCount(); got != 1 {
		t.Fatalf("upstream request count=%d, want one successful forward", got)
	}
	if got := len(h.upstream.Ledger()); got != 2 {
		t.Fatalf("ledger attempts=%d, want two SDK attempts", got)
	}
	if len(h.audit.snapshot()) != 2 {
		t.Fatalf("audit records=%d, want one per incoming SDK attempt", len(h.audit.snapshot()))
	}
}
