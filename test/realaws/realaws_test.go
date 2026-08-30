//go:build realaws

package realaws

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestRealAWSContract(t *testing.T) {
	// These guards intentionally precede SDK/config construction: an ordinary
	// tagged run must not inspect credentials or perform DNS/network work.
	if os.Getenv("KORDN_REALAWS_OPT_IN") != "1" {
		t.Skip("real AWS disabled: set KORDN_REALAWS_OPT_IN=1 in the dedicated nightly job")
	}
	// The token is an independent CI safety switch. It is intentionally only
	// checked for presence and is never sent to AWS or included in diagnostics.
	if strings.TrimSpace(os.Getenv("KORDN_REALAWS_TOKEN")) == "" {
		t.Fatal("real AWS opt-in requires KORDN_REALAWS_TOKEN")
	}
	account := strings.TrimSpace(os.Getenv("KORDN_REALAWS_ACCOUNT"))
	role := strings.TrimSpace(os.Getenv("KORDN_REALAWS_ROLE"))
	if account == "" || role == "" {
		t.Fatal("real AWS opt-in requires KORDN_REALAWS_ACCOUNT and KORDN_REALAWS_ROLE")
	}
	allowed := strings.TrimSpace(os.Getenv("KORDN_REALAWS_ALLOWED_ACCOUNT"))
	if allowed == "" || account != allowed {
		t.Fatal("real AWS account is not on the explicit allowlist")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg, err := sdkconfig.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("real AWS credential configuration: %v", err)
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatalf("real AWS STS identity preflight: %v", err)
	}
	if identity.Account == nil || aws.ToString(identity.Account) != account {
		t.Fatalf("STS account %q does not match expected account", aws.ToString(identity.Account))
	}
	if identity.Arn == nil || !roleMatches(aws.ToString(identity.Arn), role) {
		t.Fatalf("STS role %q does not match expected role", aws.ToString(identity.Arn))
	}
	if os.Getenv("KORDN_REALAWS_RESOURCE_TEST") == "1" {
		t.Run("resource", func(t *testing.T) { runResourceTest(t, ctx, account) })
	}
}

func roleMatches(actual, expected string) bool {
	if actual == expected {
		return true
	}
	name := expected
	if marker := strings.LastIndex(name, ":role/"); marker >= 0 {
		name = name[marker+len(":role/"):]
	}
	name = strings.TrimPrefix(name, "role/")
	return strings.HasSuffix(actual, ":role/"+name) || strings.Contains(actual, ":assumed-role/"+name+"/")
}

func runResourceTest(t *testing.T, parent context.Context, account string) {
	region := strings.TrimSpace(os.Getenv("KORDN_REALAWS_RESOURCE_REGION"))
	if region == "" {
		t.Fatal("resource test requires KORDN_REALAWS_RESOURCE_REGION")
	}
	cli := os.Getenv("KORDN_REALAWS_AWS_CLI")
	if cli == "" {
		cli = "aws"
	}
	version, err := exec.CommandContext(parent, cli, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "aws-cli/2.27.50") {
		t.Fatalf("AWS CLI must be exact 2.27.50: %v %q", err, version)
	}
	prefix := fmt.Sprintf("kordn-compat-%s-%d", account, time.Now().UnixNano())
	// Register cleanup before create, so a timeout or partial create still has
	// a bounded best-effort disposer.
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = exec.CommandContext(ctx, cli, "s3api", "delete-bucket", "--bucket", prefix, "--region", region).CombinedOutput()
	}
	t.Cleanup(cleanup)
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	createArgs := []string{"s3api", "create-bucket", "--bucket", prefix, "--region", region}
	if region != "us-east-1" {
		createArgs = append(createArgs, "--create-bucket-configuration", "LocationConstraint="+region)
	}
	if out, err := exec.CommandContext(ctx, cli, createArgs...).CombinedOutput(); err != nil {
		t.Fatalf("create low-risk resource: %v %q", err, out)
	}
	if out, err := exec.CommandContext(ctx, cli, "s3api", "head-bucket", "--bucket", prefix, "--region", region).CombinedOutput(); err != nil {
		t.Fatalf("read low-risk resource: %v %q", err, out)
	}
	if out, err := exec.CommandContext(ctx, cli, "s3api", "delete-bucket", "--bucket", prefix, "--region", region).CombinedOutput(); err != nil {
		t.Fatalf("delete low-risk resource: %v %q", err, out)
	}
}
