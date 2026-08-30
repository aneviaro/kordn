//go:build compat

package compatibility

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTerraformActualSandboxedApplyAndLaterDeniedOperation(t *testing.T) {
	const expectedAccountID = "123456789012"

	terraform := requirePinnedExecutable(t, "terraform")
	aws := requirePinnedExecutable(t, "awscli")
	mirror := os.Getenv("KORDN_TERRAFORM_MIRROR")
	if mirror == "" {
		if os.Getenv("KORDN_EXTERNAL_REQUIRED") == "1" {
			t.Fatal("external Terraform job must provide KORDN_TERRAFORM_MIRROR; network provider installation is forbidden")
		}
		t.Skip("Terraform external test requires KORDN_TERRAFORM_MIRROR; CI dynamically provisions the exact pinned provider mirror/cache")
	}
	// GetCallerIdentity is needed while Terraform initializes and plans. Keep
	// that operation allowed, and make the later local-exec resource use the
	// immutable, operation-distinct GetSessionToken deny rule.
	run := newFixtureRun(t, "GetSessionToken")
	dir := t.TempDir()
	writeFile := func(name, value string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("main.tf", `terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}
provider "aws" {
  region = "us-east-1"
  access_key = "`+run.fakeCred.AccessKeyID+`"
  secret_key = "`+run.fakeCred.SecretAccessKey+`"
  token = "`+run.fakeCred.SessionToken+`"
  skip_credentials_validation = true
  skip_requesting_account_id = true
  endpoints {
    sts = "`+run.endpoint()+`"
  }
}
data "aws_caller_identity" "current" {}
resource "terraform_data" "fixture_apply" {
  input = data.aws_caller_identity.current.account_id
}
`)
	writeFile(".terraformrc", `provider_installation {
  filesystem_mirror {
    path = "`+mirror+`"
  }
  direct {
    exclude = ["*/*"]
  }
}`)
	env := append(os.Environ(), run.env...)
	env = append(env, "TF_CLI_CONFIG_FILE="+filepath.Join(dir, ".terraformrc"), "TF_IN_AUTOMATION=1")
	init := run.command(t, terraform, "-chdir="+dir, "init", "-input=false")
	init.Env = env
	if output, err := runOutput(t, init); err != nil {
		t.Fatalf("terraform init failed: %v\n%s", err, output)
	}
	plan := run.command(t, terraform, "-chdir="+dir, "plan", "-input=false", "-out="+filepath.Join(dir, "plan.out"))
	plan.Env = env
	if output, err := runOutput(t, plan); err != nil {
		t.Fatalf("terraform plan failed: %v\n%s", err, output)
	}
	apply := run.command(t, terraform, "-chdir="+dir, "apply", "-input=false", "-auto-approve", filepath.Join(dir, "plan.out"))
	apply.Env = env
	if output, err := runOutput(t, apply); err != nil {
		t.Fatalf("terraform apply failed: %v\n%s", err, output)
	}
	run.assertLedgerAtLeast(t, "GetCallerIdentity", 1)
	run.assertAudit(t, "GetCallerIdentity", "allow")
	state := run.command(t, terraform, "-chdir="+dir, "state", "show", "terraform_data.fixture_apply")
	state.Env = env
	stateOutput, stateErr := runOutput(t, state)
	if stateErr != nil || !strings.Contains(string(stateOutput), "terraform_data.fixture_apply") || !containsTerraformStringAttribute(stateOutput, "input", expectedAccountID) {
		t.Fatalf("first Terraform apply did not persist fixture resource/account: err=%v output=%s", stateErr, stateOutput)
	}

	// Add a genuinely later resource only after the first apply completed. Its
	// child AWS CLI mutation is denied by the immutable fixture policy; the
	// previously applied terraform_data remains in state.
	writeFile("main.tf", `terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}
provider "aws" {
  region = "us-east-1"
  access_key = "`+run.fakeCred.AccessKeyID+`"
  secret_key = "`+run.fakeCred.SecretAccessKey+`"
  token = "`+run.fakeCred.SessionToken+`"
  skip_credentials_validation = true
  skip_requesting_account_id = true
  endpoints {
    sts = "`+run.endpoint()+`"
  }
}
data "aws_caller_identity" "current" {}
resource "terraform_data" "fixture_apply" {
  input = data.aws_caller_identity.current.account_id
}
resource "terraform_data" "later_denied_mutation" {
  input = "later-denied"
  provisioner "local-exec" {
    command = "`+aws+` sts get-session-token --duration-seconds 900 --endpoint-url https://`+fixtureHost+` --output json >/dev/null"
  }
}
`)
	beforeSession := run.ledgerCount("GetSessionToken")
	denied := run.command(t, terraform, "-chdir="+dir, "apply", "-input=false", "-auto-approve")
	denied.Env = env
	output, err := runOutput(t, denied)
	if err == nil || !strings.Contains(string(output), "AccessDenied") {
		t.Fatalf("later denied Terraform operation was not local: err=%v output=%s", err, output)
	}
	if afterSession := run.ledgerCount("GetSessionToken"); afterSession != beforeSession {
		t.Fatalf("denied Terraform mutation reached fakeAWS: before=%d after=%d ledger=%+v", beforeSession, afterSession, run.fake.Ledger())
	}
	run.assertLedger(t, "GetSessionToken", 0)

	// Inspect state only after the denied apply has failed. This proves the
	// successful first apply remains persisted, rather than merely checking
	// the state before Terraform attempted the denied operation.
	persisted := run.command(t, terraform, "-chdir="+dir, "state", "show", "terraform_data.fixture_apply")
	persisted.Env = env
	persistedOutput, persistedErr := runOutput(t, persisted)
	if persistedErr != nil || !strings.Contains(string(persistedOutput), "terraform_data.fixture_apply") || !containsTerraformStringAttribute(persistedOutput, "input", expectedAccountID) {
		t.Fatalf("denied Terraform apply changed or removed persisted fixture state: err=%v output=%s", persistedErr, persistedOutput)
	}

	run.assertLastAudit(t, "GetSessionToken", "deny")
	run.assertAudit(t, "GetCallerIdentity", "allow")
}

func containsTerraformStringAttribute(output []byte, name, value string) bool {
	pattern := `(?m)^\s*` + regexp.QuoteMeta(name) + `\s*=\s*"` + regexp.QuoteMeta(value) + `"\s*$`
	return regexp.MustCompile(pattern).Match(output)
}
