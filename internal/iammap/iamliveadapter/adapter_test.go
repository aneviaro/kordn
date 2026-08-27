package iamliveadapter

import (
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

func TestLookupUsesPinnedActionsAndInvokesDependencies(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Lookup("ec2", "DescribeInstances", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Primary) != 1 || result.Primary[0].Name != "DescribeInstances" || !result.DependenciesCertain {
		t.Fatalf("unexpected lookup result: %+v", result)
	}
}

func TestDependentActionsModelsPassRoleFromTypedParameters(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Lookup("lambda", "CreateFunction", map[string]awsrequest.Value{
		"Role": {Kind: awsrequest.ValueString, String: "arn:aws:iam::123456789012:role/app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Dependencies) != 1 || result.Dependencies[0].Action.Name != "PassRole" || result.Dependencies[0].Resources[0] == "" {
		t.Fatalf("missing PassRole candidate: %+v", result.Dependencies)
	}
	result, err = a.Lookup("lambda", "Invoke", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Dependencies) != 0 || !result.DependenciesCertain {
		t.Fatalf("nondependent operation was not proven empty: %+v", result)
	}
}
