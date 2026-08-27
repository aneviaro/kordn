package iammap

import (
	"context"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
)

// crosscheckAdapter is a same-package test double. It wraps the real pinned
// adapter first, then introduces disagreement for the fail-closed checks.
type crosscheckAdapter struct {
	real          *iamliveadapter.Adapter
	primary       []iamliveadapter.Action
	dependencies  []iamliveadapter.DependencyCandidate
	certain       bool
	changePrimary bool
	changeDeps    bool
}

func (a crosscheckAdapter) Lookup(service, operation string, parameters ...map[string]awsrequest.Value) (iamliveadapter.LookupResult, error) {
	result, err := a.real.Lookup(service, operation, parameters...)
	if err != nil {
		return result, err
	}
	if a.changePrimary {
		result.Primary = a.primary
	}
	if a.changeDeps {
		result.Dependencies = a.dependencies
		result.DependenciesCertain = a.certain
	}
	return result, nil
}
func (a crosscheckAdapter) Version() string { return a.real.Version() }

func TestMapperRejectsInjectedPrimaryActionDisagreement(t *testing.T) {
	real, err := iamliveadapter.New()
	if err != nil {
		t.Fatal(err)
	}
	// The real adapter performs dependency expansion before this test double
	// changes the independent primary evidence.
	wrapped := crosscheckAdapter{
		real:          real,
		primary:       []iamliveadapter.Action{{Service: "ec2", Name: "TerminateInstances"}},
		changePrimary: true,
	}
	m, err := newMapperForTest(MapperOptions{}, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	req := goldenRequest("ec2", "ec2.us-east-1.amazonaws.com", "us-east-1", "DescribeInstances", nil)
	if result, err := m.Map(context.Background(), req); result != nil || err == nil {
		t.Fatalf("injected primary action was accepted: result=%+v err=%v", result, err)
	}
}

func TestMapperRejectsInjectedDependencyDisagreement(t *testing.T) {
	real, err := iamliveadapter.New()
	if err != nil {
		t.Fatal(err)
	}
	wrapped := crosscheckAdapter{real: real, changeDeps: true, certain: true}
	m, err := newMapperForTest(MapperOptions{}, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	req := goldenRequest("lambda", "lambda.us-east-1.amazonaws.com", "us-east-1", "CreateFunction", map[string]awsrequest.Value{
		"Role": str("arn:aws:iam::123456789012:role/app"),
	})
	if result, err := m.Map(context.Background(), req); result != nil || err == nil {
		t.Fatalf("injected dependency disagreement was accepted: result=%+v err=%v", result, err)
	}
}
