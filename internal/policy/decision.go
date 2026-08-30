// Package policy owns the immutable policy-engine decision contract. The
// policy algorithm is implemented later; these types prevent other packages
// from inventing permissive, stringly typed outcomes.
package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/kordn-ai/kordn/internal/awserror"
	"github.com/kordn-ai/kordn/internal/awsrequest"
)

// DecisionResult has only the two V0.1 outcomes. There is no warn, learn, ask,
// or remote-approval result.
type DecisionResult string

const (
	DecisionAllow DecisionResult = "allow"
	DecisionDeny  DecisionResult = "deny"
)

func (r DecisionResult) Valid() bool { return r == DecisionAllow || r == DecisionDeny }

// DecisionInput is the immutable cross-package input to one policy
// evaluation. Request and Mapping are pointers to make absence explicit and
// fail closed; implementations must not mutate either value.
type DecisionInput struct {
	RunID         string                        `json:"run_id"`
	Endpoint      awsrequest.AWSEndpoint        `json:"endpoint"`
	Request       *awsrequest.DecodedAWSRequest `json:"request"`
	Mapping       *awsrequest.MappingResult     `json:"mapping"`
	PolicyHash    string                        `json:"policy_hash"`
	MapperVersion string                        `json:"mapper_version"`
}

// Validate checks the cross-package decision boundary without evaluating a
// policy. A future engine should call this before looking at any requirement;
// absent or malformed input is never an implicit allow.
func (i DecisionInput) Validate() error {
	if i.RunID == "" || i.PolicyHash == "" || i.MapperVersion == "" {
		return errors.New("run, policy hash, and mapper version are required")
	}
	if err := i.Endpoint.Validate(); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if i.Request == nil || i.Mapping == nil {
		return errors.New("request and mapping are required")
	}
	if err := i.Request.Validate(); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if err := i.Mapping.Validate(); err != nil {
		return fmt.Errorf("mapping: %w", err)
	}
	if i.Request.Partition != i.Endpoint.Partition || i.Request.EndpointHost != i.Endpoint.Host || i.Request.Service != i.Endpoint.Service {
		return errors.New("request endpoint does not match decision endpoint")
	}
	if i.Mapping.Service != i.Request.Service || i.Mapping.Operation != i.Request.Operation {
		return errors.New("mapping service and operation do not match decoded request")
	}
	if i.Mapping.MapperVersion != i.MapperVersion {
		return errors.New("mapper version does not match mapping")
	}
	return nil
}

// Decision is the complete local result. ReasonCode is a closed awserror value
// and matched rule IDs are explanatory audit data, not a second result.
type Decision struct {
	Result         DecisionResult      `json:"result"`
	ReasonCode     awserror.ReasonCode `json:"reason_code"`
	MatchedRuleIDs []string            `json:"matched_rule_ids"`
}

func (d Decision) Valid() bool {
	if !d.Result.Valid() || !d.ReasonCode.Valid() {
		return false
	}
	if d.Result == DecisionAllow {
		return d.ReasonCode == awserror.ReasonAllRequirementsAllowed
	}
	return d.ReasonCode != awserror.ReasonAllRequirementsAllowed
}

// PolicyEngine evaluates one authenticated, mapped request synchronously.
type PolicyEngine interface {
	Evaluate(ctx context.Context, input DecisionInput) Decision
}
