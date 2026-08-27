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

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kordn-ai/kordn/internal/awserror"
	"github.com/kordn-ai/kordn/internal/awsrequest"
)

const (
	maxPolicyRules        = 10_000
	maxRuleValues         = 1_000
	maxRequirements       = 1_000
	maxRequirementValues  = 1_000
	maxMapperTextLength   = 512
	maxConditionHintItems = 1_000
	maxEvaluationCombos   = 100_000
)

type compiledRule struct {
	id                       string
	effect                   string
	actions                  []Glob
	resources                []Glob
	regions, accounts        map[string]struct{}
	partitions               map[string]struct{}
	allowAWSRequiredWildcard bool
}

// Engine is an immutable policy snapshot. NewEngine copies every policy slice
// and compiles every pattern, so a caller can safely reuse or mutate the
// config object after construction.
type Engine struct {
	defaultDeny bool
	rules       []compiledRule
	hash        string
}

// NewEngine validates and snapshots a configuration policy. The parameter is
// interface-shaped to avoid a config<->policy test import cycle. The accepted
// value is config.Policy (or a pointer to it); all fields are copied here.
func NewEngine(input interface{}) (*Engine, error) {
	policy, err := copyPolicy(input)
	if err != nil {
		return nil, err
	}
	if policy.defaultValue != "deny" {
		return nil, errors.New("policy default must be deny")
	}
	if len(policy.rules) > maxPolicyRules {
		return nil, errors.New("policy has too many rules")
	}
	engine := &Engine{defaultDeny: true, rules: make([]compiledRule, 0, len(policy.rules))}
	seenIDs := make(map[string]struct{}, len(policy.rules))
	for index, source := range policy.rules {
		rule, err := compileRule(source)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", index, err)
		}
		if _, ok := seenIDs[rule.id]; ok {
			return nil, fmt.Errorf("rule %q is duplicated", rule.id)
		}
		seenIDs[rule.id] = struct{}{}
		engine.rules = append(engine.rules, rule)
	}
	sort.Slice(engine.rules, func(i, j int) bool { return engine.rules[i].id < engine.rules[j].id })
	engine.hash, err = snapshotPolicyHash(policy)
	if err != nil {
		return nil, fmt.Errorf("policy hash: %w", err)
	}
	return engine, nil
}

// NewPolicyEngine is the constructor named by the PolicyEngine contract.
func NewPolicyEngine(policy interface{}) (*Engine, error) { return NewEngine(policy) }

// PolicyHash returns the canonical hash captured by this immutable snapshot.
func (e *Engine) PolicyHash() string {
	if e == nil {
		return ""
	}
	return e.hash
}
func (e *Engine) Hash() string { return e.PolicyHash() }

// New is a concise constructor alias for embedding packages.
func New(policy interface{}) (*Engine, error) { return NewEngine(policy) }

type policySnapshot struct {
	defaultValue string
	rules        []ruleSnapshot
}
type ruleSnapshot struct {
	ID, Effect                                        string
	Actions, Resources, Regions, Accounts, Partitions []string
	Wildcard                                          bool
}

func copyPolicy(input interface{}) (policySnapshot, error) {
	value := reflect.ValueOf(input)
	if !value.IsValid() {
		return policySnapshot{}, errors.New("policy is nil")
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return policySnapshot{}, errors.New("policy is nil")
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return policySnapshot{}, errors.New("policy must be a struct")
	}
	defaultField, rulesField := value.FieldByName("Default"), value.FieldByName("Rules")
	if !defaultField.IsValid() || defaultField.Kind() != reflect.String || !rulesField.IsValid() || rulesField.Kind() != reflect.Slice {
		return policySnapshot{}, errors.New("unsupported policy type")
	}
	result := policySnapshot{defaultValue: defaultField.String(), rules: make([]ruleSnapshot, 0, rulesField.Len())}
	for i := 0; i < rulesField.Len(); i++ {
		rv := rulesField.Index(i)
		if rv.Kind() == reflect.Pointer {
			if rv.IsNil() {
				return policySnapshot{}, errors.New("nil rule")
			}
			rv = rv.Elem()
		}
		if rv.Kind() != reflect.Struct {
			return policySnapshot{}, errors.New("rule must be a struct")
		}
		rule := ruleSnapshot{}
		var err error
		if rule.ID, err = stringField(rv, "ID"); err != nil {
			return policySnapshot{}, err
		}
		if rule.Effect, err = stringField(rv, "Effect"); err != nil {
			return policySnapshot{}, err
		}
		if rule.Actions, err = stringSliceField(rv, "Actions"); err != nil {
			return policySnapshot{}, err
		}
		if rule.Resources, err = stringSliceField(rv, "Resources"); err != nil {
			return policySnapshot{}, err
		}
		if rule.Regions, err = stringSliceField(rv, "Regions"); err != nil {
			return policySnapshot{}, err
		}
		if rule.Accounts, err = stringSliceField(rv, "Accounts"); err != nil {
			return policySnapshot{}, err
		}
		if rule.Partitions, err = stringSliceField(rv, "Partitions"); err != nil {
			return policySnapshot{}, err
		}
		flag := rv.FieldByName("AllowAWSRequiredWildcard")
		if !flag.IsValid() || flag.Kind() != reflect.Bool {
			return policySnapshot{}, errors.New("rule wildcard field is invalid")
		}
		rule.Wildcard = flag.Bool()
		result.rules = append(result.rules, rule)
	}
	return result, nil
}
func stringField(v reflect.Value, name string) (string, error) {
	f := v.FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.String {
		return "", fmt.Errorf("rule %s field is invalid", name)
	}
	return f.String(), nil
}
func stringSliceField(v reflect.Value, name string) ([]string, error) {
	f := v.FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.Slice {
		return nil, fmt.Errorf("rule %s field is invalid", name)
	}
	out := make([]string, f.Len())
	for i := range out {
		if f.Index(i).Kind() != reflect.String {
			return nil, fmt.Errorf("rule %s values are invalid", name)
		}
		out[i] = f.Index(i).String()
	}
	return out, nil
}

func snapshotPolicyHash(policy policySnapshot) (string, error) {
	type canonicalRule struct {
		ID         string   `json:"id"`
		Effect     string   `json:"effect"`
		Actions    []string `json:"actions"`
		Resources  []string `json:"resources"`
		Regions    []string `json:"regions"`
		Accounts   []string `json:"accounts"`
		Partitions []string `json:"partitions"`
		Wildcard   bool     `json:"allowAwsRequiredWildcard"`
	}
	canonical := struct {
		Default string          `json:"default"`
		Rules   []canonicalRule `json:"rules"`
	}{Default: policy.defaultValue, Rules: make([]canonicalRule, 0, len(policy.rules))}
	for _, r := range policy.rules {
		canonical.Rules = append(canonical.Rules, canonicalRule{r.ID, r.Effect, normalizeValues(r.Actions, true), normalizeValues(r.Resources, false), normalizeValues(r.Regions, false), normalizeValues(r.Accounts, false), normalizeValues(r.Partitions, false), r.Wildcard})
	}
	sort.Slice(canonical.Rules, func(i, j int) bool { return canonical.Rules[i].ID < canonical.Rules[j].ID })
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", digest[:]), nil
}
func normalizeValues(values []string, lower bool) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if lower {
			value = asciiLower(value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func compileRule(source ruleSnapshot) (compiledRule, error) {
	if len(source.ID) == 0 || len(source.ID) > 128 || !validIdentifier(source.ID, true) {
		return compiledRule{}, errors.New("rule ID is invalid")
	}
	if source.Effect != "allow" && source.Effect != "deny" {
		return compiledRule{}, errors.New("rule effect is invalid")
	}
	if source.Effect == "deny" && source.Wildcard {
		return compiledRule{}, errors.New("wildcard acknowledgement is only valid on allow rules")
	}
	if len(source.Actions) == 0 || len(source.Actions) > maxRuleValues || len(source.Resources) == 0 || len(source.Resources) > maxRuleValues {
		return compiledRule{}, errors.New("rule action and resource lists are out of bounds")
	}
	result := compiledRule{id: source.ID, effect: source.Effect, allowAWSRequiredWildcard: source.Wildcard,
		regions: make(map[string]struct{}, len(source.Regions)), accounts: make(map[string]struct{}, len(source.Accounts)), partitions: make(map[string]struct{}, len(source.Partitions))}
	seenActions := make(map[string]struct{}, len(source.Actions))
	for _, value := range source.Actions {
		key := asciiLower(value)
		if _, ok := seenActions[key]; ok {
			return compiledRule{}, errors.New("rule actions contain duplicates")
		}
		seenActions[key] = struct{}{}
		glob, err := CompileActionGlob(value)
		if err != nil {
			return compiledRule{}, fmt.Errorf("action: %w", err)
		}
		result.actions = append(result.actions, glob)
	}
	seenResources := make(map[string]struct{}, len(source.Resources))
	for _, value := range source.Resources {
		if _, ok := seenResources[value]; ok {
			return compiledRule{}, errors.New("rule resources contain duplicates")
		}
		seenResources[value] = struct{}{}
		glob, err := CompileGlob(value)
		if err != nil {
			return compiledRule{}, fmt.Errorf("resource: %w", err)
		}
		result.resources = append(result.resources, glob)
	}
	if err := compileConstraintSet(source.Regions, result.regions, "region", validRegion); err != nil {
		return compiledRule{}, err
	}
	if err := compileConstraintSet(source.Accounts, result.accounts, "account", validAccount); err != nil {
		return compiledRule{}, err
	}
	if err := compileConstraintSet(source.Partitions, result.partitions, "partition", validPartition); err != nil {
		return compiledRule{}, err
	}
	return result, nil
}

func compileConstraintSet(values []string, destination map[string]struct{}, label string, valid func(string) bool) error {
	if len(values) > maxRuleValues {
		return fmt.Errorf("%s constraints exceed limit", label)
	}
	for _, value := range values {
		if value == "" || !valid(value) {
			return fmt.Errorf("invalid %s constraint", label)
		}
		if _, ok := destination[value]; ok {
			return fmt.Errorf("duplicate %s constraint", label)
		}
		destination[value] = struct{}{}
	}
	return nil
}

func validIdentifier(value string, allowPunctuation bool) bool {
	for i, r := range value {
		if i == 0 && !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		if allowPunctuation && (r == '.' || r == '_' || r == '-') {
			continue
		}
		return false
	}
	return true
}

func validRegion(value string) bool {
	if len(value) > maxMapperTextLength || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	if value[len(value)-1] < '0' || value[len(value)-1] > '9' {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return strings.ContainsRune(value, '-')
}
func validAccount(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func validPartition(value string) bool {
	switch value {
	case "aws", "aws-us-gov", "aws-cn", "aws-iso", "aws-iso-b", "aws-iso-f":
		return true
	}
	return false
}

func (e *Engine) Evaluate(ctx context.Context, input DecisionInput) Decision {
	if e == nil || ctx == nil {
		return internalDecision()
	}
	if err := ctx.Err(); err != nil {
		return internalDecision()
	}
	if err := input.Validate(); err != nil {
		return internalDecision()
	}
	if input.PolicyHash != e.hash {
		return internalDecision()
	}
	if input.Mapping.Confidence != awsrequest.ConfidenceHigh {
		return Decision{Result: DecisionDeny, ReasonCode: awserror.ReasonMappingLowConfidence}
	}
	if err := validateEvaluationInput(input); err != nil {
		return internalDecision()
	}

	requirements := snapshotRequirements(input.Mapping.Requirements)
	for _, requirement := range requirements {
		if requirement.ScopeKind == awsrequest.ScopeUnresolved {
			if requirement.Dependent {
				return Decision{Result: DecisionDeny, ReasonCode: awserror.ReasonDependentPermissionUnresolved}
			}
			return Decision{Result: DecisionDeny, ReasonCode: awserror.ReasonResourceUnresolved}
		}
	}

	matched := make(map[string]struct{})
	wildcardMissing, uncovered, explicitDeny := false, false, false
	for _, requirement := range requirements {
		for _, resource := range requirement.Resources {
			if err := ctx.Err(); err != nil {
				return internalDecision()
			}
			covered, sawUnacknowledged := false, false
			for ruleIndex, rule := range e.rules {
				// Check periodically inside the rule scan as well as at the
				// resource boundary. A large immutable snapshot must still
				// stop promptly when its caller is cancelled.
				if ruleIndex&63 == 0 {
					if err := ctx.Err(); err != nil {
						return internalDecision()
					}
				}
				if !ruleMatches(rule, requirement.Action, resource, requirement.ScopeKind, input) {
					continue
				}
				matched[rule.id] = struct{}{}
				if rule.effect == "deny" {
					explicitDeny = true
					continue
				}
				if requirement.ScopeKind == awsrequest.ScopeKnownGlobal {
					if rule.allowAWSRequiredWildcard && ruleHasLiteralStar(rule.resources) {
						covered = true
					} else {
						sawUnacknowledged = true
					}
				} else {
					covered = true
				}
			}
			if !covered {
				if sawUnacknowledged {
					wildcardMissing = true
				} else {
					uncovered = true
				}
			}
		}
	}
	if explicitDeny {
		return Decision{Result: DecisionDeny, ReasonCode: awserror.ReasonExplicitDeny, MatchedRuleIDs: sortedIDs(matched)}
	}
	if wildcardMissing {
		return Decision{Result: DecisionDeny, ReasonCode: awserror.ReasonAWSRequiredWildcardNotApproved, MatchedRuleIDs: sortedIDs(matched)}
	}
	if uncovered {
		return Decision{Result: DecisionDeny, ReasonCode: awserror.ReasonPolicyNoMatchingAllow, MatchedRuleIDs: sortedIDs(matched)}
	}
	if err := ctx.Err(); err != nil {
		return internalDecision()
	}
	return Decision{Result: DecisionAllow, ReasonCode: awserror.ReasonAllRequirementsAllowed, MatchedRuleIDs: sortedIDs(matched)}
}

func internalDecision() Decision {
	return Decision{Result: DecisionDeny, ReasonCode: awserror.ReasonInternalFailClosed}
}

func snapshotRequirements(values []awsrequest.IAMRequirement) []awsrequest.IAMRequirement {
	result := make([]awsrequest.IAMRequirement, len(values))
	copy(result, values)
	for i := range result {
		result[i].Resources = append([]string(nil), values[i].Resources...)
		sort.Strings(result[i].Resources)
	}
	sort.Slice(result, func(i, j int) bool { return requirementKey(result[i]) < requirementKey(result[j]) })
	return result
}
func requirementKey(r awsrequest.IAMRequirement) string {
	return asciiLower(r.Action) + "\x00" + string(r.ScopeKind) + "\x00" + fmt.Sprint(r.Dependent) + "\x00" + strings.Join(r.Resources, "\x00")
}
func sortedIDs(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for id := range values {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func ruleHasLiteralStar(resources []Glob) bool {
	for _, resource := range resources {
		if resource.pattern == "*" {
			return true
		}
	}
	return false
}

// ruleMatches deliberately obtains constraints from the resource identity.
// ARN fields are authoritative, including empty Region and account fields; a
// request's endpoint and caller identity must not turn a global or accountless
// ARN into a regional or account-scoped resource. The sole non-ARN context
// supported here is the mapper's known-global "*" resource, for which the
// request/endpoint context is the only available identity evidence.
func ruleMatches(rule compiledRule, action, resource string, scope awsrequest.ScopeKind, input DecisionInput) bool {
	actionOK := false
	for _, glob := range rule.actions {
		if glob.Match(action) {
			actionOK = true
			break
		}
	}
	if !actionOK {
		return false
	}
	resourceOK := false
	for _, glob := range rule.resources {
		if glob.Match(resource) {
			resourceOK = true
			break
		}
	}
	if !resourceOK {
		return false
	}
	if strings.HasPrefix(resource, "arn:") {
		arn, err := parseARN(resource)
		if err != nil || arn.partition != input.Request.Partition {
			return false
		}
		// Empty ARN fields are meaningful. In particular, IAM ARNs have no
		// Region and S3 ARNs have no account; neither may inherit the request
		// context for a constrained rule. A non-empty regional ARN must still
		// belong to the request's endpoint Region, preventing cross-region
		// authorization; that consistency check is separate from constraint
		// evaluation and does not provide a fallback value.
		if arn.region != "" && arn.region != input.Request.Region {
			return false
		}
		return constraintMatches(rule.regions, arn.region) &&
			constraintMatches(rule.accounts, arn.account) &&
			constraintMatches(rule.partitions, arn.partition)
	}

	// "*" is a known-global resource, not an ARN. Its scope is explicitly
	// supplied by the mapper, so request/endpoint context is valid here. All
	// other non-ARN exact resources lack proven Region/account/partition
	// context and fail closed when constraints are present.
	if resource == "*" && scope == awsrequest.ScopeKnownGlobal {
		return constraintMatches(rule.regions, input.Request.Region) &&
			constraintMatches(rule.accounts, input.Request.CallerAccountID) &&
			constraintMatches(rule.partitions, input.Request.Partition)
	}
	if len(rule.regions) != 0 || len(rule.accounts) != 0 || len(rule.partitions) != 0 {
		return false
	}
	return true
}
func constraintMatches(values map[string]struct{}, value string) bool {
	if len(values) == 0 {
		return true
	}
	_, ok := values[value]
	return ok
}

type arnContext struct{ partition, service, region, account, resource string }

func parseARN(value string) (arnContext, error) {
	parts := strings.SplitN(value, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || !validPartition(parts[1]) || parts[2] == "" || parts[5] == "" {
		return arnContext{}, errors.New("malformed ARN")
	}
	if parts[3] != "" && !validRegion(parts[3]) {
		return arnContext{}, errors.New("malformed ARN region")
	}
	if parts[4] != "" && !validAccount(parts[4]) {
		return arnContext{}, errors.New("malformed ARN account")
	}
	for _, r := range parts[2] {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
			return arnContext{}, errors.New("malformed ARN service")
		}
	}
	return arnContext{parts[1], parts[2], parts[3], parts[4], parts[5]}, nil
}

func validateEvaluationInput(input DecisionInput) error {
	if len(input.Mapping.Requirements) == 0 || len(input.Mapping.Requirements) > maxRequirements {
		return errors.New("requirements are out of bounds")
	}
	if len(input.Mapping.Service) > maxMapperTextLength || len(input.Mapping.Operation) > maxMapperTextLength || len(input.Mapping.MapperVersion) > maxMapperTextLength {
		return errors.New("mapping text is out of bounds")
	}
	combos := 0
	for _, requirement := range input.Mapping.Requirements {
		if len(requirement.Action) == 0 || len(requirement.Action) > MaxGlobLength || strings.ContainsAny(requirement.Action, "*?") {
			return errors.New("requirement action is out of bounds or not concrete")
		}
		if _, err := CompileActionGlob(requirement.Action); err != nil {
			return err
		}
		if len(requirement.Resources) > maxRequirementValues {
			return errors.New("requirement resources are out of bounds")
		}
		combos += len(requirement.Resources)
		if combos > maxEvaluationCombos {
			return errors.New("requirement combinations exceed limit")
		}
		parts := strings.SplitN(requirement.Action, ":", 2)
		if len(parts) != 2 || (!requirement.Dependent && !strings.EqualFold(parts[0], input.Mapping.Service)) {
			return errors.New("requirement action service disagrees with mapping")
		}
		for _, resource := range requirement.Resources {
			if len(resource) == 0 || len(resource) > MaxGlobLength || !utf8.ValidString(resource) {
				return errors.New("requirement resource is out of bounds")
			}
			for _, r := range resource {
				if unicode.IsControl(r) {
					return errors.New("requirement resource contains control syntax")
				}
			}
			if strings.HasPrefix(resource, "arn:") {
				if _, err := parseARN(resource); err != nil {
					return err
				}
			}
		}
		if len(requirement.ConditionHint) > maxConditionHintItems {
			return errors.New("condition hints are out of bounds")
		}
		for key, values := range requirement.ConditionHint {
			if len(key) == 0 || len(key) > MaxGlobLength || !utf8.ValidString(key) || len(values) > maxRequirementValues {
				return errors.New("condition hint is out of bounds")
			}
			for _, value := range values {
				if len(value) > MaxGlobLength || !utf8.ValidString(value) {
					return errors.New("condition hint value is out of bounds")
				}
			}
		}
	}
	if (input.Endpoint.IsGlobal()) != (input.Request.Region == "") || input.Endpoint.Region != input.Request.Region {
		return errors.New("endpoint and request scope disagree")
	}
	return nil
}
