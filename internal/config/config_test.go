package config

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/internal/awserror"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/policy"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

func TestLoadValidDefaultsAndRoundTrip(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream.Profile != "kordn-prod-ceiling" || cfg.Upstream.Region != "us-east-1" {
		t.Fatalf("unexpected upstream: %#v", cfg.Upstream)
	}
	if cfg.Proxy.Listen != DefaultListen || cfg.Proxy.MaxInMemoryBodyBytes != DefaultMaxInMemoryBodyBytes || cfg.Proxy.MaxSpoolBodyBytes != DefaultMaxSpoolBodyBytes {
		t.Fatalf("defaults were not applied: %#v", cfg.Proxy)
	}
	if cfg.Policy.Default != PolicyDeny || cfg.Audit.Fsync != FsyncBatch || cfg.Audit.FailureMode != AuditDeny {
		t.Fatalf("secure defaults were not applied: policy=%#v audit=%#v", cfg.Policy, cfg.Audit)
	}
	if cfg.PolicyHash == "" || !strings.HasPrefix(cfg.PolicyHash, "sha256:") {
		t.Fatalf("missing policy hash %q", cfg.PolicyHash)
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Config
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if err := roundTrip.Validate(); err != nil {
		t.Fatalf("JSON round-trip did not preserve valid typed config: %v", err)
	}
	hash, err := PolicyHash(roundTrip.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if hash != cfg.PolicyHash {
		t.Fatalf("policy hash changed after round-trip: %s != %s", hash, cfg.PolicyHash)
	}
}

func TestLoadPublishedExample(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "examples", "policies", "deny-by-default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Policy.Rules) != 0 || cfg.Policy.Default != PolicyDeny {
		t.Fatalf("published example is not deny by default: %#v", cfg.Policy)
	}
	if cfg.Audit.Path == "" || !filepath.IsAbs(cfg.Audit.Path) {
		t.Fatalf("audit path was not normalized: %q", cfg.Audit.Path)
	}
}

func TestSchemaCheck(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate config package")
	}
	root := filepath.Join(filepath.Dir(sourceFile), "..", "..")
	configSchema := compileSchema(t, filepath.Join(root, "api", "config.schema.json"))
	auditSchema := compileSchema(t, filepath.Join(root, "api", "audit.schema.json"))

	for _, name := range []string{"deny-by-default.yaml", "aws-cli-read-only.yaml"} {
		data, err := os.ReadFile(filepath.Join(root, "examples", "policies", name))
		if err != nil {
			t.Fatal(err)
		}
		instance := yamlJSONInstance(t, data)
		if err := configSchema.Validate(instance); err != nil {
			t.Fatalf("published example %s does not validate against config schema: %v", name, err)
		}
	}

	for _, tc := range auditSchemaFixtures() {
		t.Run("audit/"+tc.name, func(t *testing.T) {
			err := auditSchema.Validate(tc.instance)
			if tc.valid && err != nil {
				t.Fatalf("valid audit event rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("invalid audit event was accepted")
			}
		})
	}

	// JSON Schema has no portable uniqueBy or cross-property comparison
	// keyword. The repository's pinned schema gate therefore runs the same
	// strict Config.Load semantic phase for these direct fixtures. This makes
	// make schema-check predict startup acceptance rather than merely checking
	// the structural subset expressible by JSON Schema.
	for _, tc := range configSchemaFixtures() {
		t.Run("config/"+tc.name, func(t *testing.T) {
			schErr, loadErr := validateConfigFixture(t, configSchema, tc.yaml)
			if tc.valid {
				if schErr != nil || loadErr != nil {
					t.Fatalf("valid fixture rejected: schema=%v load=%v", schErr, loadErr)
				}
				return
			}
			if loadErr == nil {
				t.Fatal("invalid fixture was accepted by Config.Load")
			}
			if tc.schemaReject != (schErr != nil) {
				t.Fatalf("schema/semantic phase mismatch: schema=%v load=%v", schErr, loadErr)
			}
		})
	}

	assertSchemaEnum(t, filepath.Join(root, "api", "audit.schema.json"),
		[]string{
			string(awserror.ReasonExplicitDeny),
			string(awserror.ReasonPolicyNoMatchingAllow),
			string(awserror.ReasonAWSRequiredWildcardNotApproved),
			string(awserror.ReasonUnknownEndpoint),
			string(awserror.ReasonUnsupportedPartition),
			string(awserror.ReasonUnknownOperation),
			string(awserror.ReasonMappingLowConfidence),
			string(awserror.ReasonResourceUnresolved),
			string(awserror.ReasonDependentPermissionUnresolved),
			string(awserror.ReasonInvalidInboundSignature),
			string(awserror.ReasonUnsupportedSigningScheme),
			string(awserror.ReasonUnsupportedPayloadMode),
			string(awserror.ReasonRequestTooLarge),
			string(awserror.ReasonAuditUnavailable),
			string(awserror.ReasonUpstreamCredentialUnavailable),
			string(awserror.ReasonUpstreamTransportError),
			string(awserror.ReasonInternalFailClosed),
			string(awserror.ReasonAllRequirementsAllowed),
		},
	)
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	sch, err := compiler.Compile(path)
	if err != nil {
		t.Fatalf("compile schema %s: %v", path, err)
	}
	return sch
}

func yamlJSONInstance(t *testing.T, data []byte) any {
	t.Helper()
	var yamlValue any
	if err := yaml.Unmarshal(data, &yamlValue); err != nil {
		t.Fatalf("decode YAML fixture: %v", err)
	}
	jsonData, err := json.Marshal(yamlValue)
	if err != nil {
		t.Fatalf("marshal YAML fixture: %v", err)
	}
	var instance any
	if err := json.Unmarshal(jsonData, &instance); err != nil {
		t.Fatalf("decode JSON fixture: %v", err)
	}
	return instance
}

type configSchemaFixture struct {
	name         string
	yaml         string
	valid        bool
	schemaReject bool
}

func configSchemaFixtures() []configSchemaFixture {
	const prefix = "apiVersion: kordn.dev/v1alpha1\nkind: LocalRunPolicy\n"
	const upstream = "upstream:\n  profile: kordn-prod-ceiling\n  region: us-east-1\n"
	return []configSchemaFixture{
		{name: "absent-defaulted-sections", yaml: prefix + upstream, valid: true},
		{name: "audit-defaults", yaml: prefix + upstream + "audit: {}\n", valid: true},
		{name: "audit-ordinary-redaction", yaml: prefix + upstream + "audit:\n  logResourceArns: true\n  hashResourceNames: false\n", valid: true},
		{name: "audit-hash-with-explicit-redaction", yaml: prefix + upstream + "audit:\n  logResourceArns: false\n  hashResourceNames: true\n", valid: true},
		{name: "audit-hash-with-default-log-redaction", yaml: prefix + upstream + "audit:\n  hashResourceNames: true\n", schemaReject: true},
		{name: "optional-role-identities", yaml: prefix + "upstream:\n  profile: kordn-prod-ceiling\n  region: us-east-1\n  assumeRoleArn: arn:aws:iam::123456789012:role/ceiling\n  externalId: external-value\n  sourceIdentity: source-value\n", valid: true},
		{name: "invalid-port", yaml: prefix + upstream + "proxy:\n  listen: 127.0.0.1:99999\n", schemaReject: true},
		{name: "spool-less-than-memory", yaml: prefix + upstream + "proxy:\n  maxInMemoryBodyBytes: 8388608\n  maxSpoolBodyBytes: 8388607\n", schemaReject: false},
		{name: "spool-default-less-than-memory", yaml: prefix + upstream + "proxy:\n  maxSpoolBodyBytes: 1\n", schemaReject: false},
		{name: "external-id-without-role", yaml: prefix + upstream + "  externalId: external-value\n", schemaReject: true},
		{name: "source-identity-with-empty-role", yaml: prefix + "upstream:\n  profile: kordn-prod-ceiling\n  region: us-east-1\n  assumeRoleArn: \"\"\n  sourceIdentity: source-value\n", schemaReject: true},
		{name: "duplicate-rule-id", yaml: prefix + upstream + "policy:\n  rules:\n    - id: same-rule\n      effect: allow\n      actions: [s3:GetObject]\n      resources: [\"*\"]\n    - id: same-rule\n      effect: deny\n      actions: [s3:PutObject]\n      resources: [\"*\"]\n", schemaReject: false},
		{name: "duplicate-region-constraint", yaml: prefix + upstream + "policy:\n  rules:\n    - id: duplicate-region\n      effect: allow\n      actions: [s3:GetObject]\n      resources: [\"*\"]\n      regions: [us-east-1, us-east-1]\n", schemaReject: true},
		{name: "unknown-field", yaml: prefix + upstream + "unknown: value\n", schemaReject: true},
	}
}

func validateConfigFixture(t *testing.T, sch *jsonschema.Schema, data string) (schemaErr, loadErr error) {
	t.Helper()
	schemaErr = sch.Validate(yamlJSONInstance(t, []byte(data)))
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	_, loadErr = Load(path)
	return schemaErr, loadErr
}

type auditSchemaFixture struct {
	name     string
	instance any
	valid    bool
}

func auditSchemaFixtures() []auditSchemaFixture {
	valid := map[string]any{
		"schema_version": "kordn.audit/v1",
		"event_id":       "evt_test",
		"run_id":         "run_test",
		"timestamp":      "2026-08-17T15:04:05.123456Z",
		"event_type":     "aws.request.decision",
		"connection_id":  "conn_test",
		"request": map[string]any{
			"host": "ecs.eu-west-1.amazonaws.com", "partition": "aws", "service": "ecs",
			"operation": "UpdateService", "region": "eu-west-1", "protocol": "json1.1",
			"method": "POST", "payload_bytes": 198,
		},
		"iam_requirements": []any{map[string]any{
			"action": "ecs:UpdateService", "resources": []any{"arn:aws:ecs:eu-west-1:123456789012:service/prod/checkout"},
			"scope_kind": "exact", "dependent": false,
		}},
		"mapping":   map[string]any{"confidence": "high", "mapper_version": "mapper-test"},
		"decision":  map[string]any{"result": "allow", "reason_code": "all_requirements_allowed", "matched_rule_ids": []any{"allow-one"}, "policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		"timing_ms": map[string]any{"decode": 0.1, "map": 0.2, "policy": 0.1, "local_total": 0.5},
	}
	withDecision := func(result, reason string) map[string]any {
		event := cloneMap(valid)
		decision := cloneMap(valid["decision"].(map[string]any))
		decision["result"] = result
		decision["reason_code"] = reason
		event["decision"] = decision
		return event
	}
	validDeny := withDecision("deny", "explicit_deny")
	invalidAllowReason := withDecision("allow", "explicit_deny")
	invalidDenyReason := withDecision("deny", "all_requirements_allowed")
	unknown := cloneMap(valid)
	unknown["authorization"] = "secret-like-field"
	invalidEnum := cloneMap(valid)
	invalidEnum["event_type"] = "aws.request.maybe"
	return []auditSchemaFixture{
		{name: "valid-decision", instance: valid, valid: true},
		{name: "valid-deny-decision", instance: validDeny, valid: true},
		{name: "invalid-allow-denial-reason", instance: invalidAllowReason, valid: false},
		{name: "invalid-deny-success-reason", instance: invalidDenyReason, valid: false},
		{name: "unknown-secret-like-field", instance: unknown, valid: false},
		{name: "invalid-event-enum", instance: invalidEnum, valid: false},
	}
}

func cloneMap(source map[string]any) map[string]any {
	copy := make(map[string]any, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func assertSchemaEnum(t *testing.T, path string, want []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	properties, ok := document["properties"].(map[string]any)
	if !ok {
		t.Fatal("schema has no properties")
	}
	decision, ok := properties["decision"].(map[string]any)
	if !ok {
		t.Fatal("audit schema has no decision property")
	}
	decisionProperties, ok := decision["properties"].(map[string]any)
	if !ok {
		t.Fatal("decision schema has no properties")
	}
	reason, ok := decisionProperties["reason_code"].(map[string]any)
	if !ok {
		t.Fatal("decision schema has no reason_code property")
	}
	enum, ok := reason["enum"].([]any)
	if !ok || len(enum) != len(want) {
		t.Fatalf("reason enum has wrong shape or length: %#v", reason["enum"])
	}
	for i, expected := range want {
		value, ok := enum[i].(string)
		if !ok || value != expected {
			t.Fatalf("reason enum[%d] = %#v, want %q", i, enum[i], expected)
		}
	}
}

func TestPolicyHashIsOrderIndependent(t *testing.T) {
	first := Policy{
		Default: PolicyDeny,
		Rules: []Rule{
			{ID: "z", Effect: EffectAllow, Actions: []string{"S3:GetObject", "s3:GetObject"}, Resources: []string{"b", "a"}, Regions: []string{"us-east-1", "eu-west-1"}},
			{ID: "a", Effect: EffectDeny, Actions: []string{"iam:*"}, Resources: []string{"*"}},
		},
	}
	second := Policy{
		Default: PolicyDeny,
		Rules: []Rule{
			{ID: "a", Effect: EffectDeny, Actions: []string{"iam:*"}, Resources: []string{"*"}},
			{ID: "z", Effect: EffectAllow, Actions: []string{"s3:getobject"}, Resources: []string{"a", "b"}, Regions: []string{"eu-west-1", "us-east-1"}},
		},
	}
	one, err := PolicyHash(first)
	if err != nil {
		t.Fatal(err)
	}
	two, err := PolicyHash(second)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatalf("semantically equal policies have different hashes: %s != %s", one, two)
	}
	if first.Rules[0].Actions[0] != "S3:GetObject" {
		t.Fatal("canonicalization mutated the input policy")
	}
}

func TestMalformedFixturesFailDeterministically(t *testing.T) {
	fixtures := []string{
		"unknown-field.yaml",
		"unsafe-listener.yaml",
		"absent-profile.yaml",
		"unknown-allow.yaml",
		"duplicate-key.yaml",
		"unsupported-policy.yaml",
	}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			path := filepath.Join("testdata", fixture)
			_, firstErr := Load(path)
			if firstErr == nil {
				t.Fatal("malformed configuration unexpectedly loaded")
			}
			_, secondErr := Load(path)
			if secondErr == nil || secondErr.Error() != firstErr.Error() {
				t.Fatalf("failure was not deterministic: %v / %v", firstErr, secondErr)
			}
		})
	}
}

func TestUnsafeSemanticInputsFailBeforeAuditCreation(t *testing.T) {
	base := Config{
		APIVersion: APIVersion,
		Kind:       Kind,
		Upstream:   Upstream{Profile: "ceiling", Region: "us-east-1", RoleSessionName: DefaultRoleSessionName, DurationSeconds: DefaultRoleDurationSeconds},
		Proxy:      Proxy{Listen: DefaultListen, NonAWSTraffic: DefaultNonAWSTraffic, UpstreamProxy: DefaultUpstreamProxy, MaxInMemoryBodyBytes: DefaultMaxInMemoryBodyBytes, MaxSpoolBodyBytes: DefaultMaxSpoolBodyBytes},
		Policy:     Policy{Default: PolicyDeny},
		Audit:      Audit{Path: filepath.Join(os.TempDir(), "kordn-never-create", "events.jsonl"), Fsync: FsyncBatch, FailureMode: AuditDeny},
	}
	if err := base.Validate(); err == nil {
		t.Fatal("temporary audit path was accepted")
	}
	if _, err := os.Stat(filepath.Dir(base.Audit.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("validation had an unexpected filesystem side effect: %v", err)
	}

	cases := []struct {
		name string
		edit func(*Config)
	}{
		{"non-loopback", func(c *Config) { c.Proxy.Listen = "0.0.0.0:0" }},
		{"bad-sts-duration", func(c *Config) { c.Audit.Path = DefaultAuditPath; c.Upstream.DurationSeconds = 899 }},
		{"bad-body-order", func(c *Config) {
			c.Audit.Path = DefaultAuditPath
			c.Proxy.MaxSpoolBodyBytes = c.Proxy.MaxInMemoryBodyBytes - 1
		}},
		{"regex-operator", func(c *Config) {
			c.Audit.Path = DefaultAuditPath
			c.Policy.Rules = []Rule{{ID: "bad", Effect: EffectAllow, Actions: []string{"ec2:(Describe.*)"}, Resources: []string{"*"}}}
		}},
		{"redaction-conflict", func(c *Config) {
			c.Audit.Path = DefaultAuditPath
			c.Audit.LogResourceARNs = true
			c.Audit.HashResourceNames = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			tc.edit(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe configuration unexpectedly validated")
			}
		})
	}
}

func TestConfigSymlinkResolvesBeforeUse(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	data, err := os.ReadFile(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	cfg, err := Load(link)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SourcePath != resolved {
		t.Fatalf("config path was not resolved: %q != %q", cfg.SourcePath, resolved)
	}
}

func TestSharedContracts(t *testing.T) {
	t.Run("protocol-and-payload-enums", func(t *testing.T) {
		protocols := []awsrequest.AWSProtocol{
			awsrequest.ProtocolJSON10, awsrequest.ProtocolJSON11, awsrequest.ProtocolQuery,
			awsrequest.ProtocolEC2Query, awsrequest.ProtocolRESTJSON, awsrequest.ProtocolRESTXML,
		}
		for _, protocol := range protocols {
			if !protocol.Valid() {
				t.Errorf("supported protocol %q was rejected", protocol)
			}
		}
		if awsrequest.AWSProtocol("http").Valid() {
			t.Error("unknown protocol was accepted")
		}
		for _, mode := range []awsrequest.PayloadHashMode{awsrequest.PayloadHashSHA256, awsrequest.PayloadHashEmpty, awsrequest.PayloadHashUnsigned} {
			if !mode.Valid() {
				t.Errorf("supported payload mode %q was rejected", mode)
			}
		}
		for _, mode := range []awsrequest.PayloadHashMode{awsrequest.PayloadHashStreaming, awsrequest.PayloadHashEventStream, awsrequest.PayloadHashUnsupported} {
			if mode.Valid() {
				t.Errorf("unsupported payload mode %q was accepted", mode)
			}
		}
		if awsrequest.SigningScheme("sigv4a").Supported() || !awsrequest.SigningHeaderV4.Supported() {
			t.Error("signing scheme closure is not fail-closed")
		}
	})

	t.Run("scope-invariants", func(t *testing.T) {
		valid := []awsrequest.IAMRequirement{
			{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/key"}, ScopeKind: awsrequest.ScopeExact},
			{Action: "s3:GetObject", Resources: []string{"a", "b"}, ScopeKind: awsrequest.ScopeSet},
			{Action: "iam:ListUsers", Resources: []string{"*"}, ScopeKind: awsrequest.ScopeKnownGlobal},
			{Action: "s3:GetObject", ScopeKind: awsrequest.ScopeUnresolved},
		}
		for _, requirement := range valid {
			if err := requirement.Validate(); err != nil {
				t.Errorf("valid %q requirement rejected: %v", requirement.ScopeKind, err)
			}
		}
		invalid := []awsrequest.IAMRequirement{
			{Action: "s3:GetObject", Resources: nil, ScopeKind: awsrequest.ScopeExact},
			{Action: "s3:GetObject", Resources: nil, ScopeKind: awsrequest.ScopeSet},
			{Action: "iam:ListUsers", Resources: []string{"arn:other"}, ScopeKind: awsrequest.ScopeKnownGlobal},
			{Action: "s3:GetObject", Resources: []string{"x"}, ScopeKind: awsrequest.ScopeKind("wildcard")},
			{Action: "s3:Get:Object", Resources: []string{"x"}, ScopeKind: awsrequest.ScopeExact},
			{Action: "s3:GetObject", Resources: []string{"x", "x"}, ScopeKind: awsrequest.ScopeSet},
		}
		for _, requirement := range invalid {
			if err := requirement.Validate(); err == nil {
				t.Errorf("invalid %q requirement was accepted", requirement.ScopeKind)
			}
		}
	})

	t.Run("endpoint-validation", func(t *testing.T) {
		valid := awsrequest.AWSEndpoint{Partition: "aws", Host: "ecs.eu-west-1.amazonaws.com", Service: "ecs", Region: "eu-west-1"}
		if err := valid.Validate(); err != nil {
			t.Fatal(err)
		}
		global := awsrequest.AWSEndpoint{Partition: "aws", Host: "iam.amazonaws.com", Service: "iam", Global: true, Scope: awsrequest.ScopeGlobal}
		if err := global.Validate(); err != nil {
			t.Fatal(err)
		}
		invalid := []awsrequest.AWSEndpoint{
			{Partition: "aws", Host: "ECS.eu-west-1.amazonaws.com", Service: "ecs", Region: "eu-west-1"},
			{Partition: "aws", Host: "ecs.eu-west-1.amazonaws.com.", Service: "ecs", Region: "eu-west-1"},
			{Partition: "aws", Host: "127.0.0.1:443", Service: "ecs", Region: "eu-west-1"},
			{Partition: "aws", Host: "ecs.amazonaws.com", Service: "ecs"},
			{Partition: "aws", Host: "ecs.amazonaws.com", Service: "ecs", Global: true, Scope: awsrequest.ScopeRegional},
		}
		for _, endpoint := range invalid {
			if err := endpoint.Validate(); err == nil {
				t.Errorf("invalid endpoint was accepted: %#v", endpoint)
			}
		}
	})

	t.Run("allow-and-deny-decisions", func(t *testing.T) {
		endpoint := awsrequest.AWSEndpoint{Partition: "aws", Host: "s3.us-east-1.amazonaws.com", Service: "s3", Region: "us-east-1"}
		request := &awsrequest.DecodedAWSRequest{
			Partition: "aws", EndpointHost: endpoint.Host, Service: "s3", Region: "us-east-1", Protocol: awsrequest.ProtocolRESTXML,
			Operation: "GetObject", Method: "GET", CanonicalPath: "/bucket/key", CanonicalQuery: make(map[string][]string),
			Headers: http.Header{}, Parameters: map[string]awsrequest.Value{}, PayloadHashMode: awsrequest.PayloadHashSHA256,
		}
		mapping := &awsrequest.MappingResult{
			Service: "s3", Operation: "GetObject", MapperVersion: "mapper-test", Confidence: awsrequest.ConfidenceHigh,
			Requirements: []awsrequest.IAMRequirement{{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/key"}, ScopeKind: awsrequest.ScopeExact}},
			Evidence:     []awsrequest.MappingEvidence{{Source: "model", Field: "operation"}},
		}
		input := policy.DecisionInput{RunID: "run-test", Endpoint: endpoint, Request: request, Mapping: mapping, PolicyHash: "sha256:policy", MapperVersion: "mapper-test"}
		if err := input.Validate(); err != nil {
			t.Fatal(err)
		}
		allow := policy.Decision{Result: policy.DecisionAllow, ReasonCode: awserror.ReasonAllRequirementsAllowed}
		deny := policy.Decision{Result: policy.DecisionDeny, ReasonCode: awserror.ReasonExplicitDeny, MatchedRuleIDs: []string{"deny-test"}}
		if !allow.Valid() || !deny.Valid() {
			t.Fatalf("valid decisions rejected: allow=%#v deny=%#v", allow, deny)
		}
		if (policy.Decision{Result: policy.DecisionAllow, ReasonCode: awserror.ReasonExplicitDeny}).Valid() || (policy.Decision{Result: policy.DecisionDeny, ReasonCode: awserror.ReasonAllRequirementsAllowed}).Valid() {
			t.Error("decision result/reason mismatch was accepted")
		}
	})

	t.Run("reason-closure", func(t *testing.T) {
		want := []awserror.ReasonCode{
			awserror.ReasonExplicitDeny, awserror.ReasonPolicyNoMatchingAllow,
			awserror.ReasonAWSRequiredWildcardNotApproved, awserror.ReasonUnknownEndpoint,
			awserror.ReasonUnsupportedPartition, awserror.ReasonUnknownOperation,
			awserror.ReasonMappingLowConfidence, awserror.ReasonResourceUnresolved,
			awserror.ReasonDependentPermissionUnresolved, awserror.ReasonInvalidInboundSignature,
			awserror.ReasonUnsupportedSigningScheme, awserror.ReasonUnsupportedPayloadMode,
			awserror.ReasonRequestTooLarge, awserror.ReasonAuditUnavailable,
			awserror.ReasonUpstreamCredentialUnavailable, awserror.ReasonUpstreamTransportError,
			awserror.ReasonInternalFailClosed, awserror.ReasonAllRequirementsAllowed,
		}
		if !reflect.DeepEqual(awserror.AllReasonCodes, want) {
			t.Fatalf("stable reason set changed: got=%v want=%v", awserror.AllReasonCodes, want)
		}
		for _, reason := range want {
			if !reason.Valid() {
				t.Errorf("stable reason %q is not valid", reason)
			}
		}
		if awserror.ReasonCode("not-a-reason").Valid() {
			t.Error("unknown reason was accepted")
		}
	})
}
