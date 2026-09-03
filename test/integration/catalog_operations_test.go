package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	sdkcredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/kordn-ai/kordn/internal/audit"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/cache"
	"github.com/kordn-ai/kordn/internal/config"
	"github.com/kordn-ai/kordn/internal/credentials"
	"github.com/kordn-ai/kordn/internal/iammap"
	"github.com/kordn-ai/kordn/internal/policy"
	"github.com/kordn-ai/kordn/internal/proxy"
	"github.com/kordn-ai/kordn/internal/runtime"
	"github.com/kordn-ai/kordn/internal/sigv4"
	"github.com/kordn-ai/kordn/test/integration/fakeaws"
)

const catalogAccount = "123456789012"

type catalogOperationFixture struct {
	Name              string `json:"name"`
	Source            string `json:"source"`
	SourceURL         string `json:"source_url"`
	ExpectedService   string `json:"expected_service"`
	ExpectedOperation string `json:"expected_operation"`
	ExpectedProtocol  string `json:"expected_protocol"`
}

type catalogOperationFixtureFile struct {
	Entries []catalogOperationFixture `json:"entries"`
}

type catalogOperationRequest struct {
	host        string
	service     string
	region      string
	operation   string
	protocol    string
	method      string
	path        string
	contentType string
	target      string
	body        string
	wantStatus  int
}

func catalogOperationRequests() map[string]catalogOperationRequest {
	return map[string]catalogOperationRequest{
		"ListUsers": {
			host: "iam.amazonaws.com", service: "iam", region: "us-east-1", operation: "ListUsers", protocol: "query",
			method: http.MethodPost, path: "/", contentType: "application/x-www-form-urlencoded; charset=utf-8", body: "Action=ListUsers&Version=2010-05-08", wantStatus: http.StatusOK,
		},
		"GetObject": {
			host: "s3.us-east-1.amazonaws.com", service: "s3", region: "us-east-1", operation: "GetObject", protocol: "rest-xml",
			method: http.MethodGet, path: "/fixture/object.txt", contentType: "application/xml", wantStatus: http.StatusOK,
		},
		"CreateFunction": {
			host: "lambda.us-east-1.amazonaws.com", service: "lambda", region: "us-east-1", operation: "CreateFunction", protocol: "rest-json",
			method: http.MethodPost, path: "/2015-03-31/functions", contentType: "application/json", body: `{"FunctionName":"fixture-function","Role":"arn:aws:iam::123456789012:role/fixture","Code":{"ZipFile":"ZmFrZQ=="}}`, wantStatus: http.StatusForbidden,
		},
		"BatchExecuteStatement": {
			host: "dynamodb.us-east-1.amazonaws.com", service: "dynamodb", region: "us-east-1", operation: "BatchExecuteStatement", protocol: "json1.0",
			method: http.MethodPost, path: "/", contentType: "application/x-amz-json-1.0", target: "DynamoDB_20120810.BatchExecuteStatement", body: `{"Statements":[{"Statement":"SELECT * FROM \"read_table\""},{"Statement":"INSERT INTO \"write_table\" VALUE {'id': '1'}"}]}`, wantStatus: http.StatusOK,
		},
	}
}

func loadCatalogOperationFixtures(t *testing.T) []catalogOperationFixture {
	t.Helper()
	path := filepath.Join("..", "fixtures", "sigv4", "aws-operation-examples.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read catalog operation fixtures %q: %v", path, err)
	}
	var file catalogOperationFixtureFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse catalog operation fixtures %q: %v", path, err)
	}
	return file.Entries
}

func TestCatalogOperations(t *testing.T) {
	requests := catalogOperationRequests()
	fixtures := loadCatalogOperationFixtures(t)
	if len(fixtures) < 4 {
		t.Fatalf("catalog fixture entries = %d, want at least 4", len(fixtures))
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			tc, ok := requests[fixture.ExpectedOperation]
			if !ok {
				t.Fatalf("fixture %q operation %q has no production request", fixture.Name, fixture.ExpectedOperation)
			}
			if fixture.Source == "" || fixture.SourceURL == "" {
				t.Fatalf("fixture %q source attribution is incomplete", fixture.Name)
			}
			if tc.service != fixture.ExpectedService || tc.protocol != fixture.ExpectedProtocol {
				t.Fatalf("fixture %q identity = %s/%s, want %s/%s", fixture.Name, fixture.ExpectedService, fixture.ExpectedProtocol, tc.service, tc.protocol)
			}
			selected := allowEverythingPolicy(t)
			h := newCatalogHarness(t, selected, tc.host, tc.service, tc.region)
			response := h.call(t, tc.host, tc.service, tc.region, tc.method, tc.path, tc.contentType, tc.target, []byte(tc.body))
			responseBody, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatalf("%s %s read response: %v", tc.service, tc.operation, err)
			}
			if response.StatusCode != tc.wantStatus {
				t.Fatalf("%s %s response=%d body=%q want=%d", tc.service, tc.operation, response.StatusCode, responseBody, tc.wantStatus)
			}
			ledger := h.upstream.Ledger()
			wantProtocol := fakeProtocol(tc.protocol)
			if len(ledger) != 0 && (ledger[0].Protocol != wantProtocol || (tc.service != "s3" && ledger[0].Action != tc.operation)) {
				t.Fatalf("%s %s ledger=%+v want one %s", tc.service, tc.operation, ledger, tc.protocol)
			}
			if tc.wantStatus == http.StatusOK || tc.wantStatus == http.StatusCreated {
				if len(ledger) != 1 {
					t.Fatalf("%s %s ledger=%+v want one request", tc.service, tc.operation, ledger)
				}
			} else if len(ledger) != 0 {
				t.Fatalf("%s %s denial forwarded: %+v", tc.service, tc.operation, ledger)
			}
			event := h.lastDecision(t)
			if event.Request.Operation != tc.operation || event.Request.Service != tc.service || event.Request.Protocol != awsrequest.AWSProtocol(tc.protocol) {
				t.Fatalf("audit request=%+v want %s/%s/%s", event.Request, tc.service, tc.operation, tc.protocol)
			}
			wantDecision := "allow"
			if tc.wantStatus == http.StatusForbidden {
				wantDecision = "deny"
			}
			if event.Decision.Result != wantDecision {
				t.Fatalf("audit decision=%+v", event.Decision)
			}
			mapping, mapErr := h.mapper.snapshot()
			if tc.operation == "CreateFunction" {
				// The pinned IAM definition also requires lambda:PassCapacityProvider,
				// while map.json has no matching extraction record. The vertical path
				// must therefore reject this request before policy rather than omit a
				// dependent permission. The policy package test separately proves the
				// conjunctive lambda:CreateFunction + iam:PassRole decision.
				if mapping != nil || mapErr == nil || !strings.Contains(strings.ToLower(mapErr.Error()), "lambda:passcapacityprovider") {
					t.Fatalf("CreateFunction mapping = %+v, error = %v, want fail-closed missing dependent evidence", mapping, mapErr)
				}
			} else {
				assertCatalogMapping(t, tc.operation, mapping, mapErr)
			}
			assertCatalogNativeResponse(t, tc.protocol, response.StatusCode, responseBody, event.EventID)
			assertNoCatalogSensitiveMaterial(t, responseBody, h.auditText(), mapping, h.server.MetricsSnapshot())
		})
	}
}

func TestCatalogOperationsDenialsDoNotForward(t *testing.T) {
	cases := []struct {
		name, host, service, region, method, path, contentType, target, body, denyAction, wantReason string
	}{
		{"IAMExplicitDeny", "iam.amazonaws.com", "iam", "us-east-1", http.MethodPost, "/", "application/x-www-form-urlencoded", "", "Action=ListUsers&Version=2010-05-08", "iam:ListUsers", "explicit_deny"},
		{"S3DefaultDeny", "s3.us-east-1.amazonaws.com", "s3", "us-east-1", http.MethodGet, "/fixture/object.txt", "application/xml", "", "", "s3:GetObject", "policy_no_matching_allow"},
		{"LambdaMissingDependent", "lambda.us-east-1.amazonaws.com", "lambda", "us-east-1", http.MethodPost, "/2015-03-31/functions", "application/json", "", `{"FunctionName":"fixture-function","Role":"arn:aws:iam::123456789012:role/fixture","Code":{"ZipFile":"ZmFrZQ=="}}`, "iam:PassRole", "dependent_permission_unresolved"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{{ID: "deny-target", Effect: config.EffectDeny, Actions: []string{tc.denyAction}, Resources: []string{"*"}}}}
			if tc.name == "S3DefaultDeny" || tc.name == "LambdaMissingDependent" {
				p.Rules = nil
				if tc.name == "LambdaMissingDependent" {
					p.Rules = []config.Rule{{ID: "allow-primary", Effect: config.EffectAllow, Actions: []string{"lambda:CreateFunction"}, Resources: []string{"*"}}}
				}
			}
			h := newCatalogHarness(t, p, tc.host, tc.service, tc.region)
			response := h.call(t, tc.host, tc.service, tc.region, tc.method, tc.path, tc.contentType, tc.target, []byte(tc.body))
			responseBody, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatalf("%s read denial response: %v", tc.name, err)
			}
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("%s response=%d body=%q want=403", tc.name, response.StatusCode, responseBody)
			}
			if len(h.upstream.Ledger()) != 0 {
				t.Fatalf("%s forwarded request: %+v", tc.name, h.upstream.Ledger())
			}
			event := h.lastDecision(t)
			if event.Decision.Result != "deny" || event.Decision.ReasonCode != tc.wantReason {
				mapping, mapErr := h.mapper.snapshot()
				t.Fatalf("%s decision=%+v want reason %s; mapping=%+v error=%v", tc.name, event.Decision, tc.wantReason, mapping, mapErr)
			}
			if event.Request.Operation == "Unknown" {
				t.Fatalf("%s audit lost operation: %+v", tc.name, event.Request)
			}
			assertCatalogDenialRequirements(t, tc.name, event.IAMRequirements)
			assertCatalogDenialResponse(t, tc.service, response.Header.Get("Content-Type"), responseBody, event.EventID)
			mapping, _ := h.mapper.snapshot()
			assertNoCatalogSensitiveMaterial(t, responseBody, h.auditText(), mapping, h.server.MetricsSnapshot())
		})
	}
}

func TestCatalogOperationsWildcardAndConjunction(t *testing.T) {
	p := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{
		{ID: "iam-global", Effect: config.EffectAllow, Actions: []string{"iam:ListUsers"}, Resources: []string{"*"}},
	}}
	h := newCatalogHarness(t, p, "iam.amazonaws.com", "iam", "us-east-1")
	response := h.call(t, "iam.amazonaws.com", "iam", "us-east-1", http.MethodPost, "/", "application/x-www-form-urlencoded", "", []byte("Action=ListUsers&Version=2010-05-08"))
	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	event := h.lastDecision(t)
	if response.StatusCode != http.StatusForbidden || event.Decision.ReasonCode != "aws_required_wildcard_not_approved" || len(h.upstream.Ledger()) != 0 {
		t.Fatalf("missing wildcard acknowledgement response=%d decision=%+v ledger=%+v", response.StatusCode, event.Decision, h.upstream.Ledger())
	}
	mapping, mapErr := h.mapper.snapshot()
	assertCatalogMapping(t, "ListUsers", mapping, mapErr)
	assertCatalogDenialResponse(t, "iam", response.Header.Get("Content-Type"), responseBody, event.EventID)

	p = config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{
		{ID: "iam-global", Effect: config.EffectAllow, Actions: []string{"iam:ListUsers"}, Resources: []string{"*"}, AllowAWSRequiredWildcard: true},
		{ID: "s3-object", Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::fixture/*"}},
		{ID: "dynamo-select", Effect: config.EffectAllow, Actions: []string{"dynamodb:PartiQLSelect"}, Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/read_table"}},
		{ID: "dynamo-insert", Effect: config.EffectAllow, Actions: []string{"dynamodb:PartiQLInsert"}, Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/write_table"}},
	}}
	for _, request := range []struct{ host, service, method, path, contentType, target, body string }{
		{"s3.us-east-1.amazonaws.com", "s3", http.MethodGet, "/fixture/object.txt", "application/xml", "", ""},
		{"dynamodb.us-east-1.amazonaws.com", "dynamodb", http.MethodPost, "/", "application/x-amz-json-1.0", "DynamoDB_20120810.BatchExecuteStatement", `{"Statements":[{"Statement":"SELECT * FROM \"read_table\""},{"Statement":"INSERT INTO \"write_table\" VALUE {'id': '1'}"}]}`},
	} {
		requestHarness := newCatalogHarness(t, p, request.host, request.service, "us-east-1")
		response := requestHarness.call(t, request.host, request.service, "us-east-1", request.method, request.path, request.contentType, request.target, []byte(request.body))
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("conjunctive request %s status=%d ledger=%+v audit=%+v", request.service, response.StatusCode, requestHarness.upstream.Ledger(), requestHarness.audit.events)
		}
	}

	missingActionPolicy := config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{{
		ID:        "dynamo-select-only",
		Effect:    config.EffectAllow,
		Actions:   []string{"dynamodb:PartiQLSelect"},
		Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/read_table"},
	}}}
	batch := catalogOperationRequests()["BatchExecuteStatement"]
	missing := newCatalogHarness(t, missingActionPolicy, batch.host, batch.service, batch.region)
	response = missing.call(t, batch.host, batch.service, batch.region, batch.method, batch.path, batch.contentType, batch.target, []byte(batch.body))
	response.Body.Close()
	event = missing.lastDecision(t)
	if response.StatusCode != http.StatusForbidden || event.Decision.ReasonCode != "policy_no_matching_allow" || len(missing.upstream.Ledger()) != 0 {
		t.Fatalf("BatchExecuteStatement missing action response=%d decision=%+v ledger=%+v", response.StatusCode, event.Decision, missing.upstream.Ledger())
	}
	mapping, mapErr = missing.mapper.snapshot()
	assertCatalogMapping(t, "BatchExecuteStatement", mapping, mapErr)
	if len(event.IAMRequirements) != 2 {
		t.Fatalf("BatchExecuteStatement audit requirements=%+v, want both mandatory actions", event.IAMRequirements)
	}
}

func TestCatalogOperationsUnresolvedApplicabilityDoesNotForward(t *testing.T) {
	tc := catalogOperationRequests()["BatchExecuteStatement"]
	tc.body = `{"Statements":[{"Statement":"EXECUTE unknown syntax"}]}`
	h := newCatalogHarness(t, allowEverythingPolicy(t), tc.host, tc.service, tc.region)
	response := h.call(t, tc.host, tc.service, tc.region, tc.method, tc.path, tc.contentType, tc.target, []byte(tc.body))
	response.Body.Close()
	event := h.lastDecision(t)
	mapping, mapErr := h.mapper.snapshot()
	if response.StatusCode != http.StatusForbidden || len(h.upstream.Ledger()) != 0 || event.Decision.ReasonCode != "resource_unresolved" || event.Request.Operation != "BatchExecuteStatement" || mapping != nil || mapErr == nil {
		t.Fatalf("unresolved BatchExecuteStatement response=%d ledger=%+v event=%+v mapping=%+v error=%v", response.StatusCode, h.upstream.Ledger(), event, mapping, mapErr)
	}
}

func TestCatalogOperationsUnknownFailClosed(t *testing.T) {
	cases := []catalogOperationRequest{
		{host: "iam.amazonaws.com", service: "iam", region: "us-east-1", operation: "query-unknown", method: http.MethodPost, path: "/", contentType: "application/x-www-form-urlencoded", body: "Action=NotInCatalog&Version=2010-05-08"},
		{host: "iam.amazonaws.com", service: "iam", region: "us-east-1", operation: "query-duplicate-action", method: http.MethodPost, path: "/", contentType: "application/x-www-form-urlencoded", body: "Action=ListUsers&Action=GetRole&Version=2010-05-08"},
		{host: "dynamodb.us-east-1.amazonaws.com", service: "dynamodb", region: "us-east-1", operation: "json-unknown-target", method: http.MethodPost, path: "/", contentType: "application/x-amz-json-1.0", target: "DynamoDB_20120810.NotInCatalog", body: `{}`},
		{host: "iam.amazonaws.com", service: "iam", region: "us-east-1", operation: "protocol-disagreement", method: http.MethodPost, path: "/", contentType: "application/x-amz-json-1.0", target: "DynamoDB_20120810.GetItem", body: `{}`},
		{host: "s3.us-east-1.amazonaws.com", service: "s3", region: "us-east-1", operation: "rest-query-unknown", method: http.MethodGet, path: "/fixture/object.txt?unsupported=1"},
	}
	for _, tc := range cases {
		t.Run(tc.operation, func(t *testing.T) {
			h := newCatalogHarness(t, allowEverythingPolicy(t), tc.host, tc.service, tc.region)
			response := h.call(t, tc.host, tc.service, tc.region, tc.method, tc.path, tc.contentType, tc.target, []byte(tc.body))
			responseBody, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusForbidden || len(h.upstream.Ledger()) != 0 {
				t.Fatalf("%s response=%d ledger=%+v", tc.operation, response.StatusCode, h.upstream.Ledger())
			}
			decisions := h.decisionEvents()
			if len(decisions) != 1 || decisions[0].Decision.ReasonCode != "unknown_operation" || decisions[0].Request.Operation != "Unknown" {
				t.Fatalf("%s decisions=%+v, want one unknown_operation for Unknown", tc.operation, decisions)
			}
			assertNoCatalogSensitiveMaterial(t, responseBody, h.auditText(), h.server.MetricsSnapshot())
		})
	}
}

type catalogDecoderFunc func(context.Context, *awsrequest.VerifiedRequest, awsrequest.AWSEndpoint) (*awsrequest.DecodedAWSRequest, error)

func (f catalogDecoderFunc) Decode(ctx context.Context, request *awsrequest.VerifiedRequest, endpoint awsrequest.AWSEndpoint) (*awsrequest.DecodedAWSRequest, error) {
	return f(ctx, request, endpoint)
}

type catalogMapperFunc func(context.Context, *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error)

func (f catalogMapperFunc) Map(ctx context.Context, request *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	return f(ctx, request)
}

func TestCatalogOperationsInjectedEvidenceFailuresDoNotForward(t *testing.T) {
	listUsers := catalogOperationRequests()["ListUsers"]
	getObject := catalogOperationRequests()["GetObject"]
	cases := []struct {
		name          string
		request       catalogOperationRequest
		options       catalogHarnessOptions
		wantReason    string
		wantOperation string
	}{
		{
			name:    "corrupt-catalog-record",
			request: listUsers,
			options: catalogHarnessOptions{wrapDecoder: func(inner awsrequest.AWSRequestDecoder) awsrequest.AWSRequestDecoder {
				return catalogDecoderFunc(func(ctx context.Context, request *awsrequest.VerifiedRequest, endpoint awsrequest.AWSEndpoint) (*awsrequest.DecodedAWSRequest, error) {
					decoded, err := inner.Decode(ctx, request, endpoint)
					if err != nil {
						return nil, err
					}
					evidence := awsrequest.DecodeFailureEvidence{
						Service:           decoded.Service,
						Protocol:          decoded.Protocol,
						ProtocolAvailable: true,
						ProtocolCertainty: awsrequest.EvidenceAuthoritative,
					}
					return nil, awsrequest.NewDecodeFailureError(evidence, errors.New("catalog record is contradictory"))
				})
			}},
			wantReason:    "unknown_operation",
			wantOperation: "Unknown",
		},
		{
			name:    "mapper-source-disagreement",
			request: getObject,
			options: catalogHarnessOptions{wrapMapper: func(inner awsrequest.IAMMapper) awsrequest.IAMMapper {
				return catalogMapperFunc(func(ctx context.Context, request *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
					mapping, err := inner.Map(ctx, request)
					if err != nil {
						return nil, err
					}
					corrupt := *mapping
					corrupt.Service = "iam"
					return &corrupt, nil
				})
			}},
			wantReason:    "mapping_low_confidence",
			wantOperation: "GetObject",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCatalogHarnessWithOptions(t, allowEverythingPolicy(t), tc.request.host, tc.request.service, tc.request.region, tc.options)
			response := h.call(t, tc.request.host, tc.request.service, tc.request.region, tc.request.method, tc.request.path, tc.request.contentType, tc.request.target, []byte(tc.request.body))
			responseBody, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			decisions := h.decisionEvents()
			if response.StatusCode != http.StatusForbidden || len(h.upstream.Ledger()) != 0 || len(decisions) != 1 {
				t.Fatalf("%s response=%d ledger=%+v decisions=%+v", tc.name, response.StatusCode, h.upstream.Ledger(), decisions)
			}
			event := decisions[0]
			if event.Decision.ReasonCode != tc.wantReason || event.Request.Operation != tc.wantOperation {
				t.Fatalf("%s decision=%+v request=%+v, want reason=%q operation=%q", tc.name, event.Decision, event.Request, tc.wantReason, tc.wantOperation)
			}
			if len(event.IAMRequirements) != 1 || event.IAMRequirements[0].Action != tc.request.service+":Unknown" || event.IAMRequirements[0].ScopeKind != awsrequest.ScopeUnresolved {
				t.Fatalf("%s fail-closed audit requirements=%+v", tc.name, event.IAMRequirements)
			}
			assertCatalogDenialResponse(t, tc.request.service, response.Header.Get("Content-Type"), responseBody, event.EventID)
		})
	}
}

func assertCatalogDenialRequirements(t *testing.T, name string, requirements []audit.Requirement) {
	t.Helper()
	if len(requirements) != 1 {
		t.Fatalf("%s audit requirements=%+v, want exactly one", name, requirements)
	}
	got := requirements[0]
	var want audit.Requirement
	switch name {
	case "IAMExplicitDeny":
		want = audit.Requirement{Action: "iam:ListUsers", Resources: []string{"*"}, ScopeKind: awsrequest.ScopeKnownGlobal}
	case "S3DefaultDeny":
		want = audit.Requirement{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::fixture/object.txt"}, ScopeKind: awsrequest.ScopeExact}
	case "LambdaMissingDependent":
		want = audit.Requirement{Action: "lambda:Unknown", Resources: []string{"unknown"}, ScopeKind: awsrequest.ScopeUnresolved}
	default:
		t.Fatalf("unknown denial requirement case %q", name)
	}
	if got.Action != want.Action || got.ScopeKind != want.ScopeKind || got.Dependent != want.Dependent || len(got.Resources) != 1 || got.Resources[0] != want.Resources[0] {
		t.Fatalf("%s audit requirement=%+v, want %+v", name, got, want)
	}
}

func assertCatalogMapping(t *testing.T, operation string, mapping *awsrequest.MappingResult, err error) {
	t.Helper()
	if err != nil || mapping == nil {
		t.Fatalf("%s mapping = %+v, error = %v, want high-confidence mapping", operation, mapping, err)
	}
	if mapping.Operation != operation || mapping.Confidence != awsrequest.ConfidenceHigh {
		t.Fatalf("%s mapping identity/confidence = %+v", operation, mapping)
	}
	switch operation {
	case "ListUsers":
		if len(mapping.Requirements) != 1 || mapping.Requirements[0].Action != "iam:ListUsers" || mapping.Requirements[0].ScopeKind != awsrequest.ScopeKnownGlobal || len(mapping.Requirements[0].Resources) != 1 || mapping.Requirements[0].Resources[0] != "*" {
			t.Fatalf("ListUsers requirements = %+v, want iam:ListUsers known_global *", mapping.Requirements)
		}
	case "GetObject":
		if len(mapping.Requirements) != 1 || mapping.Requirements[0].Action != "s3:GetObject" || mapping.Requirements[0].ScopeKind != awsrequest.ScopeExact || len(mapping.Requirements[0].Resources) != 1 || mapping.Requirements[0].Resources[0] != "arn:aws:s3:::fixture/object.txt" {
			t.Fatalf("GetObject requirements = %+v, want exact object ARN", mapping.Requirements)
		}
	case "BatchExecuteStatement":
		got := make(map[string]string, len(mapping.Requirements))
		for _, requirement := range mapping.Requirements {
			if len(requirement.Resources) == 1 {
				got[requirement.Action] = requirement.Resources[0]
			}
		}
		want := map[string]string{
			"dynamodb:PartiQLInsert": "arn:aws:dynamodb:us-east-1:123456789012:table/write_table",
			"dynamodb:PartiQLSelect": "arn:aws:dynamodb:us-east-1:123456789012:table/read_table",
		}
		if len(mapping.Requirements) != len(want) {
			t.Fatalf("BatchExecuteStatement requirements = %+v, want two conjunctive actions", mapping.Requirements)
		}
		for action, resource := range want {
			if got[action] != resource {
				t.Fatalf("BatchExecuteStatement requirement %q = %q, want %q; all = %+v", action, got[action], resource, mapping.Requirements)
			}
		}
	}
}

func assertCatalogNativeResponse(t *testing.T, protocol string, status int, body []byte, eventID string) {
	t.Helper()
	switch protocol {
	case "query":
		var document struct {
			RequestID string `xml:"ResponseMetadata>RequestId"`
		}
		if err := xml.Unmarshal(body, &document); err != nil || document.RequestID == "" {
			t.Fatalf("query response status=%d body=%q request ID=%q error=%v", status, body, document.RequestID, err)
		}
	case "rest-xml":
		if status == http.StatusOK && string(body) != "fixture object" {
			t.Fatalf("REST-XML GetObject body=%q, want fixture object", body)
		}
	case "json1.0", "rest-json":
		var document map[string]any
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatalf("%s response status=%d body=%q error=%v", protocol, status, body, err)
		}
		if status == http.StatusForbidden && !strings.Contains(string(body), eventID) {
			t.Fatalf("%s denial body=%q, want event ID %q", protocol, body, eventID)
		}
	}
}

func assertCatalogDenialResponse(t *testing.T, service, contentType string, body []byte, eventID string) {
	t.Helper()
	switch service {
	case "iam", "s3":
		if !strings.Contains(strings.ToLower(contentType), "xml") {
			t.Fatalf("%s denial Content-Type = %q, want XML", service, contentType)
		}
		var document struct {
			RequestID string `xml:"RequestId"`
			Message   string `xml:"Message"`
			Error     struct {
				Message string `xml:"Message"`
			} `xml:"Error"`
		}
		if err := xml.Unmarshal(body, &document); err != nil {
			t.Fatalf("%s denial XML = %q, error = %v", service, body, err)
		}
		message := document.Message
		if message == "" {
			message = document.Error.Message
		}
		if document.RequestID != eventID || !strings.Contains(message, eventID) {
			t.Fatalf("%s denial request ID/message = %q/%q, want correlated event ID %q", service, document.RequestID, message, eventID)
		}
	case "lambda":
		if !strings.Contains(strings.ToLower(contentType), "json") {
			t.Fatalf("lambda denial Content-Type = %q, want JSON", contentType)
		}
		var document struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &document); err != nil || !strings.Contains(document.Message, eventID) {
			t.Fatalf("lambda denial JSON = %q, message = %q, event ID = %q, error = %v", body, document.Message, eventID, err)
		}
	}
}

func assertNoCatalogSensitiveMaterial(t *testing.T, values ...any) {
	t.Helper()
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("marshal catalog evidence for secret check: %v", err)
	}
	text := string(encoded)
	for _, secret := range []string{
		"catalog-inbound-secret",
		"catalog-inbound-token",
		"catalog-upstream-secret",
		"catalog-upstream-token",
		"AWS4-HMAC-SHA256 Credential=",
		"Authorization",
		"X-Amz-Security-Token",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("catalog response/audit/mapping/metrics leaked %q", secret)
		}
	}
}

func allowEverythingPolicy(t *testing.T) config.Policy {
	t.Helper()
	return config.Policy{Default: config.PolicyDeny, Rules: []config.Rule{{ID: "catalog-allow", Effect: config.EffectAllow, Actions: []string{"*:*"}, Resources: []string{"*"}, AllowAWSRequiredWildcard: true}}}
}

type catalogHarness struct {
	upstream *fakeaws.Server
	server   *proxy.Server
	client   *http.Client
	fake     aws.Credentials
	audit    *catalogAudit
	mapper   *catalogMapper
	clock    time.Time
}

type catalogMapper struct {
	inner *iammap.Mapper
	mu    sync.Mutex
	last  *awsrequest.MappingResult
	err   error
}

func (m *catalogMapper) Map(ctx context.Context, request *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	result, err := m.inner.Map(ctx, request)
	m.mu.Lock()
	m.last, m.err = result, err
	m.mu.Unlock()
	return result, err
}

func (m *catalogMapper) snapshot() (*awsrequest.MappingResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last, m.err
}

type catalogAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *catalogAudit) Write(_ context.Context, event audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := event.Validate(); err != nil {
		return err
	}
	a.events = append(a.events, event)
	return nil
}
func (a *catalogAudit) Flush(context.Context) error { return nil }

type catalogHarnessOptions struct {
	wrapDecoder func(awsrequest.AWSRequestDecoder) awsrequest.AWSRequestDecoder
	wrapMapper  func(awsrequest.IAMMapper) awsrequest.IAMMapper
}

func newCatalogHarness(t *testing.T, selected config.Policy, host, service, region string) *catalogHarness {
	t.Helper()
	return newCatalogHarnessWithOptions(t, selected, host, service, region, catalogHarnessOptions{})
}

func newCatalogHarnessWithOptions(
	t *testing.T,
	selected config.Policy,
	host, service, region string,
	options catalogHarnessOptions,
) *catalogHarness {
	t.Helper()
	clock := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fake := aws.Credentials{AccessKeyID: "CATALOGINBOUND01", SecretAccessKey: "catalog-inbound-secret", SessionToken: "catalog-inbound-token"}
	real := aws.Credentials{AccessKeyID: "CATALOGUPSTREAM1", SecretAccessKey: "catalog-upstream-secret", SessionToken: "catalog-upstream-token"}
	aud := &catalogAudit{}
	upstream := fakeaws.NewWithConfig(fakeaws.Config{Credentials: real, Host: host, Service: service, Region: region, Clock: func() time.Time { return clock }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "fixture request body unavailable", http.StatusBadRequest)
			return
		}
		operation := fakeOperation(r, requestBody)
		protocol := fakeProtocolFromRequest(r)
		response := fakeaws.CatalogResponse(fakeService(r), operation, protocol, "catalog-request-id")
		if response.Status == 0 {
			http.Error(w, "fixture operation unavailable", http.StatusNotImplemented)
			return
		}
		for key, values := range response.Headers {
			w.Header()[key] = append([]string(nil), values...)
		}
		w.Header().Set("X-Amzn-Requestid", "catalog-request-id")
		w.WriteHeader(response.Status)
		_, _ = w.Write(response.Body)
	})})
	t.Cleanup(upstream.Close)
	verifier, err := sigv4.NewVerifier(credentialsForCatalog(fake), sigv4.WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := awsrequest.NewConfiguredDecoder(awsrequest.DecoderOptions{CallerAccountID: catalogAccount})
	if err != nil {
		t.Fatal(err)
	}
	var configuredDecoder awsrequest.AWSRequestDecoder = decoder
	if options.wrapDecoder != nil {
		configuredDecoder = options.wrapDecoder(configuredDecoder)
	}
	productionMapper, err := iammap.NewMapper()
	if err != nil {
		t.Fatal(err)
	}
	mapper := &catalogMapper{inner: productionMapper}
	var configuredMapper awsrequest.IAMMapper = mapper
	if options.wrapMapper != nil {
		configuredMapper = options.wrapMapper(configuredMapper)
	}
	engine, err := policy.NewEngine(selected)
	if err != nil {
		t.Fatal(err)
	}
	resigner, err := sigv4.NewResigner(sdkcredentials.NewStaticCredentialsProvider(real.AccessKeyID, real.SecretAccessKey, real.SessionToken), sigv4.WithResignClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	transport := proxy.NewOutboundTransport(runtime.CapturedProxySettings{}, proxy.TransportConfig{Dialer: proxy.DialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}), RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs})
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	t.Cleanup(transport.CloseIdleConnections)
	caches, err := cache.NewRunCaches(cache.CacheOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := proxy.NewServer(proxy.Config{ListenAddr: "127.0.0.1:0", Username: "catalog-user", Password: "catalog-password", RunID: "catalog-run", PolicyHash: engine.PolicyHash(), InboundAuthenticator: verifier, Decoder: configuredDecoder, Mapper: configuredMapper, Policy: engine, Audit: aud, Resigner: resigner, Upstream: proxy.NewNoReplayRoundTripper(transport), Caches: caches, LogResourceARNs: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, err := url.Parse("http://catalog-user:catalog-password@" + server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: server.CA().CertPool()}}
	t.Cleanup(clientTransport.CloseIdleConnections)
	return &catalogHarness{upstream: upstream, server: server, client: &http.Client{Transport: clientTransport}, fake: fake, audit: aud, mapper: mapper, clock: clock}
}

func (h *catalogHarness) call(t *testing.T, host, service, region, method, path, contentType, target string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://"+host+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Method = method
	req.Host = host
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if target != "" {
		req.Header.Set("X-Amz-Target", target)
	}
	req.Header.Set("X-Amz-Date", h.clock.Format("20060102T150405Z"))
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", hash)
	if err := v4.NewSigner().SignHTTP(context.Background(), h.fake, req, hash, service, region, h.clock); err != nil {
		t.Fatal(err)
	}
	response, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (h *catalogHarness) decisionEvents() []audit.Event {
	h.audit.mu.Lock()
	defer h.audit.mu.Unlock()
	var decisions []audit.Event
	for _, event := range h.audit.events {
		if event.EventType == audit.RequestDecision {
			decisions = append(decisions, event)
		}
	}
	return decisions
}

func (h *catalogHarness) lastDecision(t *testing.T) audit.Event {
	t.Helper()
	decisions := h.decisionEvents()
	if len(decisions) != 1 {
		t.Fatalf("audit request decisions = %d, want 1: %s", len(decisions), h.auditText())
	}
	return decisions[0]
}
func (h *catalogHarness) auditText() string {
	h.audit.mu.Lock()
	defer h.audit.mu.Unlock()
	data, _ := json.Marshal(h.audit.events)
	return string(data)
}

func credentialsForCatalog(c aws.Credentials) credentials.FakeCredential {
	return credentials.FakeCredential{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}
}

func fakeOperation(r *http.Request, body []byte) string {
	if target := r.Header.Get("X-Amz-Target"); target != "" {
		return target[strings.LastIndex(target, ".")+1:]
	}
	for _, part := range strings.Split(string(body), "&") {
		if strings.HasPrefix(part, "Action=") {
			return strings.TrimPrefix(part, "Action=")
		}
	}
	if operation := map[string]string{"/2015-03-31/functions": "CreateFunction"}[r.URL.Path]; operation != "" {
		return operation
	}
	if strings.HasPrefix(r.Host, "s3") {
		return "GetObject"
	}
	return ""
}
func fakeService(r *http.Request) string {
	if strings.HasPrefix(r.Host, "iam") {
		return "iam"
	}
	if strings.HasPrefix(r.Host, "s3") {
		return "s3"
	}
	if strings.HasPrefix(r.Host, "lambda") {
		return "lambda"
	}
	return "dynamodb"
}
func fakeProtocolFromRequest(r *http.Request) fakeaws.Protocol {
	if strings.HasPrefix(r.Host, "dynamodb") {
		return fakeaws.JSON10
	}
	if strings.Contains(r.Header.Get("X-Amz-Target"), "Json10") {
		return fakeaws.JSON10
	}
	if r.Header.Get("X-Amz-Target") != "" {
		return fakeaws.JSON11
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "json") {
		return fakeaws.RESTJSON
	}
	if strings.Contains(ct, "xml") || strings.HasPrefix(r.Host, "s3") {
		return fakeaws.RESTXML
	}
	return fakeaws.Query
}
func fakeProtocol(value string) fakeaws.Protocol { return fakeaws.Protocol(value) }
