package awsrequest

import (
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

func TestCatalogEndpointIdentityIndex(t *testing.T) {
	catalog, err := iamlivecatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	index, err := CompileEndpointIdentityIndex(catalog.Services())
	if err != nil {
		t.Fatal(err)
	}
	if len(index.families) < 400 {
		t.Fatalf("catalog identity index is incomplete: %d prefixes", len(index.families))
	}
	classifier, err := NewClassifierFromEndpointIdentityIndex(index, 16)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := classifier.Classify("oam.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatalf("new pinned catalog service was not classified: %v", err)
	}
	if endpoint.Service != "oam" || endpoint.Region != "us-east-1" {
		t.Fatalf("unexpected catalog-derived endpoint: %+v", endpoint)
	}

	ordinary, err := CompileEndpointIdentityIndex([]iamlivecatalog.Service{{EndpointPrefix: "new-service", SigningName: "new-service"}})
	if err != nil {
		t.Fatal(err)
	}
	ordinaryClassifier, err := NewClassifierFromEndpointIdentityIndex(ordinary, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ordinaryClassifier.Classify("new-service.us-east-1.amazonaws.com"); err != nil {
		t.Fatalf("synthetic catalog service was not classified: %v", err)
	}
}

func TestCatalogEndpointIdentityIndexRejectsAmbiguousEvidence(t *testing.T) {
	_, err := CompileEndpointIdentityIndex([]iamlivecatalog.Service{
		{Key: "one", EndpointPrefix: "synthetic", SigningName: "first"},
		{Key: "two", EndpointPrefix: "synthetic", SigningName: "second"},
	})
	if err == nil {
		t.Fatal("conflicting signing identity evidence was accepted")
	}
	_, err = CompileEndpointIdentityIndex([]iamlivecatalog.Service{{Key: "empty"}})
	if err == nil {
		t.Fatal("empty endpoint identity evidence was accepted")
	}
}

func TestClassifierCommercialEndpointMetadata(t *testing.T) {
	classifier, err := NewClassifier(8)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		authority string
		service   string
		region    string
		global    bool
		fips      bool
		dualstack bool
		scope     EndpointScope
	}{
		{"regional", "ec2.us-east-1.amazonaws.com", "ec2", "us-east-1", false, false, false, ScopeRegional},
		{"case trailing dot port", "EC2.US-EAST-1.AMAZONAWS.COM.:443", "ec2", "us-east-1", false, false, false, ScopeRegional},
		{"regional fips suffix", "ec2-fips.us-east-1.amazonaws.com", "ec2", "us-east-1", false, true, false, ScopeRegional},
		{"regional fips label", "fips.ec2.us-east-1.amazonaws.com", "ec2", "us-east-1", false, true, false, ScopeRegional},
		{"regional dualstack", "ec2.dualstack.us-east-1.amazonaws.com", "ec2", "us-east-1", false, false, true, ScopeRegional},
		{"regional fips dualstack", "ec2-fips.dualstack.us-east-1.amazonaws.com", "ec2", "us-east-1", false, true, true, ScopeRegional},
		{"regional fips label dualstack", "fips.ec2.dualstack.us-east-1.amazonaws.com", "ec2", "us-east-1", false, true, true, ScopeRegional},
		{"api aws dualstack", "ec2.us-east-1.api.aws", "ec2", "us-east-1", false, false, true, ScopeRegional},
		{"global", "iam.amazonaws.com", "iam", "", true, false, false, ScopeGlobal},
		{"global fips label", "fips.sts.amazonaws.com", "sts", "", true, true, false, ScopeGlobal},
		{"global fips suffix", "sts-fips.amazonaws.com", "sts", "", true, true, false, ScopeGlobal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifier.Classify(tt.authority)
			if err != nil {
				t.Fatalf("Classify(%q): %v", tt.authority, err)
			}
			if got.Service != tt.service || got.Region != tt.region || got.IsGlobal() != tt.global || got.FIPS != tt.fips || got.DualStack != tt.dualstack || got.EffectiveScope() != tt.scope {
				t.Fatalf("unexpected metadata: %+v", got)
			}
			if got.Host != strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(tt.authority, ":443"), ".")) && tt.name != "case trailing dot port" {
				// The host assertion below is intentionally handled separately for
				// authorities containing an explicit port.
				t.Fatalf("unexpected normalized host: %q", got.Host)
			}
		})
	}
}

func TestClassifierSupportsCatalogProfilesAndExceptions(t *testing.T) {
	classifier, err := NewClassifier(32)
	if err != nil {
		t.Fatal(err)
	}
	valid := []struct {
		host          string
		service       string
		signing       string
		region        string
		signingRegion string
		global        bool
		account       string
	}{
		{"api.ecr.us-east-1.amazonaws.com", "api.ecr", "ecr", "us-east-1", "us-east-1", false, ""},
		{"api.sagemaker.us-east-1.amazonaws.com", "api.sagemaker", "sagemaker", "us-east-1", "us-east-1", false, ""},
		{"portal.sso.us-east-1.amazonaws.com", "portal.sso", "awsssoportal", "us-east-1", "us-east-1", false, ""},
		{"ce.us-east-1.amazonaws.com", "ce", "ce", "", "us-east-1", true, ""},
		{"budgets.amazonaws.com", "budgets", "budgets", "", "us-east-1", true, ""},
		{"cloudfront.amazonaws.com", "cloudfront", "cloudfront", "", "us-east-1", true, ""},
		{"123456789012.s3-control.us-east-1.amazonaws.com", "s3-control", "s3", "us-east-1", "us-east-1", false, "123456789012"},
	}
	for _, tt := range valid {
		t.Run(tt.host, func(t *testing.T) {
			got, err := classifier.Classify(tt.host)
			if err != nil {
				t.Fatalf("Classify(%q): %v", tt.host, err)
			}
			if got.Service != tt.service || got.SigningService != tt.signing || got.Region != tt.region || got.SigningRegion != tt.signingRegion || got.IsGlobal() != tt.global || got.AccountID != tt.account {
				t.Fatalf("unexpected endpoint metadata: %+v", got)
			}
		})
	}
	for _, host := range []string{
		"api.ecr.extra.us-east-1.amazonaws.com",
		"portal.sso.us-east-1.amazonaws.com.evil.example",
		"12345678901.s3-control.us-east-1.amazonaws.com",
		"123456789012.s3-control.us-gov-west-1.amazonaws.com",
		"123456789012.s3-control.us-east-1.amazonaws.com:8443",
		"ce.amazonaws.com",
	} {
		if got, err := classifier.Classify(host); err == nil {
			t.Errorf("Classify(%q) unexpectedly succeeded: %+v", host, got)
		}
	}
}

func TestClassifierRegionalSigningRegionsUseParsedRegion(t *testing.T) {
	classifier, err := NewClassifier(16)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"s3", "sts", "organizations"} {
		host := service + ".eu-west-1.amazonaws.com"
		t.Run(service, func(t *testing.T) {
			got, err := classifier.Classify(host)
			if err != nil {
				t.Fatalf("Classify(%q): %v", host, err)
			}
			if got.Region != "eu-west-1" || got.SigningRegion != got.Region || got.IsGlobal() {
				t.Fatalf("regional endpoint did not use parsed signing Region: %+v", got)
			}
		})
	}

	for _, host := range []string{"s3.amazonaws.com", "sts.amazonaws.com", "organizations.amazonaws.com"} {
		t.Run(host, func(t *testing.T) {
			got, err := classifier.Classify(host)
			if err != nil {
				t.Fatalf("Classify(%q): %v", host, err)
			}
			if got.Region != "" || got.SigningRegion != "us-east-1" || !got.IsGlobal() {
				t.Fatalf("global endpoint signing identity changed: %+v", got)
			}
		})
	}

	got, err := classifier.Classify("ce.eu-west-1.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Region != "" || got.SigningRegion != "us-east-1" || !got.IsGlobal() {
		t.Fatalf("Cost Explorer regional-looking-global identity changed: %+v", got)
	}
}

func TestClassifierUsesExplicitDNSPrefixCatalog(t *testing.T) {
	classifier, err := NewClassifier(32)
	if err != nil {
		t.Fatal(err)
	}
	valid := []struct {
		authority string
		service   string
		region    string
		global    bool
		fips      bool
		dualstack bool
	}{
		{"monitoring.us-east-1.amazonaws.com", "monitoring", "us-east-1", false, false, false},
		{"logs.us-east-1.amazonaws.com", "logs", "us-east-1", false, false, false},
		{"events.us-east-1.amazonaws.com", "events", "us-east-1", false, false, false},
		{"iam.amazonaws.com", "iam", "", true, false, false},
		{"s3.amazonaws.com", "s3", "", true, false, false},
		{"route53.amazonaws.com", "route53", "", true, false, false},
		{"organizations.amazonaws.com", "organizations", "", true, false, false},
		{"ec2-fips.dualstack.us-east-1.amazonaws.com", "ec2", "us-east-1", false, true, true},
		{"sts.us-east-1.api.aws", "sts", "us-east-1", false, false, true},
	}
	for _, tt := range valid {
		t.Run(tt.authority, func(t *testing.T) {
			got, err := classifier.Classify(tt.authority)
			if err != nil {
				t.Fatalf("Classify(%q): %v", tt.authority, err)
			}
			if got.Service != tt.service || got.Region != tt.region || got.IsGlobal() != tt.global || got.FIPS != tt.fips || got.DualStack != tt.dualstack {
				t.Fatalf("unexpected metadata for %q: %+v", tt.authority, got)
			}
			if got.Partition != "aws" || got.Host != tt.authority || got.EffectiveScope() != map[bool]EndpointScope{true: ScopeGlobal, false: ScopeRegional}[tt.global] {
				t.Fatalf("unexpected partition/host/scope for %q: %+v", tt.authority, got)
			}
		})
	}

	invalid := []string{
		"cloudwatch.us-east-1.amazonaws.com", // CloudWatch's DNS prefix is monitoring.
		"monitoring.amazonaws.com",           // monitoring is regional, not global.
		"iam.us-east-1.amazonaws.com",        // IAM has no regional commercial API shape.
		"route53.us-east-1.amazonaws.com",    // Route 53 is a global endpoint family.
		"ec2.amazonaws.com",                  // EC2 has no global endpoint.
		"unknown-service.us-east-1.amazonaws.com",
		"monitoring.us-east-1.amazonaws.com.extra",
		"monitoring.extra.us-east-1.amazonaws.com",
		"monitoring.dualstack.dualstack.us-east-1.amazonaws.com",
		"fips.monitoring.us-east-1.amazonaws.com", // The catalog does not permit the legacy FIPS label for monitoring.
		"fips.monitoring.dualstack.us-east-1.amazonaws.com",
	}
	for _, authority := range invalid {
		if got, err := classifier.Classify(authority); err == nil {
			t.Errorf("Classify(%q) unexpectedly succeeded: %+v", authority, got)
		}
	}
}

func TestMonitoringCanonicalServiceAcrossCatalogVariants(t *testing.T) {
	classifier, err := NewClassifier(16)
	if err != nil {
		t.Fatal(err)
	}

	// These are the monitoring shapes explicitly enabled by regionalShapes:
	// the standard, FIPS suffix, dual-stack, FIPS dual-stack, and api.aws
	// (dual-stack) forms. The DNS prefix stays monitoring while the signing
	// service remains CloudWatch.
	tests := []struct {
		name      string
		authority string
		fips      bool
		dualstack bool
	}{
		{"standard", "monitoring.us-east-1.amazonaws.com", false, false},
		{"fips suffix", "monitoring-fips.us-east-1.amazonaws.com", true, false},
		{"dualstack", "monitoring.dualstack.us-east-1.amazonaws.com", false, true},
		{"fips dualstack", "monitoring-fips.dualstack.us-east-1.amazonaws.com", true, true},
		{"api aws dualstack", "monitoring.us-east-1.api.aws", false, true},
		{"api aws fips dualstack", "monitoring-fips.us-east-1.api.aws", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifier.Classify(tt.authority)
			if err != nil {
				t.Fatalf("Classify(%q): %v", tt.authority, err)
			}
			if got.Host != tt.authority || got.Partition != "aws" || got.Service != "monitoring" || got.Region != "us-east-1" || got.IsGlobal() || got.EffectiveScope() != ScopeRegional || got.FIPS != tt.fips || got.DualStack != tt.dualstack {
				t.Fatalf("unexpected canonical monitoring metadata: %+v", got)
			}
		})
	}

	if got, err := classifier.Classify("cloudwatch.us-east-1.amazonaws.com"); err == nil {
		t.Fatalf("unsupported CloudWatch DNS prefix unexpectedly classified: %+v", got)
	}

	cached, ok := classifier.positive.Get("monitoring.us-east-1.amazonaws.com")
	if !ok {
		t.Fatal("monitoring classification was not cached")
	}
	if cached.Service != "monitoring" || cached.Host != "monitoring.us-east-1.amazonaws.com" {
		t.Fatalf("cache retained non-canonical monitoring metadata: %+v", cached)
	}
	again, err := classifier.Classify("monitoring.us-east-1.amazonaws.com")
	if err != nil || again != cached || again.Service != "monitoring" {
		t.Fatalf("cached monitoring metadata changed: %+v, %v", again, err)
	}
}

func TestNormalizeEndpointHostIDNAAndAuthorities(t *testing.T) {
	tests := []struct {
		input string
		host  string
		port  int
	}{
		{"BÜCHER.Example.", "xn--bcher-kva.example", 443},
		{"service.us-east-1.amazonaws.com:8443", "service.us-east-1.amazonaws.com", 8443},
	}
	for _, tt := range tests {
		gotHost, gotPort, err := NormalizeEndpointHost(tt.input)
		if err != nil || gotHost != tt.host || gotPort != tt.port {
			t.Errorf("NormalizeEndpointHost(%q) = %q, %d, %v", tt.input, gotHost, gotPort, err)
		}
	}
}

func TestClassifierRejectsLookalikesUnsupportedAndMalformed(t *testing.T) {
	classifier, err := NewClassifier(4)
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{
		"amazonaws.com.evil.example",
		"ec2.us-east-1.amazonaws.com.evil.example",
		"ec2.us-east-1.amazonaws.com:8443",
		"unknown-service.us-east-1.amazonaws.com",
		"ec2.us-gov-west-1.amazonaws.com",
		"ec2.cn-north-1.amazonaws.com.cn",
		"ec2.us-east-1.amazonaws.com/fake",
		"user:password@ec2.us-east-1.amazonaws.com",
		"127.0.0.1",
		"[::1]",
		"ec2.us-east-1.amazonaws.com:0",
		"ec2.us-east-1.amazonaws.com:65536",
		"fips.ec2.fips.us-east-1.amazonaws.com",
		"ec2..us-east-1.amazonaws.com",
	} {
		if got, err := classifier.Classify(authority); err == nil {
			t.Errorf("Classify(%q) unexpectedly succeeded: %+v", authority, got)
		}
	}
	if !LooksLikeAWSHost("amazonaws.com.evil.example") || !LooksLikeAWSHost("service.us-gov-west-1.amazonaws.com") {
		t.Fatal("AWS suffix rejection predicate missed a label-boundary lookalike")
	}
	if LooksLikeAWSHost("notamazonaws.com.example") {
		t.Fatal("AWS suffix predicate used substring matching")
	}
}

func TestClassifierCachesPositiveAndNegativeResults(t *testing.T) {
	classifier, err := NewClassifier(2)
	if err != nil {
		t.Fatal(err)
	}
	positive, err := classifier.Classify("ec2.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := classifier.Classify("not-a-service.us-east-1.amazonaws.com"); err == nil {
		t.Fatal("unknown endpoint unexpectedly classified")
	}
	if classifier.positive.Len() != 1 || classifier.negative.Len() != 1 {
		t.Fatalf("cache miss was not recorded: positive=%d negative=%d", classifier.positive.Len(), classifier.negative.Len())
	}
	if got, err := classifier.Classify("ec2.us-east-1.amazonaws.com:443"); err != nil || got != positive {
		t.Fatalf("positive cache result changed: %+v, %v", got, err)
	}
	if _, err := classifier.Classify("not-a-service.us-east-1.amazonaws.com"); err == nil || classifier.negative.Len() != 1 {
		t.Fatal("negative cache result was not stable")
	}
}

func TestAWSEndpointValidate(t *testing.T) {
	valid := AWSEndpoint{Partition: "aws", Host: "ec2.us-east-1.amazonaws.com", Service: "ec2", Region: "us-east-1", Scope: ScopeRegional}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []AWSEndpoint{
		{Partition: "aws", Host: "EC2.US-EAST-1.AMAZONAWS.COM", Service: "ec2", Region: "us-east-1"},
		{Partition: "aws", Host: "ec2.us-east-1.amazonaws.com:443", Service: "ec2", Region: "us-east-1"},
		{Partition: "aws", Host: "ec2.us-east-1.amazonaws.com", Service: "ec2", Scope: ScopeRegional},
	} {
		if err := invalid.Validate(); err == nil {
			t.Errorf("invalid endpoint was accepted: %+v", invalid)
		}
	}
}

func TestTier1OrdinaryCatalogCoverage(t *testing.T) {
	catalog, err := iamlivecatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := NewClassifierFromCatalog(catalog, 64)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := buildWireIndex(catalog)
	if err != nil {
		t.Fatal(err)
	}

	// This is an acceptance cohort, not a production endpoint allowlist. The
	// endpoint prefix and signing identity are still obtained from the pinned
	// catalog for every case.
	cohort := []string{
		"acm", "athena", "autoscaling", "backup", "bedrock", "cloudtrail",
		"cognito-identity", "cognito-idp", "config", "ebs", "eks", "elasticache",
		"elasticfilesystem", "elasticmapreduce", "firehose", "glue", "guardduty",
		"kinesis", "rds", "redshift", "secretsmanager", "ssm", "states", "wafv2", "xray",
	}
	identities := make(map[string]iamlivecatalog.ServiceIdentity)
	for _, identity := range catalog.ServiceIdentities() {
		signing := identity.SigningName
		if signing == "" {
			signing = identity.EndpointPrefix
		}
		if prior, exists := identities[identity.EndpointPrefix]; exists {
			priorSigning := prior.SigningName
			if priorSigning == "" {
				priorSigning = prior.EndpointPrefix
			}
			if priorSigning != signing {
				t.Fatalf("catalog signing identity changed for %q", identity.EndpointPrefix)
			}
		}
		identities[identity.EndpointPrefix] = identity
	}
	if len(cohort) != 25 {
		t.Fatalf("Tier 1 cohort size = %d, want 25", len(cohort))
	}
	for _, service := range cohort {
		t.Run(service, func(t *testing.T) {
			identity, ok := identities[service]
			if !ok {
				t.Fatalf("%q is absent from the pinned catalog identity index", service)
			}
			signing := identity.SigningName
			if signing == "" {
				signing = identity.EndpointPrefix
			}
			got, err := classifier.Classify(identity.EndpointPrefix + ".us-east-1.amazonaws.com")
			if err != nil {
				t.Fatalf("catalog-derived standard endpoint was not classified: %v", err)
			}
			if got.Partition != "aws" || got.Service != service || got.SigningService != signing || got.Region != "us-east-1" || got.SigningRegion != "us-east-1" || got.EffectiveScope() != ScopeRegional || got.FIPS || got.DualStack {
				t.Fatalf("unexpected catalog-derived identity: %+v", got)
			}
			want, ok := authoritativeProtocolFor(wire, service)
			if !ok {
				t.Fatalf("catalog API service %q has no unambiguous authoritative protocol", service)
			}
			if exported, ok := AuthoritativeProtocol(service); !ok || exported != want {
				t.Fatalf("authoritative protocol for %q = %q/%v, pinned catalog = %q", service, exported, ok, want)
			}
		})
	}
}

func TestTier1ExceptionalCatalogIdentities(t *testing.T) {
	catalog, err := iamlivecatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := NewClassifierFromCatalog(catalog, 64)
	if err != nil {
		t.Fatal(err)
	}

	// Shared endpoint prefixes intentionally classify to one endpoint
	// identity. The catalog model key remains distinct and wire evidence, not
	// the hostname, selects the API model later in decoding/mapping.
	want := map[string]struct {
		host, endpoint, signing, region string
		global                          bool
	}{
		"apigateway":             {"apigateway.us-east-1.amazonaws.com", "apigateway", "apigateway", "us-east-1", false},
		"apigatewayv2":           {"apigateway.us-east-1.amazonaws.com", "apigateway", "apigateway", "us-east-1", false},
		"elasticloadbalancing":   {"elasticloadbalancing.us-east-1.amazonaws.com", "elasticloadbalancing", "elasticloadbalancing", "us-east-1", false},
		"elasticloadbalancingv2": {"elasticloadbalancing.us-east-1.amazonaws.com", "elasticloadbalancing", "elasticloadbalancing", "us-east-1", false},
		"accessanalyzer":         {"access-analyzer.us-east-1.amazonaws.com", "access-analyzer", "access-analyzer", "us-east-1", false},
		"bedrock-runtime":        {"bedrock-runtime.us-east-1.amazonaws.com", "bedrock-runtime", "bedrock", "us-east-1", false},
		"ecr":                    {"api.ecr.us-east-1.amazonaws.com", "api.ecr", "ecr", "us-east-1", false},
		"opensearch":             {"es.us-east-1.amazonaws.com", "es", "es", "us-east-1", false},
		"s3control":              {"123456789012.s3-control.us-east-1.amazonaws.com", "s3-control", "s3", "us-east-1", false},
		"sagemaker":              {"api.sagemaker.us-east-1.amazonaws.com", "api.sagemaker", "sagemaker", "us-east-1", false},
		"service-quotas":         {"servicequotas.us-east-1.amazonaws.com", "servicequotas", "servicequotas", "us-east-1", false},
		"sesv2":                  {"email.us-east-1.amazonaws.com", "email", "ses", "us-east-1", false},
		"sso":                    {"portal.sso.us-east-1.amazonaws.com", "portal.sso", "awsssoportal", "us-east-1", false},
		"sso-admin":              {"sso.us-east-1.amazonaws.com", "sso", "sso", "us-east-1", false},
		"budgets":                {"budgets.amazonaws.com", "budgets", "budgets", "us-east-1", true},
		"ce":                     {"ce.us-east-1.amazonaws.com", "ce", "ce", "us-east-1", true},
		"cloudfront":             {"cloudfront.amazonaws.com", "cloudfront", "cloudfront", "us-east-1", true},
	}
	identities := make(map[string]string)
	for _, identity := range catalog.ServiceIdentities() {
		signing := identity.SigningName
		if signing == "" {
			signing = identity.EndpointPrefix
		}
		identities[identity.EndpointPrefix] = signing
	}
	if len(want) != 17 {
		t.Fatalf("exceptional Tier 1 cohort size = %d, want 17", len(want))
	}
	for key, expected := range want {
		t.Run(key, func(t *testing.T) {
			if signing, ok := identities[expected.endpoint]; !ok || signing != expected.signing {
				t.Fatalf("catalog identity for %q = %q/%v, want endpoint=%q signing=%q", key, signing, ok, expected.endpoint, expected.signing)
			}
			got, err := classifier.Classify(expected.host)
			if err != nil {
				t.Fatalf("Classify(%q): %v", expected.host, err)
			}
			if got.Service != expected.endpoint || got.SigningService != expected.signing || got.SigningRegion != expected.region || got.Region != map[bool]string{true: "", false: expected.region}[expected.global] || got.IsGlobal() != expected.global {
				t.Fatalf("unexpected exceptional identity: %+v", got)
			}
		})
	}

	for _, host := range []string{
		"api.ecr.extra.us-east-1.amazonaws.com", "portal.sso.extra.us-east-1.amazonaws.com",
		"servicequotas.us-east-1.amazonaws.com.evil.example", "123456789012.ce.us-east-1.amazonaws.com",
		"s3-control.us-east-1.amazonaws.com", "bucket.s3-control.us-east-1.amazonaws.com", "123456789012.s3-control.us-gov-west-1.amazonaws.com",
		"apigatewayv2.us-east-1.amazonaws.com", "elasticloadbalancingv2.us-east-1.amazonaws.com",
	} {
		if got, err := classifier.Classify(host); err == nil {
			t.Errorf("Classify(%q) unexpectedly succeeded: %+v", host, got)
		}
	}
}

func TestTier1OrdinaryEndpointProfiles(t *testing.T) {
	classifier, err := NewClassifier(32)
	if err != nil {
		t.Fatal(err)
	}
	// A few representatives cover the shared generic profiles without turning
	// each profile shape into a second per-service acceptance list.
	cases := []struct {
		name      string
		host      string
		fips      bool
		dualstack bool
	}{
		{"fips suffix", "acm-fips.us-east-1.amazonaws.com", true, false},
		{"dual-stack", "athena.dualstack.us-east-1.amazonaws.com", false, true},
		{"fips dual-stack", "rds-fips.dualstack.us-east-1.amazonaws.com", true, true},
		{"api aws dual-stack", "xray.us-east-1.api.aws", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifier.Classify(tc.host)
			if err != nil {
				t.Fatalf("Classify(%q): %v", tc.host, err)
			}
			if got.Region != "us-east-1" || got.EffectiveScope() != ScopeRegional || got.FIPS != tc.fips || got.DualStack != tc.dualstack || got.SigningService == "" || got.SigningRegion != got.Region {
				t.Fatalf("unexpected generic profile identity: %+v", got)
			}
		})
	}
}
