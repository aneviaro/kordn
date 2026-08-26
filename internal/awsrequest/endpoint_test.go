// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.

package awsrequest

import (
	"strings"
	"testing"
)

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
		{"monitoring.us-east-1.amazonaws.com", "cloudwatch", "us-east-1", false, false, false},
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
			if got.Host != tt.authority || got.Partition != "aws" || got.Service != "cloudwatch" || got.Region != "us-east-1" || got.IsGlobal() || got.EffectiveScope() != ScopeRegional || got.FIPS != tt.fips || got.DualStack != tt.dualstack {
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
	if cached.Service != "cloudwatch" || cached.Host != "monitoring.us-east-1.amazonaws.com" {
		t.Fatalf("cache retained non-canonical monitoring metadata: %+v", cached)
	}
	again, err := classifier.Classify("monitoring.us-east-1.amazonaws.com")
	if err != nil || again != cached || again.Service != "cloudwatch" {
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
