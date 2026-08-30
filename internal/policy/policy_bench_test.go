package policy

import (
	"context"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/config"
)

func benchmarkPolicy(b *testing.B, rules int) (*Engine, DecisionInput) {
	b.Helper()
	p := config.Policy{Default: config.PolicyDeny, Rules: make([]config.Rule, rules)}
	for i := range p.Rules {
		p.Rules[i] = config.Rule{ID: "rule-" + string(rune('a'+i%26)) + string(rune('0'+i/26)), Effect: config.EffectAllow, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bench/*"}}
	}
	// Rule IDs must be unique even at larger benchmark sizes.
	for i := range p.Rules {
		p.Rules[i].ID = "rule-" + benchmarkDecimal(i)
	}
	e, err := NewEngine(p)
	if err != nil {
		b.Fatal(err)
	}
	mapping := awsrequest.MappingResult{Service: "s3", Operation: "GetObject", MapperVersion: "benchmark", Confidence: awsrequest.ConfidenceHigh, Requirements: []awsrequest.IAMRequirement{{Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bench/key"}, ScopeKind: awsrequest.ScopeExact}}}
	hash, err := config.PolicyHash(p)
	if err != nil {
		b.Fatal(err)
	}
	ep := awsrequest.AWSEndpoint{Partition: "aws", Host: "s3.us-east-1.amazonaws.com", Service: "s3", Region: "us-east-1"}
	req := &awsrequest.DecodedAWSRequest{Partition: "aws", EndpointHost: ep.Host, Service: "s3", Region: ep.Region, CallerAccountID: "123456789012", Protocol: awsrequest.ProtocolRESTXML, Operation: "GetObject", Method: "GET", CanonicalPath: "/bench/key", PayloadHashMode: awsrequest.PayloadHashSHA256}
	return e, DecisionInput{RunID: "benchmark", Endpoint: ep, Request: req, Mapping: &mapping, PolicyHash: hash, MapperVersion: "benchmark"}
}

func benchmarkDecimal(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func BenchmarkPolicyMatch10(b *testing.B)   { benchmarkPolicyMatch(b, 10) }
func BenchmarkPolicyMatch100(b *testing.B)  { benchmarkPolicyMatch(b, 100) }
func BenchmarkPolicyMatch1000(b *testing.B) { benchmarkPolicyMatch(b, 1000) }

func benchmarkPolicyMatch(b *testing.B, rules int) {
	e, input := benchmarkPolicy(b, rules)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Evaluate(context.Background(), input)
	}
}
