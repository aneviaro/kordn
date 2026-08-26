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

// Package awsrequest owns the endpoint, protocol, decoded-request, and mapper
// contracts shared by the proxy, mapper, and policy packages.
package awsrequest

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/idna"

	"github.com/kordn-ai/kordn/internal/cache"
)

// EndpointScope distinguishes a regional endpoint from a modeled AWS global
// endpoint. A global endpoint may still have a signing Region in the decoded
// request; endpoint scope and signing scope are intentionally separate.
type EndpointScope string

const (
	ScopeRegional EndpointScope = "regional"
	ScopeGlobal   EndpointScope = "global"
)

// AWSEndpoint is a positive endpoint classification. Host is the exact,
// normalized DNS host used for CONNECT and inner-Host agreement checks; it is
// not a suffix or a user-provided display label.
type AWSEndpoint struct {
	Partition string        `json:"partition"`
	Host      string        `json:"host"`
	Service   string        `json:"service"`
	Region    string        `json:"region"`
	Global    bool          `json:"global"`
	Scope     EndpointScope `json:"scope,omitempty"`
	FIPS      bool          `json:"fips,omitempty"`
	DualStack bool          `json:"dualstack,omitempty"`
}

func (e AWSEndpoint) IsGlobal() bool { return e.Global || e.Scope == ScopeGlobal }

func (e AWSEndpoint) EffectiveScope() EndpointScope {
	if e.IsGlobal() {
		return ScopeGlobal
	}
	return ScopeRegional
}

// Validate checks the shape of a classifier result. Supported service and
// partition catalogs remain the classifier's responsibility, so this method
// does not perform network or metadata lookups.
func (e AWSEndpoint) Validate() error {
	if strings.TrimSpace(e.Partition) == "" {
		return errors.New("endpoint partition is required")
	}
	if strings.TrimSpace(e.Host) == "" {
		return errors.New("endpoint host is required")
	}
	if len(e.Host) > 253 || e.Host != strings.ToLower(e.Host) || strings.HasSuffix(e.Host, ".") {
		return errors.New("endpoint host must be normalized to lowercase without a trailing dot")
	}
	if strings.ContainsAny(e.Host, " \t\r\n:/") {
		return errors.New("endpoint host must be a normalized DNS host without a port")
	}
	for _, label := range strings.Split(e.Host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("endpoint host contains an invalid DNS label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return errors.New("endpoint host contains a non-ASCII DNS label")
			}
		}
	}
	if strings.TrimSpace(e.Service) == "" {
		return errors.New("endpoint service is required")
	}
	if e.Scope != "" && e.Scope != ScopeRegional && e.Scope != ScopeGlobal {
		return fmt.Errorf("unsupported endpoint scope %q", e.Scope)
	}
	if e.Scope == ScopeRegional && e.Global {
		return errors.New("regional endpoint scope conflicts with global endpoint")
	}
	if !e.IsGlobal() && strings.TrimSpace(e.Region) == "" {
		return errors.New("regional endpoint Region is required")
	}
	return nil
}

// EndpointClassifier positively classifies a normalized host. Unknown,
// custom, and unsupported-partition hosts must be returned as errors; there is
// no permissive fallback endpoint.
type EndpointClassifier interface {
	Classify(host string) (AWSEndpoint, error)
}

// NormalizeEndpointHost canonicalizes a host or host:port authority. It
// accepts only DNS names (not IP literals or userinfo), removes one DNS root
// dot, applies IDNA lookup processing, and returns a lower-case ASCII host and
// an explicit port. AWS endpoints are TLS on port 443.
func NormalizeEndpointHost(authority string) (string, int, error) {
	if authority == "" || strings.TrimSpace(authority) != authority || strings.ContainsAny(authority, "\x00\r\n/@") {
		return "", 0, errors.New("endpoint authority is malformed")
	}
	var host string
	port := 443
	if strings.HasPrefix(authority, "[") {
		return "", 0, errors.New("IPv6 endpoint is not an AWS DNS endpoint")
	}
	if strings.Count(authority, ":") == 1 {
		var portText string
		var ok bool
		host, portText, ok = strings.Cut(authority, ":")
		if len(portText) > 5 {
			return "", 0, errors.New("endpoint authority port is invalid")
		}
		if !ok || host == "" || portText == "" {
			return "", 0, errors.New("endpoint authority port is malformed")
		}
		value := 0
		for _, char := range portText {
			if char < '0' || char > '9' {
				return "", 0, errors.New("endpoint authority port is malformed")
			}
			value = value*10 + int(char-'0')
			if value > 65535 {
				return "", 0, errors.New("endpoint authority port is invalid")
			}
		}
		if value == 0 {
			return "", 0, errors.New("endpoint authority port is invalid")
		}
		port = value
	} else if strings.Contains(authority, ":") {
		return "", 0, errors.New("endpoint authority IPv6 form is malformed")
	} else {
		host = authority
	}
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if host == "" || strings.HasSuffix(host, ".") || len(host) > 253 {
		return "", 0, errors.New("endpoint hostname is malformed")
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", 0, errors.New("endpoint hostname is not valid IDNA")
	}
	ascii = strings.ToLower(ascii)
	if net.ParseIP(ascii) != nil {
		return "", 0, errors.New("endpoint hostname must be DNS")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", 0, errors.New("endpoint hostname has an invalid label")
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
				return "", 0, errors.New("endpoint hostname has a non-ASCII label")
			}
		}
	}
	return ascii, port, nil
}

// Classifier is the explicit commercial AWS endpoint catalog. Positive and
// negative results are cached independently so malformed or unsupported names
// cannot cause repeated work or become a permissive fallback.
type Classifier struct {
	positive *cache.LRU[string, AWSEndpoint]
	negative *cache.LRU[string, struct{}]
	mu       sync.Mutex
}

// NewClassifier creates a commercial endpoint classifier. A zero capacity
// selects a conservative default; capacities are shared by positive and
// negative caches.
func NewClassifier(capacity int) (*Classifier, error) {
	if capacity <= 0 {
		capacity = 256
	}
	positive, err := cache.NewLRU[string, AWSEndpoint](capacity)
	if err != nil {
		return nil, err
	}
	negative, err := cache.NewLRU[string, struct{}](capacity)
	if err != nil {
		return nil, err
	}
	return &Classifier{positive: positive, negative: negative}, nil
}

// NewCommercialClassifier is a descriptive alias for NewClassifier.
func NewCommercialClassifier(capacity int) (*Classifier, error) { return NewClassifier(capacity) }

// NewEndpointClassifier constructs the built-in commercial catalog. The
// optional capacity keeps the zero-argument form convenient without exposing
// an unbounded cache.
func NewEndpointClassifier(capacity ...int) (*Classifier, error) {
	selected := 256
	if len(capacity) > 0 {
		selected = capacity[0]
	}
	return NewClassifier(selected)
}

func NewCommercialEndpointClassifier(capacity ...int) (*Classifier, error) {
	return NewEndpointClassifier(capacity...)
}

var defaultClassifier = mustClassifier()

// DefaultEndpointClassifier is a read-only interface view of the default
// bounded classifier.
var DefaultEndpointClassifier EndpointClassifier = defaultClassifier

func mustClassifier() *Classifier {
	classifier, err := NewClassifier(256)
	if err != nil {
		panic(err)
	}
	return classifier
}

// DefaultClassifier returns the process-wide immutable catalog. Its caches
// contain no security decision and are bounded; callers may instead create a
// per-run classifier with NewClassifier.
func DefaultClassifier() EndpointClassifier { return defaultClassifier }

func ClassifyEndpoint(host string) (AWSEndpoint, error) { return defaultClassifier.Classify(host) }
func NormalizeHost(host string) (string, int, error)    { return NormalizeEndpointHost(host) }
func ParseEndpoint(host string) (AWSEndpoint, error)    { return defaultClassifier.Classify(host) }

func (c *Classifier) Classify(authority string) (AWSEndpoint, error) {
	if c == nil {
		return AWSEndpoint{}, errors.New("endpoint classifier is unavailable")
	}
	host, port, err := NormalizeEndpointHost(authority)
	if err != nil || port != 443 {
		return AWSEndpoint{}, errors.New("unsupported AWS endpoint")
	}
	if endpoint, ok := c.positive.Get(host); ok {
		return endpoint, nil
	}
	if _, ok := c.negative.Get(host); ok {
		return AWSEndpoint{}, errors.New("unsupported AWS endpoint")
	}
	// Serializing a miss avoids duplicate catalog work and makes negative
	// caching stable under a burst of malformed requests.
	c.mu.Lock()
	defer c.mu.Unlock()
	if endpoint, ok := c.positive.Get(host); ok {
		return endpoint, nil
	}
	if _, ok := c.negative.Get(host); ok {
		return AWSEndpoint{}, errors.New("unsupported AWS endpoint")
	}
	endpoint, ok := classifyCommercialHost(host)
	if !ok {
		c.negative.Put(host, struct{}{})
		return AWSEndpoint{}, errors.New("unsupported AWS endpoint")
	}
	c.positive.Put(host, endpoint)
	return endpoint, nil
}

// LooksLikeAWSHost is a rejection predicate, not an AWS classifier. It is
// used to keep unsupported AWS partitions, unknown AWS services, and suffix
// lookalikes from being silently turned into proxy relays. It deliberately
// does not classify by substring: complete DNS label sequences are required.
func LooksLikeAWSHost(authority string) bool {
	host, _, err := NormalizeEndpointHost(authority)
	if err != nil {
		return false
	}
	labels := strings.Split(host, ".")
	for i := 0; i+1 < len(labels); i++ {
		if labels[i] == "amazonaws" && labels[i+1] == "com" {
			return true
		}
	}
	if len(labels) >= 2 && labels[len(labels)-2] == "api" && labels[len(labels)-1] == "aws" {
		return true
	}
	return false
}

var regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)

type endpointShape uint16

const (
	shapeRegional endpointShape = 1 << iota
	shapeRegionalFIPS
	shapeRegionalFIPSLabel
	shapeRegionalFIPSLabelDualStack
	shapeRegionalDualStack
	shapeRegionalFIPSDualStack
	shapeRegionalAPIAWS
	shapeRegionalFIPSAPIAWS
	shapeGlobal
	shapeGlobalFIPSLabel
	shapeGlobalFIPSSuffix
)

// endpointFamily is a reviewed, positive catalog entry. DNSPrefix is kept
// separate from Service because AWS DNS names are not service identifiers in
// general (for example, CloudWatch uses monitoring). Shapes are exact host
// label layouts; they are not inferred from a service name or a suffix.
type endpointFamily struct {
	DNSPrefix string
	Service   string
	Shapes    endpointShape
}

const regionalShapes = shapeRegional | shapeRegionalFIPS | shapeRegionalDualStack | shapeRegionalFIPSDualStack | shapeRegionalAPIAWS | shapeRegionalFIPSAPIAWS

// commercialEndpointCatalog is deliberately small. Adding an AWS service or
// endpoint variant requires an explicit entry and a fixture; an AWS-looking
// hostname that is not in this table is not classified.
var commercialEndpointCatalog = map[string]endpointFamily{
	"sts": {
		DNSPrefix: "sts", Service: "sts",
		Shapes: regionalShapes | shapeGlobal | shapeGlobalFIPSLabel | shapeGlobalFIPSSuffix,
	},
	"iam": {
		DNSPrefix: "iam", Service: "iam",
		Shapes: shapeGlobal | shapeGlobalFIPSLabel | shapeGlobalFIPSSuffix,
	},
	"s3": {
		DNSPrefix: "s3", Service: "s3",
		Shapes: regionalShapes | shapeGlobal,
	},
	"ec2": {
		DNSPrefix: "ec2", Service: "ec2",
		Shapes: regionalShapes | shapeRegionalFIPSLabel | shapeRegionalFIPSLabelDualStack,
	},
	"ecs": {
		DNSPrefix: "ecs", Service: "ecs",
		Shapes: regionalShapes,
	},
	"monitoring": {
		DNSPrefix: "monitoring", Service: "cloudwatch",
		Shapes: regionalShapes,
	},
	"logs": {
		DNSPrefix: "logs", Service: "logs",
		Shapes: regionalShapes,
	},
	"lambda": {
		DNSPrefix: "lambda", Service: "lambda",
		Shapes: regionalShapes,
	},
	"dynamodb": {
		DNSPrefix: "dynamodb", Service: "dynamodb",
		Shapes: regionalShapes,
	},
	"kms": {
		DNSPrefix: "kms", Service: "kms",
		Shapes: regionalShapes,
	},
	"sqs": {
		DNSPrefix: "sqs", Service: "sqs",
		Shapes: regionalShapes,
	},
	"sns": {
		DNSPrefix: "sns", Service: "sns",
		Shapes: regionalShapes,
	},
	"events": {
		DNSPrefix: "events", Service: "events",
		Shapes: regionalShapes,
	},
	"cloudformation": {
		DNSPrefix: "cloudformation", Service: "cloudformation",
		Shapes: regionalShapes,
	},
	"route53": {
		DNSPrefix: "route53", Service: "route53",
		Shapes: shapeGlobal | shapeGlobalFIPSLabel | shapeGlobalFIPSSuffix,
	},
	"organizations": {
		DNSPrefix: "organizations", Service: "organizations",
		Shapes: regionalShapes | shapeGlobal | shapeGlobalFIPSLabel | shapeGlobalFIPSSuffix,
	},
}

func classifyCommercialHost(host string) (AWSEndpoint, bool) {
	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return AWSEndpoint{}, false
	}

	suffix := ""
	body := labels
	switch {
	case len(labels) >= 2 && labels[len(labels)-2] == "amazonaws" && labels[len(labels)-1] == "com":
		suffix = "amazonaws.com"
		body = labels[:len(labels)-2]
	case len(labels) >= 2 && labels[len(labels)-2] == "api" && labels[len(labels)-1] == "aws":
		suffix = "api.aws"
		body = labels[:len(labels)-2]
	default:
		return AWSEndpoint{}, false
	}

	if suffix == "api.aws" {
		return classifyAPIAWSEndpoint(host, body)
	}
	return classifyAmazonAWSEndpoint(host, body)
}

func classifyAPIAWSEndpoint(host string, body []string) (AWSEndpoint, bool) {
	// The commercial api.aws catalog uses service[ -fips ].region.api.aws.
	// api.aws is itself the dual-stack form, so a second dualstack label is
	// not accepted.
	if len(body) != 2 {
		return AWSEndpoint{}, false
	}
	prefix, fips := body[0], false
	if strings.HasSuffix(prefix, "-fips") {
		fips = true
		prefix = strings.TrimSuffix(prefix, "-fips")
	}
	family, ok := commercialEndpointCatalog[prefix]
	if !ok || family.DNSPrefix != prefix {
		return AWSEndpoint{}, false
	}
	region := body[1]
	if !validCommercialRegion(region) {
		return AWSEndpoint{}, false
	}
	shape := shapeRegionalAPIAWS
	if fips {
		shape = shapeRegionalFIPSAPIAWS
	}
	if family.Shapes&shape == 0 {
		return AWSEndpoint{}, false
	}
	return awsEndpoint(family, host, region, false, fips, true), true
}

func classifyAmazonAWSEndpoint(host string, body []string) (AWSEndpoint, bool) {
	var family endpointFamily
	var prefix string
	var region string
	var shape endpointShape
	fips, dualstack, global := false, false, false

	switch len(body) {
	case 1:
		// service.amazonaws.com is a global endpoint. Only a catalogued
		// family may claim this shape. The -fips spelling is a separate
		// explicit global shape, not a generic service-name modifier.
		prefix, global, shape = body[0], true, shapeGlobal
		if strings.HasSuffix(prefix, "-fips") {
			prefix, fips, shape = strings.TrimSuffix(prefix, "-fips"), true, shapeGlobalFIPSSuffix
		}
	case 2:
		switch {
		case body[0] == "fips":
			// fips.service.amazonaws.com is the explicit global FIPS form.
			prefix, fips, global, shape = body[1], true, true, shapeGlobalFIPSLabel
		case strings.HasSuffix(body[0], "-fips"):
			// service-fips.region.amazonaws.com is the regional FIPS form.
			prefix, region, fips, shape = strings.TrimSuffix(body[0], "-fips"), body[1], true, shapeRegionalFIPS
		default:
			prefix, region, shape = body[0], body[1], shapeRegional
		}
	case 3:
		switch {
		case body[0] == "fips":
			// fips.service.region.amazonaws.com is retained only for
			// families that explicitly list this legacy shape.
			prefix, region, fips, shape = body[1], body[2], true, shapeRegionalFIPSLabel
		case strings.HasSuffix(body[0], "-fips") && body[1] == "dualstack":
			prefix, region, fips, dualstack, shape = strings.TrimSuffix(body[0], "-fips"), body[2], true, true, shapeRegionalFIPSDualStack
		case body[1] == "dualstack":
			prefix, region, dualstack, shape = body[0], body[2], true, shapeRegionalDualStack
		default:
			return AWSEndpoint{}, false
		}
	case 4:
		// Keep the legacy FIPS label form explicit as well; it is not
		// inferred for every service family.
		if body[0] != "fips" || body[2] != "dualstack" {
			return AWSEndpoint{}, false
		}
		prefix, region, fips, dualstack, shape = body[1], body[3], true, true, shapeRegionalFIPSLabelDualStack
	default:
		return AWSEndpoint{}, false
	}

	family, ok := commercialEndpointCatalog[prefix]
	if !ok || family.DNSPrefix != prefix || family.Shapes&shape == 0 {
		return AWSEndpoint{}, false
	}
	if !global {
		if !validCommercialRegion(region) {
			return AWSEndpoint{}, false
		}
	} else {
		region = ""
	}
	return awsEndpoint(family, host, region, global, fips, dualstack), true
}

func validCommercialRegion(region string) bool {
	return regionPattern.MatchString(region) && supportedRegion(region)
}

func awsEndpoint(family endpointFamily, host, region string, global, fips, dualstack bool) AWSEndpoint {
	return AWSEndpoint{
		Partition: "aws",
		Host:      host,
		Service:   family.Service,
		Region:    region,
		Global:    global,
		Scope:     scopeFor(global),
		FIPS:      fips,
		DualStack: dualstack,
	}
}

func scopeFor(global bool) EndpointScope {
	if global {
		return ScopeGlobal
	}
	return ScopeRegional
}

var supportedRegions = map[string]struct{}{
	"af-south-1": {}, "ap-east-1": {}, "ap-northeast-1": {}, "ap-northeast-2": {}, "ap-northeast-3": {}, "ap-south-1": {}, "ap-south-2": {}, "ap-southeast-1": {}, "ap-southeast-2": {}, "ap-southeast-3": {}, "ap-southeast-4": {}, "ap-southeast-5": {}, "ap-southeast-7": {}, "ca-central-1": {}, "ca-west-1": {}, "eu-central-1": {}, "eu-central-2": {}, "eu-north-1": {}, "eu-south-1": {}, "eu-south-2": {}, "eu-west-1": {}, "eu-west-2": {}, "eu-west-3": {}, "il-central-1": {}, "me-central-1": {}, "me-south-1": {}, "mx-central-1": {}, "sa-east-1": {}, "us-east-1": {}, "us-east-2": {}, "us-west-1": {}, "us-west-2": {},
}

func supportedRegion(region string) bool { _, ok := supportedRegions[region]; return ok }
