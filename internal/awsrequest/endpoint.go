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
	Partition string `json:"partition"`
	Host      string `json:"host"`
	// Service is the exact API/catalog endpoint prefix. It is deliberately
	// independent from the SigV4 credential scope service.
	Service        string `json:"service"`
	SigningService string `json:"signing_service"`
	SigningRegion  string `json:"signing_region"`
	// Region is the observed regional host identity. It is empty for global
	// endpoints, even when SigningRegion is non-empty.
	Region    string        `json:"region"`
	Global    bool          `json:"global"`
	Scope     EndpointScope `json:"scope,omitempty"`
	FIPS      bool          `json:"fips,omitempty"`
	DualStack bool          `json:"dualstack,omitempty"`
	// AccountID is typed evidence extracted from an approved account-labelled
	// host, not caller identity and never a substitute for it.
	AccountID string `json:"account_id,omitempty"`
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
	if err := validateEndpointService(e.Service); err != nil {
		return fmt.Errorf("endpoint service: %w", err)
	}
	if e.SigningService != "" && !validSigningIdentity(e.SigningService) {
		return errors.New("endpoint signing service is invalid")
	}
	if e.SigningRegion != "" && !validSigningRegion(e.SigningRegion) {
		return errors.New("endpoint signing Region is invalid")
	}
	if e.SigningService != "" && e.SigningRegion == "" {
		return errors.New("endpoint signing Region is required with signing service")
	}
	if e.SigningRegion != "" && e.SigningService == "" {
		return errors.New("endpoint signing service is required with signing Region")
	}
	if err := validateEndpointAccountID(e.AccountID); err != nil {
		return err
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
	if e.IsGlobal() && e.Region != "" {
		return errors.New("global endpoint Region must be empty")
	}
	if e.SigningService != "" && !e.IsGlobal() && e.SigningRegion != e.Region {
		return errors.New("regional endpoint signing Region disagrees with endpoint Region")
	}
	return nil
}

func validateEndpointService(value string) error {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return errors.New("must be a lowercase DNS-like API prefix")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("must contain non-empty DNS-like labels")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return errors.New("must contain only ASCII DNS-like labels")
			}
		}
	}
	return nil
}

func validSigningIdentity(value string) bool {
	return ValidateSigningService(value) == nil
}

// ValidateSigningService validates the bounded SigV4 service-scope identity.
// AWS service scopes use bounded safe dotted labels and may preserve catalog case.
func ValidateSigningService(value string) error {
	if value == "" || len(value) > 128 {
		return errors.New("signing service must be non-empty and bounded")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("signing service must contain non-empty DNS-like labels")
		}
		for _, r := range label {
			if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return errors.New("signing service contains unsupported syntax")
			}
		}
	}
	return nil
}

func validSigningRegion(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return false
		}
	}
	return true
}

func validateEndpointAccountID(value string) error {
	if value == "" {
		return nil
	}
	if len(value) != 12 {
		return errors.New("endpoint account ID must be exactly 12 ASCII digits")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return errors.New("endpoint account ID must be exactly 12 ASCII digits")
		}
	}
	return nil
}

// EndpointIdentityEqual compares every classifier identity dimension. Empty
// signing fields are accepted only for compatibility with pre-identity
// contracts; classified endpoints always carry them explicitly.
func EndpointIdentityEqual(a, b AWSEndpoint) bool {
	serviceMatch := a.SigningService == "" || b.SigningService == "" || a.SigningService == b.SigningService
	regionMatch := a.SigningRegion == "" || b.SigningRegion == "" || a.SigningRegion == b.SigningRegion
	return a.Partition == b.Partition && a.Host == b.Host && a.Service == b.Service &&
		a.Region == b.Region && a.EffectiveScope() == b.EffectiveScope() &&
		a.FIPS == b.FIPS && a.DualStack == b.DualStack && a.AccountID == b.AccountID &&
		serviceMatch && regionMatch
}

// SameEndpoint is the concise package-native identity comparison used by
// decoders, mappers, and the proxy stage boundary.
func SameEndpoint(a, b AWSEndpoint) bool { return EndpointIdentityEqual(a, b) }

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
	catalog  *EndpointIdentityIndex
	mu       sync.Mutex
}

// NewClassifier creates a commercial endpoint classifier. A zero capacity
// selects a conservative default; capacities are shared by positive and
// negative caches.
func NewClassifier(capacity int) (*Classifier, error) {
	index, err := loadEndpointIdentityIndex()
	if err != nil {
		return nil, err
	}
	return newClassifier(index, capacity)
}

func newClassifier(index *EndpointIdentityIndex, capacity int) (*Classifier, error) {
	if index == nil || len(index.families) == 0 {
		return nil, errors.New("endpoint identity index is unavailable")
	}
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
	return &Classifier{positive: positive, negative: negative, catalog: index}, nil
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
	endpoint, ok := classifyCommercialHost(host, c.catalog.families)
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
	shapeRegionalGlobal
	shapeAccountRegional
	shapeAccountRegionalDualStack
)

// endpointFamily is a reviewed, positive catalog entry. Service is the exact
// API/catalog prefix while SigningService is the independent SigV4 identity.
// Shapes are exact host label layouts; they are not inferred from a service
// name or a suffix.
type endpointFamily struct {
	DNSPrefix      string
	Service        string
	SigningService string
	SigningRegion  string
	Shapes         endpointShape
	AccountLabel   bool
}

const regionalShapes = shapeRegional | shapeRegionalFIPS | shapeRegionalDualStack | shapeRegionalFIPSDualStack | shapeRegionalAPIAWS | shapeRegionalFIPSAPIAWS

func classifyCommercialHost(host string, families map[string]endpointFamily) (AWSEndpoint, bool) {
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
		return classifyAPIAWSEndpoint(host, body, families)
	}
	return classifyAmazonAWSEndpoint(host, body, families)
}

func classifyAPIAWSEndpoint(host string, body []string, families map[string]endpointFamily) (AWSEndpoint, bool) {
	// api.aws is the dual-stack regional profile. Both the catalog prefix and
	// its optional -fips spelling may contain multiple DNS labels.
	if len(body) < 2 {
		return AWSEndpoint{}, false
	}
	region := body[len(body)-1]
	if !validCommercialRegion(region) {
		return AWSEndpoint{}, false
	}
	prefixLabels := body[:len(body)-1]
	fips := false
	if len(prefixLabels) > 0 && strings.HasSuffix(prefixLabels[len(prefixLabels)-1], "-fips") {
		fips = true
		prefixLabels = append([]string(nil), prefixLabels...)
		prefixLabels[len(prefixLabels)-1] = strings.TrimSuffix(prefixLabels[len(prefixLabels)-1], "-fips")
	}
	prefix := strings.Join(prefixLabels, ".")
	family, ok := families[prefix]
	if !ok || family.DNSPrefix != prefix {
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

func classifyAmazonAWSEndpoint(host string, body []string, families map[string]endpointFamily) (AWSEndpoint, bool) {
	// Global forms consume the complete catalog prefix, so multi-label
	// prefixes remain exact matches rather than becoming arbitrary subdomains.
	if endpoint, ok := classifyGlobalAmazonEndpoint(host, body, families); ok {
		return endpoint, true
	}

	// Account-qualified forms are deliberately opt-in metadata (currently S3
	// Control). A numeric label is never treated as a generic service prefix.
	if len(body) > 1 && validAccountLabel(body[0]) {
		if endpoint, ok := classifyRegionalAmazonBody(host, body[1:], families, body[0]); ok {
			return endpoint, true
		}
	}
	return classifyRegionalAmazonBody(host, body, families, "")
}

func classifyGlobalAmazonEndpoint(host string, body []string, families map[string]endpointFamily) (AWSEndpoint, bool) {
	if len(body) == 0 {
		return AWSEndpoint{}, false
	}
	prefixLabels := append([]string(nil), body...)
	fips, shape := false, shapeGlobal
	if prefixLabels[0] == "fips" {
		if len(prefixLabels) == 1 {
			return AWSEndpoint{}, false
		}
		prefixLabels = prefixLabels[1:]
		fips, shape = true, shapeGlobalFIPSLabel
	} else if strings.HasSuffix(prefixLabels[len(prefixLabels)-1], "-fips") {
		prefixLabels[len(prefixLabels)-1] = strings.TrimSuffix(prefixLabels[len(prefixLabels)-1], "-fips")
		fips, shape = true, shapeGlobalFIPSSuffix
	}
	prefix := strings.Join(prefixLabels, ".")
	family, ok := families[prefix]
	if !ok || family.DNSPrefix != prefix || family.Shapes&shape == 0 {
		return AWSEndpoint{}, false
	}
	return awsEndpoint(family, host, "", true, fips, false), true
}

func classifyRegionalAmazonBody(host string, body []string, families map[string]endpointFamily, account string) (AWSEndpoint, bool) {
	if len(body) < 2 {
		return AWSEndpoint{}, false
	}
	region := body[len(body)-1]
	if !validCommercialRegion(region) {
		return AWSEndpoint{}, false
	}

	// A reviewed regional-looking global endpoint is parsed before the generic
	// profile and never exposes the hostname's region as endpoint scope.
	if family, ok := families[strings.Join(body[:len(body)-1], ".")]; ok && family.Shapes&shapeRegionalGlobal != 0 {
		// Account-qualified hosts are an explicit shape override, not a
		// generic prefix. Never let a numeric label turn a regional-looking
		// global service (for example ce) into an account-qualified endpoint.
		if account != "" {
			return AWSEndpoint{}, false
		}
		return awsEndpointWithAccount(family, host, "", true, false, false, ""), true
	}

	prefixLabels := body[:len(body)-1]
	shape := shapeRegional
	fips, dualstack := false, false
	switch {
	case len(prefixLabels) >= 2 && prefixLabels[len(prefixLabels)-1] == "dualstack":
		dualstack = true
		shape = shapeRegionalDualStack
		prefixLabels = prefixLabels[:len(prefixLabels)-1]
		if len(prefixLabels) > 0 && prefixLabels[0] == "fips" {
			prefixLabels = prefixLabels[1:]
			fips, shape = true, shapeRegionalFIPSLabelDualStack
		} else if len(prefixLabels) > 0 && strings.HasSuffix(prefixLabels[len(prefixLabels)-1], "-fips") {
			prefixLabels[len(prefixLabels)-1] = strings.TrimSuffix(prefixLabels[len(prefixLabels)-1], "-fips")
			fips, shape = true, shapeRegionalFIPSDualStack
		}
	case len(prefixLabels) > 0 && prefixLabels[0] == "fips":
		fips, shape = true, shapeRegionalFIPSLabel
		prefixLabels = prefixLabels[1:]
	case len(prefixLabels) > 0 && strings.HasSuffix(prefixLabels[len(prefixLabels)-1], "-fips"):
		fips, shape = true, shapeRegionalFIPS
		prefixLabels[len(prefixLabels)-1] = strings.TrimSuffix(prefixLabels[len(prefixLabels)-1], "-fips")
	}
	prefix := strings.Join(prefixLabels, ".")
	if account != "" {
		// Account-qualified forms are a separate reviewed shape family. They
		// must not inherit ordinary regional or FIPS acceptance from the
		// service profile.
		if fips {
			return AWSEndpoint{}, false
		}
		if dualstack {
			shape = shapeAccountRegionalDualStack
		} else {
			shape = shapeAccountRegional
		}
	}
	family, ok := families[prefix]
	if !ok || family.DNSPrefix != prefix || family.Shapes&shape == 0 {
		return AWSEndpoint{}, false
	}
	if account != "" && !family.AccountLabel {
		return AWSEndpoint{}, false
	}
	return awsEndpointWithAccount(family, host, region, false, fips, dualstack, account), true
}

func validAccountLabel(value string) bool {
	return len(value) == 12 && validateEndpointAccountID(value) == nil
}

func validCommercialRegion(region string) bool {
	return regionPattern.MatchString(region) && supportedRegion(region)
}

func awsEndpoint(family endpointFamily, host, region string, global, fips, dualstack bool) AWSEndpoint {
	return awsEndpointWithAccount(family, host, region, global, fips, dualstack, "")
}

func awsEndpointWithAccount(family endpointFamily, host, region string, global, fips, dualstack bool, account string) AWSEndpoint {
	signingRegion := family.SigningRegion
	if !global {
		// Family-level signing-region overrides describe global endpoints only.
		// Regional endpoints always sign in the region parsed from their host.
		signingRegion = region
	}
	return AWSEndpoint{
		Partition:      "aws",
		Host:           host,
		Service:        family.Service,
		SigningService: family.SigningService,
		SigningRegion:  signingRegion,
		Region:         region,
		Global:         global,
		Scope:          scopeFor(global),
		FIPS:           fips,
		DualStack:      dualstack,
		AccountID:      account,
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
