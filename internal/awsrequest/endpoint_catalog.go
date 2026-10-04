package awsrequest

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

// EndpointIdentityIndex is the immutable endpoint-prefix index compiled from
// one pinned catalog. It contains no operation or IAM evidence; those remain
// owned by iamlivecatalog and the mapper respectively.
type EndpointIdentityIndex struct {
	families map[string]endpointFamily
}

// endpointOverrides contains only endpoint shapes which cannot be derived
// from an API model. Ordinary services use the bounded regional profile below.
// The table is intentionally about DNS shape, not service coverage.
type endpointOverride struct {
	shapes        endpointShape
	signingRegion string
	accountLabel  bool
}

// endpointOverrides contains shape metadata only. The catalog remains the
// allowlist of endpoint and signing identities; these entries do not add
// services which are absent from that catalog.
var endpointOverrides = map[string]endpointOverride{
	"sts":           {shapes: regionalShapes | shapeGlobal | shapeGlobalFIPSLabel | shapeGlobalFIPSSuffix, signingRegion: "us-east-1"},
	"iam":           {shapes: shapeGlobal | shapeGlobalFIPSLabel | shapeGlobalFIPSSuffix, signingRegion: "us-east-1"},
	"s3":            {shapes: regionalShapes | shapeGlobal, signingRegion: "us-east-1"},
	"ec2":           {shapes: regionalShapes | shapeRegionalFIPSLabel | shapeRegionalFIPSLabelDualStack},
	"route53":       {shapes: shapeGlobal | shapeGlobalFIPSLabel | shapeGlobalFIPSSuffix, signingRegion: "us-east-1"},
	"organizations": {shapes: regionalShapes | shapeGlobal | shapeGlobalFIPSLabel | shapeGlobalFIPSSuffix, signingRegion: "us-east-1"},
	// CloudWatch's endpoint prefix and SigV4 service are both monitoring.
	"monitoring": {shapes: regionalShapes},

	// These services have reviewed global endpoint forms. ce intentionally
	// keeps its regional-looking hostname while remaining globally scoped.
	"budgets":    {shapes: shapeGlobal, signingRegion: "us-east-1"},
	"ce":         {shapes: shapeRegionalGlobal, signingRegion: "us-east-1"},
	"cloudfront": {shapes: shapeGlobal, signingRegion: "us-east-1"},

	// S3 Control's account-qualified hostname is an explicit exception to the
	// ordinary service[.region] profile.
	"s3-control": {shapes: shapeAccountRegional | shapeAccountRegionalDualStack, accountLabel: true},
}

// loadEndpointIdentityIndex obtains the only production endpoint identity
// source. Catalog loading is deliberately performed before a classifier can
// accept traffic, so malformed or incomplete pinned evidence fails closed.
func loadEndpointIdentityIndex() (*EndpointIdentityIndex, error) {
	catalog, err := iamlivecatalog.Load()
	if err != nil {
		return nil, fmt.Errorf("load iamlive catalog: %w", err)
	}
	return CompileCatalogEndpointIdentityIndex(catalog)
}

// CompileCatalogEndpointIdentityIndex compiles the immutable service view of a
// pinned catalog without retaining the catalog's operation or mapping data.
func CompileCatalogEndpointIdentityIndex(catalog *iamlivecatalog.Catalog) (*EndpointIdentityIndex, error) {
	if catalog == nil {
		return nil, errors.New("catalog endpoint identity is unavailable")
	}
	return compileEndpointIdentityViews(catalog.ServiceIdentities())
}

// NewClassifierFromCatalog compiles a catalog identity index and publishes a
// classifier only after the complete index has been validated.
func NewClassifierFromCatalog(catalog *iamlivecatalog.Catalog, capacity int) (*Classifier, error) {
	index, err := CompileCatalogEndpointIdentityIndex(catalog)
	if err != nil {
		return nil, err
	}
	return NewClassifierFromEndpointIdentityIndex(index, capacity)
}

// CompileEndpointIdentityIndex compiles service-model metadata without
// retaining operation-level data. An omitted signing name has the AWS model
// meaning of the endpoint prefix; any other disagreement for one prefix is
// ambiguous and rejected.
func CompileEndpointIdentityIndex(services []iamlivecatalog.Service) (*EndpointIdentityIndex, error) {
	views := make([]iamlivecatalog.ServiceIdentity, len(services))
	for i, service := range services {
		views[i] = iamlivecatalog.ServiceIdentity{EndpointPrefix: service.EndpointPrefix, SigningName: service.SigningName}
	}
	return compileEndpointIdentityViews(views)
}

func compileEndpointIdentityViews(services []iamlivecatalog.ServiceIdentity) (*EndpointIdentityIndex, error) {
	if len(services) == 0 {
		return nil, errors.New("catalog endpoint identity is empty")
	}
	identities := make(map[string]string, len(services))
	for _, service := range services {
		prefix := service.EndpointPrefix
		if err := validateEndpointPrefix(prefix); err != nil {
			return nil, fmt.Errorf("catalog endpoint prefix %q: invalid endpoint prefix: %w", prefix, err)
		}
		signing := service.SigningName
		if signing == "" {
			signing = prefix
		}
		if err := validateSigningName(signing); err != nil {
			return nil, fmt.Errorf("catalog endpoint prefix %q: invalid signing name: %w", prefix, err)
		}
		if prior, ok := identities[prefix]; ok && prior != signing {
			return nil, fmt.Errorf("catalog endpoint prefix %q has ambiguous signing names %q and %q", prefix, prior, signing)
		}
		identities[prefix] = signing
	}

	families := make(map[string]endpointFamily, len(identities))
	for prefix, signing := range identities {
		family := endpointFamily{DNSPrefix: prefix, Service: prefix, SigningService: signing, Shapes: regionalShapes}
		if override, ok := endpointOverrides[prefix]; ok {
			family.Shapes = override.shapes
			family.SigningRegion = override.signingRegion
			family.AccountLabel = override.accountLabel
		}
		families[prefix] = family
	}
	return &EndpointIdentityIndex{families: families}, nil
}

// NewClassifierFromEndpointIdentityIndex constructs a classifier from a
// previously compiled immutable catalog view. It is useful to callers that
// need to validate a reviewed catalog before publishing a classifier.
func NewClassifierFromEndpointIdentityIndex(index *EndpointIdentityIndex, capacity int) (*Classifier, error) {
	if index == nil || len(index.families) == 0 {
		return nil, errors.New("endpoint identity index is unavailable")
	}
	return newClassifier(index, capacity)
}

func validateEndpointPrefix(prefix string) error {
	if prefix == "" || prefix != strings.ToLower(prefix) || len(prefix) > 253 {
		return errors.New("endpoint prefix must be lowercase and non-empty")
	}
	for _, label := range strings.Split(prefix, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("endpoint prefix contains an invalid DNS label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return errors.New("endpoint prefix contains a non-ASCII DNS label")
			}
		}
	}
	return nil
}

func validateSigningName(name string) error {
	if !validSigningIdentity(name) {
		return errors.New("signing name must be a bounded lowercase SigV4 service identity")
	}
	return nil
}
