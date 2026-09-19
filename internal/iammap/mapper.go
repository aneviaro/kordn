// Package iammap is Kordn's fail-closed authorization mapping boundary.
package iammap

import (
	"context"
	"errors"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iammap/data"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
	"sort"
	"strings"
	"time"
)

// MapperVersion identifies Kordn's enforcement mapper contract. The selected
// authorization data is carried separately by AuthorizationDataVersion.
const MapperVersion = "kordn-iammap/v4"

type MapperOptions struct {
	Timeout    time.Duration
	Classifier awsrequest.EndpointClassifier
}

type mapperAdapter interface {
	Version() string
}
type wireLookupAdapter interface {
	LookupRequestContext(context.Context, string, string, iamliveadapter.WireIdentity, map[string]awsrequest.Value) (iamliveadapter.LookupResult, error)
}

type Mapper struct {
	timeout    time.Duration
	classifier awsrequest.EndpointClassifier
	adapter    mapperAdapter
}

func NewMapper(options ...MapperOptions) (*Mapper, error) {
	o := MapperOptions{Timeout: time.Second, Classifier: awsrequest.DefaultEndpointClassifier}
	if len(options) > 0 {
		o = options[0]
	}
	if o.Timeout <= 0 || o.Timeout > time.Minute {
		return nil, errors.New("mapper timeout is invalid")
	}
	if o.Classifier == nil {
		o.Classifier = awsrequest.DefaultEndpointClassifier
	}
	a, e := iamliveadapter.New()
	if e != nil {
		return nil, e
	}
	return &Mapper{timeout: o.Timeout, classifier: o.Classifier, adapter: a}, nil
}
func NewIAMMapper(o ...MapperOptions) (*Mapper, error) { return NewMapper(o...) }
func (m *Mapper) Version() string {
	if m == nil {
		return ""
	}
	return MapperVersion
}
func (m *Mapper) IamLiveVersion() string {
	if m == nil || m.adapter == nil {
		return ""
	}
	return m.adapter.Version()
}
func (m *Mapper) AuthorizationDataVersion() string { return data.AuthorizationDataVersion() }
func (m *Mapper) Map(ctx context.Context, req *awsrequest.DecodedAWSRequest) (result *awsrequest.MappingResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if m == nil || m.adapter == nil {
		return nil, mappingFailure(MappingFailureLowConfidence, "mapper", errors.New("mapper unavailable"))
	}
	if req == nil {
		return nil, mappingFailure(MappingFailureLowConfidence, "input", errors.New("decoded request is required"))
	}
	if e := req.Validate(); e != nil {
		return nil, mappingFailure(MappingFailureLowConfidence, "input", e)
	}
	if e := ctx.Err(); e != nil {
		return nil, mappingContextFailure(e)
	}
	wctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = mappingFailure(MappingFailurePanic, "mapper", ErrMapperPanic)
		}
	}()
	result, err = m.mapOne(wctx, req)
	if err != nil {
		if contextErr := mappingContextFailure(err); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	if contextErr := mappingContextFailure(wctx.Err()); contextErr != nil {
		return nil, contextErr
	}
	if result == nil {
		return nil, mappingFailure(MappingFailureInvalidResult, "result", errors.New("nil mapping"))
	}
	return result, nil
}
func (m *Mapper) mapOne(ctx context.Context, req *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	ep, e := m.classifier.Classify(req.EndpointHost)
	if e != nil || ep.Partition != req.Partition || ep.Service != req.Service || ep.Region != req.Region || ep.IsGlobal() != (req.Region == "") {
		return nil, mappingFailure(MappingFailureCatalogInconsistency, "endpoint", e)
	}
	protocol, ok := awsrequest.AuthoritativeProtocol(req.Service)
	if !ok || protocol != req.Protocol {
		return nil, mappingFailure(MappingFailureCatalogInconsistency, "protocol", nil)
	}
	op := iamliveadapter.NormalizeOperation(req.Operation)
	if op == "" {
		return nil, mappingFailure(MappingFailureUnknownWireOperation, "wire", nil)
	}
	identity := iamliveadapter.WireIdentity{Protocol: req.Protocol, Method: req.Method, Path: req.CanonicalPath, Query: req.CanonicalQuery}
	if req.Protocol == awsrequest.ProtocolJSON10 || req.Protocol == awsrequest.ProtocolJSON11 {
		if req.Headers == nil {
			return nil, mappingFailure(MappingFailureUnknownWireOperation, "wire", nil)
		}
		targets := req.Headers.Values("X-Amz-Target")
		if len(targets) != 1 {
			return nil, mappingFailure(MappingFailureUnknownWireOperation, "wire", nil)
		}
		identity.Target = targets[0]
	}
	wire, ok := m.adapter.(wireLookupAdapter)
	if !ok {
		return nil, mappingFailure(MappingFailureCatalogInconsistency, "adapter", nil)
	}
	lookup, lookupErr := wire.LookupRequestContext(ctx, req.Service, op, identity, req.Parameters)
	if lookupErr != nil {
		if contextErr := mappingContextFailure(lookupErr); contextErr != nil {
			return nil, lookupErr
		}
		var failure *iamliveadapter.Failure
		if errors.As(lookupErr, &failure) {
			detail := failure.SafeDetail()
			switch failure.Kind {
			case iamliveadapter.FailureUnknownWireOperation, iamliveadapter.FailureIncompleteWireIdentity:
				return nil, mappingFailure(MappingFailureUnknownWireOperation, "wire", lookupErr)
			case iamliveadapter.FailureAmbiguousWireOperation:
				return nil, mappingFailure(MappingFailureAmbiguousWireOperation, "wire", lookupErr)
			case iamliveadapter.FailureUnresolvedApplicability:
				return nil, mappingFailure(MappingFailureUnresolvedPrimaryResource, "resource", lookupErr)
			case iamliveadapter.FailureUnresolvedDependency:
				return nil, mappingFailureWithDetail(MappingFailureUnresolvedDependency, "dependency", lookupErr, detail)
			default:
				return nil, mappingFailure(MappingFailureCatalogInconsistency, "catalog", lookupErr)
			}
		}
		return nil, mappingFailure(MappingFailureCatalogInconsistency, "catalog", lookupErr)
	}
	canonical := lookup.Operation
	primaries := lookup.PrimaryOccurrences
	if canonical == "" || len(primaries) == 0 {
		return nil, mappingFailure(MappingFailureCatalogInconsistency, "catalog", nil)
	}
	reqs := make([]awsrequest.IAMRequirement, 0, len(primaries))
	var expectedDependencies []string
	for _, primary := range primaries {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		rawAction := primary.Action.Service + ":" + primary.Action.Name
		action := canonicalAction(rawAction)
		if action == "" || primary.Operation != canonical {
			return nil, mappingFailure(MappingFailureCatalogInconsistency, "catalog", nil)
		}
		res, scope, e := resourceForPrimaryContext(ctx, req, primary, action)
		if e != nil {
			if contextErr := mappingContextFailure(e); contextErr != nil {
				return nil, e
			}
			return nil, mappingFailure(MappingFailureUnresolvedPrimaryResource, "resource", e)
		}
		if scope == awsrequest.ScopeUnresolved || len(res) == 0 {
			return nil, mappingFailure(MappingFailureUnresolvedPrimaryResource, "resource", nil)
		}
		if primary.Scope != "" && string(scope) != primary.Scope && !(primary.Scope == "exact" && scope == awsrequest.ScopeSet) {
			return nil, mappingFailure(MappingFailureCatalogInconsistency, "catalog", nil)
		}
		reqs = append(reqs, awsrequest.IAMRequirement{Action: action, Resources: res, ScopeKind: scope})
		expectedDependencies = append(expectedDependencies, primary.DefinitionDependencies...)
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	deps, e := dependencies(ctx, req, expectedDependencies, lookup.DependencyOccurrences)
	if e != nil {
		if contextErr := mappingContextFailure(e); contextErr != nil {
			return nil, e
		}
		return nil, e
	}
	for _, d := range deps {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if d.ScopeKind == awsrequest.ScopeUnresolved {
			return nil, mappingFailure(MappingFailureUnresolvedDependency, "dependency", nil)
		}
		reqs = append(reqs, d)
	}
	sortRequirements(reqs)
	r := &awsrequest.MappingResult{Service: req.Service, Operation: canonical, Requirements: reqs, MapperVersion: MapperVersion, IamLiveVersion: m.adapter.Version(), AuthorizationDataVersion: data.AuthorizationDataVersion(), Confidence: awsrequest.ConfidenceHigh, Evidence: []awsrequest.MappingEvidence{{Source: "endpoint", Field: "service", Value: req.Service}, {Source: "endpoint", Field: "partition", Value: req.Partition}, {Source: "endpoint", Field: "region", Value: req.Region}, {Source: "protocol", Field: "protocol", Value: string(req.Protocol)}, {Source: "decoder", Field: "operation", Value: canonical}}}
	if e = r.Validate(); e != nil {
		return nil, mappingFailure(MappingFailureInvalidResult, "result", e)
	}
	return r, nil
}
func sortRequirements(v []awsrequest.IAMRequirement) {
	sort.Slice(v, func(i, j int) bool {
		if v[i].Action != v[j].Action {
			return v[i].Action < v[j].Action
		}
		return strings.Join(v[i].Resources, "\x00") < strings.Join(v[j].Resources, "\x00")
	})
	for i := range v {
		sort.Strings(v[i].Resources)
	}
}
