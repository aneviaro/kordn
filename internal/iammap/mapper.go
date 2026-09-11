// Package iammap is Kordn's fail-closed authorization mapping boundary.
package iammap

import (
	"context"
	"errors"
	"fmt"
	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iammap/data"
	"github.com/kordn-ai/kordn/internal/iammap/iamliveadapter"
	"sort"
	"strings"
	"time"
)

// MapperVersion identifies Kordn's enforcement mapper contract. The selected
// authorization data is carried separately by AuthorizationDataVersion.
const MapperVersion = "kordn-iammap/v3"

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
func (m *Mapper) Map(ctx context.Context, req *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if m == nil || m.adapter == nil {
		return nil, errors.New("mapper unavailable")
	}
	if req == nil {
		return nil, errors.New("decoded request is required")
	}
	if e := req.Validate(); e != nil {
		return nil, fmt.Errorf("mapping input: %w", e)
	}
	if e := ctx.Err(); e != nil {
		return nil, errors.New("mapper timeout; request rejected")
	}
	wctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	ch := make(chan struct {
		r *awsrequest.MappingResult
		e error
	}, 1)
	go func() {
		x := struct {
			r *awsrequest.MappingResult
			e error
		}{}
		defer func() {
			if recover() != nil {
				x.e = errors.New("mapper panic; request rejected")
			}
			ch <- x
		}()
		x.r, x.e = m.mapOne(wctx, req)
	}()
	select {
	case <-wctx.Done():
		return nil, errors.New("mapper timeout; request rejected")
	case x := <-ch:
		if x.e != nil {
			return nil, x.e
		}
		if x.r == nil {
			return nil, errors.New("mapper returned no result")
		}
		return x.r, nil
	}
}
func (m *Mapper) mapOne(ctx context.Context, req *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	if e := ctx.Err(); e != nil {
		return nil, errors.New("mapper timeout; request rejected")
	}
	ep, e := m.classifier.Classify(req.EndpointHost)
	if e != nil || ep.Partition != req.Partition || ep.Service != req.Service || ep.Region != req.Region || ep.IsGlobal() != (req.Region == "") {
		return nil, errors.New("decoded endpoint identity disagrees")
	}
	protocol, ok := awsrequest.AuthoritativeProtocol(req.Service)
	if !ok || protocol != req.Protocol {
		return nil, errors.New("decoded protocol disagrees with endpoint service")
	}
	op := iamliveadapter.NormalizeOperation(req.Operation)
	if op == "" {
		return nil, errors.New("operation evidence is unknown")
	}
	identity := iamliveadapter.WireIdentity{Protocol: req.Protocol, Method: req.Method, Path: req.CanonicalPath, Query: req.CanonicalQuery}
	if req.Protocol == awsrequest.ProtocolJSON10 || req.Protocol == awsrequest.ProtocolJSON11 {
		if req.Headers == nil {
			return nil, errors.New("exactly one X-Amz-Target is required")
		}
		targets := req.Headers.Values("X-Amz-Target")
		if len(targets) != 1 {
			return nil, errors.New("exactly one X-Amz-Target is required")
		}
		identity.Target = targets[0]
	}
	wire, ok := m.adapter.(wireLookupAdapter)
	if !ok {
		return nil, errors.New("context-aware request adapter is required")
	}
	lookup, lookupErr := wire.LookupRequestContext(ctx, req.Service, op, identity, req.Parameters)
	if lookupErr != nil {
		return nil, fmt.Errorf("unknown operation %s:%s: %w", req.Service, op, lookupErr)
	}
	canonical := lookup.Operation
	primaries := lookup.PrimaryOccurrences
	if canonical == "" || len(primaries) == 0 {
		return nil, errors.New("iamlive primary occurrence set disagrees")
	}
	reqs := make([]awsrequest.IAMRequirement, 0, len(primaries))
	var expectedDependencies []string
	for _, primary := range primaries {
		rawAction := primary.Action.Service + ":" + primary.Action.Name
		action := canonicalAction(rawAction)
		if action == "" || primary.Operation != canonical {
			return nil, errors.New("iamlive and authorization action disagree")
		}
		res, scope, e := resourceForPrimaryContext(ctx, req, primary, action)
		if e != nil {
			return nil, e
		}
		if scope == awsrequest.ScopeUnresolved {
			return nil, errors.New("unresolved primary resource; mapping rejected")
		}
		if len(res) == 0 {
			return nil, errors.New("primary resource is empty; mapping rejected")
		}
		if primary.Scope != "" && string(scope) != primary.Scope && !(primary.Scope == "exact" && scope == awsrequest.ScopeSet) {
			return nil, errors.New("primary scope evidence disagrees")
		}
		reqs = append(reqs, awsrequest.IAMRequirement{Action: action, Resources: res, ScopeKind: scope})
		expectedDependencies = append(expectedDependencies, primary.DefinitionDependencies...)
	}
	if e := ctx.Err(); e != nil {
		return nil, errors.New("mapper timeout; request rejected")
	}
	deps, e := dependencies(ctx, req, expectedDependencies, lookup.DependencyOccurrences)
	if e != nil {
		return nil, e
	}
	for _, d := range deps {
		if d.ScopeKind == awsrequest.ScopeUnresolved {
			return nil, errors.New("unresolved dependent resource; mapping rejected")
		}
		reqs = append(reqs, d)
	}
	sortRequirements(reqs)
	r := &awsrequest.MappingResult{Service: req.Service, Operation: canonical, Requirements: reqs, MapperVersion: MapperVersion, IamLiveVersion: m.adapter.Version(), AuthorizationDataVersion: data.AuthorizationDataVersion(), Confidence: awsrequest.ConfidenceHigh, Evidence: []awsrequest.MappingEvidence{{Source: "endpoint", Field: "service", Value: req.Service}, {Source: "endpoint", Field: "partition", Value: req.Partition}, {Source: "endpoint", Field: "region", Value: req.Region}, {Source: "protocol", Field: "protocol", Value: string(req.Protocol)}, {Source: "decoder", Field: "operation", Value: canonical}}}
	if e = r.Validate(); e != nil {
		return nil, e
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
