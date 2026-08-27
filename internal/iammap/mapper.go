// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
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

const MapperVersion = "kordn-iammap/v2"

type MapperOptions struct {
	Timeout    time.Duration
	Classifier awsrequest.EndpointClassifier
}

type mapperAdapter interface {
	Lookup(string, string, ...map[string]awsrequest.Value) (iamliveadapter.LookupResult, error)
	Version() string
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
	lookup, e := m.adapter.Lookup(req.Service, op, req.Parameters)
	if e != nil {
		return nil, fmt.Errorf("unknown operation %s:%s", req.Service, op)
	}
	entry := lookup.Entry
	if e := data.ValidateEntry(entry); e != nil {
		return nil, fmt.Errorf("authorization metadata disagreement: %w", e)
	}
	canonical := entry.Operation
	// The derived mapper is an independent source of operation/action
	// evidence. A Kordn record is usable only when both sources agree exactly;
	// an altered action can never be accepted merely because it matches the
	// selected SAR record.
	if len(lookup.Primary) != 1 {
		return nil, errors.New("iamlive primary action set disagrees")
	}
	rawAction := lookup.Primary[0].Service + ":" + lookup.Primary[0].Name
	if rawAction != entry.Action {
		return nil, errors.New("iamlive and authorization action disagree")
	}
	action := canonicalAction(rawAction)
	if action == "" || action != canonicalAction(entry.Action) {
		return nil, errors.New("iamlive and authorization action disagree")
	}
	if strings.SplitN(action, ":", 2)[0] != req.Service {
		return nil, errors.New("authorization action service disagrees")
	}
	res, scope, e := resourceFor(req, entry.Resource)
	if e != nil {
		return nil, e
	}
	if scope == awsrequest.ScopeUnresolved {
		return nil, errors.New("unresolved primary resource; mapping rejected")
	}
	if len(res) == 0 {
		return nil, errors.New("primary resource is empty; mapping rejected")
	}
	if entry.Scope != "" && string(scope) != entry.Scope {
		return nil, errors.New("primary scope evidence disagrees")
	}
	if e := ctx.Err(); e != nil {
		return nil, errors.New("mapper timeout; request rejected")
	}
	reqs := []awsrequest.IAMRequirement{{Action: action, Resources: res, ScopeKind: scope}}
	deps, e := dependencies(req, entry, lookup.Dependencies, lookup.DependenciesCertain)
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
