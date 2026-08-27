// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
//
// Derived from iamlive revision 3ec1a40e560c2f00ec82c50223add810e2567efb,
// MIT licensed. Derived behavior includes the operation/action table and
// dependent-action expansion; no iamlive process, proxy, or lifecycle code is
// included. See third_party/iamlive/PROVENANCE.md.
package iamliveadapter

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/kordn-ai/kordn/internal/awsrequest"
	"github.com/kordn-ai/kordn/internal/iammap/data"
	iamlivemapper "github.com/kordn-ai/kordn/third_party/iamlive/source"
)

const UpstreamCommit = "3ec1a40e560c2f00ec82c50223add810e2567efb"
const AdapterVersion = "iamlive-derived/v1@" + UpstreamCommit

type Action = iamlivemapper.Action
type DependencyCandidate = iamlivemapper.DependencyCandidate

// DependencyResult reports both dependent-action candidates and whether the
// typed request-value inspection was certain. Empty and certain is meaningful.
type DependencyResult = iamlivemapper.DependencyResult

// LookupResult contains independent iamlive-derived action evidence and the
// dependency candidates produced from this request's concrete parameters.
type LookupResult struct {
	Entry               data.Entry
	Primary             []Action
	Dependencies        []DependencyCandidate
	DependenciesCertain bool
}

// Adapter is deliberately a small, immutable data/normalization boundary.
// Its derived operation and dependency behavior is pinned below rather than
// supplied through fields or constructor arguments.
type Adapter struct {
	entries map[string]data.Entry
}

// New is the only production construction path. It wires the pinned derived
// implementation by keeping the adapter free of substitutable function fields.
func New() (*Adapter, error) {
	es, e := data.Entries()
	if e != nil {
		return nil, e
	}
	m := map[string]data.Entry{}
	for _, x := range es {
		if x.Service == "" || x.Operation == "" || x.Action == "" {
			return nil, fmt.Errorf("invalid authorization entry")
		}
		k := key(x.Service, x.Operation)
		if _, ok := m[k]; ok {
			return nil, fmt.Errorf("duplicate authorization entry")
		}
		m[k] = x
	}
	return &Adapter{entries: m}, nil
}

func key(s, o string) string { return strings.ToLower(s) + "\x00" + strings.ToLower(o) }

// NormalizeOperation applies the upstream collector's stable identifier
// normalization without accepting arbitrary punctuation or changing meaning.
func NormalizeOperation(operation string) string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return ""
	}
	for _, r := range operation {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return ""
	}
	return operation
}

// Lookup accepts the service and wire operation, plus typed request values.
// The variadic form preserves source compatibility for metadata-only callers;
// normal mapping supplies exactly one parameter map.
func (a *Adapter) Lookup(service, operation string, parameters ...map[string]awsrequest.Value) (LookupResult, error) {
	if a == nil {
		return LookupResult{}, fmt.Errorf("adapter unavailable")
	}
	op := NormalizeOperation(operation)
	if op == "" {
		return LookupResult{}, fmt.Errorf("unknown operation")
	}
	entry, ok := a.entries[key(service, op)]
	if !ok {
		return LookupResult{}, fmt.Errorf("unknown operation")
	}
	// Do not expose the adapter's stored slice through the result.
	entry.Dependencies = append([]string(nil), entry.Dependencies...)
	var params map[string]awsrequest.Value
	if len(parameters) > 1 {
		return LookupResult{}, fmt.Errorf("too many parameter maps")
	}
	if len(parameters) == 1 {
		params = parameters[0]
	}
	primary := iamlivemapper.GetActions(service, op)
	if len(primary) == 0 {
		return LookupResult{}, fmt.Errorf("iamlive has no action mapping")
	}
	all := make([]DependencyCandidate, 0)
	certain := true
	for _, action := range primary {
		result := iamlivemapper.DependentActions(action, params)
		if !result.Certain {
			certain = false
		}
		all = append(all, result.Candidates...)
	}
	return LookupResult{Entry: entry, Primary: append([]Action(nil), primary...), Dependencies: all, DependenciesCertain: certain}, nil
}

func (a *Adapter) LookupOperation(service, operation string) (string, data.Entry, error) {
	x, e := a.Lookup(service, operation)
	if e != nil {
		return "", data.Entry{}, e
	}
	return x.Entry.Operation, x.Entry, nil
}
func (a *Adapter) Version() string {
	if a == nil || a.entries == nil {
		return ""
	}
	return AdapterVersion
}
func (a *Adapter) DataVersion() string {
	if a == nil || a.entries == nil {
		return ""
	}
	return data.AuthorizationDataVersion()
}

// Find returns all string leaves with a bounded depth. It is retained for
// Kordn's model-specific dependency resolver and is not an authorization
// decision.
func Find(v map[string]awsrequest.Value, names ...string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	out := []string{}
	var walk func(string, awsrequest.Value, int)
	walk = func(k string, v awsrequest.Value, d int) {
		if d > 16 {
			return
		}
		if v.Kind == awsrequest.ValueString && want[strings.ToLower(k)] {
			out = append(out, v.String)
		}
		if v.Kind == awsrequest.ValueObject {
			for k, x := range v.Object {
				walk(k, x, d+1)
			}
		}
		if v.Kind == awsrequest.ValueArray {
			for _, x := range v.Array {
				walk(k, x, d+1)
			}
		}
	}
	for k, v := range v {
		walk(k, v, 0)
	}
	return out
}

// Map is not the enforcement mapper. Fail closed so callers cannot mistake
// this metadata adapter for a complete policy mapping.
func (a *Adapter) Map(context.Context, *awsrequest.DecodedAWSRequest) (*awsrequest.MappingResult, error) {
	return nil, fmt.Errorf("iamlive adapter is metadata-only; use kordn mapper")
}
