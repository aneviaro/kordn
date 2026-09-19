package awsrequest

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

// wireIndex is an immutable, occurrence-preserving index of wire evidence.
// Every slice is built before publication and is never modified afterwards.
type wireIndex struct {
	authority map[string][]protocolEvidence
	query     map[queryIndexKey][]*wireCandidate
	json      map[jsonIndexKey][]*wireCandidate
	variants  map[jsonVariantKey]uint32
	rest      map[restIndexKey][]*wireCandidate
	modeled   map[modeledIndexKey][]*wireCandidate
}

type protocolEvidence struct {
	protocol AWSProtocol
	valid    bool
}

type queryIndexKey struct{ service, protocol, version, action string }
type jsonIndexKey struct{ service, protocol, target, operation string }
type jsonVariantKey struct{ service, protocol, operation, target string }
type restIndexKey struct{ service, protocol, method, path string }
type modeledIndexKey struct{ service, protocol, path, method string }

type wireCandidate struct {
	name, apiVersion, targetPrefix string
	protocol                       AWSProtocol
	method, routeTarget            string
	queryBindings                  []iamlivecatalog.QueryBinding
	fixedQuery                     url.Values
	routePath                      string
	known, routeValid              bool
}

// wireSnapshot is retained only as a source-compatible test seam. Production
// uses wireSelector, which never asks the catalog for a graph-sized snapshot.
type wireSnapshot interface {
	WireServices() []iamlivecatalog.WireService
}
type wireSelector interface {
	ForEachWireOperation(func(iamlivecatalog.WireService, iamlivecatalog.WireOperation) error) error
}

func buildWireIndex(source interface{}) (*wireIndex, error) {
	if source == nil {
		return nil, errors.New("wire catalog is unavailable")
	}
	idx := &wireIndex{
		authority: make(map[string][]protocolEvidence), query: make(map[queryIndexKey][]*wireCandidate),
		json: make(map[jsonIndexKey][]*wireCandidate), variants: make(map[jsonVariantKey]uint32),
		rest: make(map[restIndexKey][]*wireCandidate), modeled: make(map[modeledIndexKey][]*wireCandidate),
	}
	authorityModels := map[string]bool{}
	visit := func(service iamlivecatalog.WireService, original iamlivecatalog.WireOperation) error {
		authorityKey := service.EndpointPrefix + "\x00" + service.APIVersion + "\x00" + service.TargetPrefix + "\x00" + service.Protocol + "\x00" + original.Route.JSONVersion
		if service.Protocol == "json" || !authorityModels[authorityKey] {
			protocol, ok := catalogProtocol(service.Protocol, original.Route.JSONVersion)
			idx.authority[service.EndpointPrefix] = append(idx.authority[service.EndpointPrefix], protocolEvidence{protocol: protocol, valid: ok})
			authorityModels[authorityKey] = true
		}
		fixed, routePath, ok := indexRouteQuery(original.Route.URI)
		if !ok {
			return fmt.Errorf("wire index: service %q operation %q has malformed fixed route query", service.EndpointPrefix, original.Name)
		}
		protocol, protocolOK := catalogProtocol(service.Protocol, original.Route.JSONVersion)
		if !protocolOK {
			return nil
		} // authority retains negative evidence
		candidate := &wireCandidate{
			name: original.Name, apiVersion: service.APIVersion, targetPrefix: service.TargetPrefix,
			protocol: protocol, known: original.State == iamlivecatalog.EvidenceKnown,
			method: original.Route.Method, routeValid: original.Route.URI != "", routeTarget: original.Route.TargetPrefix,
			queryBindings: append([]iamlivecatalog.QueryBinding(nil), original.QueryBindings...),
			fixedQuery:    cloneURLValues(fixed), routePath: routePath,
		}
		if protocol == ProtocolJSON10 || protocol == ProtocolJSON11 {
			key := jsonIndexKey{service.EndpointPrefix, string(protocol), service.TargetPrefix, original.Name}
			idx.json[key] = append(idx.json[key], candidate)
			if original.Route.TargetPrefix != "" {
				vkey := jsonVariantKey{service.EndpointPrefix, string(protocol), original.Name, original.Route.TargetPrefix}
				idx.variants[vkey]++
			}
		}
		switch protocol {
		case ProtocolQuery, ProtocolEC2Query:
			idx.query[queryIndexKey{service.EndpointPrefix, string(protocol), service.APIVersion, original.Name}] = append(idx.query[queryIndexKey{service.EndpointPrefix, string(protocol), service.APIVersion, original.Name}], candidate)
		case ProtocolRESTJSON, ProtocolRESTXML:
			idx.rest[restIndexKey{service.EndpointPrefix, string(protocol), strings.ToUpper(original.Route.Method), ""}] = append(idx.rest[restIndexKey{service.EndpointPrefix, string(protocol), strings.ToUpper(original.Route.Method), ""}], candidate)
		case ProtocolJSON10, ProtocolJSON11:
			idx.modeled[modeledIndexKey{service.EndpointPrefix, string(protocol), routePath, strings.ToUpper(original.Route.Method)}] = append(idx.modeled[modeledIndexKey{service.EndpointPrefix, string(protocol), routePath, strings.ToUpper(original.Route.Method)}], candidate)
		}
		if protocol == ProtocolQuery || protocol == ProtocolEC2Query {
			key := modeledIndexKey{service.EndpointPrefix, string(protocol), routePath, strings.ToUpper(original.Route.Method)}
			idx.modeled[key] = append(idx.modeled[key], candidate)
		}
		return nil
	}
	if selector, ok := source.(wireSelector); ok {
		return idx, selector.ForEachWireOperation(visit)
	}
	legacy, ok := source.(wireSnapshot)
	if !ok {
		return nil, errors.New("wire catalog does not provide an immutable selector")
	}
	for _, service := range legacy.WireServices() {
		for _, operation := range service.Operations {
			if err := visit(service, operation); err != nil {
				return nil, err
			}
		}
	}
	return idx, nil
}

func indexRouteQuery(uri string) (url.Values, string, bool) {
	path, raw, present := strings.Cut(uri, "?")
	fixed, ok := modeledWireQuery(raw, present)
	if path == "" {
		path = "/"
	}
	return fixed, path, ok
}

func cloneURLValues(in url.Values) url.Values {
	if len(in) == 0 {
		return nil
	}
	out := make(url.Values, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

var (
	defaultWireIndexOnce sync.Once
	defaultWireIndex     *wireIndex
	defaultWireIndexErr  error
)

func defaultWireIndexOrNil() *wireIndex {
	defaultWireIndexOnce.Do(func() {
		catalog, err := iamlivecatalog.Load()
		if err != nil {
			defaultWireIndexErr = err
			return
		}
		built, buildErr := buildWireIndex(catalog)
		if buildErr != nil {
			defaultWireIndexErr = buildErr
			return
		}
		defaultWireIndex = built
	})
	if defaultWireIndexErr != nil {
		return nil
	}
	return defaultWireIndex
}

func defaultWireCatalog() *wireIndex { return defaultWireIndexOrNil() }

func indexRouteCandidates(idx *wireIndex, service string, protocol AWSProtocol, path, method string) []*wireCandidate {
	if idx == nil {
		return nil
	}
	return idx.modeled[modeledIndexKey{service, string(protocol), path, strings.ToUpper(method)}]
}
