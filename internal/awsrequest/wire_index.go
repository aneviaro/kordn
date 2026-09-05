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
	query     map[queryIndexKey][]wireCandidate
	json      map[jsonIndexKey][]wireCandidate
	variants  map[jsonVariantKey][]wireCandidate
	rest      map[restIndexKey][]wireCandidate
	modeled   map[modeledIndexKey][]wireCandidate
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
	service      string
	apiVersion   string
	targetPrefix string
	protocol     AWSProtocol
	operation    iamlivecatalog.WireOperation
	fixedQuery   url.Values
	routePath    string
}

// wireSnapshot is deliberately narrow. Production and tests must explicitly
// provide the compact, occurrence-preserving snapshot before construction.
type wireSnapshot interface {
	WireServices() []iamlivecatalog.WireService
}

func buildWireIndex(source wireSnapshot) (*wireIndex, error) {
	if source == nil {
		return nil, errors.New("wire catalog is unavailable")
	}
	services := source.WireServices() // exactly one snapshot
	idx := &wireIndex{
		authority: make(map[string][]protocolEvidence),
		query:     make(map[queryIndexKey][]wireCandidate),
		json:      make(map[jsonIndexKey][]wireCandidate),
		variants:  make(map[jsonVariantKey][]wireCandidate),
		rest:      make(map[restIndexKey][]wireCandidate),
		modeled:   make(map[modeledIndexKey][]wireCandidate),
	}
	for _, service := range services {
		if service.Protocol == "json" {
			for _, operation := range service.Operations {
				protocol, ok := catalogProtocol(service.Protocol, operation.Route.JSONVersion)
				idx.authority[service.EndpointPrefix] = append(idx.authority[service.EndpointPrefix], protocolEvidence{protocol: protocol, valid: ok})
			}
		} else {
			protocol, ok := catalogProtocol(service.Protocol, "")
			idx.authority[service.EndpointPrefix] = append(idx.authority[service.EndpointPrefix], protocolEvidence{protocol: protocol, valid: ok})
		}
		for _, original := range service.Operations {
			fixed, routePath, ok := indexRouteQuery(original.Route.URI)
			if !ok {
				return nil, fmt.Errorf("wire index: service %q operation %q has malformed fixed route query", service.EndpointPrefix, original.Name)
			}
			protocol, protocolOK := catalogProtocol(service.Protocol, original.Route.JSONVersion)
			if !protocolOK {
				continue // authority retains this as negative evidence
			}
			op := original
			op.QueryBindings = append([]iamlivecatalog.QueryBinding(nil), original.QueryBindings...)
			candidate := wireCandidate{
				service: service.EndpointPrefix, apiVersion: service.APIVersion,
				targetPrefix: service.TargetPrefix, protocol: protocol,
				operation: op, fixedQuery: cloneURLValues(fixed), routePath: routePath,
			}
			if protocol == ProtocolJSON10 || protocol == ProtocolJSON11 {
				key := jsonIndexKey{service.EndpointPrefix, string(protocol), service.TargetPrefix, original.Name}
				idx.json[key] = append(idx.json[key], candidate)
				if original.Route.TargetPrefix != "" {
					// Keep target ownership evidence keyed by the wire target,
					// including occurrences supplied by variant models.
					vkey := jsonVariantKey{service.EndpointPrefix, string(protocol), original.Name, original.Route.TargetPrefix}
					idx.variants[vkey] = append(idx.variants[vkey], candidate)
				}
			}
			switch protocol {
			case ProtocolQuery, ProtocolEC2Query:
				key := queryIndexKey{service.EndpointPrefix, string(protocol), service.APIVersion, original.Name}
				idx.query[key] = append(idx.query[key], candidate)
			case ProtocolRESTJSON, ProtocolRESTXML:
				// URI templates contain path parameters, so method is the bounded route
				// discriminator; each retained candidate performs exact template matching.
				key := restIndexKey{service.EndpointPrefix, string(protocol), strings.ToUpper(original.Route.Method), ""}
				idx.rest[key] = append(idx.rest[key], candidate)
			case ProtocolJSON10, ProtocolJSON11:
				// JSON is also checked against its modeled envelope before body parsing.
				key := modeledIndexKey{service.EndpointPrefix, string(protocol), routePath, strings.ToUpper(original.Route.Method)}
				idx.modeled[key] = append(idx.modeled[key], candidate)
			}
			if protocol == ProtocolQuery || protocol == ProtocolEC2Query {
				key := modeledIndexKey{service.EndpointPrefix, string(protocol), routePath, strings.ToUpper(original.Route.Method)}
				idx.modeled[key] = append(idx.modeled[key], candidate)
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

func indexRouteCandidates(idx *wireIndex, service string, protocol AWSProtocol, path, method string) []wireCandidate {
	if idx == nil {
		return nil
	}
	return idx.modeled[modeledIndexKey{service, string(protocol), path, strings.ToUpper(method)}]
}
