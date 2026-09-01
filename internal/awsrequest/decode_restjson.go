package awsrequest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"
	"strings"

	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

func decodeRESTJSONBody(body []byte, service, path, method string, q url.Values, c wireCatalog, l DecodeLimits) (string, map[string]Value, error) {
	p := map[string]Value{}
	if len(bytes.TrimSpace(body)) > 0 {
		d := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(body)))
		d.UseNumber()
		v, e := parseJSONValue(d, 0, l)
		if e != nil || v.Kind != ValueObject {
			return "", nil, errors.New("REST-JSON body is malformed")
		}
		var extra json.Token
		if e = d.Decode(&extra); e != io.EOF {
			return "", nil, errors.New("REST-JSON body has trailing data")
		}
		p = v.Object
	}
	op, route, e := restOperationFromCatalog(service, path, method, q, ProtocolRESTJSON, c, l)
	if e != nil {
		return "", nil, e
	}
	for k, v := range route {
		if old, ok := p[k]; ok && !reflect.DeepEqual(old, v) {
			return "", nil, errors.New("REST path/body evidence conflicts")
		}
		p[k] = v
	}
	return op, p, nil
}

// restOperation is retained as an in-package convenience for callers that
// exercise the REST-JSON matcher directly. The decoder uses the injected
// catalog explicitly.
func restOperation(service, path, method string, q url.Values, l DecodeLimits) (string, map[string]Value, error) {
	return restOperationFromCatalog(service, path, method, q, ProtocolRESTJSON, defaultWireCatalog(), l)
}

func defaultWireCatalog() wireCatalog {
	c, err := iamlivecatalog.Load()
	if err != nil {
		return nil
	}
	return c
}

// restOperationFromCatalog matches only raw, exact service operation records.
// It intentionally does not use Catalog.Operation, whose normalized index is
// allowed to collapse equivalent records and resolve aliases.
func restOperationFromCatalog(service, path, method string, q url.Values, protocol AWSProtocol, c wireCatalog, l DecodeLimits) (string, map[string]Value, error) {
	if len(path) > l.MaxPathBytes || !strings.HasPrefix(path, "/") {
		return "", nil, errors.New("REST path is malformed")
	}
	if e := validateRESTQuery(q, l); e != nil {
		return "", nil, e
	}
	method = strings.ToUpper(method)
	matches := 0
	var operation string
	var params map[string]Value
	if c != nil {
		for _, s := range c.Services() {
			if s.EndpointPrefix != service {
				continue
			}
			wire, ok := catalogProtocol(s.Protocol, "")
			if !ok || wire != protocol {
				continue
			}
			for _, o := range s.Operations {
				if o.Service != service || o.Route.Method != method {
					continue
				}
				candidate, ok, err := matchRESTURI(o.Route.URI, path, q, l)
				if err != nil {
					return "", nil, err
				}
				if !ok || !matchRESTQueryBindings(o.Route.URI, o.QueryBindings, q, l) {
					continue
				}
				matches++
				if o.State != iamlivecatalog.EvidenceKnown {
					return "", nil, errors.New("REST operation is contradictory or unsupported")
				}
				operation, params = o.Name, candidate
			}
		}
	}
	if matches == 0 {
		return "", nil, errors.New("unknown REST operation")
	}
	if matches != 1 {
		return "", nil, errors.New("ambiguous REST operation")
	}
	return operation, params, nil
}

// matchRESTURI preserves escaped path boundaries: an escaped slash remains in
// one parameter segment and is never allowed to satisfy an individual segment.
func matchRESTURI(uri, requestPath string, q url.Values, l DecodeLimits) (map[string]Value, bool, error) {
	templatePath, templateQuery, _ := strings.Cut(uri, "?")
	templateTrailing := templatePath != "/" && strings.HasSuffix(templatePath, "/")
	requestTrailing := requestPath != "/" && strings.HasSuffix(requestPath, "/")
	if templateTrailing != requestTrailing {
		return nil, false, nil
	}
	templateParts, ok := restPathParts(templatePath)
	if !ok {
		return nil, false, errors.New("REST catalog route is malformed")
	}
	requestParts, ok := restPathParts(requestPath)
	if !ok {
		return nil, false, errors.New("REST path is malformed")
	}
	params := map[string]Value{}
	i := 0
	for j, part := range templateParts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
			greedy := strings.HasSuffix(name, "+")
			if greedy {
				name = strings.TrimSuffix(name, "+")
			}
			if !validOperation(name) || (greedy && j != len(templateParts)-1) {
				return nil, false, errors.New("REST catalog route is malformed")
			}
			count := 1
			if greedy {
				count = len(requestParts) - i
			}
			if count < 1 || i+count > len(requestParts) {
				return nil, false, nil
			}
			values := make([]string, count)
			for n := 0; n < count; n++ {
				decoded, err := url.PathUnescape(requestParts[i+n])
				if err != nil || !validPathValue(decoded, l) {
					return nil, false, errors.New("REST path parameter is malformed")
				}
				values[n] = decoded
			}
			params[name] = Value{Kind: ValueString, String: strings.Join(values, "/")}
			i += count
			continue
		}
		if i >= len(requestParts) || requestParts[i] != part {
			return nil, false, nil
		}
		i++
	}
	if i != len(requestParts) {
		return nil, false, nil
	}
	want := url.Values{}
	if templateQuery != "" {
		for _, field := range strings.Split(templateQuery, "&") {
			parts := strings.SplitN(field, "=", 2)
			key, err := url.QueryUnescape(parts[0])
			if err != nil || key == "" {
				return nil, false, errors.New("REST catalog query is malformed")
			}
			value := ""
			if len(parts) == 2 {
				value, err = url.QueryUnescape(parts[1])
				if err != nil {
					return nil, false, errors.New("REST catalog query is malformed")
				}
			}
			if _, exists := want[key]; exists {
				return nil, false, errors.New("REST catalog query is ambiguous")
			}
			want[key] = []string{value}
		}
	}
	for key, values := range want {
		actual, ok := q[key]
		if !ok || !reflect.DeepEqual(actual, values) {
			return nil, false, nil
		}
	}
	return params, true, nil
}

// matchRESTQueryBindings applies the Smithy input shape rather than guessing
// from operation names or treating every query parameter as a wildcard. An
// operation's required query members must be present, and every supplied
// non-routing query name must be modeled by that operation.
func matchRESTQueryBindings(uri string, bindings []iamlivecatalog.QueryBinding, q url.Values, l DecodeLimits) bool {
	fixed := map[string]bool{}
	_, query, _ := strings.Cut(uri, "?")
	if query != "" {
		for _, field := range strings.Split(query, "&") {
			parts := strings.SplitN(field, "=", 2)
			key, err := url.QueryUnescape(parts[0])
			if err != nil || key == "" || len(key) > l.MaxTokenBytes {
				return false
			}
			fixed[key] = true
		}
	}
	modeled := map[string]iamlivecatalog.QueryBinding{}
	for _, binding := range bindings {
		if binding.LocationName == "" || len(binding.LocationName) > l.MaxTokenBytes {
			return false
		}
		if _, exists := modeled[binding.LocationName]; exists {
			return false
		}
		modeled[binding.LocationName] = binding
	}
	for key := range q {
		if !fixed[key] {
			if _, ok := modeled[key]; !ok {
				return false
			}
		}
	}
	for key, binding := range modeled {
		if binding.Required {
			if _, ok := q[key]; !ok {
				return false
			}
		}
	}
	return true
}

func restPathParts(path string) ([]string, bool) {
	if path == "/" {
		return nil, true
	}
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return nil, false
	}
	parts := strings.Split(path[1:], "/")
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
	}
	return parts, true
}

func validateRESTQuery(q url.Values, l DecodeLimits) error {
	if len(q) > l.MaxParameters {
		return errors.New("REST query parameter limit exceeded")
	}
	for key, values := range q {
		if key == "" || len(key) > l.MaxTokenBytes || len(values) != 1 || len(values[0]) > l.MaxTokenBytes {
			return errors.New("malformed REST query parameter")
		}
	}
	return nil
}

func validPathValue(v string, l DecodeLimits) bool {
	return v != "" && len(v) <= l.MaxTokenBytes && !strings.ContainsAny(v, "\x00\r\n*?")
}
