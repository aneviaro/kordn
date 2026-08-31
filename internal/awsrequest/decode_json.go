package awsrequest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kordn-ai/kordn/internal/iamlivecatalog"
)

type DecodeLimits struct {
	MaxBodyBytes  int64
	MaxParameters int
	MaxDepth      int
	MaxTokenBytes int
	MaxPathBytes  int
}

func DefaultDecodeLimits() DecodeLimits { return DecodeLimits{8 << 20, 2048, 32, 4096, 8192} }

type DecoderOptions struct {
	Limits          DecodeLimits
	Classifier      EndpointClassifier
	CallerAccountID string // trusted run context; never read from request data
}

// wireCatalog is intentionally unexported: production decoders always use the
// pinned embedded catalog, while same-package tests can inject malformed or
// ambiguous records without creating a runtime operation override.
type wireCatalog interface {
	Services() []iamlivecatalog.Service
}

type Decoder struct {
	limits          DecodeLimits
	classifier      EndpointClassifier
	callerAccountID string
	catalog         wireCatalog
	configErr       error
}

func NewConfiguredDecoder(o DecoderOptions) (*Decoder, error) {
	if err := validateCallerAccountID(o.CallerAccountID); err != nil {
		return nil, fmt.Errorf("caller account ID: %w", err)
	}
	x := o.Limits
	if x.MaxBodyBytes == 0 {
		x = DefaultDecodeLimits()
	}
	if o.Classifier == nil {
		o.Classifier = DefaultEndpointClassifier
	}
	d := newDecoder(x, o.Classifier, o.CallerAccountID)
	if d.configErr != nil {
		return nil, fmt.Errorf("decoder configuration: %w", d.configErr)
	}
	return d, nil
}

func NewDecoder(l ...DecodeLimits) *Decoder {
	x := DefaultDecodeLimits()
	if len(l) > 0 {
		x = l[0]
	}
	if x.MaxBodyBytes <= 0 {
		x.MaxBodyBytes = 8 << 20
	}
	if x.MaxParameters <= 0 {
		x.MaxParameters = 2048
	}
	if x.MaxDepth <= 0 {
		x.MaxDepth = 32
	}
	if x.MaxTokenBytes <= 0 {
		x.MaxTokenBytes = 4096
	}
	if x.MaxPathBytes <= 0 {
		x.MaxPathBytes = 8192
	}
	return newDecoder(x, DefaultEndpointClassifier, "")
}

func newDecoder(x DecodeLimits, c EndpointClassifier, account string) *Decoder {
	configErr := validateCallerAccountID(account)
	d := DefaultDecodeLimits()
	if x.MaxBodyBytes > 0 {
		d.MaxBodyBytes = x.MaxBodyBytes
	}
	if x.MaxParameters > 0 {
		d.MaxParameters = x.MaxParameters
	}
	if x.MaxDepth > 0 {
		d.MaxDepth = x.MaxDepth
	}
	if x.MaxTokenBytes > 0 {
		d.MaxTokenBytes = x.MaxTokenBytes
	}
	if x.MaxPathBytes > 0 {
		d.MaxPathBytes = x.MaxPathBytes
	}
	cat, catErr := iamlivecatalog.Load()
	if configErr == nil {
		configErr = catErr
	}
	return &Decoder{limits: d, classifier: c, callerAccountID: account, catalog: cat, configErr: configErr}
}
func (d *Decoder) WithClassifier(c EndpointClassifier) *Decoder {
	if c != nil {
		d.classifier = c
	}
	return d
}
func Decode(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return NewDecoder().Decode(ctx, r, e)
}
func DecodeRequest(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return Decode(ctx, r, e)
}
func DecodeJSON(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return Decode(ctx, r, e)
}
func DecodeJSONRequest(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return Decode(ctx, r, e)
}
func DecodeQuery(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return Decode(ctx, r, e)
}
func DecodeEC2Query(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return Decode(ctx, r, e)
}
func DecodeRESTJSON(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return Decode(ctx, r, e)
}
func DecodeRESTJSONRequest(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return DecodeRESTJSON(ctx, r, e)
}
func DecodeRESTXML(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return Decode(ctx, r, e)
}
func DecodeRESTXMLRequest(ctx context.Context, r *VerifiedRequest, e AWSEndpoint) (*DecodedAWSRequest, error) {
	return DecodeRESTXML(ctx, r, e)
}

func (d *Decoder) Decode(ctx context.Context, v *VerifiedRequest, e AWSEndpoint) (out *DecodedAWSRequest, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err = ctx.Err(); err != nil {
		return nil, fmt.Errorf("decode cancelled: %w", err)
	}
	if v == nil {
		return nil, errors.New("verified request is required")
	}
	if err = v.Validate(); err != nil {
		return nil, fmt.Errorf("verified request: %w", err)
	}
	if d == nil || d.classifier == nil {
		return nil, errors.New("decoder is unavailable")
	}
	// Check permanent configuration before touching the request body. This is
	// also retained on Decoder for callers that construct one in-package.
	if d.configErr != nil {
		return nil, fmt.Errorf("decoder configuration: %w", d.configErr)
	}
	if err = e.Validate(); err != nil || !sameEndpoint(e, v.Endpoint) {
		return nil, errors.New("endpoint evidence disagrees")
	}
	ce, cerr := d.classifier.Classify(e.Host)
	if cerr != nil || !sameEndpoint(ce, e) {
		return nil, errors.New("endpoint identity could not be revalidated")
	}
	r := v.Request
	if r == nil || r.URL == nil {
		return nil, errors.New("request URL is unavailable")
	}
	host, _, he := NormalizeEndpointHost(r.Host)
	if he != nil {
		host, _, he = NormalizeEndpointHost(r.URL.Host)
	}
	if he != nil || host != e.Host {
		return nil, errors.New("request host disagrees with endpoint")
	}
	if v.SigningService != e.Service || v.SigningRegion == "" || (!e.IsGlobal() && v.SigningRegion != e.Region) {
		return nil, errors.New("credential scope disagrees with endpoint")
	}
	if v.SigningScheme != SigningHeaderV4 || !v.PayloadMode.Supported() {
		return nil, errors.New("unsupported authenticated request")
	}
	if len(r.URL.EscapedPath()) > d.limits.MaxPathBytes {
		return nil, errors.New("request path exceeds limit")
	}
	protocol, err := protocolFromHeaders(v.Protocol, r.Header, r.URL.Path)
	if err != nil {
		return nil, err
	}
	if want, ok := authoritativeProtocolFor(d.catalog, e.Service); !ok || protocol != want {
		return nil, fmt.Errorf("protocol %q is not authoritative for endpoint service %q", protocol, e.Service)
	}
	body, berr := readAndRestore(r, d.limits.MaxBodyBytes)
	if berr != nil {
		return nil, berr
	}
	out = &DecodedAWSRequest{Partition: e.Partition, EndpointHost: e.Host, Service: e.Service, Region: e.Region, CallerAccountID: d.callerAccountID, Protocol: protocol, Method: r.Method, CanonicalPath: r.URL.EscapedPath(), CanonicalQuery: url.Values{}, Headers: safeHeaders(r.Header), Parameters: map[string]Value{}, PayloadHashMode: v.PayloadMode, PayloadBytes: int64(len(body))}
	if out.CanonicalPath == "" {
		out.CanonicalPath = "/"
	}
	switch protocol {
	case ProtocolJSON10, ProtocolJSON11:
		out.Operation, out.Parameters, err = decodeJSONBody(body, r.Header, e.Service, protocol, d.catalog, d.limits)
	case ProtocolQuery, ProtocolEC2Query:
		var q url.Values
		q, err = parseQueryString(r.URL.RawQuery, d.limits)
		if err == nil {
			out.Operation, out.Parameters, out.CanonicalQuery, err = decodeQueryBody(body, q, e.Service, protocol, d.catalog, d.limits)
		}
	case ProtocolRESTJSON:
		out.Operation, out.Parameters, err = decodeRESTJSONBody(body, e.Service, out.CanonicalPath, out.Method, r.URL.Query(), d.catalog, d.limits)
	case ProtocolRESTXML:
		out.Operation, out.Parameters, err = decodeRESTXMLBody(body, e.Service, out.CanonicalPath, out.Method, r.URL.Query(), d.catalog, d.limits)
	default:
		err = errors.New("unsupported AWS protocol")
	}
	if err != nil {
		return nil, err
	}
	if protocol != ProtocolJSON10 && protocol != ProtocolJSON11 && len(r.Header.Values("X-Amz-Target")) > 0 {
		return nil, errors.New("JSON target is not valid for this protocol")
	}
	if protocol != ProtocolQuery && protocol != ProtocolEC2Query {
		q, qe := parseQueryString(r.URL.RawQuery, d.limits)
		if qe != nil {
			return nil, qe
		}
		if _, ok := q["Action"]; ok {
			return nil, errors.New("query Action conflicts with protocol operation")
		}
	}
	if err = out.Validate(); err != nil {
		return nil, fmt.Errorf("decoded request: %w", err)
	}
	return out, nil
}

func validateCallerAccountID(account string) error {
	if account == "" {
		return nil // unknown/unavailable caller context
	}
	if len(account) != 12 {
		return errors.New("must be empty or exactly 12 ASCII digits")
	}
	for i := 0; i < len(account); i++ {
		if account[i] < '0' || account[i] > '9' {
			return errors.New("must be empty or exactly 12 ASCII digits")
		}
	}
	return nil
}

func readAndRestore(r *http.Request, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, errors.New("body limit is invalid")
	}
	if r.Body == nil {
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(nil)), nil }
		return nil, nil
	}
	if r.ContentLength > max {
		return nil, errors.New("request body exceeds decoder limit")
	}
	original := r.Body
	getBody := r.GetBody
	b, readErr := io.ReadAll(io.LimitReader(original, max+1))
	if readErr != nil || int64(len(b)) > max {
		r.Body = &compositeBody{prefix: bytes.NewReader(append([]byte(nil), b...)), rest: original}
		if getBody != nil {
			r.GetBody = getBody
		}
		if readErr != nil {
			return b, fmt.Errorf("request body: %w", readErr)
		}
		return b, errors.New("request body exceeds decoder limit")
	}
	closeErr := original.Close()
	saved := append([]byte(nil), b...)
	r.Body = io.NopCloser(bytes.NewReader(saved))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(saved)), nil }
	if closeErr != nil {
		return b, fmt.Errorf("request body close: %w", closeErr)
	}
	return b, nil
}

type compositeBody struct {
	prefix *bytes.Reader
	rest   io.ReadCloser
	closed bool
}

func (b *compositeBody) Read(p []byte) (int, error) {
	if b.prefix.Len() > 0 {
		return b.prefix.Read(p)
	}
	return b.rest.Read(p)
}
func (b *compositeBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	return b.rest.Close()
}

func readBoundedBody(ctx context.Context, b io.Reader, max int64) ([]byte, error) {
	if b == nil {
		return nil, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	v, e := io.ReadAll(io.LimitReader(b, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(v)) > max {
		return nil, errors.New("request body exceeds decoder limit")
	}
	return v, nil
}

func AuthoritativeProtocol(service string) (AWSProtocol, bool) {
	p, ok := authoritativeProtocolForDefault(service)
	return p, ok
}

// authoritativeProtocolFor requires one unambiguous wire protocol among the
// exact endpoint-prefix records. It deliberately does not consult aliases or
// a hand-maintained service table.
func authoritativeProtocolFor(c wireCatalog, service string) (AWSProtocol, bool) {
	if c == nil || service == "" {
		return "", false
	}
	var found AWSProtocol
	seen := map[AWSProtocol]bool{}
	for _, s := range c.Services() {
		if s.EndpointPrefix != service {
			continue
		}
		if s.Protocol == "json" {
			for _, o := range s.Operations {
				p, ok := catalogProtocol(s.Protocol, o.Route.JSONVersion)
				if !ok {
					return "", false
				}
				seen[p] = true
			}
			continue
		}
		p, ok := catalogProtocol(s.Protocol, "")
		if !ok {
			return "", false
		}
		seen[p] = true
	}
	if len(seen) != 1 {
		return "", false
	}
	for p := range seen {
		found = p
	}
	return found, true
}

func authoritativeProtocolForDefault(service string) (AWSProtocol, bool) {
	c, err := iamlivecatalog.Load()
	if err != nil {
		return "", false
	}
	return authoritativeProtocolFor(c, service)
}

func catalogProtocol(protocol, jsonVersion string) (AWSProtocol, bool) {
	switch protocol {
	case "query":
		return ProtocolQuery, true
	case "ec2":
		return ProtocolEC2Query, true
	case "rest-json":
		return ProtocolRESTJSON, true
	case "rest-xml":
		return ProtocolRESTXML, true
	case "json":
		switch jsonVersion {
		case "1.0":
			return ProtocolJSON10, true
		case "1.1":
			return ProtocolJSON11, true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

func protocolFromHeaders(claimed AWSProtocol, h http.Header, path string) (AWSProtocol, error) {
	v := h.Values("Content-Type")
	if len(v) > 1 {
		return "", errors.New("content type is duplicated")
	}
	c := ""
	if len(v) == 1 {
		c = strings.ToLower(strings.TrimSpace(strings.Split(v[0], ";")[0]))
	}
	var inferred AWSProtocol
	switch {
	case c == "application/x-amz-json-1.0":
		inferred = ProtocolJSON10
	case c == "application/x-amz-json-1.1":
		inferred = ProtocolJSON11
	case c == "application/x-www-form-urlencoded":
		inferred = ProtocolQuery
	case c == "application/json":
		inferred = ProtocolRESTJSON
	case c == "application/xml" || c == "text/xml":
		inferred = ProtocolRESTXML
	case c == "":
		inferred = claimed
	default:
		return "", fmt.Errorf("unsupported content type %q", c)
	}
	if claimed == ProtocolEC2Query && inferred == ProtocolQuery {
		inferred = claimed
	}
	if inferred != claimed {
		return "", fmt.Errorf("protocol evidence disagrees: %q and %q", claimed, inferred)
	}
	if path == "" {
		return "", errors.New("invalid request path")
	}
	return inferred, nil
}
func sameEndpoint(a, b AWSEndpoint) bool {
	return a.Partition == b.Partition && a.Host == b.Host && a.Service == b.Service && a.Region == b.Region && a.IsGlobal() == b.IsGlobal() && a.FIPS == b.FIPS && a.DualStack == b.DualStack
}
func safeHeaders(h http.Header) http.Header {
	o := make(http.Header)
	for k, v := range h {
		l := strings.ToLower(k)
		if l == "authorization" || l == "proxy-authorization" || l == "x-amz-security-token" || l == "cookie" || strings.Contains(l, "signature") {
			continue
		}
		o[k] = append([]string(nil), v...)
	}
	return o
}

func targetOperation(target, service string, max int) (string, error) {
	c, err := iamlivecatalog.Load()
	if err != nil {
		return "", errors.New("JSON catalog is unavailable")
	}
	return targetOperationFor(target, service, "", c, max)
}

func targetOperationFor(target, service string, protocol AWSProtocol, c wireCatalog, max int) (string, error) {
	if len(target) == 0 || len(target) > max || strings.ContainsAny(target, "\x00\r\n") {
		return "", errors.New("JSON target is malformed")
	}
	sep := "."
	if strings.Contains(target, "#") {
		sep = "#"
	}
	if strings.Count(target, sep) != 1 {
		return "", errors.New("JSON target is malformed")
	}
	p := strings.SplitN(target, sep, 2)
	if len(p) != 2 || p[0] == "" || p[1] == "" || !validOperation(p[1]) {
		return "", errors.New("JSON target is malformed")
	}
	matches := 0
	for _, s := range c.Services() {
		if s.EndpointPrefix != service || s.TargetPrefix != p[0] {
			continue
		}
		for _, o := range s.Operations {
			wire, ok := catalogProtocol(s.Protocol, o.Route.JSONVersion)
			if !ok || (protocol != "" && wire != protocol) {
				continue
			}
			if o.Service == service && o.Name == p[1] && o.Route.TargetPrefix == p[0] {
				matches++
				if o.State != iamlivecatalog.EvidenceKnown {
					return "", errors.New("JSON operation is absent, contradictory, or ambiguous")
				}
			}
		}
	}
	if matches != 1 {
		return "", errors.New("JSON operation is absent, contradictory, or ambiguous")
	}
	return p[1], nil
}
func decodeJSONBody(body []byte, h http.Header, service string, protocol AWSProtocol, c wireCatalog, l DecodeLimits) (string, map[string]Value, error) {
	t := h.Values("X-Amz-Target")
	if len(t) != 1 {
		return "", nil, errors.New("JSON operation target is missing or duplicated")
	}
	op, e := targetOperationFor(t[0], service, protocol, c, l.MaxTokenBytes)
	if e != nil {
		return "", nil, e
	}
	if len(body) == 0 {
		return "", nil, errors.New("JSON body is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	v, e := parseJSONValue(dec, 0, l)
	if e != nil {
		return "", nil, e
	}
	var x json.Token
	if e = dec.Decode(&x); e != io.EOF {
		return "", nil, errors.New("JSON body has trailing data")
	}
	if v.Kind != ValueObject {
		return "", nil, errors.New("JSON body must be an object")
	}
	return op, v.Object, nil
}
func parseJSONValue(dec *json.Decoder, depth int, l DecodeLimits) (Value, error) {
	if depth > l.MaxDepth {
		return Value{}, errors.New("JSON nesting exceeds limit")
	}
	t, e := dec.Token()
	if e != nil {
		return Value{}, errors.New("malformed JSON body")
	}
	switch x := t.(type) {
	case json.Delim:
		if x == '{' {
			m := map[string]Value{}
			for dec.More() {
				k, e := dec.Token()
				if e != nil {
					return Value{}, errors.New("malformed JSON object")
				}
				s, ok := k.(string)
				if !ok || s == "" || len(s) > l.MaxTokenBytes {
					return Value{}, errors.New("invalid JSON object key")
				}
				if _, ok = m[s]; ok {
					return Value{}, fmt.Errorf("duplicate JSON member %q", s)
				}
				v, e := parseJSONValue(dec, depth+1, l)
				if e != nil {
					return Value{}, e
				}
				m[s] = v
				if len(m) > l.MaxParameters {
					return Value{}, errors.New("JSON parameter limit exceeded")
				}
			}
			if _, e = dec.Token(); e != nil {
				return Value{}, errors.New("malformed JSON object")
			}
			return Value{Kind: ValueObject, Object: m}, nil
		}
		if x == '[' {
			a := []Value{}
			for dec.More() {
				v, e := parseJSONValue(dec, depth+1, l)
				if e != nil {
					return Value{}, e
				}
				a = append(a, v)
				if len(a) > l.MaxParameters {
					return Value{}, errors.New("JSON parameter limit exceeded")
				}
			}
			if _, e = dec.Token(); e != nil {
				return Value{}, errors.New("malformed JSON array")
			}
			return Value{Kind: ValueArray, Array: a}, nil
		}
		return Value{}, errors.New("malformed JSON delimiter")
	case string:
		if len(x) > l.MaxTokenBytes {
			return Value{}, errors.New("JSON string exceeds limit")
		}
		return Value{Kind: ValueString, String: x}, nil
	case bool:
		return Value{Kind: ValueBoolean, Bool: x}, nil
	case nil:
		return Value{Kind: ValueNull}, nil
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			f, e := x.Float64()
			if e != nil || f != f {
				return Value{}, errors.New("JSON number is invalid")
			}
			return Value{Kind: ValueNumber, Float: f}, nil
		}
		i, e := x.Int64()
		if e != nil {
			return Value{}, errors.New("JSON integer is invalid")
		}
		return Value{Kind: ValueInteger, Int: i}, nil
	}
	return Value{}, errors.New("unsupported JSON value")
}

func validOperation(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
