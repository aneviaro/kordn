// Package sigv4 contains the deliberately small, header-SigV4-only
// authentication boundary used by the local AWS proxy.  This file does not
// use net/url.Values for canonicalization: Values interprets '+' as a space
// and consequently cannot represent an AWS query string without changing it.
package sigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Canonical is the material used by SigV4's string-to-sign.  It intentionally
// contains no credentials or authorization values.
type Canonical struct {
	Method        string
	URI           string
	Query         string
	Headers       string
	SignedHeaders string
	PayloadHash   string
	Request       string
	Hash          string
}

// CanonicalURI returns the AWS URI-encoded path without cleaning dot
// components or decoding an encoded slash.  RawPath is honored by
// url.URL.EscapedPath, so /a%2Fb and /a/b remain different requests.
func CanonicalURI(req *http.Request) (string, error) {
	if req == nil || req.URL == nil {
		return "", newError(CodeMalformedRequest, "request URL is unavailable")
	}
	if req.URL.Opaque != "" {
		return "", newError(CodeMalformedRequest, "opaque request URL is unsupported")
	}
	if req.URL.RawPath != "" {
		if decoded, err := url.PathUnescape(req.URL.RawPath); err != nil || decoded != req.URL.Path {
			return "", newError(CodeMalformedRequest, "request path escaping is invalid")
		}
	}
	escaped := req.URL.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	if escaped[0] != '/' {
		return "", newError(CodeMalformedRequest, "request path is not absolute")
	}
	return canonicalEscapedPath(escaped)
}

func canonicalEscapedPath(escaped string) (string, error) {
	var out strings.Builder
	out.Grow(len(escaped))
	for i := 0; i < len(escaped); i++ {
		c := escaped[i]
		switch {
		case c == '/':
			// AWS's normal URI encoding leaves path separators alone.
			out.WriteByte(c)
		case c == '%':
			if i+2 >= len(escaped) || hexValue(escaped[i+1]) < 0 || hexValue(escaped[i+2]) < 0 {
				return "", newError(CodeMalformedRequest, "request path contains an invalid escape")
			}
			// Keep an existing escape an escape.  In particular, %2F must
			// never become a path separator.
			out.WriteByte('%')
			out.WriteByte(upperHex(escaped[i+1]))
			out.WriteByte(upperHex(escaped[i+2]))
			i += 2
		case isUnreserved(c):
			out.WriteByte(c)
		default:
			writeEscape(&out, c)
		}
	}
	return out.String(), nil
}

// CanonicalQuery encodes raw query components as AWS URI components. Empty
// components and duplicate pairs are retained and sorted by encoded key then
// encoded value. A literal '+' is encoded as %2B, not treated as a space.
func CanonicalQuery(req *http.Request) (string, error) {
	if req == nil || req.URL == nil {
		return "", newError(CodeMalformedRequest, "request URL is unavailable")
	}
	return canonicalRawQuery(req.URL.RawQuery)
}

type queryPair struct{ key, value string }

func canonicalRawQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	parts := strings.Split(raw, "&")
	pairs := make([]queryPair, 0, len(parts))
	for _, part := range parts {
		key, value := part, ""
		if at := strings.IndexByte(part, '='); at >= 0 {
			key, value = part[:at], part[at+1:]
		}
		decodedKey, err := percentDecodeQuery(key)
		if err != nil {
			return "", newError(CodeMalformedRequest, "request query contains an invalid escape")
		}
		decodedValue, err := percentDecodeQuery(value)
		if err != nil {
			return "", newError(CodeMalformedRequest, "request query contains an invalid escape")
		}
		pairs = append(pairs, queryPair{key: awsEncode(decodedKey), value: awsEncode(decodedValue)})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})
	var out strings.Builder
	for i, pair := range pairs {
		if i != 0 {
			out.WriteByte('&')
		}
		out.WriteString(pair.key)
		out.WriteByte('=')
		out.WriteString(pair.value)
	}
	return out.String(), nil
}

func percentDecodeQuery(value string) ([]byte, error) {
	decoded := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			decoded = append(decoded, value[i])
			continue
		}
		if i+2 >= len(value) || hexValue(value[i+1]) < 0 || hexValue(value[i+2]) < 0 {
			return nil, errors.New("invalid percent escape")
		}
		decoded = append(decoded, byte(hexValue(value[i+1])<<4|hexValue(value[i+2])))
		i += 2
	}
	return decoded, nil
}

// CanonicalHeaders validates and canonicalizes the requested signed header
// set. Header names must already be the lowercase, sorted, unique list from
// Authorization. Host is read from Request.Host because net/http stores it
// outside Header.
func CanonicalHeaders(req *http.Request, signed []string) (headers, signedHeaders string, err error) {
	if req == nil {
		return "", "", newError(CodeMalformedRequest, "request is unavailable")
	}
	if len(signed) == 0 {
		return "", "", newError(CodeMalformedAuthorization, "signed headers are empty")
	}
	last := ""
	seen := make(map[string]struct{}, len(signed))
	var out strings.Builder
	for _, name := range signed {
		if !validHeaderName(name) || name != strings.ToLower(name) || (last != "" && name <= last) {
			return "", "", newError(CodeMalformedAuthorization, "signed headers are not sorted")
		}
		if _, ok := seen[name]; ok {
			return "", "", newError(CodeMalformedAuthorization, "signed headers contain a duplicate")
		}
		seen[name] = struct{}{}
		last = name
		value, err := signedHeaderValue(req, name)
		if err != nil {
			return "", "", err
		}
		out.WriteString(name)
		out.WriteByte(':')
		out.WriteString(normalizeHeaderValue(value))
		out.WriteByte('\n')
	}
	return out.String(), strings.Join(signed, ";"), nil
}

func signedHeaderValue(req *http.Request, name string) (string, error) {
	if name == "host" {
		values, present := headerValues(req.Header, name)
		if present && req.Host != "" {
			return "", newError(CodeMalformedRequest, "host header is ambiguous")
		}
		if present {
			if len(values) != 1 || values[0] == "" {
				return "", newError(CodeMalformedRequest, "host header is duplicated")
			}
			if !validHeaderValue(values[0]) {
				return "", newError(CodeMalformedRequest, "host header contains invalid bytes")
			}
			return values[0], nil
		}
		if req.Host != "" {
			return req.Host, nil
		}
		if req.URL != nil && req.URL.Host != "" {
			return req.URL.Host, nil
		}
		return "", newError(CodeMalformedRequest, "signed host header is missing")
	}
	values, present := headerValues(req.Header, name)
	if !present && name == "content-length" && req.ContentLength > 0 {
		return strconv.FormatInt(req.ContentLength, 10), nil
	}
	if !present || len(values) != 1 {
		return "", newError(CodeMalformedRequest, "signed header is missing or duplicated")
	}
	if !validHeaderValue(values[0]) {
		return "", newError(CodeMalformedRequest, "signed header contains invalid bytes")
	}
	return values[0], nil
}

func headerValues(header http.Header, name string) ([]string, bool) {
	var result []string
	present := false
	for key, values := range header {
		if strings.EqualFold(key, name) {
			present = true
			result = append(result, values...)
		}
	}
	return result, present
}

func normalizeHeaderValue(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	space := false
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case ' ', '\t':
			space = true
		default:
			if space && out.Len() != 0 {
				out.WriteByte(' ')
			}
			out.WriteByte(value[i])
			space = false
		}
	}
	return out.String()
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c == '-' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		// HTTP field values permit horizontal tab and visible/obs-text bytes,
		// but no other C0 controls or DEL. Rejecting them here keeps canonical
		// material identical to what a valid HTTP request can carry.
		if (value[i] < 0x20 && value[i] != '\t') || value[i] == 0x7f {
			return false
		}
	}
	return true
}

// BuildCanonicalRequest builds the exact five-line canonical request plus
// payload hash. payloadHash must be either a lowercase SHA-256 hex string or
// one of the explicitly handled AWS payload constants.
func BuildCanonicalRequest(req *http.Request, signed []string, payloadHash string) (Canonical, error) {
	if req == nil || req.URL == nil {
		return Canonical{}, newError(CodeMalformedRequest, "request URL is unavailable")
	}
	if strings.ContainsAny(req.Method, "\x00\r\n ") || req.Method == "" {
		return Canonical{}, newError(CodeMalformedRequest, "request method is invalid")
	}
	uri, err := CanonicalURI(req)
	if err != nil {
		return Canonical{}, err
	}
	query, err := CanonicalQuery(req)
	if err != nil {
		return Canonical{}, err
	}
	headers, names, err := CanonicalHeaders(req, signed)
	if err != nil {
		return Canonical{}, err
	}
	if !validPayloadHash(payloadHash) {
		return Canonical{}, newError(CodeUnsupportedPayload, "payload hash mode is unsupported")
	}
	// The canonical-header string ends in a newline and the SigV4 grammar
	// contributes another separator before SignedHeaders. The resulting
	// empty visual line is part of the AWS canonical request format.
	request := strings.Join([]string{req.Method, uri, query, headers, names, payloadHash}, "\n")
	hash := sha256.Sum256([]byte(request))
	return Canonical{Method: req.Method, URI: uri, Query: query, Headers: headers, SignedHeaders: names, PayloadHash: payloadHash, Request: request, Hash: hex.EncodeToString(hash[:])}, nil
}

func validPayloadHash(value string) bool {
	if value == "UNSIGNED-PAYLOAD" || len(value) == sha256.Size*2 {
		if len(value) != sha256.Size*2 {
			return true
		}
		for i := 0; i < len(value); i++ {
			if !isLowerHex(value[i]) {
				return false
			}
		}
		return true
	}
	return false
}

func awsEncode(value []byte) string {
	var out strings.Builder
	out.Grow(len(value))
	for _, c := range value {
		if isUnreserved(c) {
			out.WriteByte(c)
		} else {
			writeEscape(&out, c)
		}
	}
	return out.String()
}

func isUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func writeEscape(out *strings.Builder, c byte) {
	const digits = "0123456789ABCDEF"
	out.WriteByte('%')
	out.WriteByte(digits[c>>4])
	out.WriteByte(digits[c&15])
}

func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

func isLowerHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - ('a' - 'A')
	}
	return c
}

// canonicalRequest is retained as a small package-local seam for tests and
// for callers that prefer the unexported implementation naming convention.
func canonicalRequest(req *http.Request, signed []string, payloadHash string) (Canonical, error) {
	return BuildCanonicalRequest(req, signed, payloadHash)
}
