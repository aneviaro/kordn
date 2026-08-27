// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var sensitiveHeaders = map[string]struct{}{"authorization": {}, "proxy-authorization": {}, "x-amz-security-token": {}, "cookie": {}, "set-cookie": {}, "x-api-key": {}, "x-amz-date": {}}

func IsSensitiveHeader(name string) bool { _, ok := sensitiveHeaders[strings.ToLower(name)]; return ok }
func RedactHeader(name, value string) string {
	if IsSensitiveHeader(name) || strings.Contains(strings.ToLower(name), "token") || strings.Contains(strings.ToLower(name), "secret") || strings.Contains(strings.ToLower(name), "credential") || strings.Contains(strings.ToLower(name), "signature") {
		return "[REDACTED]"
	}
	return RedactString(value)
}
func RedactHeaders(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for k, v := range in {
		out[k] = make([]string, len(v))
		for i, x := range v {
			out[k][i] = RedactHeader(k, x)
		}
	}
	return out
}
func RedactQuery(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		out[k] = make([]string, len(v))
		for i, x := range v {
			if strings.Contains(lk, "sig") || strings.Contains(lk, "token") || strings.Contains(lk, "key") || strings.Contains(lk, "credential") || strings.Contains(lk, "auth") {
				out[k][i] = "[REDACTED]"
			} else {
				out[k][i] = RedactString(x)
			}
		}
	}
	return out
}
func RedactEnv(in []string) []string {
	out := make([]string, 0, len(in))
	for _, item := range in {
		k, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "aws_") || strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "credential") || strings.Contains(lk, "password") || strings.Contains(lk, "authorization") {
			out = append(out, k+"=[REDACTED]")
		} else {
			out = append(out, k+"="+RedactString(strings.TrimPrefix(item, k+"=")))
		}
	}
	return out
}

// sensitiveValues is the process-local registry for values which cannot be
// recognized from their shape alone. Callers register credentials immediately
// after obtaining them; this keeps exact values out of diagnostics without
// requiring the redaction package to know every provider's token format.
var sensitiveValues struct {
	sync.RWMutex
	values map[string]struct{}
}

// RegisterSensitiveValue adds one exact value to the central redaction
// registry. Empty values are ignored because registering them would redact
// every string. Values are never returned by this package.
func RegisterSensitiveValue(value string) {
	if value == "" {
		return
	}
	sensitiveValues.Lock()
	if sensitiveValues.values == nil {
		sensitiveValues.values = make(map[string]struct{})
	}
	sensitiveValues.values[value] = struct{}{}
	sensitiveValues.Unlock()
}

// RegisterSensitiveValues registers all non-empty values in one operation.
func RegisterSensitiveValues(values ...string) {
	for _, value := range values {
		RegisterSensitiveValue(value)
	}
}

// AWS access keys are normally 20 characters with one of these documented
// prefixes. AWS secret keys are 40 characters from this alphabet, and STS
// session tokens have stable provider prefixes but variable lengths. These
// shape checks cover unlabelled values; arbitrary short strings still require
// explicit registration because they cannot be distinguished from ordinary
// diagnostic text.
var secretText = regexp.MustCompile(`(?i)(\b(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b|\b[A-Za-z0-9/+=]{40}\b|\b(?:IQoJ|FwoGZXIvYXdz)[A-Za-z0-9/+=_-]{16,}\b|Bearer[[:space:]]+[A-Za-z0-9._~+/=-]+|AWS4-HMAC-SHA256[^[:space:]]*|(?:(?:secret|token|password|signature|credential)[[:space:]_:-]*[=:][[:space:]]*)[^,;[:space:]]+)`)

func RedactString(value string) string {
	// Replace longer values first so registering a token and one of its
	// components cannot leave the remainder of the token in output.
	sensitiveValues.RLock()
	registered := make([]string, 0, len(sensitiveValues.values))
	for candidate := range sensitiveValues.values {
		registered = append(registered, candidate)
	}
	sensitiveValues.RUnlock()
	sort.SliceStable(registered, func(i, j int) bool { return len(registered[i]) > len(registered[j]) })
	for _, candidate := range registered {
		value = strings.ReplaceAll(value, candidate, "[REDACTED]")
	}
	return secretText.ReplaceAllString(value, "[REDACTED]")
}

// RedactStructured recursively walks maps, slices, and scalar values. It is
// intended for diagnostics and has no path that serializes the original value.
func RedactStructured(value interface{}) interface{} {
	switch x := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, v := range x {
			lk := strings.ToLower(k)
			key := RedactString(k)
			if strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "password") || strings.Contains(lk, "authorization") || strings.Contains(lk, "credential") || strings.Contains(lk, "signature") {
				out[key] = "[REDACTED]"
			} else {
				out[key] = RedactStructured(v)
			}
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(x))
		for k, v := range x {
			lk := strings.ToLower(k)
			key := RedactString(k)
			if strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "password") || strings.Contains(lk, "authorization") || strings.Contains(lk, "credential") || strings.Contains(lk, "signature") {
				out[key] = "[REDACTED]"
			} else {
				out[key] = RedactString(v)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, v := range x {
			out[i] = RedactStructured(v)
		}
		return out
	case []string:
		out := make([]string, len(x))
		for i, v := range x {
			out[i] = RedactString(v)
		}
		return out
	case string:
		return RedactString(x)
	default:
		return value
	}
}
func RedactError(error) error { return errors.New("operation failed") }
func HashResource(resource string) string {
	sum := sha256.Sum256([]byte(resource))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func HashResourceForRun(runID, resource string) string {
	mac := hmac.New(sha256.New, []byte("kordn-audit-resource\x00"+runID))
	_, _ = mac.Write([]byte(resource))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}
func DeterministicResourceHash(resource string) string { return HashResource(resource) }
func RedactResource(resource string, logARNs, hashNames bool) string {
	if resource == "" {
		return ""
	}
	if !logARNs {
		return "[REDACTED]"
	}
	if hashNames {
		return HashResource(resource)
	}
	return resource
}
func MustRedact(v interface{}) string { return fmt.Sprint(RedactStructured(v)) }

func redactEvent(e Event) Event {
	out := cloneEvent(e)
	out.SchemaVersion = RedactString(out.SchemaVersion)
	out.EventID = RedactString(out.EventID)
	out.RunID = RedactString(out.RunID)
	out.EventType = EventType(RedactString(string(out.EventType)))
	if out.RootProcess != nil {
		out.RootProcess.Argv0 = RedactString(out.RootProcess.Argv0)
		out.RootProcess.CommandHash = RedactString(out.RootProcess.CommandHash)
	}
	if out.Request != nil {
		out.Request.Host = RedactString(out.Request.Host)
		out.Request.Partition = RedactString(out.Request.Partition)
		out.Request.Service = RedactString(out.Request.Service)
		out.Request.Operation = RedactString(out.Request.Operation)
		out.Request.Region = RedactString(out.Request.Region)
		out.Request.Method = RedactString(out.Request.Method)
	}
	for i := range out.IAMRequirements {
		out.IAMRequirements[i].Action = RedactString(out.IAMRequirements[i].Action)
		for j := range out.IAMRequirements[i].Resources {
			out.IAMRequirements[i].Resources[j] = RedactString(out.IAMRequirements[i].Resources[j])
		}
	}
	if out.Mapping != nil {
		out.Mapping.MapperVersion = RedactString(out.Mapping.MapperVersion)
	}
	if out.Decision != nil {
		out.Decision.Result = RedactString(out.Decision.Result)
		out.Decision.ReasonCode = RedactString(out.Decision.ReasonCode)
		out.Decision.PolicyHash = RedactString(out.Decision.PolicyHash)
		for i := range out.Decision.MatchedRuleIDs {
			out.Decision.MatchedRuleIDs[i] = RedactString(out.Decision.MatchedRuleIDs[i])
		}
	}
	if out.Upstream != nil {
		out.Upstream.Profile = RedactString(out.Upstream.Profile)
		out.Upstream.PrincipalARN = RedactString(out.Upstream.PrincipalARN)
		out.Upstream.AWSRequestID = RedactString(out.Upstream.AWSRequestID)
	}
	out.Status = RedactString(out.Status)
	out.ErrorCode = RedactString(out.ErrorCode)
	return out
}
