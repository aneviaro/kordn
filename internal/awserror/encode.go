// Copyright 2026 Kordn AI contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awserror

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

// AWSProtocol is an alias so response callers can remain within this package.
type AWSProtocol = awsrequest.AWSProtocol

// Classification records who produced a denial. Upstream responses must not
// be relabeled as local policy decisions.
type Classification string

const (
	ClassificationLocalDeny            Classification = "local_deny"
	ClassificationLocalPolicyDeny      Classification = ClassificationLocalDeny
	ClassificationUpstreamAccessDenied Classification = "upstream_access_denied"
	ClassificationUpstreamError        Classification = "upstream_error"

	// Short names are useful at proxy call sites.
	LocalDeny            = ClassificationLocalDeny
	LocalPolicyDenial    = ClassificationLocalDeny
	LocalPolicyDeny      = ClassificationLocalDeny
	UpstreamAccessDenied = ClassificationUpstreamAccessDenied
	UpstreamError        = ClassificationUpstreamError
)

// Denial contains only non-secret response metadata. UpstreamResponse is
// returned unchanged for upstream classifications and is never serialized
// into a local error body.
type Denial struct {
	Service    string
	Operation  string
	ReasonCode ReasonCode
	// Reason and RequestID are compatibility aliases for callers using the
	// terminology of the wire protocols. When set, they must agree with the
	// canonical fields.
	Reason           ReasonCode
	EventID          string
	RequestID        string
	Classification   Classification
	UpstreamResponse *http.Response
}

// IsLocalPolicyDeny reports whether this denial may be encoded by Kordn.
func (d Denial) IsLocalPolicyDeny() bool { return d.Classification == ClassificationLocalPolicyDeny }

// Encode creates a protocol-native local policy denial. A response received
// from AWS is returned by identity for upstream classifications; it must not
// be relabeled or rewritten. Invalid local metadata fails closed by returning
// nil rather than emitting an unsafe response.
func Encode(protocol awsrequest.AWSProtocol, denial Denial) *http.Response {
	if denial.Classification == ClassificationUpstreamAccessDenied || denial.Classification == ClassificationUpstreamError {
		return denial.UpstreamResponse
	}
	if denial.Classification != ClassificationLocalDeny || !protocol.Supported() {
		return nil
	}
	denial, ok := normalizeDenial(denial)
	if !ok {
		return nil
	}
	return encodeLocal(protocol, denial)
}

// Encoder is a stateless implementation for components that prefer the
// Section 17 interface over the package function.
type ErrorEncoder interface {
	Encode(awsrequest.AWSProtocol, Denial) *http.Response
}

type Encoder struct{}

func (Encoder) Encode(protocol awsrequest.AWSProtocol, denial Denial) *http.Response {
	return Encode(protocol, denial)
}

func NewEncoder() Encoder { return Encoder{} }

var _ ErrorEncoder = Encoder{}

// EncodeDenial is the convenient scalar form of Encode.
func EncodeDenial(protocol awsrequest.AWSProtocol, service, operation string, reason ReasonCode, eventID string, classification Classification) *http.Response {
	return Encode(protocol, Denial{Service: service, Operation: operation, ReasonCode: reason, EventID: eventID, Classification: classification})
}

func normalizeDenial(denial Denial) (Denial, bool) {
	if denial.Reason != "" {
		if !denial.Reason.Valid() || (denial.ReasonCode.Valid() && denial.Reason != denial.ReasonCode) {
			return Denial{}, false
		}
		denial.ReasonCode = denial.Reason
	}
	if denial.RequestID != "" {
		if denial.EventID != "" && denial.EventID != denial.RequestID {
			return Denial{}, false
		}
		denial.EventID = denial.RequestID
	}
	if !boundedToken(denial.Service, 128) || !boundedToken(denial.Operation, 128) || !denial.ReasonCode.Valid() || denial.ReasonCode == ReasonAllRequirementsAllowed || !boundedToken(denial.EventID, 128) {
		return Denial{}, false
	}
	denial.Classification = ClassificationLocalDeny
	return denial, true
}

func denialMessage(denial Denial) string {
	return fmt.Sprintf("Kordn denied %s:%s (%s); event %s", denial.Service, denial.Operation, denial.ReasonCode, denial.EventID)
}

func boundedToken(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, r := range value {
		if r > 0x7f || r < 0x21 || r == '/' || r == '\\' || r == '<' || r == '>' || r == '"' || r == '\'' || r == '&' || r == '?' || r == '#' || r == '%' {
			return false
		}
	}
	return true
}

func setBody(response *http.Response, body []byte, contentType string) *http.Response {
	response.StatusCode = http.StatusForbidden
	response.Status = "403 Forbidden"
	response.ProtoMajor, response.ProtoMinor = 1, 1
	response.Header.Set("Content-Type", contentType)
	response.Header.Set("Content-Length", itoa(len(body)))
	response.ContentLength = int64(len(body))
	response.Body = io.NopCloser(strings.NewReader(string(body)))
	return response
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
