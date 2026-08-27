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
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

func TestEncodeLocalProtocols(t *testing.T) {
	for _, protocol := range []awsrequest.AWSProtocol{awsrequest.ProtocolJSON10, awsrequest.ProtocolJSON11, awsrequest.ProtocolRESTJSON, awsrequest.ProtocolQuery, awsrequest.ProtocolEC2Query, awsrequest.ProtocolRESTXML} {
		response := Encode(protocol, Denial{Service: "s3", Operation: "GetObject", ReasonCode: ReasonExplicitDeny, EventID: "evt-1", Classification: LocalPolicyDeny})
		if response == nil || response.StatusCode != 403 || response.ContentLength <= 0 {
			t.Fatalf("%s: invalid response", protocol)
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if protocol == awsrequest.ProtocolQuery || protocol == awsrequest.ProtocolEC2Query || protocol == awsrequest.ProtocolRESTXML {
			if err := xml.Unmarshal(body, new(interface{})); err != nil {
				t.Fatalf("%s XML: %v", protocol, err)
			}
		} else {
			var value map[string]interface{}
			if err := json.Unmarshal(body, &value); err != nil {
				t.Fatalf("%s JSON: %v", protocol, err)
			}
		}
	}
}

func TestEncodeDoesNotRelabelUpstream(t *testing.T) {
	for _, classification := range []Classification{UpstreamAccessDenied, UpstreamError} {
		upstream := &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("AWS response"))}
		response := Encode(awsrequest.ProtocolRESTJSON, Denial{Classification: classification, UpstreamResponse: upstream})
		if response != upstream {
			t.Fatal("upstream response was rewritten")
		}
	}
}

func TestEncodeRejectsAllowReason(t *testing.T) {
	if response := Encode(awsrequest.ProtocolRESTJSON, Denial{
		Service: "s3", Operation: "GetObject", ReasonCode: ReasonAllRequirementsAllowed,
		EventID: "evt", Classification: LocalDeny,
	}); response != nil {
		t.Fatal("allow reason was encoded as a denial")
	}
}
