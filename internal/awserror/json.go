package awserror

import (
	"encoding/json"
	"net/http"

	"github.com/kordn-ai/kordn/internal/awsrequest"
)

type jsonError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

func encodeJSON(protocol awsrequest.AWSProtocol, denial Denial) *http.Response {
	body, err := json.Marshal(jsonError{Type: "AccessDeniedException", Message: denialMessage(denial)})
	if err != nil {
		return nil
	}
	response := &http.Response{Header: make(http.Header)}
	response.Header.Set("x-amzn-ErrorType", "AccessDeniedException")
	response.Header.Set("x-amzn-RequestId", denial.EventID)
	contentType := "application/x-amz-json-1.1"
	if protocol == awsrequest.ProtocolJSON10 {
		contentType = "application/x-amz-json-1.0"
	}
	return setBody(response, body, contentType)
}

func encodeRESTJSON(denial Denial) *http.Response {
	body, err := json.Marshal(struct {
		Message string `json:"message"`
	}{Message: denialMessage(denial)})
	if err != nil {
		return nil
	}
	response := &http.Response{Header: make(http.Header)}
	response.Header.Set("x-amzn-ErrorType", "AccessDeniedException")
	response.Header.Set("x-amzn-RequestId", denial.EventID)
	return setBody(response, body, "application/json")
}

func encodeLocal(protocol awsrequest.AWSProtocol, denial Denial) *http.Response {
	switch protocol {
	case awsrequest.ProtocolJSON10, awsrequest.ProtocolJSON11:
		return encodeJSON(protocol, denial)
	case awsrequest.ProtocolRESTJSON:
		return encodeRESTJSON(denial)
	case awsrequest.ProtocolQuery, awsrequest.ProtocolEC2Query:
		return encodeQueryXML(denial)
	case awsrequest.ProtocolRESTXML:
		return encodeRESTXML(denial)
	default:
		return nil
	}
}
