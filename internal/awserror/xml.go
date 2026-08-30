package awserror

import (
	"encoding/xml"
	"net/http"
)

type queryErrorResponse struct {
	XMLName   xml.Name   `xml:"ErrorResponse"`
	Error     queryError `xml:"Error"`
	RequestID string     `xml:"RequestId"`
}
type queryError struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}
type restError struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

func encodeQueryXML(denial Denial) *http.Response {
	body, err := xml.Marshal(queryErrorResponse{Error: queryError{Type: "Sender", Code: "AccessDenied", Message: denialMessage(denial)}, RequestID: denial.EventID})
	if err != nil {
		return nil
	}
	return setBody(&http.Response{Header: make(http.Header)}, body, "text/xml")
}

func encodeRESTXML(denial Denial) *http.Response {
	body, err := xml.Marshal(restError{Code: "AccessDenied", Message: denialMessage(denial), RequestID: denial.EventID})
	if err != nil {
		return nil
	}
	response := &http.Response{Header: make(http.Header)}
	response.Header.Set("x-amz-request-id", denial.EventID)
	return setBody(response, body, "application/xml")
}
