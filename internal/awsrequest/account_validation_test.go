package awsrequest

import (
	"context"
	"testing"
)

func TestCallerAccountContextValidation(t *testing.T) {
	for _, account := range []string{" ", "12345678901", "1234567890123", "12345678901x", "12345678901*", "+12345678901", "１２３４５６７８９０１２"} {
		if decoder, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: account}); err == nil || decoder != nil {
			t.Errorf("malformed account %q accepted: decoder=%v err=%v", account, decoder, err)
		}
	}
	for _, account := range []string{"", "000000000000", "123456789012"} {
		if decoder, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: account}); err != nil || decoder == nil {
			t.Errorf("valid account %q rejected: decoder=%v err=%v", account, decoder, err)
		}
	}
}

func TestDecodedRequestRejectsMalformedAccountDirectly(t *testing.T) {
	r := &DecodedAWSRequest{Partition: "aws", EndpointHost: "sts.us-east-1.amazonaws.com", Service: "sts", Region: "us-east-1", CallerAccountID: "12345678901 ", Protocol: ProtocolQuery, Operation: "GetCallerIdentity", Method: "POST", CanonicalPath: "/", PayloadHashMode: PayloadHashSHA256}
	if err := r.Validate(); err == nil {
		t.Fatal("malformed direct account accepted")
	}
}

func TestInvalidConfiguredAccountCannotConsumeBody(t *testing.T) {
	body := &trackedBody{data: []byte("Action=GetCallerIdentity")}
	_, v := stsRequest(body)
	if decoder, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: "123456789012 "}); err == nil {
		// A constructor that accepts an invalid permanent context would violate
		// the boundary contract; this branch also ensures no decode is attempted.
		if _, err := decoder.Decode(context.Background(), v, v.Endpoint); err == nil {
			t.Fatal("invalid configured account decoded")
		}
	}
	if body.closeCount != 0 || len(body.data) == 0 {
		t.Fatalf("invalid context touched body: close=%d remaining=%q", body.closeCount, body.data)
	}
}
