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

func TestS3ControlAccountEndpointEvidence(t *testing.T) {
	classifier, err := NewClassifier(16)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := classifier.Classify("123456789012.s3-control.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.AccountID != "123456789012" || endpoint.Service != "s3-control" || endpoint.SigningService != "s3" || endpoint.Region != "us-east-1" {
		t.Fatalf("account-qualified endpoint evidence was not retained: %+v", endpoint)
	}
	for _, host := range []string{
		"12345678901.s3-control.us-east-1.amazonaws.com",
		"1234567890123.s3-control.us-east-1.amazonaws.com",
		"12345678901x.s3-control.us-east-1.amazonaws.com",
		"123456789012.ce.us-east-1.amazonaws.com",
		"bucket.s3-control.us-east-1.amazonaws.com",
		"123456789012.s3-control.us-gov-west-1.amazonaws.com",
	} {
		if got, err := classifier.Classify(host); err == nil {
			t.Errorf("malformed or unapproved account host %q classified as %+v", host, got)
		}
	}
}

func TestS3ControlAccountMismatchRejectedBeforeDecode(t *testing.T) {
	classifier, err := NewClassifier(16)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := classifier.Classify("123456789012.s3-control.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	_, verified := stsRequest(&trackedBody{data: []byte("Action=ListAccessPoints")})
	verified.Request.URL.Host = endpoint.Host
	verified.Request.Host = endpoint.Host
	verified.Endpoint = endpoint
	verified.SigningService = endpoint.SigningService
	verified.SigningRegion = endpoint.SigningRegion
	decoder, err := NewConfiguredDecoder(DecoderOptions{Classifier: classifier, CallerAccountID: "210987654321"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode(context.Background(), verified, endpoint); err == nil {
		t.Fatal("S3 Control endpoint/caller account mismatch reached decoding")
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
