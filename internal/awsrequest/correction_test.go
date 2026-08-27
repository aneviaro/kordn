package awsrequest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type trackedBody struct {
	data       []byte
	closeCount int
}

func (b *trackedBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}
func (b *trackedBody) Close() error { b.closeCount++; return nil }

type errorBody struct {
	trackedBody
	fail error
}

func (b *errorBody) Read(p []byte) (int, error) {
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	return 0, b.fail
}

func stsRequest(body io.ReadCloser) (*http.Request, *VerifiedRequest) {
	e, _ := DefaultEndpointClassifier.Classify("sts.us-east-1.amazonaws.com")
	r, _ := http.NewRequest(http.MethodPost, "https://sts.us-east-1.amazonaws.com/", nil)
	r.Host = e.Host
	r.Body = body
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.URL.RawQuery = "Action=GetCallerIdentity"
	return r, &VerifiedRequest{Request: r, Endpoint: e, Protocol: ProtocolQuery, SigningScheme: SigningHeaderV4, SigningRegion: e.Region, SigningService: e.Service, PayloadMode: PayloadHashSHA256}
}

func TestDecoderProtocolAuthorityRejectsCrossProtocolSpoofs(t *testing.T) {
	cases := []struct {
		service, host   string
		protocol        AWSProtocol
		content, target string
	}{
		{"ec2", "ec2.us-east-1.amazonaws.com", ProtocolJSON11, "application/x-amz-json-1.1", "AmazonEC2.DescribeInstances"},
		{"ecs", "ecs.us-east-1.amazonaws.com", ProtocolQuery, "application/x-www-form-urlencoded", ""},
		{"sts", "sts.us-east-1.amazonaws.com", ProtocolJSON11, "application/x-amz-json-1.1", "AWSSecurityTokenServiceV20110615.GetCallerIdentity"},
		{"s3", "s3.us-east-1.amazonaws.com", ProtocolRESTJSON, "application/json", ""},
		{"cloudwatch", "monitoring.us-east-1.amazonaws.com", ProtocolJSON11, "application/x-amz-json-1.1", "GraniteServiceVersion20100831.PutMetricData"},
		{"logs", "logs.us-east-1.amazonaws.com", ProtocolQuery, "application/x-www-form-urlencoded", ""},
		{"iam", "iam.amazonaws.com", ProtocolJSON11, "application/x-amz-json-1.1", "IAM_20100508.GetRole"},
		{"lambda", "lambda.us-east-1.amazonaws.com", ProtocolQuery, "application/x-www-form-urlencoded", ""},
		{"dynamodb", "dynamodb.us-east-1.amazonaws.com", ProtocolJSON11, "application/x-amz-json-1.1", "DynamoDB_20120810.GetItem"},
	}
	for _, tc := range cases {
		t.Run(tc.service, func(t *testing.T) {
			e, err := DefaultEndpointClassifier.Classify(tc.host)
			if err != nil {
				t.Fatal(err)
			}
			r, _ := http.NewRequest(http.MethodPost, "https://"+tc.host+"/", strings.NewReader("Action=GetCallerIdentity"))
			r.Host = e.Host
			r.Header.Set("Content-Type", tc.content)
			if tc.target != "" {
				r.Header.Set("X-Amz-Target", tc.target)
			}
			v := &VerifiedRequest{Request: r, Endpoint: e, Protocol: tc.protocol, SigningScheme: SigningHeaderV4, SigningRegion: e.Region, SigningService: e.Service, PayloadMode: PayloadHashSHA256}
			if _, err := NewDecoder().Decode(context.Background(), v, e); err == nil {
				t.Fatal("cross-protocol request was accepted")
			}
		})
	}
}

func TestDecoderNoGetBodyRestoresStreamAndClose(t *testing.T) {
	original := &trackedBody{data: []byte("abcdef")}
	r, v := stsRequest(original)
	d := NewDecoder(DecodeLimits{MaxBodyBytes: 3})
	if _, err := d.Decode(context.Background(), v, v.Endpoint); err == nil {
		t.Fatal("oversize body accepted")
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || string(got) != "abcdef" {
		t.Fatalf("restored body %q: %v", got, err)
	}
	if err := r.Body.Close(); err != nil || original.closeCount != 1 {
		t.Fatalf("close was not delegated: %v count=%d", err, original.closeCount)
	}
	bad := &errorBody{trackedBody: trackedBody{data: []byte("ab")}, fail: errors.New("reader failed")}
	r, v = stsRequest(bad)
	if _, err := NewDecoder().Decode(context.Background(), v, v.Endpoint); err == nil {
		t.Fatal("reader failure accepted")
	}
	got, err = io.ReadAll(r.Body)
	if string(got) != "ab" || err == nil {
		t.Fatalf("error body not restored with reader error: %q %v", got, err)
	}
	_ = r.Body.Close()
	if bad.closeCount != 1 {
		t.Fatalf("error body close count=%d", bad.closeCount)
	}
}

func TestConfiguredDecoderUsesTrustedCallerContext(t *testing.T) {
	_, v := stsRequest(io.NopCloser(strings.NewReader("")))
	v.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	d, err := NewConfiguredDecoder(DecoderOptions{CallerAccountID: "123456789012"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Decode(context.Background(), v, v.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if out.CallerAccountID != "123456789012" {
		t.Fatalf("caller context not retained: %q", out.CallerAccountID)
	}
}
