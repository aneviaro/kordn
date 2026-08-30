package sigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func BenchmarkCanonicalization(b *testing.B) {
	req, err := http.NewRequest(http.MethodPost, "https://dynamodb.us-east-1.amazonaws.com/", strings.NewReader(`{"TableName":"bench","Key":{"id":{"S":"one"}}}`))
	if err != nil {
		b.Fatal(err)
	}
	req.Host = "dynamodb.us-east-1.amazonaws.com"
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810.GetItem")
	h := sha256.Sum256([]byte(`{"TableName":"bench","Key":{"id":{"S":"one"}}}`))
	payload := hex.EncodeToString(h[:])
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := BuildCanonicalRequest(req, signed, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCanonicalQuery(b *testing.B) {
	req, err := http.NewRequest(http.MethodGet, "https://s3.us-east-1.amazonaws.com/bucket/key?versionId=a%2Bb&partNumber=2", nil)
	if err != nil {
		b.Fatal(err)
	}
	req.Host = "s3.us-east-1.amazonaws.com"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CanonicalQuery(req); err != nil {
			b.Fatal(err)
		}
	}
}
