package audit

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRegisteredSensitiveValuesAreRedactedExactly(t *testing.T) {
	const configured = "configured-sensitive-value"
	RegisterSensitiveValue(configured)
	if got := RedactString("prefix=" + configured + " suffix"); strings.Contains(got, configured) {
		t.Fatalf("registered value leaked: %q", got)
	}
}

func TestSecretScannerRedactsCapturedDiagnostics(t *testing.T) {
	accessKey := "AKIAIOSFODNN7EXAMPLE"
	assumedKey := "ASIAIOSFODNN7EXAMPLE"
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	token := "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQ"
	bearer := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig"
	signature := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	captured := []string{
		"body aws_access_key_id=" + accessKey + " aws_secret_access_key=" + secret + " aws_session_token=" + token,
		"unlabelled AWS material: " + accessKey + " " + assumedKey + " " + secret + " " + token,
		"Authorization: " + bearer,
		"Authorization: AWS4-HMAC-SHA256 Credential=" + accessKey + "/scope, Signature=" + signature,
		"argv --access-key " + assumedKey + " --signature=" + signature,
	}
	for _, value := range captured {
		redacted := RedactString(value)
		for _, secretValue := range []string{accessKey, assumedKey, secret, token, bearer, signature} {
			if strings.Contains(redacted, secretValue) {
				t.Fatalf("secret leaked by RedactString: %q", secretValue)
			}
		}
	}

	headers := RedactHeaders(http.Header{
		"Authorization":   []string{bearer},
		"Cookie":          []string{"session=" + token},
		"X-Amz-Signature": []string{signature},
		"X-Diagnostic":    []string{"secret=" + secret},
	})
	for _, values := range headers {
		for _, value := range values {
			if strings.Contains(value, secret) || strings.Contains(value, token) || strings.Contains(value, signature) {
				t.Fatalf("secret leaked by header redaction: %q", value)
			}
		}
	}
	env := RedactEnv([]string{"AWS_ACCESS_KEY_ID=" + accessKey, "AWS_SECRET_ACCESS_KEY=" + secret, "SAFE=body token=" + token})
	if strings.Contains(strings.Join(env, "\n"), accessKey) || strings.Contains(strings.Join(env, "\n"), secret) || strings.Contains(strings.Join(env, "\n"), token) {
		t.Fatal("secret leaked by environment redaction")
	}
	query := RedactQuery(url.Values{"X-Amz-Signature": {signature}, "body": {"token=" + token}})
	if strings.Contains(query.Encode(), signature) || strings.Contains(query.Encode(), token) {
		t.Fatal("secret leaked by query redaction")
	}
	if got := RedactError(errors.New("credential_process leaked " + secret)); got.Error() != "operation failed" {
		t.Fatalf("error was not sanitized: %v", got)
	}
}
