// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package audit

import (
	"strings"
	"testing"
)

func FuzzAuditRedaction(f *testing.F) {
	const accessKey = "AKIA1234567890123456"
	RegisterSensitiveValue(accessKey)
	f.Add("Authorization: AWS4-HMAC-SHA256 Credential=" + accessKey)
	f.Add("ordinary diagnostic text")
	f.Fuzz(func(t *testing.T, input string) {
		out := RedactString(input)
		if strings.Contains(out, accessKey) {
			t.Fatal("access key was retained")
		}
		_ = MustRedact(map[string]string{"input": input})
	})
}
