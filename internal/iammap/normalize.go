// Copyright 2026 Kordn AI contributors
// Licensed under the Apache License, Version 2.0.
package iammap

import (
	"strings"
	"unicode"
)

func normalizeOperation(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return ""
		}
	}
	return s
}
func canonicalAction(s string) string {
	p := strings.SplitN(s, ":", 2)
	if len(p) != 2 {
		return ""
	}
	return strings.ToLower(p[0]) + ":" + p[1]
}
