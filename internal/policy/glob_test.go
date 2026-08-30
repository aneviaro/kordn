package policy

import "testing"

func TestGlobSemantics(t *testing.T) {
	cases := []struct {
		pattern, value string
		action, want   bool
	}{
		{"a*b", "axxxb", false, true}, {"a?b", "acb", false, true}, {"a?b", "ab", false, false},
		{"S3:Get*", "s3:getobject", true, true}, {"S3:Get*", "s3:GETOBJECT", true, true}, {"arn:*:X", "ARN:aws:X", false, false},
	}
	for _, tc := range cases {
		var got bool
		if tc.action {
			got = MatchActionGlob(tc.pattern, tc.value)
		} else {
			got = MatchGlob(tc.pattern, tc.value)
		}
		if got != tc.want {
			t.Errorf("%q %q: got %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
	for _, pattern := range []string{"", "a[bc]", "a\\b", string(make([]byte, MaxGlobLength+1))} {
		if _, err := CompileGlob(pattern); err == nil {
			t.Errorf("malformed glob %q accepted", pattern)
		}
	}
}
