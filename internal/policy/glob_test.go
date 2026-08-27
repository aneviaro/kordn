// Copyright 2026 Kordn AI contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
