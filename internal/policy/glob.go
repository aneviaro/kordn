package policy

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// These limits are deliberately shared by rule construction and matching.
// Besides making resource use predictable, they prevent a caller from using
// an unusually large string to turn the matcher into an allocation oracle.
const (
	MaxGlobLength = 512
	maxGlobSteps  = (MaxGlobLength + 1) * (MaxGlobLength + 1)
)

// Glob is a validated, allocation-free (while matching) glob pattern. The
// only operators are '*' (zero or more bytes) and '?' (one byte).
type Glob struct {
	pattern string
	action  bool
}

// CompileGlob validates a resource glob. Use CompileActionGlob for the
// ASCII-folded action form.
func CompileGlob(pattern string) (Glob, error) { return compileGlob(pattern, false) }

// CompileActionGlob validates an action glob and makes matching ASCII
// case-insensitive.
func CompileActionGlob(pattern string) (Glob, error) { return compileGlob(pattern, true) }

func compileGlob(pattern string, action bool) (Glob, error) {
	if err := validateGlobPattern(pattern, action); err != nil {
		return Glob{}, err
	}
	if action {
		pattern = asciiLower(pattern)
	}
	return Glob{pattern: pattern, action: action}, nil
}

func validateGlobPattern(pattern string, action bool) error {
	if len(pattern) == 0 || len(pattern) > MaxGlobLength || !utf8.ValidString(pattern) {
		return errors.New("glob is empty, too long, or not valid UTF-8")
	}
	for _, r := range pattern {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("[](){}|+^$\\", r) {
			return errors.New("glob contains unsupported syntax")
		}
	}
	if action {
		colon := strings.IndexByte(pattern, ':')
		if pattern != "*" && (colon <= 0 || colon == len(pattern)-1 || strings.Count(pattern, ":") != 1) {
			return errors.New("action glob must use service:operation form")
		}
		for _, r := range pattern {
			if r > unicode.MaxASCII || !(r == ':' || r == '*' || r == '?' ||
				(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-') {
				return errors.New("action glob contains unsupported characters")
			}
		}
	}
	return nil
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Match reports whether value matches the compiled pattern. Matching uses a
// bounded dynamic-programming table over bytes: '*' matches zero or more
// bytes and '?' matches one byte. The fixed-size rows keep both work and
// matching time bounded by the validated input lengths. Action matching folds
// ASCII only; resources are compared as bytes.
func (g Glob) Match(value string) bool {
	if g.pattern == "" || len(value) > MaxGlobLength || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	if g.action {
		for _, r := range value {
			if r > unicode.MaxASCII || !(r == ':' || r == '*' || r == '?' ||
				(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
		value = asciiLower(value)
	}

	// The dimensions are bounded by CompileGlob and the value check above.
	// Use two rows rather than allocating one boolean per DP cell.
	var previous, current [MaxGlobLength + 1]bool
	previous[0] = true
	steps := 0
	for patternIndex := 1; patternIndex <= len(g.pattern); patternIndex++ {
		steps++
		if steps > maxGlobSteps {
			return false
		}
		previous[patternIndex] = previous[patternIndex-1] && g.pattern[patternIndex-1] == '*'
	}
	for valueIndex := 1; valueIndex <= len(value); valueIndex++ {
		current[0] = false
		for patternIndex := 1; patternIndex <= len(g.pattern); patternIndex++ {
			steps++
			if steps > maxGlobSteps {
				return false
			}
			switch g.pattern[patternIndex-1] {
			case '*':
				current[patternIndex] = previous[patternIndex] || current[patternIndex-1]
			case '?':
				current[patternIndex] = previous[patternIndex-1]
			default:
				current[patternIndex] = previous[patternIndex-1] && g.pattern[patternIndex-1] == value[valueIndex-1]
			}
		}
		previous, current = current, previous
	}
	return previous[len(g.pattern)]
}

// MatchGlob is the public convenience form. Invalid patterns never match.
func MatchGlob(pattern, value string) bool {
	g, err := CompileGlob(pattern)
	return err == nil && g.Match(value)
}

// MatchActionGlob is the action-specific convenience form.
func MatchActionGlob(pattern, value string) bool {
	g, err := CompileActionGlob(pattern)
	return err == nil && g.Match(value)
}

// GlobMatch is retained as a descriptive alias for MatchGlob.
func GlobMatch(pattern, value string) bool { return MatchGlob(pattern, value) }
