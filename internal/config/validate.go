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

package config

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	// These bounds are intentionally finite. They prevent a malformed policy
	// from turning request buffering or policy evaluation into an unbounded
	// resource allocation while leaving the documented defaults unchanged.
	maxRules           = 10_000
	maxRuleList        = 1_000
	maxPatternLength   = 512
	maxMemoryBodyBytes = int64(64 * 1024 * 1024)
	maxSpoolBodyBytes  = int64(512 * 1024 * 1024)
	maxAuditPathLength = 4_096
	maxProfileLength   = 64
)

var (
	profilePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// Regions are deliberately syntactic here. Endpoint support is owned by
	// awsrequest; configuration validation must not perform DNS or metadata
	// lookups.
	regionPattern     = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$`)
	accountPattern    = regexp.MustCompile(`^[0-9]{12}$`)
	ruleIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	roleARNPattern    = regexp.MustCompile(`^arn:([A-Za-z0-9-]+):iam::([0-9]{12}):role/([^\x00\r\n]+)$`)
	externalIDPattern = regexp.MustCompile(`^[A-Za-z0-9_+=,.@:/-]+$`)
	identityPattern   = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]+$`)
)

// Validate applies semantic and filesystem safety checks. It performs no
// credential, network, listener, audit-file creation, or child-process work.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if c.Kind != Kind {
		return fmt.Errorf("kind must be %q", Kind)
	}
	if err := validateUpstream(c.Upstream); err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	if err := validateProxy(c.Proxy); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	if err := validatePolicy(c.Policy); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if err := normalizeAndValidateAudit(&c.Audit); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}

func validateUpstream(up Upstream) error {
	if up.Profile == "" {
		return errors.New("an explicit profile is required")
	}
	if len(up.Profile) > maxProfileLength || !profilePattern.MatchString(up.Profile) {
		return errors.New("profile contains unsupported characters")
	}
	if strings.EqualFold(up.Profile, "default") {
		return errors.New("the default profile is not permitted; choose an explicit shared-config profile")
	}
	if !regionPattern.MatchString(up.Region) || len(up.Region) > 64 {
		return fmt.Errorf("region %q is invalid", up.Region)
	}

	if up.AssumeRoleARN == "" {
		if up.ExternalID != "" || up.SourceIdentity != "" {
			return errors.New("externalId and sourceIdentity require assumeRoleArn")
		}
	} else {
		match := roleARNPattern.FindStringSubmatch(up.AssumeRoleARN)
		if match == nil || len(up.AssumeRoleARN) > 2048 || !supportedPartition(match[1]) {
			return errors.New("assumeRoleArn must be a valid IAM role ARN in a supported partition")
		}
	}
	if len(up.RoleSessionName) < 2 || len(up.RoleSessionName) > 64 || !identityPattern.MatchString(up.RoleSessionName) {
		return errors.New("roleSessionName must be 2-64 characters using the STS session-name character set")
	}
	if up.DurationSeconds < 900 || up.DurationSeconds > 43_200 {
		return errors.New("durationSeconds must be between 900 and 43200")
	}
	if up.ExternalID != "" && (len(up.ExternalID) < 2 || len(up.ExternalID) > 1_224 || !externalIDPattern.MatchString(up.ExternalID)) {
		return errors.New("externalId must be 2-1224 characters using the STS external-id character set")
	}
	if up.SourceIdentity != "" && (len(up.SourceIdentity) < 2 || len(up.SourceIdentity) > 64 || !identityPattern.MatchString(up.SourceIdentity)) {
		return errors.New("sourceIdentity must be 2-64 characters using the STS source-identity character set")
	}
	return nil
}

func validateProxy(proxy Proxy) error {
	if proxy.Listen == "" {
		return errors.New("listen is required")
	}
	host, port, err := net.SplitHostPort(proxy.Listen)
	if err != nil {
		return fmt.Errorf("listen must be host:port: %w", err)
	}
	if host == "" {
		return errors.New("listen host is required")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen must use an IPv4 or IPv6 loopback address")
	}
	if !decimalPort(port) {
		return errors.New("listen port must be a decimal number between 0 and 65535")
	}
	var portNumber int
	for _, digit := range port {
		portNumber = portNumber*10 + int(digit-'0')
	}
	if portNumber > 65_535 {
		return errors.New("listen port must be between 0 and 65535")
	}
	if len(port) > 1 && port[0] == '0' {
		return errors.New("listen port must use its normalized decimal form")
	}
	if proxy.NonAWSTraffic != DefaultNonAWSTraffic {
		return fmt.Errorf("nonAwsTraffic %q is unsupported; only tunnel is permitted", proxy.NonAWSTraffic)
	}
	if proxy.UpstreamProxy != DefaultUpstreamProxy && proxy.UpstreamProxy != "none" {
		return fmt.Errorf("upstreamProxy %q is unsupported; use inherit or none", proxy.UpstreamProxy)
	}
	if proxy.MaxInMemoryBodyBytes <= 0 || proxy.MaxInMemoryBodyBytes > maxMemoryBodyBytes {
		return fmt.Errorf("maxInMemoryBodyBytes must be between 1 and %d", maxMemoryBodyBytes)
	}
	if proxy.MaxSpoolBodyBytes <= 0 || proxy.MaxSpoolBodyBytes > maxSpoolBodyBytes {
		return fmt.Errorf("maxSpoolBodyBytes must be between 1 and %d", maxSpoolBodyBytes)
	}
	if proxy.MaxSpoolBodyBytes < proxy.MaxInMemoryBodyBytes {
		return errors.New("maxSpoolBodyBytes must be at least maxInMemoryBodyBytes")
	}
	return nil
}

func decimalPort(value string) bool {
	if value == "" || len(value) > 5 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validatePolicy(policy Policy) error {
	if policy.Default != PolicyDeny {
		return fmt.Errorf("default must be deny, got %q", policy.Default)
	}
	if len(policy.Rules) > maxRules {
		return fmt.Errorf("rules exceed maximum of %d", maxRules)
	}
	seen := make(map[string]struct{}, len(policy.Rules))
	for i, rule := range policy.Rules {
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		if _, exists := seen[rule.ID]; exists {
			return fmt.Errorf("rule %q is duplicated", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
	return nil
}

func validateRule(rule Rule) error {
	if !ruleIDPattern.MatchString(rule.ID) {
		return errors.New("id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}
	if rule.Effect != EffectAllow && rule.Effect != EffectDeny {
		return fmt.Errorf("effect %q is unsupported; only allow and deny are permitted", rule.Effect)
	}
	if rule.Effect == EffectDeny && rule.AllowAWSRequiredWildcard {
		return errors.New("allowAwsRequiredWildcard is only valid on allow rules")
	}
	if len(rule.Actions) == 0 || len(rule.Actions) > maxRuleList {
		return errors.New("actions must contain between 1 and 1000 entries")
	}
	if len(rule.Resources) == 0 || len(rule.Resources) > maxRuleList {
		return errors.New("resources must contain between 1 and 1000 entries")
	}
	for _, action := range rule.Actions {
		if err := validatePattern(action); err != nil {
			return fmt.Errorf("action: %w", err)
		}
		if action != "*" {
			parts := strings.Split(action, ":")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" || !validActionPart(parts[0]) || !validActionPart(parts[1]) {
				return fmt.Errorf("action %q must use service:operation form", action)
			}
		}
	}
	for _, resource := range rule.Resources {
		if err := validatePattern(resource); err != nil {
			return fmt.Errorf("resource: %w", err)
		}
	}
	if err := validateStringSet(rule.Regions, "region", func(s string) bool { return regionPattern.MatchString(s) }); err != nil {
		return err
	}
	if err := validateStringSet(rule.Accounts, "account", accountPattern.MatchString); err != nil {
		return err
	}
	if err := validateStringSet(rule.Partitions, "partition", supportedPartition); err != nil {
		return err
	}
	return nil
}

func validActionPart(value string) bool {
	// IAM service and operation names are ASCII identifiers. Keeping this
	// grammar deliberately narrower than the rule glob grammar prevents a
	// Unicode lookalike from becoming an action accepted by one package and
	// rejected by another.
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '*' || r == '?') {
			return false
		}
	}
	return true
}

func validatePattern(value string) error {
	if value == "" || len(value) > maxPatternLength {
		return errors.New("pattern is empty or too long")
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("[](){}|+^$\\", r) {
			return fmt.Errorf("pattern %q uses unsupported operator or control syntax", value)
		}
	}
	return nil
}

func validateStringSet(values []string, label string, valid func(string) bool) error {
	if len(values) > maxRuleList {
		return fmt.Errorf("%ss exceed maximum of %d entries", label, maxRuleList)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || !valid(value) {
			return fmt.Errorf("%s %q is invalid", label, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s %q is duplicated", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func supportedPartition(partition string) bool {
	switch partition {
	case "aws", "aws-us-gov", "aws-cn", "aws-iso", "aws-iso-b", "aws-iso-f":
		return true
	default:
		return false
	}
}

func normalizeAndValidateAudit(audit *Audit) error {
	if audit.Path == "" || len(audit.Path) > maxAuditPathLength {
		return errors.New("path is required and must be bounded")
	}
	if audit.Fsync != FsyncBatch && audit.Fsync != FsyncDecision {
		return fmt.Errorf("fsync %q is unsupported; use batch or decision", audit.Fsync)
	}
	if audit.FailureMode != AuditDeny {
		return fmt.Errorf("failureMode %q is unsupported; only deny is permitted", audit.FailureMode)
	}
	if audit.LogResourceARNs && audit.HashResourceNames {
		return errors.New("logResourceArns and hashResourceNames cannot both be enabled")
	}

	expanded, err := expandPath(audit.Path)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(expanded)
	if err != nil {
		return fmt.Errorf("make path absolute: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if unsafeRuntimePath(absolute) {
		return fmt.Errorf("audit path %q is unsafe", absolute)
	}
	resolved, exists, err := resolveTargetOrParent(absolute)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	if unsafeRuntimePath(resolved) {
		return fmt.Errorf("resolved audit path %q is unsafe", resolved)
	}
	if exists {
		info, statErr := os.Stat(resolved)
		if statErr != nil {
			return fmt.Errorf("stat audit path: %w", statErr)
		}
		if !info.Mode().IsRegular() {
			return errors.New("existing audit path must be a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o600 != 0o600 {
			return fmt.Errorf("existing audit file mode %04o is unsafe; expected 0600", info.Mode().Perm())
		}
		if !ownedByCurrentUser(info) {
			return errors.New("existing audit file is not owned by the current user")
		}
	}
	// Do not create audit directories during validation. Inspect only existing
	// ancestors; the runtime writer will create missing components securely.
	if err := validateExistingAncestors(filepath.Dir(resolved)); err != nil {
		return err
	}
	audit.Path = filepath.Clean(resolved)
	return nil
}

// resolveTargetOrParent resolves all existing symlinks and retains missing
// final components. This permits the documented default audit path to be
// validated before its runtime directory exists without following a future
// replacement symlink.
func resolveTargetOrParent(path string) (resolved string, exists bool, err error) {
	if _, statErr := os.Lstat(path); statErr == nil {
		resolved, err = filepath.EvalSymlinks(path)
		return filepath.Clean(resolved), true, err
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", false, statErr
	}

	var suffix []string
	candidate := path
	for {
		if _, statErr := os.Lstat(candidate); statErr == nil {
			resolved, evalErr := filepath.EvalSymlinks(candidate)
			if evalErr != nil {
				return "", false, evalErr
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), false, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", false, statErr
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", false, errors.New("no existing parent for path")
		}
		suffix = append(suffix, filepath.Base(candidate))
		candidate = parent
	}
}

func validateExistingAncestors(path string) error {
	// The writer may create a missing suffix later, but every existing
	// directory it will traverse must already be a private, stable directory.
	// Walk to the nearest existing ancestor first, then inspect it and all of
	// its parents without creating anything.
	current := filepath.Clean(path)
	for {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("audit parent %q is not a directory", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat audit parent %q: %w", current, err)
		}
		next := filepath.Dir(current)
		if next == current {
			return errors.New("path has no existing parent")
		}
		current = next
	}

	for {
		info, err := os.Stat(current)
		if err != nil {
			return fmt.Errorf("stat audit parent %q: %w", current, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("audit parent %q is not a directory", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("audit parent %q is group/world-writable", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func unsafeRuntimePath(path string) bool {
	path = filepath.Clean(path)
	if path == string(filepath.Separator) {
		return true
	}

	// Compare canonical temporary roots as well as the platform's reported
	// TempDir. On macOS /tmp is commonly a symlink, and accepting its spelling
	// would otherwise make the security check dependent on the spelling used
	// by the caller.
	temporaryRoots := []string{filepath.Clean(os.TempDir()), "/tmp"}
	if canonical, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		temporaryRoots = append(temporaryRoots, filepath.Clean(canonical))
	}
	for _, root := range temporaryRoots {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	for _, prefix := range []string{"/dev", "/proc", "/sys"} {
		if path == prefix || strings.HasPrefix(path, prefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// CanonicalPolicy returns deterministic JSON for the typed semantic policy.
// Rules and all list-valued constraints are sets in the policy language; rule
// order and YAML formatting therefore do not affect the policy identity.
func CanonicalPolicy(policy Policy) ([]byte, error) {
	canonical := canonicalPolicy{Default: string(policy.Default), Rules: make([]canonicalRule, 0, len(policy.Rules))}
	for _, rule := range policy.Rules {
		canonical.Rules = append(canonical.Rules, canonicalRule{
			ID:                       rule.ID,
			Effect:                   string(rule.Effect),
			Actions:                  normalizeSet(rule.Actions, true),
			Resources:                normalizeSet(rule.Resources, false),
			Regions:                  normalizeSet(rule.Regions, false),
			Accounts:                 normalizeSet(rule.Accounts, false),
			Partitions:               normalizeSet(rule.Partitions, false),
			AllowAWSRequiredWildcard: rule.AllowAWSRequiredWildcard,
		})
	}
	sort.Slice(canonical.Rules, func(i, j int) bool { return canonical.Rules[i].ID < canonical.Rules[j].ID })
	return json.Marshal(canonical)
}

type canonicalPolicy struct {
	Default string          `json:"default"`
	Rules   []canonicalRule `json:"rules"`
}

type canonicalRule struct {
	ID                       string   `json:"id"`
	Effect                   string   `json:"effect"`
	Actions                  []string `json:"actions"`
	Resources                []string `json:"resources"`
	Regions                  []string `json:"regions"`
	Accounts                 []string `json:"accounts"`
	Partitions               []string `json:"partitions"`
	AllowAWSRequiredWildcard bool     `json:"allowAwsRequiredWildcard"`
}

func normalizeSet(values []string, lower bool) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if lower {
			value = strings.ToLower(value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// PolicyHash returns the stable sha256 identity of a typed semantic policy.
func PolicyHash(policy Policy) (string, error) {
	canonical, err := CanonicalPolicy(policy)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return fmt.Sprintf("sha256:%x", digest[:]), nil
}

// CanonicalPolicyHash is a descriptive alias for PolicyHash.
func CanonicalPolicyHash(policy Policy) (string, error) { return PolicyHash(policy) }
