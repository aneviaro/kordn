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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Load reads, strictly decodes, normalizes, and validates one configuration
// document. It performs filesystem inspection only; credential, network,
// listener, audit-file creation, and child-process side effects are outside
// this package.
func Load(path string) (*Config, error) {
	canonical, err := canonicalExistingPath(path)
	if err != nil {
		return nil, fmt.Errorf("config path: %w", err)
	}
	if err := validateOwnedMode(canonical); err != nil {
		return nil, fmt.Errorf("config path: %w", err)
	}
	data, err := os.ReadFile(canonical)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	root, err := decodeRoot(data)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("decode config: root must be a mapping")
	}
	if err := rejectNullNodes(root); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config fields: %w", err)
	}
	// decodeRoot checks this too. Keeping the typed decoder check makes the
	// one-document contract explicit if yaml.v3 changes its behavior.
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("decode config: multiple YAML documents are not supported")
		}
		return nil, fmt.Errorf("decode config: trailing document: %w", err)
	}

	applyDefaults(&cfg, root)
	cfg.SourcePath = canonical
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.PolicyHash, err = PolicyHash(cfg.Policy)
	if err != nil {
		return nil, fmt.Errorf("policy hash: %w", err)
	}
	return &cfg, nil
}

// LoadFile is an explicit file-oriented alias for Load.
func LoadFile(path string) (*Config, error) { return Load(path) }

func decodeRoot(data []byte) (yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return yaml.Node{}, err
	}
	if document.Kind == 0 {
		return yaml.Node{}, errors.New("empty YAML document")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return yaml.Node{}, errors.New("multiple YAML documents are not supported")
		}
		return yaml.Node{}, fmt.Errorf("trailing YAML document: %w", err)
	}
	if document.Kind == yaml.DocumentNode {
		if len(document.Content) != 1 {
			return yaml.Node{}, errors.New("invalid YAML document")
		}
		return *document.Content[0], nil
	}
	return document, nil
}

// rejectNullNodes avoids yaml.v3's useful-but-permissive behavior of turning
// null into a Go zero value. The public document has no nullable fields; an
// explicit empty value must be represented by an empty string or list where
// the semantic validator can reject it as appropriate.
func rejectNullNodes(node yaml.Node) error {
	if node.Tag == "!!null" {
		return errors.New("null values are not supported")
	}
	if node.Kind == yaml.AliasNode {
		return errors.New("YAML aliases are not supported")
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Value == "<<" {
				return errors.New("YAML merge keys are not supported")
			}
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return errors.New("mapping keys must be strings")
			}
		}
	}
	for _, child := range node.Content {
		if err := rejectNullNodes(*child); err != nil {
			return err
		}
	}
	return nil
}

func applyDefaults(cfg *Config, root yaml.Node) {
	if !hasField(root, "upstream", "roleSessionName") {
		cfg.Upstream.RoleSessionName = DefaultRoleSessionName
	}
	if !hasField(root, "upstream", "durationSeconds") {
		cfg.Upstream.DurationSeconds = DefaultRoleDurationSeconds
	}
	if !hasField(root, "proxy", "listen") {
		cfg.Proxy.Listen = DefaultListen
	}
	if !hasField(root, "proxy", "nonAwsTraffic") {
		cfg.Proxy.NonAWSTraffic = DefaultNonAWSTraffic
	}
	if !hasField(root, "proxy", "upstreamProxy") {
		cfg.Proxy.UpstreamProxy = DefaultUpstreamProxy
	}
	if !hasField(root, "proxy", "maxInMemoryBodyBytes") {
		cfg.Proxy.MaxInMemoryBodyBytes = DefaultMaxInMemoryBodyBytes
	}
	if !hasField(root, "proxy", "maxSpoolBodyBytes") {
		cfg.Proxy.MaxSpoolBodyBytes = DefaultMaxSpoolBodyBytes
	}
	if !hasField(root, "policy", "default") {
		cfg.Policy.Default = PolicyDeny
	}
	if !hasField(root, "audit", "path") {
		cfg.Audit.Path = DefaultAuditPath
	}
	if !hasField(root, "audit", "fsync") {
		cfg.Audit.Fsync = FsyncBatch
	}
	if !hasField(root, "audit", "failureMode") {
		cfg.Audit.FailureMode = AuditDeny
	}
	if !hasField(root, "audit", "logResourceArns") {
		cfg.Audit.LogResourceARNs = DefaultAuditLogResourceARNs
	}
	if !hasField(root, "audit", "hashResourceNames") {
		cfg.Audit.HashResourceNames = DefaultAuditHashResourceNames
	}
}

func hasField(root yaml.Node, path ...string) bool {
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = *root.Content[0]
	}
	for _, name := range path {
		if root.Kind != yaml.MappingNode {
			return false
		}
		var next *yaml.Node
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == name {
				next = root.Content[i+1]
				break
			}
		}
		if next == nil {
			return false
		}
		root = *next
	}
	return true
}

func canonicalExistingPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is empty")
	}
	expanded, err := expandPath(path)
	if err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(expanded)
	if err != nil {
		return "", fmt.Errorf("make path absolute: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return filepath.Clean(resolved), nil
}

// expandPath expands only a leading home marker. Environment variables,
// command substitution, and arbitrary user-name expansion are deliberately
// rejected for security-sensitive startup paths.
func expandPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is empty")
	}
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	if strings.HasPrefix(path, "~") {
		return "", errors.New("only the current user's home marker is supported")
	}
	if strings.HasPrefix(path, "$") || strings.Contains(path, "${") {
		return "", errors.New("environment-variable path expansion is not supported")
	}
	return filepath.Clean(path), nil
}

func validateOwnedMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("group/world-writable mode %04o is unsafe", info.Mode().Perm())
	}
	if !ownedByCurrentUser(info) {
		return errors.New("is not owned by the current user")
	}
	return nil
}

// ownedByCurrentUser uses the numeric UID exposed by the native stat
// structure. Falling back to a named owner is supported on platforms whose
// FileInfo does not expose a UID, but an unavailable owner is never trusted.
func ownedByCurrentUser(info os.FileInfo) bool {
	if info == nil || info.Sys() == nil {
		return false
	}
	current, err := user.Current()
	if err != nil {
		return false
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return false
	}
	uid := value.FieldByName("Uid")
	if uid.IsValid() {
		switch {
		case uid.Kind() >= reflect.Uint && uid.Kind() <= reflect.Uint64:
			return strconv.FormatUint(uid.Uint(), 10) == current.Uid
		case uid.Kind() >= reflect.Int && uid.Kind() <= reflect.Int64:
			return strconv.FormatInt(uid.Int(), 10) == current.Uid
		}
	}
	owner := value.FieldByName("Owner")
	return owner.IsValid() && owner.Kind() == reflect.String && owner.String() == current.Username
}
