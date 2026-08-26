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

// Package awsrequest owns the endpoint, protocol, decoded-request, and mapper
// contracts shared by the proxy, mapper, and policy packages.
package awsrequest

import (
	"errors"
	"fmt"
	"strings"
)

// EndpointScope distinguishes a regional endpoint from a modeled AWS global
// endpoint. A global endpoint may still have a signing Region in the decoded
// request; endpoint scope and signing scope are intentionally separate.
type EndpointScope string

const (
	ScopeRegional EndpointScope = "regional"
	ScopeGlobal   EndpointScope = "global"
)

// AWSEndpoint is a positive endpoint classification. Host is the exact,
// normalized DNS host used for CONNECT and inner-Host agreement checks; it is
// not a suffix or a user-provided display label.
type AWSEndpoint struct {
	Partition string        `json:"partition"`
	Host      string        `json:"host"`
	Service   string        `json:"service"`
	Region    string        `json:"region"`
	Global    bool          `json:"global"`
	Scope     EndpointScope `json:"scope,omitempty"`
}

func (e AWSEndpoint) IsGlobal() bool { return e.Global || e.Scope == ScopeGlobal }

func (e AWSEndpoint) EffectiveScope() EndpointScope {
	if e.IsGlobal() {
		return ScopeGlobal
	}
	return ScopeRegional
}

// Validate checks the shape of a classifier result. Supported service and
// partition catalogs remain the classifier's responsibility, so this method
// does not perform network or metadata lookups.
func (e AWSEndpoint) Validate() error {
	if strings.TrimSpace(e.Partition) == "" {
		return errors.New("endpoint partition is required")
	}
	if strings.TrimSpace(e.Host) == "" {
		return errors.New("endpoint host is required")
	}
	if len(e.Host) > 253 || e.Host != strings.ToLower(e.Host) || strings.HasSuffix(e.Host, ".") {
		return errors.New("endpoint host must be normalized to lowercase without a trailing dot")
	}
	if strings.ContainsAny(e.Host, " \t\r\n:/") {
		return errors.New("endpoint host must be a normalized DNS host without a port")
	}
	for _, label := range strings.Split(e.Host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("endpoint host contains an invalid DNS label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return errors.New("endpoint host contains a non-ASCII DNS label")
			}
		}
	}
	if strings.TrimSpace(e.Service) == "" {
		return errors.New("endpoint service is required")
	}
	if e.Scope != "" && e.Scope != ScopeRegional && e.Scope != ScopeGlobal {
		return fmt.Errorf("unsupported endpoint scope %q", e.Scope)
	}
	if e.Scope == ScopeRegional && e.Global {
		return errors.New("regional endpoint scope conflicts with global endpoint")
	}
	if !e.IsGlobal() && strings.TrimSpace(e.Region) == "" {
		return errors.New("regional endpoint Region is required")
	}
	return nil
}

// EndpointClassifier positively classifies a normalized host. Unknown,
// custom, and unsupported-partition hosts must be returned as errors; there is
// no permissive fallback endpoint.
type EndpointClassifier interface {
	Classify(host string) (AWSEndpoint, error)
}
