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

// Package awserror owns stable local failure reasons. Human-readable error
// messages are not compatibility or policy contracts.
package awserror

// ReasonCode is a closed set of machine-readable local outcomes.
type ReasonCode string

const (
	ReasonExplicitDeny                   ReasonCode = "explicit_deny"
	ReasonPolicyNoMatchingAllow          ReasonCode = "policy_no_matching_allow"
	ReasonAWSRequiredWildcardNotApproved ReasonCode = "aws_required_wildcard_not_approved"
	ReasonUnknownEndpoint                ReasonCode = "unknown_endpoint"
	ReasonUnsupportedPartition           ReasonCode = "unsupported_partition"
	ReasonUnknownOperation               ReasonCode = "unknown_operation"
	ReasonMappingLowConfidence           ReasonCode = "mapping_low_confidence"
	ReasonResourceUnresolved             ReasonCode = "resource_unresolved"
	ReasonDependentPermissionUnresolved  ReasonCode = "dependent_permission_unresolved"
	ReasonInvalidInboundSignature        ReasonCode = "invalid_inbound_signature"
	ReasonUnsupportedSigningScheme       ReasonCode = "unsupported_signing_scheme"
	ReasonUnsupportedPayloadMode         ReasonCode = "unsupported_payload_mode"
	ReasonRequestTooLarge                ReasonCode = "request_too_large"
	ReasonAuditUnavailable               ReasonCode = "audit_unavailable"
	ReasonUpstreamCredentialUnavailable  ReasonCode = "upstream_credential_unavailable"
	ReasonUpstreamTransportError         ReasonCode = "upstream_transport_error"
	ReasonInternalFailClosed             ReasonCode = "internal_fail_closed"
	ReasonAllRequirementsAllowed         ReasonCode = "all_requirements_allowed"

	// Short aliases keep call sites readable while all values remain members
	// of this single closed type.
	ExplicitDeny                   = ReasonExplicitDeny
	PolicyNoMatchingAllow          = ReasonPolicyNoMatchingAllow
	AWSRequiredWildcardNotApproved = ReasonAWSRequiredWildcardNotApproved
	UnknownEndpoint                = ReasonUnknownEndpoint
	UnsupportedPartition           = ReasonUnsupportedPartition
	UnknownOperation               = ReasonUnknownOperation
	MappingLowConfidence           = ReasonMappingLowConfidence
	ResourceUnresolved             = ReasonResourceUnresolved
	DependentPermissionUnresolved  = ReasonDependentPermissionUnresolved
	InvalidInboundSignature        = ReasonInvalidInboundSignature
	UnsupportedSigningScheme       = ReasonUnsupportedSigningScheme
	UnsupportedPayloadMode         = ReasonUnsupportedPayloadMode
	RequestTooLarge                = ReasonRequestTooLarge
	AuditUnavailable               = ReasonAuditUnavailable
	UpstreamCredentialUnavailable  = ReasonUpstreamCredentialUnavailable
	UpstreamTransportError         = ReasonUpstreamTransportError
	InternalFailClosed             = ReasonInternalFailClosed
	AllRequirementsAllowed         = ReasonAllRequirementsAllowed
)

var allReasonCodes = [...]ReasonCode{
	ReasonExplicitDeny,
	ReasonPolicyNoMatchingAllow,
	ReasonAWSRequiredWildcardNotApproved,
	ReasonUnknownEndpoint,
	ReasonUnsupportedPartition,
	ReasonUnknownOperation,
	ReasonMappingLowConfidence,
	ReasonResourceUnresolved,
	ReasonDependentPermissionUnresolved,
	ReasonInvalidInboundSignature,
	ReasonUnsupportedSigningScheme,
	ReasonUnsupportedPayloadMode,
	ReasonRequestTooLarge,
	ReasonAuditUnavailable,
	ReasonUpstreamCredentialUnavailable,
	ReasonUpstreamTransportError,
	ReasonInternalFailClosed,
	ReasonAllRequirementsAllowed,
}

// AllReasonCodes is the complete stable set used by schemas and audit code.
// Callers should treat it as read-only.
var AllReasonCodes = append([]ReasonCode(nil), allReasonCodes[:]...)

func (r ReasonCode) Valid() bool {
	for _, candidate := range allReasonCodes {
		if r == candidate {
			return true
		}
	}
	return false
}
