# Expand Tier 1 AWS Endpoint Coverage Implementation Plan

## Overview

Expand Kordn's positive commercial-partition AWS endpoint boundary by deriving
candidate API and signing identities from every unambiguous service in the
pinned iamlive catalog. The 42 Tier 1 identifiers listed in the backlog are the
required acceptance cohort, not a new runtime allowlist or ceiling.

The classifier will continue to recognize bounded generic commercial AWS
hostname shapes. `internal/awsrequest` remains the positive interception
boundary by validating exact AWS suffixes, commercial Regions, supported shape
profiles, and catalog identity agreement. It will not maintain a separate
per-operation endpoint map or per-service/per-Region endpoint dataset. Static
rules are required only where a family differs from the generic regional shape,
such as global, renamed, multi-label, shared, or account-based endpoints.

Endpoint classification remains an activation boundary, not proof that an
operation is authorizable. A newly classified request must still pass SigV4
authentication, protocol and operation decoding, complete IAM mapping, policy,
audit, and upstream-signing checks. Missing or contradictory evidence remains a
local denial, and non-AWS CONNECT traffic remains byte-opaque.

## Source Spec

- Spec: `docs/backlog.md`, **Current endpoint boundary**, **Tier 1 — highest
  priority**, and **Currently unsupported request paths** under **Add a
  background AWS authorization mode**.
- Supporting contract: `AGENTS.md` and
  `docs/kordn-local-proxy-technical-spec.md`, especially the positive AWS
  interception boundary and fail-closed request pipeline.
- Prior plans:
  `docs/plans/completed/20260830-remove-limited-aws-operation-matrix.md` and
  `docs/plans/completed/20260905-refactor-catalog-backed-iam-mapping.md`.
- Status: Assumed; Tier 1 endpoint expansion is in scope, while background
  process lifecycle work remains separate.
- Last reviewed: 2026-09-19

## Repository Context

- `internal/awsrequest/endpoint.go` — owns `AWSEndpoint`, the positive
  classification algorithm, generic endpoint shapes, commercial Regions,
  hostname normalization, exceptional overrides, and positive/negative caches.
- `internal/awsrequest/endpoint_test.go` — contains current positive, variant,
  lookalike, malformed-host, and cache contracts.
- `internal/awsrequest/types.go` — `VerifiedRequest` already records
  `SigningService` and `SigningRegion`, but `AWSEndpoint.Service` is still used
  as both API-model and signing identity.
- `internal/awsrequest/decode_json.go` — requires the authenticated signing
  service to equal `AWSEndpoint.Service` and uses that same field for catalog
  protocol lookup.
- `internal/sigv4/verify.go` and `internal/sigv4/resign.go` — verify and produce
  SigV4 scopes from `AWSEndpoint.Service`; global signing Regions are maintained
  in a separate table.
- `internal/proxy/server.go` — compares only a subset of endpoint identity after
  authentication and decoding; all new identity fields must remain bound across
  stages.
- `internal/iammap/mapper.go` — reclassifies the decoded host and requires
  endpoint service/partition/Region agreement before catalog lookup.
- `internal/iamlivecatalog/types.go` — preserves API model `EndpointPrefix`,
  `SigningName`, API version, and protocol evidence. The catalog supplies all
  operation mappings; endpoint expansion must not reintroduce per-operation
  tables.
- `internal/iamlivecatalog/upstream/iamlivecore/apis/` — the pinned corpus has
  57 model occurrences for the 42 Tier 1 identifiers. Repeated CloudFront and
  RDS API versions are expected and must remain occurrence-sensitive.
- `test/integration/catalog_operations_test.go` and
  `test/fixtures/sigv4/aws-operation-examples.json` — current vertical
  classifier/authentication/decoder/mapper/policy/upstream fixture path.
- `docs/compatibility.md`, `docs/threat-model.md`, and
  `docs/security-review-checklist.md` — document the positive endpoint boundary
  and fail-closed behavior that this work must preserve.

## Implementation Constraints

- Keep one local Go binary and one `kordn run` process. Do not add a daemon,
  remote control plane, or runtime endpoint-metadata fetch.
- Keep `internal/awsrequest/endpoint.go` and its package as the positive
  interception boundary. The pinned catalog supplies candidate endpoint and
  signing identities; `awsrequest` alone decides whether a concrete normalized
  host satisfies the commercial suffix, Region, shape, and ambiguity rules.
- Use the pinned iamlive catalog as the only API-operation and default service
  identity source. Do not add or maintain per-operation endpoint, protocol,
  action, resource, or service allowlist maps.
- Continue to intercept only catalog-backed commercial `aws` partition
  endpoints on port 443. GovCloud, China, ISO partitions, custom endpoints,
  PrivateLink/VPC endpoints, and service-generated resource/data-plane hosts
  remain unsupported unless explicitly listed by a later plan.
- Treat non-AWS HTTPS CONNECT traffic as byte-opaque end-to-end TLS. Unsupported
  AWS-looking hosts must be rejected rather than tunneled or guessed.
- Match the pinned iamlive model multiset exactly when cross-checking API
  service, signing name, API version, and protocol. Do not collapse repeated
  model versions or shared endpoint families.
- Preserve the current bounded generic commercial hostname profiles for
  standard, FIPS, dual-stack, and `api.aws` regional forms. Extend the matcher
  only enough to support multi-label prefixes and explicit exceptional forms;
  do not replace it with per-service Region/variant inventories.
- Preserve authentication-before-decoding and fail closed on endpoint,
  signing, protocol, operation, resource, dependency, policy, or audit
  disagreement.
- Keep `internal/iamlivecatalog` neutral and free of classification or
  authorization decisions. Keep IAM requirements and fail-closed mapping in
  `internal/iammap`.
- Do not put the per-run CA in the system trust store and do not make non-AWS
  traffic visible to AWS request checks.

## Assumptions

- “Tier 1 coverage” means executable acceptance coverage for all 42 backlog
  identifiers. Runtime classification is not limited to that list: any
  unambiguous pinned catalog service may use the generic commercial profile.
  Incomplete operation mappings and unsupported request forms still deny
  locally.
- Shared endpoint prefixes such as `apigateway`/`apigatewayv2` and
  `elasticloadbalancing`/`elasticloadbalancingv2` are aggregated only when their
  endpoint/signing metadata agrees. Exact wire protocol, target, route, and API
  version evidence selects the model after authentication.
- `AWSEndpoint.Service` will mean the exact API/catalog endpoint prefix.
  `SigningService` and `SigningRegion` will be explicit endpoint fields used by
  SigV4 verification and re-signing. IAM namespaces remain mapper outputs and
  never substitute for either identity.
- Every unambiguous ordinary regional catalog service inherits the existing
  bounded commercial endpoint shape profiles and commercial Region validation.
  Only divergent DNS shapes, global scopes, account labels, or conflicting
  catalog metadata require static overrides or fail-closed exclusions.
- S3 Control account-prefixed endpoints are supported only with an exact
  12-decimal-digit account label retained as typed endpoint evidence and
  checked against decoded account context before authorization.
- `portal.sso` may be positively classified, but unsigned or bearer-only
  operations remain unsupported and fail closed. This plan does not add an
  unsigned authentication bypass.
- Any temporary discovery script or report used to compare the 42 identifiers
  with iamlive is removed before its task completes. Permanent source consists
  only of production family metadata, normal Go tests, and documentation.
- The Tier 1 list is a subsection of the broader background-mode backlog item,
  not a standalone `##` backlog item. Planning must not remove the parent item;
  implementation will replace only the completed Tier 1 subsection with a
  coverage link/status and recompute documented counts.

## Non-goals

- Implementing background `kordn run` lifecycle, detach/attach, startup
  signaling, or process-health behavior.
- Claiming individually verified Tier 2 or Tier 3 compatibility. Ordinary
  catalog services may become generically classifiable, but this plan's named
  acceptance cohort and documentation commitment remain Tier 1.
- Supporting GovCloud, China, ISO, custom, LocalStack, PrivateLink/VPC, or
  arbitrary CNAME endpoints.
- Supporting ECR registries, OpenSearch domains, EKS cluster endpoints,
  RDS/Redshift database endpoints, ELB resource hostnames, EFS mount targets,
  SageMaker runtime variants, or other service-generated data-plane hosts.
- Adding SigV4a, query-presigned requests, streaming SigV4 chunks, signed event
  streams, or unsigned/anonymous AWS operations.
- Treating endpoint classification as evidence that an IAM mapping is complete
  or that policy should allow the request.
- Adding a committed Botocore endpoint dataset, generated endpoint manifest,
  or per-service Region/variant matrix.

## Task Summary

1. Build the catalog-derived endpoint identity index.
2. Separate API endpoint identity from SigV4 signing identity.
3. Extend the generic endpoint matcher for catalog services.
4. Verify ordinary regional Tier 1 coverage.
5. Add and verify shared, global, and account-based exceptions.
6. Prove vertical fail-closed behavior and publish the coverage matrix.

## Implementation Tasks

### Task 1: Build the catalog-derived endpoint identity index

Goal: Compile every unambiguous pinned iamlive service identity into immutable
classifier input without creating a second API-operation dataset or a manual
service allowlist.

Context:
- The pinned catalog supplies endpoint prefix, signing name, API version,
  protocol, operation, route, IAM action, resource, and dependency evidence.
- Repeated API versions and shared endpoint prefixes are expected. They may
  share one classifier identity only when endpoint prefix and effective signing
  name agree; other disagreements must fail closed or use an explicit override.
- Advancing the pinned iamlive revision is already an explicit reviewed source
  change, so ordinary new services should not require a second code-list edit.

Files:
- Create: `internal/awsrequest/endpoint_catalog.go` — immutable catalog-derived
  endpoint identity index plus the small explicit override/exclusion table.
- Modify: `internal/awsrequest/endpoint.go` — construct `Classifier` from the
  loaded catalog index and return an error if catalog identity compilation is
  incomplete or ambiguous.
- Modify: `internal/iamlivecatalog/types.go` — expose signing-name evidence in
  the neutral read-only service view if the existing API cannot provide it
  without copies or package coupling.
- Modify: `internal/awsrequest/endpoint_test.go` — complete catalog compilation,
  collision, ambiguity, and pin-update widening contracts.

Steps:
- [x] Iterate every pinned service-model occurrence and derive its API endpoint
  prefix and effective signing name, preserving repeated versions and aliases
  while avoiding operation-level copies.
- [x] Group models by endpoint prefix only when all signing identity evidence
  agrees; reject empty, malformed, contradictory, or unsupported metadata.
- [x] Keep global scope, account-labelled shapes, and known metadata conflicts
  in a small explicit override/exclusion table owned by `awsrequest`; keep
  ordinary regional services entirely catalog-derived.
- [x] Prove a newly added unambiguous ordinary service in a synthetic catalog
  becomes classifiable without a production code-list change, while an
  ambiguous synthetic service fails classifier construction.
- [x] If a temporary extraction script or report is used during implementation,
  delete it before completing the task; retain only production code and normal
  Go tests.

Verification:
- `./scripts/init-iamlive-submodule.sh --check`
- `go test ./internal/iamlivecatalog -count=1`
- `go test ./internal/awsrequest -run '^TestCatalogEndpointIdentityIndex' -count=1`

Completion criteria:
- Every unambiguous pinned catalog endpoint prefix contributes classifier
  identity without a manual service allowlist or per-operation map.
- Conflicting catalog identity evidence fails closed before the proxy starts.
- A reviewed iamlive pin update can widen ordinary regional service coverage
  without a second source-list update.

### Task 2: Separate API endpoint identity from SigV4 signing identity

Goal: Make endpoint classification carry all identity needed by decoding,
authentication, mapping, and upstream signing without overloading one service
field.

Context:
- Tier 1 includes divergent identities such as `api.ecr`/`ecr`,
  `api.sagemaker`/`sagemaker`, `bedrock-runtime`/`bedrock`,
  `s3-control`/`s3`, `email`/`ses`, and `portal.sso`/`awsssoportal`.
- The current CloudWatch rule stores `cloudwatch` in `AWSEndpoint.Service`, even
  though the pinned model endpoint/signing identity is `monitoring`; IAM action
  prefixes belong to the mapper rather than the endpoint classifier.
- `VerifiedRequest` already exposes the credential-scope service and Region,
  but verification, decoding, re-signing, and proxy stage comparisons derive
  or compare them inconsistently.

Files:
- Modify: `internal/awsrequest/endpoint.go` — add explicit signing identity and
  typed account-host evidence to `AWSEndpoint`; strengthen validation and
  centralize complete identity comparison.
- Modify: `internal/awsrequest/types.go` — validate dotted/hyphenated API
  endpoint prefixes safely and preserve the stronger endpoint identity across
  verified and decoded contracts.
- Modify: `internal/awsrequest/decode_json.go` — compare authenticated signing
  identity with the endpoint's explicit signing fields while using API service
  for protocol and wire-catalog lookup.
- Modify: `internal/sigv4/verify.go` — validate credential scope against
  `SigningService` and `SigningRegion`; remove the independent global signing
  Region table.
- Modify: `internal/sigv4/resign.go` — sign upstream requests with the explicit
  endpoint signing service and Region.
- Modify: `internal/proxy/server.go` — bind the complete endpoint identity after
  classification, authentication, decoding, reclassification, and before
  forwarding.
- Modify: `internal/iammap/mapper.go` — keep API service/partition/Region
  reclassification checks and add typed account-host agreement where present.
- Test: `internal/awsrequest/endpoint_test.go`, `internal/awsrequest/correction_test.go`,
  `internal/awsrequest/account_validation_test.go`,
  `internal/sigv4/sigv4_test.go`, `internal/proxy/pipeline_behavior_test.go`, and
  `internal/iammap/account_context_test.go` — identity disagreement and account
  binding regressions.

Steps:
- [x] Define `AWSEndpoint.Service` as the exact API/catalog endpoint prefix and
  add required `SigningService` and `SigningRegion` fields; retain endpoint
  `Region` as the observed regional host identity and keep it empty for global
  endpoints.
- [x] Add a narrowly validated optional account ID field for approved
  account-labelled host rules; reject empty, non-decimal, non-12-digit, or
  conflicting account evidence.
- [x] Replace permissive service-string checks with bounded DNS-like API service
  validation that accepts reviewed multi-label names but rejects empty labels,
  leading/trailing dots or hyphens, Unicode, and unrelated host content.
- [x] Make SigV4 verification and re-signing consume only explicit signing
  fields; make decoders and mappers consume only API service identity.
- [x] Replace partial struct comparisons with one complete identity comparison
  covering partition, host, API service, endpoint Region/scope, signing
  service/Region, FIPS, dual-stack, and account evidence.
- [x] Correct the existing monitoring family to API/signing service
  `monitoring`; prove that its mapped IAM actions may still use the
  `cloudwatch:` namespace without weakening cross-boundary checks.
- [x] Add failures for every mismatched identity dimension and prove no mismatch
  reaches policy evaluation or upstream forwarding.

Verification:
- `go test ./internal/awsrequest -run 'Test.*(Endpoint|Monitoring|Account|Identity)' -count=1`
- `go test ./internal/sigv4 -run 'Test.*(SigningScope|Resign|Global)' -count=1`
- `go test ./internal/proxy -run 'Test.*(Pipeline|Endpoint|Identity)' -count=1`
- `go test ./internal/iammap -run 'Test.*(Reclassif|Account|Crosscheck)' -count=1`

Completion criteria:
- API-model, signing, endpoint scope, and account identities are explicit and
  cannot be substituted for one another.
- Existing supported requests still verify, decode, map, and re-sign with the
  same or tighter security semantics.
- A deliberately mismatched identity fails before policy and forwarding with a
  stable local reason.

### Task 3: Extend the generic endpoint matcher for catalog services

Goal: Apply bounded commercial hostname profiles to catalog-derived identities
while supporting multi-label and exceptional metadata.

Context:
- `regionalShapes` already recognizes common standard, FIPS, dual-stack, and
  `api.aws` layouts for explicitly catalogued families.
- The full catalog adds multi-label prefixes, regional-looking global services,
  shared model families, and optional account labels that the current
  single-label parser cannot represent.
- The matcher should remain service-generic for ordinary regional catalog
  identities; it must not become a per-operation or per-service/per-Region rule
  database.

Files:
- Modify: `internal/awsrequest/endpoint_catalog.go` — define reusable generic
  shape profiles plus only the metadata needed by exceptional families.
- Modify: `internal/awsrequest/endpoint.go` — retain normalization, AWS-looking
  rejection, commercial Region validation, cache behavior, and classifier
  entry points while supporting multi-label prefixes and bounded account tokens.
- Modify: `internal/awsrequest/endpoint_test.go` — table-driven generic-profile,
  exception, lookalike, malformed-label, and cache tests.
- Test: `internal/proxy/proxy_test.go` — unsupported AWS-looking names reject,
  while non-AWS CONNECT remains opaque.

Steps:
- [x] Preserve reusable regional/global shape profiles rather than enumerating
  API operations, service Regions, or every hostname instance.
- [x] Extend prefix matching from one DNS label to a bounded catalog-validated
  sequence so names such as `api.ecr`, `api.sagemaker`, and `portal.sso` can use
  the same regional profile machinery.
- [x] Add explicit matcher branches only for forms generic profiles cannot
  express safely: regional-looking global endpoints and 12-digit account labels.
- [x] Preserve exact `amazonaws.com` and `api.aws` suffix checks, current
  commercial Region validation, normalized CONNECT/inner-Host agreement, port
  443, positive/negative bounded caches, and rejection of unknown services.
- [x] Keep the existing 16 families on the same profiles unless identity
  separation requires a metadata correction; do not narrow previously accepted
  standard/FIPS/dual-stack forms as part of this plan.
- [x] Add negative cases for unknown service prefixes, extra labels, malformed
  account IDs, unsupported partitions, suffix lookalikes, and invalid ports.

Verification:
- `go test ./internal/awsrequest -run '^TestClassifier' -count=1`
- `go test ./internal/awsrequest -run 'Test.*(Lookalike|Rule|Account)' -count=1`
- `go test ./internal/proxy -run 'Test.*(AWS|Opaque|Host|CONNECT)' -count=1`

Completion criteria:
- Every unambiguous ordinary regional catalog identity inherits bounded generic
  commercial shapes without operation or per-Region enumeration.
- Exceptional forms produce complete endpoint and signing metadata through
  explicit small rules.
- Hosts absent from the pinned catalog, unsupported partitions, malformed
  exceptions, and suffix lookalikes remain unclassifiable.

### Task 4: Verify ordinary regional Tier 1 coverage

Goal: Prove that the catalog-derived generic classifier covers every ordinary
regional Tier 1 identifier without adding production family or Region maps.

Context:
- This batch covers: `acm`, `athena`, `autoscaling`, `backup`, `bedrock`,
  `cloudtrail`, `cognito-identity`, `cognito-idp`, `config`, `ebs`, `eks`,
  `elasticache`, `elasticfilesystem`, `elasticmapreduce`, `firehose`, `glue`,
  `guardduty`, `kinesis`, `rds`, `redshift`, `secretsmanager`, `ssm`, `states`,
  `wafv2`, and `xray`.
- RDS has repeated model versions in the pinned catalog; endpoint activation
  must not collapse catalog lookup across wire API versions.

Files:
- Modify: `internal/awsrequest/endpoint_test.go` — add a test-only Tier 1
  acceptance cohort and generated standard-host checks against the derived
  catalog index.
- Modify: `internal/awsrequest/wire_index_test.go` — prove repeated model
  versions remain exact wire-version matches after endpoint expansion.

Steps:
- [x] Keep the 25 ordinary Tier 1 identifiers only in the test acceptance
  cohort; do not add corresponding production family entries.
- [x] Generate each standard regional host from its catalog endpoint prefix and
  prove it classifies with the catalog's effective signing identity.
- [x] Add representative FIPS/dual-stack profile tests across the cohort; avoid
  duplicating every generic shape for every service.
- [x] Prove each classified API service resolves to the pinned authoritative
  protocol and that exact wire API version remains required for Query and JSON
  operation lookup.
- [x] Assert that endpoint success alone does not bypass absent, ambiguous, or
  incomplete IAM mapping evidence.

Verification:
- `go test ./internal/awsrequest -run 'TestTier1Ordinary|TestWireIndex' -count=1`
- `go test ./internal/iammap -run 'Test.*(Unknown|Ambiguous|NoScopeWidening)' -count=1`

Completion criteria:
- All 25 ordinary regional identifiers classify from catalog-derived identity
  through shared generic endpoint profiles.
- No production service allowlist, per-operation map, or per-service/per-Region
  endpoint map is introduced.
- Exact protocol/version matching and fail-closed mapping behavior remain
  unchanged.

### Task 5: Verify shared identities and add exceptional shape overrides

Goal: Verify the remaining 17 Tier 1 identifiers through catalog-derived
identity, adding static metadata only for global or account-based hostname
shapes that the catalog and generic regional profile cannot express.

Context:
- Shared endpoint families:
  `apigateway`/`apigatewayv2` and
  `elasticloadbalancing`/`elasticloadbalancingv2`.
- Renamed or signing-divergent identities: `accessanalyzer`
  (`access-analyzer`), `bedrock-runtime` (`bedrock` signing), `ecr`
  (`api.ecr`/`ecr`), `opensearch` (`es`), `s3control`
  (`s3-control`/`s3`), `sagemaker` (`api.sagemaker`/`sagemaker`),
  `service-quotas` (`servicequotas`), `sesv2` (`email`/`ses`), `sso`
  (`portal.sso`/`awsssoportal`), and `sso-admin` (`sso`).
- Global or regional-looking-global identities: `budgets`, `ce`, and
  `cloudfront`, with reviewed signing Regions rather than inferred host Regions.

Files:
- Modify: `internal/awsrequest/endpoint_catalog.go` — add only global,
  regional-looking-global, account-labelled, and conflict-resolution overrides.
- Modify: `internal/awsrequest/endpoint_test.go` — add shared-prefix,
  signing-divergence, multi-label, and exceptional-shape cases.
- Modify: `internal/awsrequest/account_validation_test.go` — add S3 Control
  account-label and mismatch cases.
- Modify: `internal/sigv4/sigv4_test.go` — cover signing-service divergence and
  global signing Regions.
- Modify: `internal/iammap/account_context_test.go` — bind approved S3 Control
  host account evidence to decoded/mapped resource context.

Steps:
- [x] Aggregate shared endpoint prefixes from catalog evidence without guessing
  an API model from hostname alone; decoder wire version/target evidence must
  continue to select the exact model.
- [x] Verify that multi-label, renamed, and signing-divergent services use the
  generic matcher directly from catalog identity without static family entries.
- [x] Add `budgets`, `ce`, and `cloudfront` overrides with explicit global scope
  and signing Region, including the regional-looking `ce` hostname.
- [x] Add bounded S3 Control account-prefixed matching, retain the 12-digit
  account as endpoint evidence, and deny account disagreement before policy.
- [x] Classify reviewed SSO portal endpoints while retaining mandatory SigV4
  and local denial for unsigned/bearer-only operations.
- [x] Add negatives for equivalent-looking unknown spellings, arbitrary
  subdomains, malformed account labels, service-generated hosts, and unsupported
  partitions.

Verification:
- `go test ./internal/awsrequest -run 'TestTier1Exceptional|Test.*Account' -count=1`
- `go test ./internal/sigv4 -run 'Test.*(SigningService|SigningRegion|Global)' -count=1`
- `go test ./internal/iammap -run 'Test.*Account' -count=1`

Completion criteria:
- All 17 identifiers have explicit acceptance coverage without production
  service entries or per-operation mapping except the minimum shape overrides.
- Signing-divergent, global, and account-labelled requests remain bound across
  classification, authentication, decoding, mapping, and re-signing.
- Unsupported unsigned and service-generated request paths still fail closed.

### Task 6: Prove vertical fail-closed behavior and publish the coverage matrix

Goal: Demonstrate that representative Tier 1 requests traverse the real proxy
pipeline safely and document family-level endpoint coverage without overstating
operation support.

Context:
- Existing catalog integration fixtures cover only IAM, S3, Lambda, and
  DynamoDB.
- Tier 1 spans Query, JSON, REST-JSON, and REST-XML plus shared families,
  multi-label identities, global signing scopes, and account-labelled hosts.
- Endpoint classification and operation authorization are separate dimensions
  and must be reported separately.

Files:
- Modify: `test/fixtures/sigv4/aws-operation-examples.json` — add attributed
  representative Tier 1 canonical request metadata with separate API and
  signing service fields.
- Modify: `test/fixtures/sigv4/README.md` — document provenance and fixture
  refresh rules.
- Modify: `test/integration/catalog_operations_test.go` — add representative
  production-pipeline requests and expected allow or stable fail-closed results.
- Modify: `internal/proxy/proxy_test.go` — add real-proxy opaque non-AWS,
  unsupported AWS-looking, host mismatch, and no-upstream-on-denial cases.
- Create: `docs/aws-endpoint-coverage.md` — document the generic
  catalog-derived classifier contract plus a Tier 1 acceptance matrix of model
  identifier, API service, signing service/Region, protocol, endpoint status,
  mapping limitations, and excluded data-plane forms.
- Modify: `docs/architecture.md` — document endpoint/API/signing/IAM identity
  separation and the catalog-derived positive-classification boundary.
- Modify: `docs/compatibility.md` — link the matrix and clarify that producer
  compatibility remains the intersection of endpoint, authentication, decoder,
  mapping, and request-form support.
- Modify: `docs/threat-model.md` — cover pin-update widening, generic-shape
  misuse, catalog ambiguity, account-label spoofing, and unsupported
  AWS-looking rejection.
- Modify: `docs/security-review-checklist.md` — strengthen the existing S20-08
  concrete checks without changing stable checklist counts unnecessarily.
- Modify: `docs/backlog.md` — replace only the completed Tier 1 subsection with
  a link/status, retain the background-mode item and Tier 2/Tier 3 verification
  lists, and distinguish generic catalog-derived classification from explicitly
  tested compatibility counts.

Steps:
- [x] Add representative vertical cases for Query, JSON, REST-JSON, and
  REST-XML; include at least one shared family, multi-label/signing-divergent
  family, global family, and S3 Control account-labelled family.
- [x] Separate fixture `api_service`, `signing_service`, endpoint Region, and
  signing Region fields so tests cannot reintroduce identity conflation.
- [x] For complete catalog evidence, prove an allowed request is re-signed with
  the reviewed signing identity and reaches fake AWS; for incomplete or
  unsupported evidence, prove a stable local denial and an empty upstream
  ledger.
- [x] Retain adversarial tests proving non-AWS CONNECT remains byte-opaque and
  unsupported AWS-looking hosts are rejected rather than tunneled or
  intercepted.
- [x] Validate that the family-level documentation covers all 42 identifiers
  while operation support continues to come from the pinned iamlive catalog.
- [x] Update only Tier 1 backlog status after all executable coverage passes;
  do not remove or mark the broader background authorization mode complete.

Verification:
- `go test ./test/integration -run '^TestCatalogOperations$|^TestSecurityAdversarialProxyBoundary$' -count=1`
- `go test -race ./internal/awsrequest ./internal/sigv4 ./internal/proxy ./internal/iammap`
- `make test-integration`
- `make test-compatibility`
- `make security-check`

Completion criteria:
- Representative Tier 1 requests prove correct endpoint, signing, protocol,
  mapping, policy, denial, audit, and upstream behavior through the production
  pipeline.
- No denied or identity-mismatched request reaches fake AWS.
- The published matrix distinguishes endpoint classification from operational
  request support and accounts for all 42 Tier 1 identifiers.
- The backlog reflects completed Tier 1 endpoint work without deleting the
  unfinished background-mode requirements.

## Cross-Task Verification

- `./scripts/init-iamlive-submodule.sh --check`
- `go test ./internal/awsrequest ./internal/sigv4 ./internal/proxy ./internal/iammap -count=1`
- `go test -race ./internal/awsrequest ./internal/sigv4 ./internal/proxy ./internal/iammap`
- `make fmt-check`
- `make test-race`
- `make test-integration`
- `make test-compatibility`
- `make security-check`
- Manual review: confirm generic shapes require an unambiguous pinned catalog
  identity, exceptions remain explicit, and no unsupported partition, custom,
  VPC, or service-generated hostname became classifiable.

## Risks and Mitigations

- Risk: Generic profiles classify an AWS-owned hostname shape that a catalog
  service does not currently publish.
  Mitigation: generic matching requires an unambiguous pinned catalog identity,
  exact AWS suffixes, bounded commercial Regions, and known shape profiles;
  authentication, operation lookup, mapping, and upstream TLS still fail closed.
- Risk: API service, signing service, and IAM namespace remain conflated.
  Mitigation: represent them in separate typed fields, compare complete
  identity at every pipeline boundary, and test known divergent families plus
  the existing monitoring correction.
- Risk: A future iamlive update widens ordinary regional classification.
  Mitigation: pin updates are explicit reviewed gitlink/hash changes; classifier
  construction rejects malformed or contradictory identities, and pin-diff
  tests report added, removed, and changed endpoint/signing groups.
- Risk: Shared endpoint families select the wrong API model or repeated model
  version.
  Mitigation: preserve all occurrences and require exact protocol, target,
  action, route, and wire API version evidence after authentication.
- Risk: S3 Control account hostnames permit tenant confusion.
  Mitigation: accept only exact 12-digit account labels and require endpoint,
  decoded request, mapper, and resource account agreement before policy.
- Risk: Classifying SSO creates an expectation that unsigned portal operations
  work.
  Mitigation: document endpoint-only support and retain mandatory SigV4; no
  unsigned bypass is introduced.
- Risk: Endpoint expansion is mistaken for complete IAM operation coverage.
  Mitigation: keep operation mapping catalog-backed, publish separate endpoint
  and mapping-status columns, and retain empty-upstream denial tests for
  incomplete mappings.

## Open Questions

- None. Ordinary services derive identity from the pinned catalog and use the
  existing generic commercial profiles; only ambiguous identity and
  hostname-shape exceptions require explicit metadata.
