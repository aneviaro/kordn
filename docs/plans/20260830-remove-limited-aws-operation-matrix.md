# Remove the Limited AWS Operation Matrix Implementation Plan

## Overview

Replace Kordn's hand-maintained operation allowlists and 28-entry IAM mapping subset with a read-only catalog built directly from a pinned `iamlive` git submodule. Kordn will embed iamlive's complete `map.json`, `iam_definition.json`, and AWS API models into the standalone binary without committing copied or generated AWS API datasets. Runtime support will be verified across varied Query, EC2 Query, JSON, REST-JSON, and REST-XML operations. The source-spec `iam / ListUsers` case will map to `iam:ListUsers` with `known_global` scope, and local denials will preserve protocol and safe operation evidence in audit.

The implementation keeps Kordn's existing security boundary: endpoint classification remains a reviewed positive catalog, inbound SigV4 verification precedes operation use, incomplete mappings remain unforwardable, and non-AWS CONNECT traffic remains byte-opaque.

## Source Spec

- Spec: `docs/backlog.md`, first item: **Remove the intentionally limited AWS operation matrix**
- Supporting contract: `docs/kordn-local-proxy-technical-spec.md`, Sections 11.2-11.7 and 15.2-15.3
- Status: Assumed; the acceptance criteria are treated as normative
- Last reviewed: 2026-08-30

## Repository Context

- `internal/awsrequest/decode_json.go` — owns protocol authority, JSON targets, the final operation check, and the current `modelOperations` and `targetModels` hand-maintained maps.
- `internal/awsrequest/decode_query.go` — parses IAM/STS/EC2 Query requests and currently rejects `ListUsers` through `operationKnown` before mapping or policy evaluation.
- `internal/awsrequest/decode_restjson.go` and `internal/awsrequest/decode_restxml.go` — contain closed hand-authored method/path routing for Lambda and S3; the upstream API catalog must retain exact URI-template and query-discriminator matching.
- `internal/awsrequest/endpoint.go` — positively classifies 16 reviewed commercial-partition service identities. This catalog remains the interception activation boundary even when the submodule describes more services.
- `internal/iammap/data/generate.go` — current offline generator for a nine-service copied snapshot; it and the copied JSON artifacts will be removed.
- `internal/iammap/data/version.go` — currently embeds copied SAR/generated data and a widening baseline; it will become a validator/version facade over the submodule-backed catalog.
- `third_party/iamlive/source/mapper.go` — current copied 28-operation derived table; it will be removed when the submodule-backed catalog is active.
- `internal/iammap/iamliveadapter/adapter.go` — guarded mapping boundary that will consume the neutral submodule-backed catalog while keeping Kordn authorization and fail-closed decisions outside upstream code.
- `internal/iammap/mapper.go`, `resources.go`, and `dependencies.go` — enforce independent endpoint/protocol/action/resource/dependency agreement, but currently require exactly one primary action and only model `iam:PassRole` dependencies.
- `internal/proxy/server.go` — authenticates before decode, but `finishFailedPipeline` discards validated state and uses JSON 1.1 plus `Unknown` for every failed stage.
- `internal/awserror/xml.go` — already emits valid AWS Query XML when the caller supplies `ProtocolQuery`; the missing behavior is evidence propagation, not a new XML encoder.
- `internal/iammap/golden_wire_test.go` — current production decoder-to-mapper golden suite and the natural focused regression location for `ListUsers`.
- `test/fixtures/sigv4/iam-list-users.json` — checked-in AWS canonical request fixture that is not yet exercised by the production pipeline.
- `Makefile` and `.github/workflows/ci.yml` — hermetic build/security gates; they do not initialize or validate a submodule today. Implementation must preserve any concurrent local edits.
- `docs/decisions/0001-iamlive-integration.md` — requires attribution and keeps Kordn authorization/fail-closed logic outside the derived adapter.

## Implementation Constraints

- Keep one local Go binary and one `kordn run` process. Add neither a daemon nor a network control plane.
- Keep non-AWS HTTPS CONNECT byte-opaque. Do not broaden interception or install the run CA in a system trust store.
- Pin `github.com/iann0036/iamlive` as a git submodule at the existing reviewed `v1.1.28` commit `3ec1a40e560c2f00ec82c50223add810e2567efb`; Kordn stores only the gitlink, pin/provenance, and its own parser—not copied AWS API data.
- Sparse-checkout only iamlive's license/notice, `iamlivecore/map.json`, `iamlivecore/iam_definition.json`, and `iamlivecore/apis/`. Exclude the nested upstream `go.mod`, because Go refuses to embed files from another module.
- Embed the selected submodule files into the release binary. Runtime metadata fetches and filesystem dependencies are forbidden.
- Keep `internal/awsrequest/endpoint.go` as the positive endpoint activation boundary. A catalogued service must not turn an AWS-looking hostname into an intercepted endpoint.
- Treat “complete” as every service and modeled API operation present in the pinned iamlive files, not only services currently in `commercialEndpointCatalog`. Runtime interception remains the intersection with the independently reviewed positive endpoint catalog.
- Preserve the existing endpoint, CONNECT/Host, signing service/Region, signing scheme, payload mode, body/path/token, content-type, protocol-authority, and cross-protocol disagreement checks.
- Preserve `exact`, `set`, `known_global`, and `unresolved` as distinct scope kinds. Missing or ambiguous resource/dependency extraction must remain `unresolved` and must never be converted to `*`.
- Support multiple primary and dependent IAM requirements as a conjunction. Do not require the IAM action prefix to equal the endpoint service when the pinned catalog authoritatively describes a cross-service requirement.
- Keep Kordn authentication, resource validation, authorization, and fail-closed decisions outside the neutral catalog parser and iamlive submodule.
- Preserve exact submodule commit, file hashes, licenses, notices, and source provenance. After one explicit submodule initialization step, normal build/check paths must remain offline under `GOPROXY=off` and `GOSUMDB=off`.
- Preserve authenticated evidence ordering: an operation value may influence mapping, audit, or a denial only after inbound signature verification and protocol/service consistency checks.
- Preserve all pre-existing and concurrent local changes.

## Assumptions

- Complete catalog coverage does not automatically make every operation forwardable. An operation with incomplete, contradictory, or non-concrete resource/dependency evidence is recognized but rejected by the mapper before policy evaluation or forwarding.
- Adding a catalogued service to interception still requires a separate reviewed `commercialEndpointCatalog` entry, endpoint shapes, protocol support, and fixtures.
- `iamlivecore/map.json` supplies call-to-action/resource/dependency templates, `iamlivecore/iam_definition.json` supplies action/resource definitions derived from AWS SAR, and `iamlivecore/apis/` supplies protocol/operation/route models.
- Representative verification uses varied operations rather than treating one operation as proof of completeness.
- Policy action syntax and glob validation remain catalog-independent. No policy schema change is needed; the existing known-global wildcard acknowledgement continues to apply to allows.
- Updating metadata means explicitly advancing the gitlink and pin, reviewing the upstream diff/provenance, and rerunning behavior contracts. Kordn has no source updater and no copied widening-baseline dataset.

## Non-goals

- Expanding AWS endpoint interception beyond the current positive commercial-partition catalog.
- Supporting GovCloud, China, ISO partitions, custom endpoints, SigV4a, presigned requests, streaming signatures, or signed event streams.
- Guaranteeing that every catalogued operation can be allowed immediately; unresolved mappings remain safe local denials.
- Supporting a source build from a GitHub-generated archive or uninitialized clone. Source builders must clone/init the pinned submodule; published binaries remain standalone.
- Implementing the later `backlog.md` items for startup diagnostics, allow-by-default policies, or agent policy-control skills.
- Adding runtime network metadata refresh, policy hot reload, or a remote authorization service.
- Replacing Kordn's policy engine or weakening known-global wildcard acknowledgement.

## Task Summary

1. Integrate the pinned iamlive submodule catalog.
2. Decode operations from the submodule-backed wire catalog.
3. Map complete IAM requirements through the guarded adapter.
4. Preserve protocol and operation evidence in local failures.
5. Add varied vertical operation and fail-closed acceptance coverage.
6. Lock the submodule integration with contracts, versioning, CI, and documentation.

## Implementation Tasks

### Task 1: Integrate the pinned iamlive submodule catalog

Goal: Replace copied operation/SAR datasets and per-operation Go tables with an immutable catalog parsed directly from selected files in the pinned iamlive submodule.

Context:
- `source/operation-model.json`, `modelOperations`, and `third_party/iamlive/source/mapper.go::operationActions` duplicate the same 28-operation subset.
- iamlive `v1.1.28` already contains the required complete inputs: `map.json`, `iam_definition.json`, and API models. Kordn should reference that upstream commit rather than maintain copies.
- A normal Go import does not expose the needed catalog: current iamlive exports its runner/global policy surface, while request-to-action functions and embedded bytes are package-private. The neutral Kordn parser therefore reads the pinned submodule files directly.
- The submodule has its own `go.mod`; Go rejects `//go:embed` across that nested module boundary. A deterministic sparse checkout must omit the upstream `go.mod` while retaining only the selected data/license paths.
- The neutral catalog must parse and index data only. Kordn's adapter/mapper remains responsible for certainty, ARN validation, policy requirements, and fail-closed outcomes.

Files:
- Create: `.gitmodules` — register `github.com/iann0036/iamlive` at `internal/iamlivecatalog/upstream`.
- Add submodule gitlink: `internal/iamlivecatalog/upstream` — pin commit `3ec1a40e560c2f00ec82c50223add810e2567efb` (`v1.1.28`).
- Create: `scripts/init-iamlive-submodule.sh` — a small Bash script containing only the git init/commit/sparse-checkout checks for `LICENSE`, `NOTICE`, `iamlivecore/map.json`, `iamlivecore/iam_definition.json`, and `iamlivecore/apis/**`, explicitly excluding `go.mod`/`go.sum`.
- Create then remove: `scripts/migrate-iamlive-catalog.sh` — one-time Bash migration that invokes catalog validation, records the old/new coverage report, removes legacy copied datasets/tables after success, and deletes itself before Task 1 completes.
- Create: `internal/iamlivecatalog/embed.go` — embed only the selected upstream submodule files into the binary.
- Create: `internal/iamlivecatalog/catalog.go` — parse once into immutable service, protocol, operation, route, action, resource-template, and dependency indexes.
- Create: `internal/iamlivecatalog/types.go` — neutral plural records for zero/many actions, resource definitions, dependent actions, service aliases, and extraction templates.
- Modify: `internal/iammap/data/version.go` — validate catalog operation/action/resource agreement and expose catalog version/hash without embedding local JSON.
- Delete: `internal/iammap/data/generate.go`, `authorization.json`, `widening-baseline.json`, and `internal/iammap/data/source/*.json` — remove Kordn-maintained AWS API/SAR copies and generator.
- Delete: `third_party/iamlive/source/mapper.go` — remove copied iamlive-derived operation and dependency tables.
- Modify: `third_party/iamlive/PROVENANCE.md` and `third_party/iamlive/UPSTREAM_COMMIT` — record the gitlink, selected embedded paths, hashes, and unchanged MIT boundary.
- Test: `internal/iamlivecatalog/catalog_test.go` and `internal/iammap/data/version_test.go` — pin, parse, completeness, uniqueness, immutability, and cross-file consistency coverage.

Steps:
- [x] Add the exact iamlive gitlink and the simple idempotent init Bash script; fail if HEAD differs, a selected file is absent, or upstream `go.mod` remains in the sparse worktree.
- [x] Implement direct embedding plus bounded, duplicate-rejecting parsing of all selected API models and both IAM datasets; do not write a generated Kordn operation/action dataset.
- [x] Preserve all service aliases, authoritative protocols, target prefixes, operation names, HTTP methods/URI templates/query discriminators, zero/many IAM actions, resource templates, dependent actions, and extraction/applicability templates without manufacturing defaults.
- [x] Retain undocumented, permissionless, conditional, missing, and contradictory records as explicit states that cannot silently become permissions.
- [x] Exercise different catalog shapes with `iam/ListUsers` (known-global Query), `dynamodb/BatchExecuteStatement` (multiple actions), `cloudwatch/ListTagsForResource` (cross-service action), and `lambda/CreateFunction` (dependent permission).
- [x] Run the one-time migration Bash script to cross-check every `map.json` action against `iam_definition.json`, emit a coverage/disagreement report, and remove the legacy copied data/table files only when all current goldens are represented.
- [x] Delete `scripts/migrate-iamlive-catalog.sh` after its report has been captured in the ADR or task commit; keep only the small reusable submodule-init script and permanent Go consistency tests.

Verification:
- `./scripts/init-iamlive-submodule.sh --check`
- `test "$(git -C internal/iamlivecatalog/upstream rev-parse HEAD)" = "$(cat third_party/iamlive/UPSTREAM_COMMIT)"`
- `test ! -e internal/iamlivecatalog/upstream/go.mod && test -s internal/iamlivecatalog/upstream/iamlivecore/map.json`
- `go test -race ./internal/iamlivecatalog ./internal/iammap/data ./internal/iammap/iamliveadapter`

Completion criteria:
- The Kordn commit contains one pinned gitlink and parser code, but no copied/generated AWS API operation, action, resource, or dependency dataset.
- Every service and operation in the selected iamlive files is indexed; no runtime operation decision depends on a hand-authored per-operation allowlist.
- Plural/global/cross-service/dependent records retain upstream meaning, while missing or contradictory evidence remains explicit.
- A prepared checkout builds and tests offline, and the release binary contains the selected data without runtime filesystem/network access.

### Task 2: Decode operations from the submodule-backed wire catalog

Goal: Replace decoder operation/protocol/route allowlists with read-only catalog lookups while retaining every existing validation boundary.

Context:
- `Decoder.Decode` already runs after SigV4 verification and independently revalidates endpoint, host, credential scope, signing mode, protocol evidence, limits, and protocol conflicts.
- Query and JSON operation names are explicit after syntax/service checks; REST protocols additionally require modeled method/path/query matching and cannot accept a name-only lookup.

Files:
- Modify: `internal/awsrequest/decode_json.go` — use `internal/iamlivecatalog` for authoritative protocol, target model identity, and operation membership; remove `modelOperations`, `operationKnown`, and `targetModels`.
- Modify: `internal/awsrequest/decode_query.go` — validate Query/EC2 Query `Action` against catalogued service operations after syntax and duplicate/conflict checks.
- Modify: `internal/awsrequest/decode_restjson.go` and `internal/awsrequest/decode_restxml.go` — match catalogued method/URI-template/query traits and preserve extracted path values.
- Modify: `internal/awsrequest/protocol.go` — expose only protocol primitives; source service authority from the catalog.
- Test: `internal/awsrequest/model_decode_test.go` — catalog-backed Query, EC2 Query, JSON 1.0/1.1, REST-JSON, and REST-XML positive/negative coverage.
- Test: `internal/awsrequest/correction_test.go` — retain disagreement, spoofing, ambiguity, body/path/token, and unsupported-evidence regressions.

Steps:
- [ ] Add a read-only catalog dependency to `Decoder` construction so tests can inject corrupt/ambiguous records without adding a runtime bypass or operation override.
- [ ] Replace authoritative protocol and JSON target maps with exact catalog records; reject missing, duplicated, contradictory, or service-mismatched model records.
- [ ] Accept well-formed Query/JSON operations only when the authenticated endpoint service's catalog contains the exact wire operation.
- [ ] Implement strict REST route matching from catalogued URI templates, HTTP methods, and modeled query discriminators; reject zero matches, multiple matches, unsupported subresources, and conflicting path/body values.
- [ ] Use commands different from Task 1 for decoder coverage: STS `GetCallerIdentity` over Query, EC2 `DescribeInstances` over EC2 Query, DynamoDB `GetItem` over JSON 1.0, and Lambda `Invoke` over REST-JSON; retain an S3 REST-XML route regression in the existing suite.
- [ ] Retain negative tests proving malformed `Action`, duplicated query/body evidence, wrong service, wrong protocol, wrong target prefix, ambiguous REST route, and genuinely absent operations fail before mapping and never become guessed operations.

Verification:
- `go test -race ./internal/awsrequest`
- `go test ./internal/awsrequest -run 'TestCatalogModel|Test.*(GetCallerIdentity|DescribeInstances|GetItem|Invoke)|Test.*Protocol|Test.*Disagreement' -count=1`
- `go test ./internal/awsrequest -run '^$' -fuzz FuzzAWSRequestConfiguredDecoder -fuzztime=2s`

Completion criteria:
- Verified representative Query, EC2 Query, JSON, REST-JSON, and REST-XML operations decode to their exact modeled service/operation identities.
- Existing supported operations continue to decode identically; the source-spec IAM `ListUsers` GET/POST assertion is exercised in the vertical acceptance task.
- No decoder source file contains a hand-authored per-operation allowlist.
- Unknown, malformed, conflicting, or ambiguous operation evidence still fails closed.

### Task 3: Map complete IAM requirements through the guarded adapter

Goal: Make the mapper consume complete submodule-backed action/resource/dependency records across varied operation shapes without treating missing extraction evidence as a wildcard.

Context:
- `Mapper.mapOne` currently requires one iamlive action, one SAR entry, an action prefix matching the endpoint service, and a resource kind handled by a closed switch.
- `MappingResult.Requirements` already supports conjunctive multiple requirements, and the policy engine already evaluates all requirements.
- Complete metadata includes multi-action and cross-service records; dependency applicability and concrete resources remain runtime facts that must be proven.

Files:
- Modify: `internal/iammap/iamliveadapter/adapter.go` — return complete primary/dependent records from `internal/iamlivecatalog` and preserve certainty/applicability information.
- Modify: `internal/iammap/mapper.go` — cross-check every mapped action against the catalogued IAM definition and emit one mandatory requirement per proven action/dependency.
- Modify: `internal/iammap/data/version.go` — replace `ValidateEntry` with whole-operation validation across all catalogued action/resource/dependency records.
- Modify: `internal/iammap/resources.go` — resolve upstream extraction templates while preserving current ARN/account/partition/Region validators and returning unresolved on absent/ambiguous evidence.
- Modify: `internal/iammap/dependencies.go` — validate catalogued dependency templates and concrete applicability/resources rather than allowing only `iam:PassRole` or a hand-authored operation switch.
- Modify: `internal/awsrequest/types.go` — extend mapping evidence only if needed to report non-secret catalog-record/provenance identifiers; do not weaken `IAMRequirement.Validate`.
- Test: `internal/iammap/golden_wire_test.go` — add representative known-global (`iam/ListUsers`), set (`ec2/TerminateInstances`), dependent (`lambda/CreateFunction`), and multi-action (`dynamodb/BatchExecuteStatement`) goldens.
- Test: `internal/iammap/mapper_test.go`, `adapter_crosscheck_test.go`, and `account_context_test.go` — independent-source disagreement and fail-closed extraction coverage.

Steps:
- [ ] Change adapter/data lookup contracts from one `Entry` to one complete operation record while keeping adapter maps immutable and defensive-copying all returned slices/maps.
- [ ] Require exact agreement among decoded service/operation, API-model identity, `map.json` primary/dependent actions, and `iam_definition.json` resource records; reject missing, extra, or contradictory evidence.
- [ ] Remove the one-primary-action and same-service-action restrictions; emit all independently verified requirements and sort them deterministically before validation/caching.
- [ ] Map an action to `known_global` and `*` only when the embedded IAM definition authoritatively lists no resource types. For resource-capable actions, resolve exact/set resources through upstream templates plus Kordn ARN validators or return `unresolved` and reject.
- [ ] Generalize dependency handling so every catalogued dependent action is conjunctive, conditionally applied only when concrete typed request evidence proves applicability, and rejected when applicability or resources are uncertain.
- [ ] Preserve timeout/panic containment, endpoint reclassification, protocol revalidation, high-confidence-only results, and non-secret evidence.
- [ ] Use different mapping examples from Tasks 1-2: S3 `GetObject` resolves an exact object ARN, EC2 `TerminateInstances` resolves an instance set, ECS `RunTask` retains `iam:PassRole`, and CloudWatch Logs `CreateDelivery` retains all mapped actions or fails closed if applicability cannot be proven.

Verification:
- `go test -race ./internal/iammap ./internal/policy`
- `go test ./internal/iammap -run 'TestWireToMappingGoldens|TestGoldenMappings|TestAdapter.*Crosscheck|Test.*(GetObject|TerminateInstances|RunTask|CreateDelivery)' -count=1`
- `go test ./internal/iammap -run '^$' -fuzz FuzzMapperInput -fuzztime=2s`

Completion criteria:
- Representative known-global, exact/set, dependent, multi-action, and cross-service records produce complete high-confidence requirements when concrete evidence is sufficient.
- Existing exact/set/global/dependent goldens remain unchanged unless the pinned submodule proves the old record wrong and an explicit gitlink update documents the correction.
- Multiple primary and dependent actions are represented as mandatory requirements rather than collapsed.
- Incomplete or ambiguous action/resource/dependency evidence returns a mapper error and cannot reach policy evaluation or upstream forwarding.

### Task 4: Preserve protocol and operation evidence in local failures

Goal: Ensure local failures use the authoritative protocol and the last safely validated operation, so IAM denials are parseable XML and audit does not regress a decoded operation to `Unknown`.

Context:
- `finishFailedPipeline` currently ignores its cause, reconstructs `ProtocolJSON11`/`Operation=Unknown`, and discards a valid decoded request on map or policy failures.
- `awserror.Encode` and `encodeQueryXML` already produce the required XML when supplied `ProtocolQuery` and a valid service/operation/event ID.
- Authentication must remain before any operation recovery used for audit or authorization.

Files:
- Modify: `internal/awsrequest/types.go` — add a bounded, non-secret decode-failure evidence type or typed error accessor for authoritative protocol and syntactically/service-validated operation state.
- Modify: `internal/awsrequest/decode_json.go`, `decode_query.go`, `decode_restjson.go`, and `decode_restxml.go` — attach only progressively validated evidence to decode errors; mark malformed/ambiguous operations as unavailable.
- Modify: `internal/proxy/server.go` — pass the successful decoded request through map/policy failure paths and replace `fallbackDecoded`/`fallbackMapping` with a single evidence-aware local-denial builder.
- Modify: `internal/awserror/encode_test.go` — assert Query XML remains well formed for catalogued operations and fallback operation tokens.
- Test: `internal/proxy/proxy_test.go` and `internal/proxy/pipeline_behavior_test.go` — protocol, operation, audit, event-ID, and no-forwarding failure-path coverage.

Steps:
- [ ] Define progressive failure evidence with explicit availability/certainty; never infer an operation from unauthenticated fields or reuse malformed/conflicting values.
- [ ] For decode failures, select the protocol from mutually consistent verified/authoritative endpoint evidence; use a validated operation only when syntax, endpoint service, protocol, and catalog agree.
- [ ] For map and policy failures, pass the complete already-validated `DecodedAWSRequest` into denial and audit construction instead of rebuilding it.
- [ ] Use `Unknown` only when operation evidence is absent, malformed, unknown, or ambiguous; keep the fallback mapping unresolved and non-authorizing.
- [ ] Make the audit request, denial body, content type, stable reason, and event/request ID derive from the same evidence object.
- [ ] Use protocol examples different from Tasks 1-3: STS `AssumeRole` (Query XML), ECS `DescribeServices` (JSON 1.1), Lambda `UpdateFunctionConfiguration` (REST-JSON), and S3 `GetBucketLocation` (REST-XML), covering decode, map, and policy failure stages.

Verification:
- `go test -race ./internal/awsrequest ./internal/awserror ./internal/proxy`
- `go test ./internal/proxy -run 'Test.*(Failure|Deny|Audit|Protocol|AssumeRole|DescribeServices|UpdateFunctionConfiguration|GetBucketLocation)' -count=1`

Completion criteria:
- Local denials for representative Query, JSON 1.0, REST-JSON, and REST-XML operations use their native wire shapes and preserve the same stable reason/event ID as audit.
- The source-spec IAM denial is valid Query XML and its corresponding audit event records `operation: ListUsers` and `protocol: query`.
- Mapping/policy failures no longer discard a validated operation.
- Malformed, unauthenticated, unknown, or ambiguous evidence remains local, unresolved, and unforwarded.

### Task 5: Add varied vertical operation and fail-closed acceptance coverage

Goal: Prove complete catalog-backed behavior with varied operations through the real verifier/decoder/mapper/policy/audit/error pipeline while retaining every source-spec `ListUsers` assertion.

Context:
- The current SigV4 fixture set contains a standalone IAM `ListUsers` example, but no mixed-operation fixture contract for the complete decoder/mapper pipeline.
- The policy engine already requires `allowAwsRequiredWildcard: true` for an allow rule over a `known_global` requirement; explicit deny and default deny are generic behaviors that need varied vertical regression coverage.

Files:
- Rename/expand: `test/fixtures/sigv4/iam-list-users.json` to `test/fixtures/sigv4/aws-operation-examples.json` — make `ListUsers` one entry in a mixed-operation fixture containing at least IAM Query, DynamoDB JSON, Lambda REST-JSON, and S3 REST-XML cases, with per-entry source attribution and expected service/operation/protocol.
- Modify: `test/fixtures/sigv4/README.md` — document the mixed fixture and each source.
- Create: `test/integration/catalog_operations_test.go` — production-pipeline coverage for all fixture entries plus varied global, exact/set, dependent, multi-action, allow, deny, audit, protocol, and no-forward cases.
- Modify: `test/integration/fakeaws/sigv4.go` and `test/integration/fakeaws/protocols_test.go` — provide protocol-correct fake-upstream responses for the representative IAM Query, S3 REST-XML, Lambda REST-JSON, and DynamoDB JSON operations.
- Modify: `test/compatibility/awscli_test.go` — add hermetic AWS CLI-equivalent scenarios for `iam list-users` and at least one differently shaped catalogued operation through the real pipeline.
- Modify: `internal/policy/engine_test.go` — pin known-global wildcard acknowledgement, exact/set resources, and conjunctive primary/dependent or multi-action behavior using different operations.
- Modify: `internal/proxy/proxy_test.go` — count upstream calls for denied/unknown/ambiguous requests across multiple services and protocols.

Steps:
- [ ] Exercise properly signed requests for at least four shapes through production authentication, decode, map, and policy: IAM `ListUsers` (known-global Query), S3 `GetObject` (exact REST-XML), Lambda `CreateFunction` (dependent REST-JSON), and DynamoDB `BatchExecuteStatement` (multi-action JSON 1.0).
- [ ] Split allow-path checks across operations: an acknowledged IAM known-global allow and an exact S3 allow each forward once and receive protocol-correct fake-upstream responses.
- [ ] Split deny checks across operations: IAM explicit deny, S3 default deny, and Lambda missing dependent-action allow each forward zero times, preserve protocol/event ID, and write complete audit requirements.
- [ ] Prove the IAM known-global allow without `allowAwsRequiredWildcard: true` is denied with `aws_required_wildcard_not_approved`, and prove a DynamoDB multi-action request cannot pass when any required action is absent or applicability is unresolved.
- [ ] Add adversarial cases across different services for malformed Query `Action`, absent catalogued JSON operation, protocol disagreement, ambiguous REST metadata, mapper source disagreement, unresolved resource/dependency extraction, and corrupt catalog records; each must produce zero upstream requests.
- [ ] Assert secrets and raw authorization/session-token values do not appear in XML, JSON, audit, metrics, or mapping evidence.

Verification:
- `go test -race ./test/integration -run 'TestCatalogOperations|Test.*Unknown.*FailClosed' -count=1`
- `go test -race -tags compat ./test/compatibility -run 'TestAWSCLI.*(ListUsers|GeneratedOperation)' -count=1`
- `make test-integration && make test-compatibility`

Completion criteria:
- All six acceptance criteria in the source spec are executable assertions.
- Allow, explicit deny, default deny, missing wildcard acknowledgement, missing dependent permission, and missing multi-action permission are covered across different operations.
- Denied/unsupported/ambiguous requests make no upstream call and produce one correlated audit decision.
- AWS CLI-compatible parsing no longer reports `invalid XML received` for local IAM denials.

### Task 6: Lock the submodule integration with contracts, versioning, CI, and documentation

Goal: Make the pinned submodule dependency reproducible and reviewable without storing a second authorization dataset or widening-baseline file in Kordn.

Context:
- The gitlink is the review boundary for upstream data changes: advancing it is an explicit source diff, not an automatic refresh.
- Full copied baselines would recreate the maintenance problem this design removes. Security regressions are instead caught by parser invariants, varied behavior contracts, and fail-closed tests over the pinned catalog.
- `mappingCacheKey` and `decisionCacheKey` already include mapper, adapter, and authorization-data versions; those values must incorporate the submodule commit/content hash.
- CI and source documentation must initialize the sparse submodule before any Go command, while release builds remain offline after initialization.

Files:
- Modify: `internal/iammap/mapper.go` and `internal/iammap/iamliveadapter/adapter.go` — bump mapper/adapter versions.
- Modify: `internal/app/commands.go` — expose submodule commit, selected-content hash, catalog schema, mapper, and adapter versions in `kordn version --json`.
- Modify: `Makefile` — add `iamlive-init` and `iamlive-check`; make build/test/security/release gates fail clearly when the submodule is absent or incorrectly prepared.
- Modify: `.github/workflows/ci.yml` — initialize the pinned sparse submodule before Go setup/gates while preserving concurrent workflow edits.
- Modify: `third_party/iamlive/PROVENANCE.md`, `THIRD_PARTY_NOTICES.md`, `license-check`, and `docs/decisions/0001-iamlive-integration.md` — record the gitlink, selected paths, content hashes, MIT notices, and neutral-catalog/enforcement boundary.
- Modify: `docs/architecture.md`, `docs/compatibility.md`, `docs/quickstart.md`, and `docs/backlog.md` — document clone/init requirements, catalog versus endpoint activation, fail-closed unresolved behavior, IAM XML denials, and completion of the first improvement.
- Modify: `docs/security-review-checklist.md` if checklist invariants or acceptance IDs need catalog coverage without changing existing numbering silently.
- Test: `internal/iamlivecatalog/catalog_test.go`, `internal/proxy/pipeline_behavior_test.go`, and `internal/iammap/mapper_test.go` — pin/content/version/cache and varied behavior-contract assertions.

Steps:
- [ ] Define `make iamlive-init` as the only network-capable preparation step. It initializes the exact gitlink, applies the required sparse checkout, and verifies selected files/license; it never tracks generated output.
- [ ] Define offline `make iamlive-check` precisely: verify submodule HEAD and `UPSTREAM_COMMIT`, reject an upstream `go.mod` in the sparse worktree, verify selected file hashes/licenses, parse every API model and IAM record, reject duplicate/contradictory indexes, and run catalog consistency tests.
- [ ] Add behavior contracts over examples not used in Tasks 1-5, such as KMS `ListKeys`, SQS `SendMessage`, SNS `Publish`, and Organizations `ListAccounts`; assert expected protocol/action shape or explicit unresolved rejection rather than broad fallback.
- [ ] Bump mapper, adapter, and catalog versions; derive the catalog data version from submodule commit plus selected-content hash, and assert mapping/decision cache keys change when that version changes.
- [ ] Run submodule initialization at the start of each CI job, then keep `iamlive-check`, ordinary tests, and release builds offline. Verify release binaries build twice identically and run without the submodule checkout present.
- [ ] Document the update procedure: intentionally advance the gitlink, update the pin/provenance/hash, inspect upstream `map.json`/definition/API-model changes, run all contracts, and review any newly resolvable or known-global permissions.
- [ ] Document source-distribution limitations: after `git clone --recurse-submodules`, run `make iamlive-init` to apply/verify the sparse checkout; `make iamlive-init` also handles a non-recursive clone. GitHub-generated source archives and plain `go install` are not supported build inputs, while published binaries are standalone.

Verification:
- `make iamlive-init && make iamlive-check`
- `make fmt-check && make lint && make test-race && make license-check && make build`
- `make test-integration && make test-compatibility && make security-check`
- `make release-snapshot`, then copy the produced binary outside the checkout and run `kordn version --json` plus the existing init/policy-validation smoke test.

Completion criteria:
- Kordn stores no copied/generated AWS operation or authorization dataset and no full widening baseline.
- CI rejects an absent, wrong, non-sparse, malformed, unattributed, or internally inconsistent submodule catalog.
- Version output, cache keys, audit mapping versions, and release provenance identify the exact submodule commit/content used by the binary.
- A prepared checkout passes all canonical gates offline, and standalone release binaries run without source/submodule files.

## Cross-Task Verification

- `make iamlive-init && make iamlive-check`
- `go test -race ./internal/iamlivecatalog ./internal/awsrequest ./internal/iammap ./internal/policy ./internal/awserror ./internal/proxy`
- `go test -race ./test/integration/...`
- `go test -race -tags compat ./test/compatibility`
- `make fmt-check && make lint && make test-race && make license-check && make build && make security-check && make release-snapshot`
- Manual acceptance: run `kordn run --config <deny-config> -- aws iam list-users`; confirm AWS CLI displays a Kordn `AccessDenied` rather than `invalid XML received`, the command does not reach AWS, and the correlated audit event names `ListUsers`.
- Manual allow acceptance against the fake or dedicated low-privilege upstream: an acknowledged `iam:ListUsers` allow forwards exactly once and returns a parseable IAM `ListUsersResponse`.
- Standalone check: copy the release binary to a directory outside the repository, temporarily make the submodule unavailable, and confirm version/init/policy-validation smoke tests still pass.

## Risks and Mitigations

- Risk: A clone, source archive, or CI job omits the submodule or leaves its nested `go.mod`, causing embed/build failures.
  Mitigation: provide one idempotent initialization script, call it before Go commands in CI/docs, reject an incorrect sparse worktree, and publish standalone binaries rather than relying on GitHub source archives.
- Risk: Sparse-checkout behavior differs across supported Git versions.
  Mitigation: pin/document a minimum Git version, use non-cone explicit paths, test initialization from a fresh clone in CI, and fail with a direct remediation command.
- Risk: API models, `map.json`, and `iam_definition.json` disagree or use different service aliases.
  Mitigation: normalize aliases explicitly, retain separate evidence inside the catalog, and reject runtime mapping unless all required records agree.
- Risk: Complete data contains multi-action, cross-service, conditional dependency, or multi-resource records that the singular current schema silently loses.
  Mitigation: model plural records first, add representative cardinality contracts, and fail catalog construction on lossy normalization.
- Risk: REST route matching accepts an AWS-looking path too broadly.
  Mitigation: require exact service, method, URI template, path decoding, and modeled query discriminators; reject zero or multiple matches.
- Risk: Resource extraction turns incomplete iamlive wildcard behavior into broad policy access.
  Mitigation: derive `known_global` only from the IAM definition's absence of resource types; all other missing/ambiguous extraction returns `unresolved` and fails closed.
- Risk: Conditional dependencies are omitted when request applicability is unclear.
  Mitigation: preserve dependency templates and certainty, require every applicable dependency as a conjunctive requirement, and reject uncertain applicability.
- Risk: Removing the full widening baseline reduces exhaustive old/new semantic comparison.
  Mitigation: make every gitlink advance explicit, publish a categorized update report during review, enforce parser invariants and varied behavior contracts, and default every newly ambiguous record to local denial.
- Risk: Embedding raw upstream files increases binary size or startup latency.
  Mitigation: embed only selected paths, build immutable indexes once, add binary-size/startup benchmarks, and keep release thresholds reviewable.
- Risk: Recovering operation evidence from a failed request creates misleading audit attribution.
  Mitigation: expose progressive typed evidence only after signature verification and consistency checks; use `Unknown` for malformed, absent, unknown, or ambiguous values.
- Risk: Submodule data or parser use violates attribution or package boundaries.
  Mitigation: verify the exact MIT license/notice and commit/content hash, keep the catalog neutral, and retain Kordn enforcement and fail-closed checks in the adapter/mapper.

## Open Questions

- None. The pinned iamlive submodule, sparse direct embedding, separate endpoint activation, no copied datasets/baseline, and fail-closed treatment of incomplete mappings are explicit decisions for this plan.
