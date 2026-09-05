# Refactor Catalog-Backed IAM Mapping Implementation Plan

## Overview

Refactor the pinned iamlive catalog and IAM mapper so each raw evidence occurrence is retained once in a compact, immutable representation, request-independent inconsistencies are compiled at catalog load, and request-time mapping is split into typed wire, primary-resource, and dependency stages. The work also replaces the large raw embedded JSON corpus with deterministic compressed packaging and makes mapper cancellation cooperative, so the existing strict latency and throughput behavior can fit the 80 MiB ordinary-process RSS budget without weakening fail-closed authorization.

The preceding hot-path refactor removed repeated catalog cloning and scanning, but the strict reference run still reported 322.8 MiB RSS. The current process retains `Catalog.services`, alias-expanded `Catalog.operations`, `Catalog.mappings`, `Catalog.actions`, `Catalog.wireServices`, operation-occurrence indexes, and the decoder's separate immutable wire index while the executable embeds roughly 56.3 MiB of raw selected JSON.

## Source Spec

- Spec: `docs/backlog.md` — `Refactor catalog-backed IAM mapping validation and dependency evaluation`
- Related plan: `docs/plans/completed/20260904-eliminate-catalog-hot-path-copies.md`
- Status: Approved backlog item; implementation details below are assumed where the backlog does not prescribe representation
- Last reviewed: 2026-09-05

## Repository Context

- `internal/iamlivecatalog/embed.go` — embeds the selected pinned license, notice, mapping, IAM-definition, and API-model files as the offline input boundary.
- `internal/iamlivecatalog/catalog.go` — `Load`/`parse` build the process-lifetime catalog; `buildWireIndexes` currently adds a second catalog-wide wire graph.
- `internal/iamlivecatalog/types.go` — `Catalog`, `Service`, `Operation`, `ActionMapping`, and `ActionDefinition` define the retained object graphs and defensive-copy public API.
- `internal/awsrequest/wire_index.go` — builds the immutable decoder index and owns exact Query/EC2 Query versions, JSON targets, and REST route/query-binding selection.
- `internal/iammap/iamliveadapter/adapter.go` — `LookupRequest`, `lookupOperation`, and `validateGraph` currently combine wire agreement, catalog graph checks, condition evaluation, and dependency extraction.
- `internal/iammap/mapper.go` — `Mapper.Map` contains timeout/panic containment; `mapOne` revalidates endpoint/protocol identity and evaluates primary and dependent requirements.
- `internal/iammap/resources.go` — owns Kordn-specific primary-resource extraction and ARN/scope validation.
- `internal/iammap/dependencies.go` — cross-checks dependent-action occurrences and rejects uncertain or unresolved resource evidence.
- `internal/iammap/data/version.go` — compatibility facade whose `Entries` and `ValidateEntry` paths still enumerate defensive catalog views and compare string-shaped records.
- `internal/proxy/server.go` — `mapReason` currently classifies mapping failures by matching error text to stable local denial reasons.
- `scripts/init-iamlive-submodule.sh` and `Makefile` — prepare and verify the exact pinned sparse source, aggregate content hash, offline gates, benchmarks, and release provenance.
- `test/integration/performance_test.go` and `test/compatibility/performance_test.go` — own the unchanged strict ordinary and compatibility RSS, latency, and throughput thresholds.
- `docs/architecture.md` and `docs/decisions/0001-iamlive-integration.md` — fix the neutral-catalog/enforcement ownership boundary and offline single-process architecture.

## Implementation Constraints

- Keep `internal/iamlivecatalog` neutral: it parses and structurally validates pinned upstream evidence. `internal/awsrequest/endpoint.go` remains the positive AWS interception boundary, and `internal/iammap` continues to own authorization and fail-closed decisions.
- Preserve every raw API-model, mapping, resource, action-definition, and dependency occurrence. Compact indexes may point to occurrence IDs or spans, but must not convert occurrence-sensitive data into sets.
- Keep shared catalog and wire indexes immutable after publication. Do not add request-path locks, lazy network reads, mutable caches, or catalog-scale request work.
- Query and EC2 Query lookup must match endpoint service, protocol, exact wire `Version`, and `Action`. JSON lookup must match modeled protocol/version, target prefix, and operation. REST lookup must retain method, URI template, fixed-query, and modeled query-binding checks.
- Represent every dependent-action occurrence as `applicable`, `inapplicable`, or `unknown`. Retain duplicate and proven-inapplicable occurrences; reject unknown applicability and any mapping/IAM-definition multiset disagreement.
- Preserve the pinned `3ec1a40e560c2f00ec82c50223add810e2567efb` source, aggregate hash `43e605716ea0ccdaeb625bad52088deece0204ad38e4b6e461e6792a1dd00869`, offline post-initialization build, and release provenance.
- Preserve Lambda `CreateFunction`'s known `lambda:PassCapacityProvider` disagreement and deny that affected mapping as `dependent_permission_unresolved`; do not omit or synthesize the missing extraction record.
- Preserve defensive-copy public catalog APIs even if their values are reconstructed on demand from compact records.
- Never widen unresolved evidence to known-global scope or `*`, and never forward a request with missing, contradictory, ambiguous, incomplete, or cancelled mapping evidence.
- Keep one local binary and one `kordn run` process. Do not add a daemon or network control plane. Non-AWS CONNECT traffic remains byte-opaque end-to-end TLS.
- Do not edit the strict threshold source files or relax Section 21 gates: ordinary RSS remains at most 80 MiB, compatibility RSS at most 150 MiB, and existing latency/throughput limits remain unchanged.

## Assumptions

- The approximately 56.3 MiB raw embedded corpus makes compact heap records alone insufficiently reliable for the 80 MiB RSS target, so deterministic compressed packaging is part of this refactor rather than optional follow-up work.
- The compressed bundle is an ignored, reproducible build input produced from the exact sparse submodule by `make iamlive-init`; it is not a checked-in authorization dataset or a second source of truth.
- Fatal source-format defects fail catalog load. Cross-file disagreements tied to individual operations are retained as typed diagnostics and fail only affected lookups, because the pinned source contains known disagreement evidence that must remain observable.
- Mapper-side wire agreement remains independent of decoder selection; compaction must not replace it with trust in the decoded operation string.
- Existing exported catalog and compatibility-facade APIs remain source-compatible unless tests prove they are repository-internal and an explicit migration is included in the same task.

## Non-goals

- Updating the pinned iamlive revision or changing selected upstream paths.
- Adding services, hand-authored per-operation mappings, or broader resource support.
- Changing endpoint classification, SigV4 verification, policy semantics, upstream signing, audit schema semantics, or denial response protocols.
- Introducing runtime-loaded plugins, network catalog loading, background workers, a daemon, or a control plane.
- Relaxing golden mappings, allocation ceilings, strict performance thresholds, or fail-closed behavior to meet the memory budget.

## Task Summary

1. Package the pinned source as a deterministic compressed bundle without changing source identity.
2. Replace duplicate retained catalog graphs with a canonical occurrence store and compact indexes.
3. Compile static mapping and IAM-definition agreement once at catalog load.
4. Split request mapping into typed wire, primary-resource, and tri-state dependency stages.
5. Make cancellation synchronous and mapping failures structurally classifiable.
6. Lock memory, compatibility, provenance, and documentation gates.

## Implementation Tasks

### Task 1: Package the pinned catalog deterministically

Goal: Remove raw selected JSON from the executable's resident input representation while preserving the exact pinned bytes, aggregate source hash, offline behavior, and reproducible release path.

Context:
- `internal/iamlivecatalog/embed.go` currently embeds every selected JSON file directly; the selected corpus is roughly 56.3 MiB before any parsed catalog objects are retained.
- `make iamlive-init` is the only permitted network-capable preparation step. All subsequent Go and release gates must remain offline.

Files:
- Create: `internal/iamlivecatalog/cmd/pack/main.go` — deterministic standard-library catalog packer.
- Create/generated: `internal/iamlivecatalog/catalog.bundle.gz` — ignored compressed bundle consumed by `go:embed`.
- Modify: `internal/iamlivecatalog/embed.go` — embed only the prepared bundle.
- Modify: `internal/iamlivecatalog/catalog.go` — stream and validate bounded bundle entries while preserving source-hash ordering.
- Modify: `scripts/init-iamlive-submodule.sh` — generate the bundle during initialization and verify exact regeneration in `--check` mode.
- Modify: `.gitignore` — ignore only the generated bundle artifact.
- Modify: `Makefile` — include bundle existence/reproducibility in `iamlive-check` and release preparation.
- Modify: `.github/workflows/ci.yml` — install the pinned Go toolchain before initialization so the packer can run.
- Modify: `.github/workflows/release.yml` — prepare the bundle before direct Go tests, strict gates, and GoReleaser builds.
- Test: `internal/iamlivecatalog/catalog_test.go` — malformed archive, duplicate/missing/oversized entry, reproducibility, and unchanged-source-hash coverage.

Steps:
- [ ] Define a canonical archive manifest/order for `LICENSE`, `NOTICE`, `iamlivecore/map.json`, `iamlivecore/iam_definition.json`, and sorted API-model paths; use fixed gzip/tar metadata so identical pinned input produces byte-identical output.
- [ ] Make the packer verify the submodule `.git` marker and exact nested top-level path before reading selected files, then reject symlinks, duplicate canonical paths, unexpected paths, missing required paths, oversized entries, truncation, or trailing archive data.
- [ ] Generate the ignored bundle atomically from the sparse pinned checkout in normal initialization; make `--check` compare a temporary regeneration byte-for-byte without mutating the working tree.
- [ ] Replace raw-file `go:embed` patterns with the single bundle and stream bounded entries through parsing instead of materializing an additional whole uncompressed corpus.
- [ ] Recompute `Catalog.SourceHash` from the original canonical path/byte sequence, not compressed bytes, and retain license/notice validation.
- [ ] Reorder or extend CI and both release jobs so setup-go and `make iamlive-init` occur before any compile, direct `go test`, strict gate, or GoReleaser invocation.

Verification:
- `make iamlive-init`
- `./scripts/init-iamlive-submodule.sh --check`
- `make iamlive-check`
- `go test ./internal/iamlivecatalog -run 'Test.*(Bundle|Embedded|SourceHash|Pinned)' -count=1`
- Run `make iamlive-init` twice and verify `sha256sum internal/iamlivecatalog/catalog.bundle.gz` is unchanged.

Completion criteria:
- The executable no longer embeds the selected JSON files individually, and catalog loading needs no runtime filesystem or network access.
- The prepared bundle is deterministic, ignored, bounded on read, and rejected if stale or inconsistent with the pinned source.
- `SourceHash()` still returns `43e605716ea0ccdaeb625bad52088deece0204ad38e4b6e461e6792a1dd00869`.

### Task 2: Build a canonical compact occurrence store

Goal: Retain normalized source evidence once and make public diagnostic views and request indexes reference that canonical storage without duplicate catalog-wide object graphs.

Context:
- `Catalog` currently retains `services`, alias-expanded `operations`, `mappings`, `actions`, `wireServices`, and occurrence positions; mappings are also cloned onto service operations.
- `internal/awsrequest/wire_index.go` already builds a separate immutable decoder index. Request performance must not regress to defensive `WireServices()` or `Services()` enumeration.

Files:
- Modify: `internal/iamlivecatalog/types.go` — add private bounded IDs/spans, interned string storage, and canonical evidence records while retaining exported view types.
- Modify: `internal/iamlivecatalog/catalog.go` — construct canonical operation, route, query-binding, mapping, action-definition, resource, and dependency occurrences.
- Modify: `internal/awsrequest/wire_index.go` — consume a narrow immutable catalog selector/iterator rather than a retained `Catalog.wireServices` clone.
- Modify: `internal/iammap/data/version.go` — build compatibility views from compiled selectors instead of repeated `Services()` scans.
- Test: `internal/iamlivecatalog/catalog_test.go` — cardinality, order, duplicate retention, mutation isolation, and overflow/bounds tests.
- Test: `internal/awsrequest/wire_index_test.go` — no-enumeration and immutable-index structural tests.
- Test: `internal/iammap/data/version_test.go` — compatibility-facade equivalence and defensive-copy tests.

Steps:
- [ ] Assign an occurrence ID before normalization/deduplication and retain source order for every API operation, action mapping, resource record, action definition, resource type, and dependent action.
- [ ] Intern repeated immutable strings and store nested occurrence lists as contiguous spans or ID slices with explicit overflow and bounds validation; do not use set semantics for evidence.
- [ ] Replace `indexedOperation.operation` copies and alias-expanded full values with occurrence references, and stop cloning mapping slices onto each retained operation.
- [ ] Remove the resident `Catalog.wireServices` graph and post-attachment `Catalog.mappings` duplicate after canonical indexes are complete.
- [ ] Add narrow immutable iteration/selection methods for the decoder, adapter, and compatibility facade; keep `Services`, `WireServices`, `Operation`, `OperationOccurrences`, `Actions`, and `Action` as mutation-isolated reconstructed views.
- [ ] Preserve duplicate API versions and all exact route/query-binding data in decoder buckets; prove request lookup stays bounded to an indexed candidate bucket.
- [ ] Assert source-to-index cardinalities, including the current 19,543 API operation occurrences, so compaction cannot silently collapse duplicates.

Verification:
- `go test ./internal/iamlivecatalog ./internal/awsrequest ./internal/iammap/data -count=1`
- `go test -race ./internal/iamlivecatalog ./internal/awsrequest ./internal/iammap/data -count=1`
- `go test ./internal/awsrequest -run 'Test.*(QueryExactVersion|RESTQuery|Variant|WireIndex|No.*Enumer)' -count=1`
- `go test ./internal/iamlivecatalog -run 'Test.*(Occurrence|Duplicate|Defensive|Mutation|Cardinality)' -count=1`

Completion criteria:
- Each raw occurrence remains addressable in source order, and equivalent values are never collapsed merely because their strings match.
- Catalog publication and all consumer indexes are immutable and lock-free on the request path.
- Public catalog results remain defensive copies while the process no longer retains a second full wire graph or mapping graph.

### Task 3: Compile static catalog agreement once

Goal: Move request-independent structural and cross-file validation into catalog loading while keeping authorization decisions and request-dependent evaluation in `internal/iammap`.

Context:
- `iamliveadapter.lookupOperation` currently performs action-definition lookup and graph validation on each request, and `validateGraph` uses action strings, positional bookkeeping, and repeated scans.
- Static invalidity must be attributable and reusable, but a known disagreement for one operation must not make unrelated catalog operations unavailable.

Files:
- Create: `internal/iamlivecatalog/validation.go` — neutral typed validation diagnostics and compiled mapping-plan assembly.
- Modify: `internal/iamlivecatalog/types.go` — private compiled plan/edge occurrence records and exported safe diagnostic state where needed.
- Modify: `internal/iamlivecatalog/catalog.go` — invoke compilation once before immutable publication.
- Modify: `internal/iammap/data/version.go` — validate compatibility entries against compiled occurrence summaries rather than string reconstruction.
- Test: `internal/iamlivecatalog/catalog_test.go` — malformed, missing, contradictory, duplicate, cyclic, extra, and known-disagreement fixtures.
- Test: `internal/iammap/data/version_test.go` — exact action/resource/dependency multiset comparison tests.

Steps:
- [ ] Compile each operation's mapping occurrences to exact action-definition occurrences and preserve every resource-type and dependent-action edge occurrence.
- [ ] Compare API mappings and IAM definitions as complete occurrence multisets, including duplicate actions, resources, and dependencies; do not substitute sorted-set or first-match equality.
- [ ] Detect source-wide structural failures during `Load` and record per-operation typed diagnostics for missing, contradictory, ambiguous, cyclic, extra, or incomplete mapping evidence.
- [ ] Mark a compiled plan usable only when all static evidence required by that operation agrees; expose bounded safe source/action/occurrence identifiers without request data or credentials.
- [ ] Encode Lambda `CreateFunction`/`lambda:PassCapacityProvider` as the expected unresolved dependency disagreement and prove its edge remains present while the operation fails closed.
- [ ] Remove request-time action-definition lookups, dependency DFS, static string disagreement checks, and repeated compatibility-facade scans after parity tests pass.

Verification:
- `go test ./internal/iamlivecatalog ./internal/iammap/data -count=1`
- `go test -race ./internal/iamlivecatalog ./internal/iammap/data -count=1`
- `go test ./internal/iamlivecatalog -run 'Test.*(Validation|Multiset|Dependency|Contradict|Lambda)' -count=1`
- `go test ./internal/iammap/data -run 'Test.*(ValidateEntry|NoWidening|Duplicate|Dependency)' -count=1`

Completion criteria:
- Request lookup retrieves one prevalidated immutable mapping plan or a typed fail-closed diagnostic; it does not rediscover static graph inconsistency.
- Exact action/resource/dependency occurrence multisets and the known Lambda disagreement are preserved.
- Neutral catalog validation does not classify endpoints, evaluate policies, synthesize permissions, or turn unresolved evidence into `*`.

### Task 4: Introduce typed request mapping stages

Goal: Separate exact wire resolution, compiled catalog selection, primary-resource evaluation, and dependency evaluation behind narrow context-aware contracts.

Context:
- `LookupResult` currently duplicates primary evidence across `Entry`, `Primary`, and `PrimaryEntries`.
- `DependenciesCertain` and `ProvenInapplicable` cannot express applicability on every occurrence and encourage positional cross-checking in `dependencies`.

Files:
- Create: `internal/iammap/iamliveadapter/types.go` — typed wire identity, primary occurrence, dependency occurrence, applicability, and lookup contracts.
- Modify: `internal/iammap/iamliveadapter/adapter.go` — reduce the adapter to exact wire agreement, compiled-plan selection, and request-dependent condition/template evaluation.
- Modify: `internal/iammap/mapper.go` — orchestrate typed stages and construct final requirements without parallel representations.
- Modify: `internal/iammap/resources.go` — accept typed primary evidence and preserve existing ARN/scope validation.
- Modify: `internal/iammap/dependencies.go` — consume occurrence-bound tri-state dependency evidence and compare exact multiplicities.
- Test: `internal/iammap/iamliveadapter/adapter_test.go` — wire ambiguity and applicability-state contract tests.
- Test: `internal/iammap/adapter_crosscheck_test.go` — injected disagreement and occurrence-multiplicity tests.
- Test: `internal/iammap/golden_wire_test.go` — wire-to-mapping behavior parity.
- Test: `internal/iammap/mapper_test.go` — stage-level fail-closed behavior.

Steps:
- [ ] Define consumer-owned interfaces whose methods accept `context.Context` first and expose only immutable, read-only evidence required by the next stage.
- [ ] Preserve independent exact wire agreement for Query/EC2 Query version/action, JSON version/target, and REST method/URI/fixed-query/modeled query bindings before selecting a mapping plan.
- [ ] Replace `Entry`/`Primary`/`PrimaryEntries` with explicit primary-action occurrences binding operation, mapping, action-definition, and resource-type occurrence IDs.
- [ ] Replace aggregate booleans with an `applicable`/`inapplicable`/`unknown` enum on every dependent occurrence; retain inapplicable occurrences and fail closed on unknown.
- [ ] Evaluate request-dependent mapping conditions and resource templates without mutating shared plans; preserve one definition-edge occurrence and all corresponding mapping occurrences.
- [ ] Make all applicable primary and dependent requirements conjunctive, reject ambiguous resource-type selection, and preserve existing ARN validators and exact/set/known-global/unresolved scope semantics.
- [ ] Remove positional `used []bool` matching and boolean certainty fallbacks after duplicate, inapplicable, unknown, malformed, and ambiguity tests cover the typed path.

Verification:
- `go test ./internal/iammap/iamliveadapter ./internal/iammap -count=1`
- `go test -race ./internal/iammap/iamliveadapter ./internal/iammap -count=1`
- `go test ./internal/iammap -run 'Test(GoldenMappings|NoScopeWidening|DependentPassRole|MapperRejectsInjected|WireToMapping)' -count=1`
- `go test ./internal/iammap -run '^$' -fuzz FuzzMapperInput -fuzztime=2s`

Completion criteria:
- Wire selection, static mapping selection, primary-resource evaluation, and dependency evaluation have separate typed contracts and structured outputs.
- Duplicate and proven-inapplicable dependency occurrences survive request evaluation; unknown applicability cannot authorize or forward.
- Normal requests perform bounded indexed lookup and request-dependent evaluation only, with no catalog-wide clone, scan, lock, or static graph traversal.

### Task 5: Make cancellation and mapper failures explicit

Goal: Guarantee repository-owned mapping work stops before `Mapper.Map` returns and stable proxy denial classification no longer depends on error-message substrings.

Context:
- `Mapper.Map` currently returns on timeout while a worker goroutine may continue because adapter/resource/dependency operations do not consume the derived context.
- `proxy.mapReason` uses phrase matching; specific dependency/resource causes can be hidden by a generic `unknown operation` wrapper.

Files:
- Create: `internal/iammap/errors.go` — closed mapping failure kinds and bounded structured error type.
- Modify: `internal/iammap/mapper.go` — synchronous panic recovery, deadline handling, and typed stage orchestration.
- Modify: `internal/iammap/iamliveadapter/adapter.go` — propagate context and typed catalog/wire failures.
- Modify: `internal/iammap/resources.go` — cancellation checks in bounded multi-value work and typed unresolved failures.
- Modify: `internal/iammap/dependencies.go` — cancellation checks and typed applicability/resource failures.
- Modify: `internal/proxy/server.go` — classify with `errors.Is`/`errors.As` and default unknown mapper failures to low confidence.
- Test: `internal/iammap/mapper_test.go` — cooperative blocking double, timeout, cancellation, panic, and goroutine-lifetime tests.
- Test: `internal/proxy/proxy_test.go` — stable reason precedence and safe-detail tests.

Steps:
- [ ] Define failure kinds for unknown/ambiguous wire operation, catalog inconsistency, unresolved primary resource, unresolved dependency, low confidence, cancellation/timeout, invalid result, and panic; wrap causes without exposing headers, bodies, parameters, or credentials.
- [ ] Remove the detached worker goroutine from `Mapper.Map`, recover panics synchronously, and use the derived deadline context throughout every repository-owned stage.
- [ ] Check cancellation in candidate loops, condition/template walks, multiset comparisons, and multi-resource evaluation so timeout completion is cooperative and prompt.
- [ ] Replace string-based `mapReason` matching with typed classification that prioritizes specific dependency/resource failures before generic wrappers and leaves stable external reason codes unchanged.
- [ ] Add blocking and high-cardinality test doubles that prove a returned timeout/cancellation leaves no active mapping work or goroutine growth.
- [ ] Verify operation names containing words such as `Dependent` cannot influence reason classification and all diagnostic fields are bounded and secret-free.

Verification:
- `go test ./internal/iammap -run 'TestMapper.*(Panic|Timeout|Cancel|Goroutine)' -count=20`
- `go test -race ./internal/iammap ./internal/proxy -count=1`
- `go test ./internal/proxy -run 'TestMapReason|Test.*FailClosed' -count=1`
- `KORDN_SOAK=1 make soak-leak`

Completion criteria:
- Returning from `Mapper.Map` guarantees repository-owned mapping work has stopped; no mapping goroutine outlives cancellation.
- Existing stable denial reasons remain compatible, with specific dependency/resource causes classified before generic wrappers.
- Mapper and proxy errors remain actionable but contain no credential, header, body, parameter, external ID, or token material.

### Task 6: Enforce RSS, compatibility, and provenance gates

Goal: Prove the complete refactor meets memory and request-path contracts and record the representation/version change without weakening existing thresholds.

Context:
- `strict-performance` and `strict-compatibility` already measure real RSS, throughput, and percentiles; their source tests are contract files, not tuning knobs for this work.
- Catalog schema, adapter, mapper, authorization-data, and release-snapshot version strings participate in audit and provenance assertions.

Files:
- Modify: `internal/iammap/iammap_bench_test.go` — add catalog-load/resident and staged-mapping measurements while preserving current hot-path benchmark names.
- Modify: `internal/awsrequest/awsrequest_bench_test.go` — retain indexed wire allocation/latency coverage if selector construction changes.
- Modify: `internal/iamlivecatalog/catalog_test.go` — assert compact representation invariants and release source identity.
- Modify: `internal/app/commands.go` — expose updated mapper/catalog metadata if version output snapshots require it.
- Modify: `internal/audit/schema_test.go` — update only expected mapper/catalog version metadata.
- Modify: `Makefile` — bump schema/catalog/adapter/mapper provenance values and keep strict targets unchanged.
- Modify: `third_party/iamlive/PROVENANCE.md` — document deterministic packaging without changing upstream provenance.
- Modify: `docs/decisions/0001-iamlive-integration.md` — record compact neutral catalog and reproducible packaging boundary.
- Modify: `docs/architecture.md` — document immutable compiled plans, typed request stages, and ownership boundaries.
- Modify: `docs/compatibility.md` — document unchanged compatibility and strict gates.
- Modify: `docs/quickstart.md` — retain accurate initialization instructions for source builds.
- Do not modify: `test/integration/performance_test.go` — ordinary strict source and thresholds.
- Do not modify: `test/compatibility/performance_test.go` — compatibility strict source and thresholds.

Steps:
- [ ] Add allocation/benchmark coverage for catalog load, retained compiled representation, exact wire selection, and staged mapping while retaining existing hot-path benchmark names and ceilings.
- [ ] Bump the catalog schema/catalog, adapter, mapper, and authorization-data versions together; update version output, audit snapshots, release-snapshot JSON, and cache/provenance assertions consistently.
- [ ] Document that the ignored compressed artifact is reproducible packaging of the same pinned evidence, not an independent authorization source, and that initialization remains the only network-capable phase.
- [ ] Run full unit, race, integration, compatibility, fuzz-smoke, soak/leak, build-matrix, security, and release-snapshot gates after the representation and evaluator changes are integrated.
- [ ] Run both strict suites with strict mode required and preserve their source files byte-for-byte; collect output proving ordinary RSS at most 80 MiB and compatibility RSS at most 150 MiB with existing latency/throughput thresholds.

Verification:
- `make benchmark-hotpath`
- `make fmt-check && make lint`
- `make test-race && make test-integration && make test-compatibility`
- `make fuzz-smoke && make security-check && make release-snapshot`
- `KORDN_STRICT_PERFORMANCE=1 make strict-performance`
- `KORDN_STRICT_PERFORMANCE=1 make strict-compatibility`
- `KORDN_SOAK=1 make soak-leak && KORDN_SOAK=1 make soak-leak-race`
- `git diff --exit-code -- test/integration/performance_test.go test/compatibility/performance_test.go`

Completion criteria:
- Ordinary strict RSS is at most 80 MiB and compatibility strict RSS is at most 150 MiB while all existing Section 21 latency and throughput gates pass.
- Golden, ambiguity, malformed-input, fuzz, timeout, allocation, no-widening, and fail-closed tests pass with unchanged strict threshold sources.
- Version output, audit metadata, release snapshot, and provenance consistently identify the compact catalog and preserve the exact upstream pin and selected-content hash.

## Cross-Task Verification

- `make iamlive-init && ./scripts/init-iamlive-submodule.sh --check && make iamlive-check`
- `make fmt-check && make lint && make test-race`
- `make test-integration && make test-compatibility && make benchmark-hotpath && make fuzz-smoke`
- `KORDN_STRICT_PERFORMANCE=1 make strict-performance`
- `KORDN_STRICT_PERFORMANCE=1 make strict-compatibility`
- `KORDN_SOAK=1 make soak-leak && KORDN_SOAK=1 make soak-leak-race`
- `make security-check && make release-snapshot`
- `git diff --exit-code -- test/integration/performance_test.go test/compatibility/performance_test.go`
- Confirm non-AWS CONNECT tests still prove opaque pass-through and no AWS request checker receives non-AWS plaintext.

## Risks and Mitigations

- Risk: Compressed packaging becomes stale, non-reproducible, or a second unreviewed data source.
  Mitigation: Generate only from the exact verified nested submodule, use fixed archive metadata and canonical paths, compare regeneration in `--check`, ignore the artifact, and hash original bytes.
- Risk: Parser peak allocations or Go allocator arenas keep RSS above 80 MiB even after retained graphs shrink.
  Mitigation: Stream bounded archive entries, release raw decode graphs as each canonical section is compiled, benchmark resident memory after each representation task, and use the unchanged strict suite as the final gate.
- Risk: String interning or compact IDs accidentally collapse duplicate evidence.
  Mitigation: Assign occurrence identity before normalization, store multiplicities explicitly, add source-to-index cardinality tests, and reconstruct public views in source order.
- Risk: Static validation in the catalog crosses into authorization policy.
  Mitigation: Limit catalog compilation to neutral source structure/agreement and typed evidence diagnostics; keep endpoint activation, ARN enforcement, authorization, and fail-closed interpretation in `internal/awsrequest`/`internal/iammap`.
- Risk: Per-operation diagnostics accidentally reject the complete pinned catalog or, conversely, allow an invalid operation.
  Mitigation: Distinguish fatal source-format failures from operation-scoped disagreements, require a compiled-valid marker before lookup, and pin the Lambda disagreement regression.
- Risk: Conditional dependency alternatives are treated as deduplicated sets or absence.
  Mitigation: Model definition-edge and mapping occurrences separately, attach tri-state applicability to every occurrence, and test duplicate applicable/inapplicable/unknown combinations.
- Risk: Removing runtime cross-checks places excessive trust in compiled data.
  Mitigation: Publish only immutable validated plans and retain independent wire identity, resource ARN/scope, applicability, result validation, and no-widening checks at the enforcement boundary.
- Risk: Cooperative cancellation checks are omitted from a long loop.
  Mitigation: Require context-aware stage interfaces, check context in every candidate/condition/resource/dependency walk, and use blocking/high-cardinality cancellation tests plus soak/leak gates.

## Open Questions

- None.
