# Eliminate Catalog Hot-Path Copies Implementation Plan

## Overview

Remove full iamlive catalog enumeration and deep copying from AWS request decoding and IAM mapping. Replace it with immutable, occurrence-preserving indexes built from the pinned catalog, while retaining Kordn's positive endpoint boundary, exact wire-version matching, defensive-copy API contracts, and fail-closed handling of absent, duplicate, or contradictory evidence.

Current HEAD `9630d3f` shows the decoder regression directly:

- `BenchmarkDecodeQuery`: `117949294 ns/op`, `33709304 B/op`, `225962 allocs/op`.
- `BenchmarkDecodeJSON`: `171618499 ns/op`, `89889949 B/op`, `602597 allocs/op`.
- The diagnostic 100-worker run reached local p50 `1226.171 ms`, p95 `4137.529 ms`, p99 `8495.312 ms`, `35.6` wall requests/second, and `1191.7 MiB` RSS.

`Catalog.Services()` deep-clones the complete 400-plus-service, 10,000-plus-operation catalog, including mappings and nested condition data. Decoder matchers call it multiple times per request, and the iamlive adapter calls it for each uncached mapping lookup. The implementation will move catalog traversal to bounded initialization and use narrow candidate sets during request processing.

## Source Spec

- Spec: User request in this session to implement recommendations 1-4 and 6 from the latency analysis, explicitly excluding recommendation 5 (performance-harness changes).
- Supporting contract: `docs/kordn-local-proxy-technical-spec.md`, Section 21.
- Supporting architecture: `docs/plans/20260830-remove-limited-aws-operation-matrix.md` and `AGENTS.md` catalog/security guidance.
- Status: Assumed; the explicit exclusion and existing security contracts are treated as normative.
- Last reviewed: 2026-09-04.

## Repository Context

- `internal/iamlivecatalog/catalog.go` — parses the pinned evidence once, owns normalized indexes, and currently exposes full defensive copies through `Services()` and `Operations()`.
- `internal/iamlivecatalog/types.go` — defines catalog records and deep-clone behavior for operations, mappings, maps, slices, and condition chains.
- `internal/iamlivecatalog/catalog_test.go` — pins catalog cardinality, occurrence retention, contradictory evidence, query bindings, and caller immutability.
- `internal/awsrequest/decode_json.go` — constructs the production decoder and repeatedly scans `wireCatalog.Services()` for protocol, envelope, JSON-target, and variant-target checks.
- `internal/awsrequest/decode_query.go` — scans all copied services to validate the exact service, API `Version`, protocol, and `Action` tuple.
- `internal/awsrequest/decode_restjson.go` — scans copied services and operations for REST method, URI-template, and modeled query-binding matches; REST-XML delegates to the same matcher.
- `internal/awsrequest/correction_test.go` — exercises exact target ownership, duplicate raw evidence, protocol disagreement, route conflicts, and injected malformed catalogs.
- `internal/awsrequest/awsrequest_bench_test.go` — contains the Query and JSON decoder benchmarks that exposed the regression.
- `internal/iammap/iamliveadapter/adapter.go` — scans `Catalog.Services()` in both request-aware and compatibility lookups before evaluating mappings, definitions, resources, and dependencies.
- `internal/iammap/iamliveadapter/adapter_test.go` — covers wire mismatch, contradictory operations, REST query bindings, conditional mappings, and occurrence-sensitive dependencies.
- `internal/iammap/adapter_crosscheck_test.go` and `internal/iammap/golden_wire_test.go` — verify independent mapper/catalog agreement and complete decoder-to-mapper behavior.
- `internal/iammap/iammap_bench_test.go` — measures production mapping behavior and must expose uncached adapter lookup cost after the scan is removed.
- `Makefile` — owns `benchmark`, `strict-performance`, and `strict-compatibility` commands after `iamlive-check`.
- `.github/workflows/ci.yml` and `.github/workflows/release.yml` — CI runs tests, while release verification enforces Section 21 latency, throughput, and memory targets.
- `docs/compatibility.md` — documents the reference-machine performance command and measured-release-gate status.

## Implementation Constraints

- Keep one local Go binary and one `kordn run` process; add no daemon, sidecar, or runtime metadata service.
- Keep `internal/iamlivecatalog` neutral. It may index and return pinned evidence, but it must not classify endpoints, authorize requests, or convert uncertainty into a permission.
- Keep `internal/awsrequest/endpoint.go` as the positive interception boundary. Catalog coverage must not broaden intercepted hosts.
- Keep public catalog outputs defensively copied. Do not make `Catalog.Services()`, `Operations()`, `Operation()`, `Actions()`, or new public selectors expose mutable internal slices, maps, or condition pointers.
- Preserve raw evidence occurrence counts. New indexes must retain equivalent records from distinct API models and versions; no deduplication may make an ambiguous request usable.
- Query and EC2 Query selection must include the exact endpoint service, modeled protocol, wire `Version`, and `Action`.
- REST selection must retain modeled input-shape query bindings as well as service, protocol, method, and URI. Unknown, missing-required, duplicate, or ambiguous query evidence must fail closed.
- JSON 1.0/1.1 selection must retain exact target prefix, operation, route, JSON version, and variant-target behavior.
- Preserve mapper tri-state dependency applicability and complete mapping/IAM-definition multisets. Candidate indexing must not cache a final result that depends on request parameters.
- Treat immutable shared indexes as read-only after construction. Publish them through `sync.Once` or constructor ownership; do not add request-path locks or mutable package state.
- Prepare the pinned catalog with `./scripts/init-iamlive-submodule.sh --check` before catalog-dependent tests and benchmarks.
- Keep Go `1.26.4`, offline build behavior, submodule pin/hash checks, and release provenance unchanged.

## Assumptions

- Production creates and reuses one configured decoder and mapper per run through `internal/app/runimpl/run.go`; package convenience decoding functions still need a shared default index so they do not rebuild it per call.
- A compact wire record needs service identity, API version, protocol metadata, target prefix, operation name/state, route fields, and query bindings. It does not need IAM mappings, action definitions, resources, or dependency conditions.
- Adapter lookup may copy the small candidate set selected by `(endpoint service, operation)` before parameter-dependent mapping evaluation; it must not copy or retain the complete catalog.
- Wall-clock benchmark thresholds remain reference-machine release checks. CI should gate structural behavior and broad allocation ceilings rather than enforce nanosecond limits on shared runners.

## Non-goals

- Modifying `test/integration/performance_test.go` or `test/compatibility/performance_test.go`, including their warm barriers, timing model, concurrency, thresholds, or fake-AWS behavior.
- Relaxing Section 21 latency, throughput, or RSS targets.
- Changing endpoint interception coverage, protocol support, authentication, SigV4 verification/resigning, policy behavior, audit durability, or AWS error responses.
- Replacing the pinned iamlive evidence, generating a separate hand-maintained AWS dataset, or changing catalog provenance.
- Returning catalog-owned mutable data to sibling packages to avoid copying.
- Caching parameter-dependent `LookupResult`, resource extraction, dependency applicability, or authorization decisions inside the catalog adapter.
- Tuning `GOMAXPROCS`, GC percentages, request concurrency, buffers, or connection pools before removing catalog-scale request work.

## Task Summary

1. Add compact occurrence-preserving catalog selectors.
2. Build and use an immutable decoder wire index.
3. Replace adapter catalog scans with indexed occurrence lookup.
4. Add allocation and benchmark regression gates.

## Implementation Tasks

### Task 1: Add compact occurrence-preserving catalog selectors

Goal: Let consumers obtain wire-only snapshots and exact raw operation occurrences without deep-copying the complete service/mapping graph on request paths.

Context:
- `Catalog.Services()` at `internal/iamlivecatalog/catalog.go:65` must remain defensive, but each call recursively clones operation mappings through `Service.Clone()` and `Operation.Clone()`.
- The normalized `Catalog.Operation()` index may collapse equivalent records. Decoder and mapper wire selection cannot use it where exact API versions and occurrence cardinality determine ambiguity.
- Catalog services are immutable after `parse()` attaches mapping states and computes the source hash, so occurrence indexes can safely store internal service/operation positions and clone only selected outputs.

Files:
- Modify: `internal/iamlivecatalog/types.go` — define compact wire evidence and service-operation occurrence result types with explicit clone helpers.
- Modify: `internal/iamlivecatalog/catalog.go` — add unexported occurrence indexes, build them after catalog assembly, and expose narrow defensive selectors.
- Test: `internal/iamlivecatalog/catalog_test.go` — verify cardinality, exact version retention, occurrence retention, and output immutability.

Steps:
- [ ] Add a compact `WireService`/`WireOperation` representation containing only endpoint prefix, API version, protocol/JSON metadata, target prefix, operation name/state, route, and copied query bindings; exclude mappings and IAM definitions.
- [ ] Add an unexported raw operation occurrence index keyed by normalized endpoint prefix and operation name. Store positions or equivalent immutable references to every `c.services[service].Operations[operation]` occurrence rather than values from the normalized/deduplicating `c.operations` index.
- [ ] Build the compact wire snapshot and occurrence index once at the end of `parse()`, after contradictory states and mappings have been attached. Pre-size maps and slices from known catalog cardinalities.
- [ ] Expose a defensive wire snapshot method for decoder initialization and an exact occurrence-selector method for adapter lookup. Clone only returned compact records or selected operations; never expose catalog-owned slices, maps, or condition pointers.
- [ ] Preserve deterministic ordering from sorted API paths, service order, and per-service operation order so duplicate counts and error outcomes do not depend on map iteration.
- [ ] Add tests showing repeated API-version records remain distinct, duplicate evidence is returned with the original multiplicity, unknown keys return zero candidates, and mutations to every returned slice/map/condition cannot affect later reads.
- [ ] Add a same-package cardinality assertion that the occurrence index contains exactly one entry for every operation held under `c.services`, including records that normalized lookup marks contradictory.

Verification:
- `./scripts/init-iamlive-submodule.sh --check`
- `go test ./internal/iamlivecatalog -count=1`
- `go test -race ./internal/iamlivecatalog -count=1`

Completion criteria:
- Decoder initialization can obtain all wire evidence without cloning any operation mappings or action definitions.
- Adapter lookup can obtain only the raw candidates for one endpoint-service/operation pair without calling `Catalog.Services()`.
- Existing public catalog immutability and catalog completeness tests continue to pass.
- Duplicate and contradictory evidence cardinality is unchanged.

### Task 2: Build and use an immutable decoder wire index

Goal: Reduce protocol and operation validation from repeated full-catalog clones/scans to lock-free lookups over one compact immutable index.

Context:
- A Query request currently reaches `Services()` through protocol authority, modeled-envelope validation, and exact action/version validation.
- JSON and REST requests use additional complete scans for target ownership, variant targets, or route candidates.
- `Decoder` instances are safe to reuse in concurrent proxy handlers when all configuration and index data remain immutable.

Files:
- Create: `internal/awsrequest/wire_index.go` — own compact key types, index construction, candidate lookup, and immutable default-index initialization.
- Modify: `internal/awsrequest/decode_json.go` — store the index on `Decoder`; replace protocol, envelope, target, and variant scans.
- Modify: `internal/awsrequest/decode_query.go` — validate exact Query/EC2 Query evidence through keyed candidates.
- Modify: `internal/awsrequest/decode_restjson.go` — obtain only REST candidates for the endpoint/protocol/method before URI and query-binding checks.
- Modify: `internal/awsrequest/correction_test.go` — migrate injected catalogs to explicit index construction and retain malformed/duplicate evidence cases.
- Test: `internal/awsrequest/wire_index_test.go` — cover index construction, keys, ambiguity, immutability, concurrency, and no request-time catalog enumeration.
- Test: `internal/iammap/golden_wire_test.go` and `test/integration/catalog_operations_test.go` — verify cross-package wire behavior remains unchanged.

Steps:
- [ ] Build maps for endpoint protocol evidence, Query tuples `(service, protocol, API version, action)`, JSON tuples `(service, protocol, target prefix, operation)`, and REST candidate groups `(service, protocol, method)`. Retain slices of candidates for zero/one/many decisions; never overwrite or deduplicate a prior occurrence.
- [ ] Precompute JSON variant-target evidence so `operationHasVariantTarget` does not perform a nested service/operation scan.
- [ ] Parse and validate modeled fixed route-query data during index construction where possible. Store an initialization error for malformed catalog evidence rather than reparsing catalog route strings on every request.
- [ ] Initialize the pinned default index once and share its immutable pointer across configured decoders and package convenience functions. Keep a non-global constructor for same-package tests; do not reset `sync.Once` state in tests.
- [ ] Change `Decoder.catalog` to an immutable wire-index dependency and propagate construction errors through the existing `configErr`/`NewConfiguredDecoder` path.
- [ ] Rewrite `authoritativeProtocolFor`, `validateModeledWireRoute`, `catalogQueryOperation`, `targetOperationFor`, `operationHasVariantTarget`, and REST matching entry points to use bounded candidate slices while preserving current validation order and error/evidence semantics.
- [ ] Keep endpoint reclassification, signing-service/region agreement, content-type precedence, exact `Version`, duplicate query rejection, route-before-body validation, and decoded failure evidence unchanged.
- [ ] Add structural tests with an instrumented source that permits catalog snapshot construction once and fails if a decode attempts source enumeration afterward.
- [ ] Add duplicate-candidate tests for Query versions, JSON target variants, and identical REST method/URI routes separated by required query bindings. Assert zero or multiple surviving candidates fail closed.
- [ ] Run concurrent decode tests under `-race` against one shared configured decoder to prove the index is read-only after publication.

Verification:
- `go test ./internal/awsrequest -count=1`
- `go test -race ./internal/awsrequest -count=1`
- `go test ./internal/iammap -run 'Test(Golden|Mapper|Catalog|Adapter)' -count=1`
- `go test ./test/integration -run 'TestCatalog' -count=1`

Completion criteria:
- No production `Decoder.Decode` path calls `Catalog.Services()`, a wire-snapshot method, or any full-catalog enumerator.
- Request-time candidate work is proportional to one exact-key bucket or one service/protocol/method REST bucket, not total catalog size.
- Exact raw evidence multiplicity and fail-closed error behavior match existing tests.
- One decoder can serve concurrent requests without locks, writes, or races in the wire index.

### Task 3: Replace adapter catalog scans with indexed occurrence lookup

Goal: Remove full-catalog copies from request-aware and compatibility IAM adapter lookups without caching parameter-dependent mapping results.

Context:
- `Adapter.LookupRequest()` at `internal/iammap/iamliveadapter/adapter.go:84` and `Adapter.Lookup()` at `:190` enumerate a deep copy of every service and operation.
- Proxy mapping caches make repeated identical decisions cheap, but the first request for each mapping key still pays the complete scan and can trigger large transient allocations.
- The catalog must remain evidence-only; `iamliveadapter` continues to own wire agreement, condition evaluation, resource extraction, dependency applicability, and `LookupResult` construction.

Files:
- Modify: `internal/iammap/iamliveadapter/adapter.go` — use the catalog occurrence selector and retain only bounded immutable candidate metadata.
- Test: `internal/iammap/iamliveadapter/adapter_test.go` — cover exact wire selection, duplicate occurrences, mapping-state failures, and parameter-dependent outcomes.
- Test: `internal/iammap/adapter_crosscheck_test.go` — preserve independent primary/dependency multiset checks.
- Test: `internal/iammap/golden_wire_test.go` — preserve production decoder-to-mapper behavior across protocols and API versions.
- Modify: `internal/iammap/iammap_bench_test.go` — distinguish indexed uncached adapter work from any higher-level repeated mapping/cache behavior.

Steps:
- [ ] Bind `Adapter` to the immutable catalog occurrence index during `New()`; remove both `a.catalog.Services()` loops.
- [ ] Select raw candidates first by endpoint service and normalized operation, then retain existing protocol, method, path, `Version`, target-prefix, JSON-version, REST URI, and query-binding checks.
- [ ] Treat zero selected records as unknown and multiple selected records as ambiguous exactly as today. Do not choose the first candidate or merge equivalent mappings.
- [ ] Deep-copy only selected operation evidence before parameter-dependent evaluation when required by the package boundary; do not retain caller-mutable values in shared index state.
- [ ] Keep `lookupOperation` evaluation per request. Do not cache conditions, resource ARNs, dependent applicability, or final results across parameter maps.
- [ ] Add tests proving two raw matching occurrences remain ambiguous, repeated names in different API versions select only through exact wire identity, and mutation of one lookup result cannot affect later lookups.
- [ ] Extend mapping benchmarks with a direct `LookupRequest` benchmark that varies parameters enough to exercise adapter evaluation rather than an outer decision cache.

Verification:
- `go test ./internal/iammap/iamliveadapter ./internal/iammap -count=1`
- `go test -race ./internal/iammap/iamliveadapter ./internal/iammap -count=1`
- `go test ./internal/iammap -run 'Test(GoldenMappings|NoScopeWidening|DependentPassRole|MapperRejectsInjected)' -count=1`

Completion criteria:
- Neither adapter lookup method calls `Catalog.Services()` or another complete catalog enumerator.
- Candidate selection preserves exact wire evidence and occurrence-sensitive ambiguity.
- Parameter-dependent resource and dependency behavior remains per-request and fail closed.
- Adapter and mapper golden/cross-check suites pass unchanged in outcome.

### Task 4: Add allocation and benchmark regression gates

Goal: Make catalog-scale request work observable in local comparisons and fail CI through stable structural/allocation contracts before it reaches release performance testing.

Context:
- Existing decoder and mapper benchmarks exposed the regression, but ordinary CI does not run them and Go benchmarks have no fail threshold.
- Shared CI runners are unsuitable for strict nanosecond gates. Allocation counts and “no catalog enumeration after initialization” behavior can use broad, deterministic test ceilings.
- Release verification already runs `strict-performance` and `strict-compatibility`; their source files are explicitly outside this plan.

Files:
- Modify: `internal/awsrequest/awsrequest_bench_test.go` — retain Query/JSON cases and add stable result sinks/setup helpers if needed.
- Modify: `internal/awsrequest/wire_index_test.go` — add broad allocation and post-initialization enumeration contracts.
- Modify: `internal/iammap/iammap_bench_test.go` — report direct indexed adapter lookup cost separately from production mapper behavior.
- Create: `scripts/bench-compare.sh` — run focused old/new benchmark samples and invoke an installed `benchstat` with actionable prerequisites.
- Modify: `Makefile` — add a focused `benchmark-hotpath` target without narrowing the existing complete `benchmark` target.
- Modify: `.github/workflows/ci.yml` — run the focused benchmark smoke after tests so benchmark failures and metrics are visible on pull requests.
- Modify: `docs/compatibility.md` — document focused local comparison and keep strict release measurements distinct from CI smoke.

Steps:
- [ ] Keep the existing Query and JSON benchmark names stable for historical comparison; ensure setup and catalog initialization remain outside timed sections and results cannot be compiler-elided.
- [ ] Add focused benchmarks for wire-index candidate lookup and direct request-aware adapter lookup, including an ambiguous/negative case that must remain fail closed.
- [ ] Add `testing.AllocsPerRun` tests with ceilings derived from repeated optimized runs and enough headroom for Go patch releases, but orders of magnitude below the current `225962`/`602597` allocations per decode.
- [ ] Add a structural spy test that fails if decode or adapter lookup invokes a complete catalog snapshot/enumerator after initialization; use this as the primary non-timing regression gate.
- [ ] Implement `scripts/bench-compare.sh` to accept baseline/candidate refs or pre-recorded files, run at least ten samples with `-benchmem`, and compare them through `benchstat`. Keep `benchstat` a documented developer prerequisite rather than adding an unpinned runtime dependency or network access to normal checks.
- [ ] Add `benchmark-hotpath` to `.PHONY`; run only the named decoder, wire-index, and adapter benchmarks with `iamlive-check`. Leave `benchmark` as the complete unfiltered suite.
- [ ] Add a CI step for `make benchmark-hotpath`. Treat benchmark command/test failures as fatal but publish timing as diagnostic output; rely on structural/allocation tests and release Section 21 checks for hard gates.
- [ ] Record the focused comparison command and reference-machine strict commands in `docs/compatibility.md`; do not present shared-runner numbers as product guarantees.
- [ ] Compare pre-change and post-change results with at least ten samples, retain the `benchstat` output in the implementing PR description or review artifact, and reject the change if catalog-copy allocations remain visible.

Verification:
- `make benchmark-hotpath`
- `./scripts/bench-compare.sh <baseline-ref> <candidate-ref>`
- `go test ./internal/awsrequest ./internal/iammap/... -count=10`
- `make fmt-check`
- `make lint`

Completion criteria:
- CI fails if request decoding or adapter lookup reintroduces complete catalog enumeration after initialization.
- Query/JSON decoder allocations fall by orders of magnitude from the recorded baseline, and focused benchmarks provide repeatable `benchstat` comparison.
- Existing complete benchmark and strict release commands remain available and unchanged in scope.
- Performance documentation distinguishes deterministic CI contracts from reference-machine release thresholds.

## Cross-Task Verification

- `./scripts/init-iamlive-submodule.sh --check`
- `make fmt-check`
- `make lint`
- `go test ./internal/iamlivecatalog ./internal/awsrequest ./internal/iammap/... -count=1`
- `go test -race ./internal/iamlivecatalog ./internal/awsrequest ./internal/iammap/... -count=1`
- `go test ./test/integration/... -count=1`
- `go test -tags compat ./test/compatibility -count=1`
- `make benchmark-hotpath`
- `make benchmark`
- `KORDN_STRICT_PERFORMANCE=1 make strict-performance`
- `KORDN_STRICT_PERFORMANCE=1 make strict-compatibility`
- Confirm `git diff -- test/integration/performance_test.go test/compatibility/performance_test.go` is empty.
- Confirm strict output meets Section 21: local p50 ≤ `3 ms`, p95 ≤ `10 ms`, p99 ≤ `25 ms`, throughput ≥ `500` requests/second at 100 connections, ordinary RSS ≤ `80 MiB`, and compatibility RSS ≤ `150 MiB`.

## Risks and Mitigations

- Risk: A keyed index accidentally deduplicates equivalent raw records and turns ambiguous evidence into an allowed operation.
  Mitigation: Store candidate slices, assert source/index cardinality, and test zero/one/many outcomes across repeated API versions.
- Risk: Returning internal index slices removes defensive-copy protection or introduces concurrent mutation races.
  Mitigation: Keep exported selector results copied, keep consumer indexes private and immutable after construction, and run shared-decoder/adapter tests under `-race`.
- Risk: Moving full service clones from requests to every decoder or adapter constructor still creates startup and RSS pressure.
  Mitigation: Build one shared compact wire index, exclude mapping/resource data from it, and use catalog-owned occurrence references to clone only adapter candidates.
- Risk: Index keys omit API `Version`, JSON version, target prefix, method, URI, or REST query bindings.
  Mitigation: Encode every authoritative wire discriminator in the key or candidate filter and retain existing cross-protocol/route-conflict tests.
- Risk: Caching adapter outputs reuses resource/dependency conclusions across different parameters.
  Mitigation: Index only immutable catalog candidates; run mapping conditions and extraction for every lookup.
- Risk: Allocation tests become brittle across Go releases.
  Mitigation: Pin CI Go `1.26.4`, use broad ceilings and structural spies as the main gate, and use `benchstat` for performance comparisons.
- Risk: Removing request allocation churn still does not meet the `80 MiB` RSS target because the embedded selected JSON is about `56.3 MiB` before parsed catalog structures.
  Mitigation: Keep the decoder index compact, avoid a second full mapping graph, measure strict RSS after the hot-path fix, and treat further catalog-representation work as a separately scoped change only if the unchanged release gate still fails.
- Risk: The unchanged warm barrier may still fail before reporting strict metrics.
  Mitigation: Do not alter it under this plan; record the failure separately and require an explicit follow-up plan if optimized request processing does not make the existing barrier pass.

## Open Questions

- None.
