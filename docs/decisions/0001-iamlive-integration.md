# ADR 0001: iamlive integration boundary

- **Status:** accepted for Task 1; mapper implementation deferred to Task 6
- **Date:** 2026-08-18
- **Decision:** minimal, attributed derivation of the mapper data/logic needed by
  Kordn, isolated behind `internal/iammap/iamliveadapter`; do not import the
  upstream application package at runtime.

## Evidence evaluated

The upstream repository was inspected at the exact revision in
`third_party/iamlive/UPSTREAM_COMMIT`. Its Go module is
`github.com/iann0036/iamlive`. The exported `iamlivecore` surface is an
application runner (`Run`/`RunWithArgs`); request mapping and resource logic
are package-private, global-state oriented, and emit policy-generation
structures rather than Kordn's required typed `IAMRequirement` result. It
therefore cannot provide the required context cancellation, bounded execution,
independent endpoint/signature evidence, explicit `unresolved` scope, or
fail-closed mapper error boundary through a clean import.

## Alternatives rejected

1. **Direct import of iamlive:** rejected because its public API does not match
   the mapper contract and would pull an application/proxy lifecycle into the
   one-process Kordn composition root. A dependency that is present but unused
   would also falsely imply a supported integration.
2. **Copy the complete iamlive proxy/application:** rejected as unnecessary,
   too broad for enforcement, and contrary to the package boundary. No source
   is copied in Task 1.
3. **Use `iam-agent-proxy` source:** rejected. No applicable license grant was
   identified; its source must not be copied, translated, or used as a
   derivative implementation.
4. **Independent mapper with no provenance:** rejected because it would lose
   traceability for any iamlive-derived AWS mapping behavior and make future
   widening review ambiguous.

## Consequences and implementation boundary

Task 6 may derive only the smallest required mapping data/logic from the pinned
MIT iamlive revision and must preserve `third_party/iamlive/LICENSE` and
`NOTICE`, add provenance headers to substantially derived files, and keep all
Kordn authorization and fail-closed code outside
`internal/iammap/iamliveadapter`. Independently sourced AWS authorization data
will retain its own source and version.

The adapter must expose mapper/data versions, convert incomplete extraction to
`unresolved` rather than `*`, and contain panics/timeouts. A golden regression
suite will compare representative exact/set/known-global/unresolved mappings.
Any update that turns unresolved scope or a dependent action into an allowable
wildcard is a release-blocking widening change and requires an ADR/test review.
The `make license-check` gate and CI must remain green before mapper changes
land.
