# Third-party notices

Kordn's original code is MIT-licensed. The dependency source of truth is
[`go.mod`](go.mod), with integrity data in [`go.sum`](go.sum). We do not
maintain a second hand-written module/version inventory here. Transitive
modules are implementation details of the declared dependencies and are not
Kordn APIs.

Release archives include this file and the retained license texts required for
bundled runtime code. The license files are deduplicated by license text, not
by module.

## iamlive — MIT

Kordn uses the iamlive revision recorded in
`third_party/iamlive/UPSTREAM_COMMIT`. iamlive is MIT-licensed by Ian Mckay.
The exact MIT text is retained at `third_party/iamlive/LICENSE`, and the
upstream dependency notice is retained at `third_party/iamlive/NOTICE`. The
selected sparse gitlink data paths are `LICENSE`, `NOTICE`,
`iamlivecore/map.json`, `iamlivecore/iam_definition.json`, and
`iamlivecore/apis/**/api-2.json`. Kordn's neutral parser and typed request-value
adaptation preserve the full selected catalog; endpoint activation,
authorization, and fail-closed checks remain Kordn-specific. Exact upstream
revision and selected-content hashes are recorded in
`third_party/iamlive/PROVENANCE.md`. No upstream runtime, proxy, or credential
code is included.

## Retained runtime license texts

- `third_party/licenses/aws-sdk-v2/LICENSE` — Apache-2.0 text for the AWS
  SDK and its Smithy Go dependency.
- `third_party/licenses/go-yaml-v3/LICENSE` — YAML package terms, including
  Apache-2.0 and MIT terms for libyaml-derived files.
- `third_party/licenses/x-net/LICENSE` and
  `third_party/licenses/x-net/PATENTS` — Go networking package terms and
  patent grant.
- `third_party/licenses/go-bsd-3-clause/LICENSE` — shared BSD-3-Clause text
  for the runtime Go text package and compatible Go modules.

The JSON Schema validator and other test-only modules remain in the normal Go
module graph for tests, but are not bundled into the production binary or
maintained as Kordn runtime dependencies.

The project does not derive code from unlicensed `iam-agent-proxy`; no such
source is a dependency.

## Release provenance

Release archives carry `LICENSE`, this notice file, the retained license
texts, SHA256 checksums, a CycloneDX JSON SBOM, Cosign keyless signature, and
GitHub build provenance. The mapper integration is the embedded attributed
adapter based on iamlive commit
`3ec1a40e560c2f00ec82c50223add810e2567efb`, resolved 2026-08-18, with MIT text
and upstream notice retained. The authorization data version combines that commit and selected-content
SHA-256; it is exposed separately from catalog schema, mapper, and adapter
versions in `kordn version --json`. No copied AWS operation dataset or full
widening baseline is stored in Kordn.
