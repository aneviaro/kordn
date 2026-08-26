# Kordn Local AWS Execution Proxy Implementation Plan

## Overview

Build the V0.1 Kordn local execution proxy as one Go binary. `kordn run -- <command>` will start a child with stable per-run fake AWS credentials and authenticated proxy settings, intercept TLS only for strictly recognized AWS endpoints, validate the child's SigV4 request, map the concrete request to enforcement-grade IAM requirements, apply an immutable deny-by-default local policy, return AWS-shaped local denials, and re-sign allowed requests with an upstream credential held only by Kordn.

This is a greenfield implementation. The repository currently contains only the source specification, so the plan establishes the project, test infrastructure, security and licensing boundaries, and release pipeline as well as the runtime.

## Source Spec

- Spec: `kordn-local-proxy-technical-spec.md`
- Status: Draft v0.1; treated as the normative implementation contract for this plan
- Last reviewed: 2026-08-18

## Repository Context

- `kordn-local-proxy-technical-spec.md` — sole existing repository artifact; defines the architecture, interfaces, package layout, security invariants, compatibility matrix, performance targets, and acceptance criteria.
- `internal/app/run.go` — planned composition root for startup ordering, fail-closed pipeline assembly, child lifecycle, and shutdown.
- `internal/proxy/server.go` — planned request boundary that separates opaque non-AWS tunneling from authenticated AWS interception.
- `internal/sigv4/verify.go` — planned authentication and integrity boundary for all intercepted AWS requests.
- `internal/iammap/mapper.go` — planned enforcement-grade conversion from decoded runtime calls to complete IAM requirements.
- `internal/policy/engine.go` — planned immutable, deny-by-default authorization boundary.
- `test/integration/fakeaws/server.go` — planned signature-validating upstream fixture used to prove that allowed requests are re-signed and denied requests never leave Kordn.

## Implementation Constraints

- Implement one local Go binary and one runtime architecture; do not add a daemon, remote broker, CLI-specific path, SDK-specific path, static-analysis authorization path, or LLM decision path.
- Pin an exact supported Go patch version and every direct dependency in `go.mod`; produce static binaries for macOS and Linux on `amd64` and `arm64`.
- Preserve the Section 17 interfaces and the Section 18 package ownership boundaries unless an implementation-driven change is recorded in `docs/architecture.md`. Only `internal/iammap/iamliveadapter` may directly import or contain substantially derived iamlive code.
- Resolve and fix the upstream profile/optional role before child launch. Never expose real credentials through the child environment, Kordn-managed files, arguments, logs, audit events, errors, or panic output.
- Bind the proxy to loopback, require a random per-run Basic proxy credential, and require a valid fake-credential SigV4 signature for every intercepted AWS request.
- Intercept only TLS requests to positively recognized commercial-partition AWS endpoints. Independently validate CONNECT authority and inner Host. Tunnel non-AWS HTTPS opaquely and reject proxy relay to loopback, metadata, link-local, multicast, unspecified, or unsafe DNS results.
- Support HTTP/1.1 and header-based `AWS4-HMAC-SHA256` in V0.1. Fail closed for SigV4a, query presigning, streaming chunk signatures, signed event streams, unknown protocols, unsupported payloads, and bodies above configured safe limits.
- Preserve `exact`, `set`, `known_global`, and `unresolved` resource scope as distinct types. Never convert an unresolved resource or dependent permission to `*`; all mapped requirements must be allowed.
- Load a strict, immutable local policy before launch. Explicit deny overrides allow; rule order is irrelevant; known-global wildcard allows require explicit acknowledgement.
- Accept every AWS decision into a bounded audit writer before considering it complete. With the default `failureMode: deny`, queue saturation or writer failure denies new AWS requests.
- Use normal public PKI verification for upstream AWS, including when chaining through a corporate proxy. Never install the per-run CA in a system trust store.
- Do not perform application-level AWS retries. Preserve upstream AWS response/error semantics except mandatory hop-by-hop header handling.
- License original code under Apache-2.0, preserve all MIT notices and exact provenance for iamlive-derived material, do not derive source from unlicensed `iam-agent-proxy`, scan dependencies, and generate release SBOM/provenance.
- Document the narrow proxy-boundary security claim and explicit same-user/direct-egress bypasses; V0.1 is not an OS sandbox.

## Assumptions

- Use module path `github.com/kordn-ai/kordn` until public repository ownership is finalized; changing the module path before the first public release is acceptable and must update generated provenance.
- Task 1 pins the newest stable Go patch supported by the release toolchain at implementation time and records it in both `go.mod` and `.go-version`; the draft spec intentionally does not choose a version.
- Use Cobra/pflag for the command tree and strict YAML decoding plus checked-in JSON Schemas for configuration and audit contracts, unless the initial dependency/license gate rejects either dependency.
- Prefer importing a pinned iamlive Go module behind `internal/iammap/iamliveadapter`. If the Task 1 spike proves its API unsuitable for fail-closed enforcement, vendor only the minimal attributed mapper/data subset and record the choice, source files, commit, and widening-regression gate in `docs/decisions/0001-iamlive-integration.md`.
- Use AWS SDK for Go v2 credential providers, STS, and upstream SigV4 signing. Independently verify inbound fake signatures because the SDK signer alone does not establish the inbound validation contract.
- The V0.1 default audit durability is bounded batch fsync, while `audit.fsync: decision` remains supported for high-assurance use and tests.
- Run real-AWS tests only in an opt-in, dedicated low-privilege account with uniquely tagged disposable resources; deterministic fake-upstream tests remain release-blocking in ordinary CI.
- Open endpoint/client compatibility questions are resolved by pinned fixtures and tests, not by broadening classification or allowing unknown requests.

## Non-goals

- Windows, browser/AWS Console access, GovCloud/China/ISO partitions, arbitrary custom endpoints, LocalStack production support, OS-level direct-egress prevention, filesystem sandboxing, or background descendants that outlive the root child.
- SigV4a, query-presigned requests, streaming-chunk uploads, AWS signed event streams, or CRT transports that cannot use the supported HTTP/1.1 path.
- Dynamic IAM/role creation, per-request STS sessions, child-selected profiles/roles, remote policy loading, policy hot reload, approvals, parameter predicates, CEL/Rego, raw IAM policy interpretation, or `unknown: allow`.
- Transactionality, rollback, or application-level retries across multiple AWS calls.
- Unauthenticated metrics/health endpoints, non-AWS authorization or payload inspection, and portable descendant-PID attribution.
- A V0.1 diagnostic bundle or Homebrew release before signed standalone binaries are reproducible.

## Task Summary

1. Bootstrap the repository and prove protocol/provenance choices.
2. Define strict configuration, schemas, and shared contracts.
3. Implement upstream credentials, fake identity, and child supervision.
4. Implement authenticated proxying, endpoint classification, and per-run PKI.
5. Verify inbound SigV4 and safely re-sign supported requests.
6. Decode AWS protocols and map complete IAM requirements.
7. Implement immutable policy decisions and AWS-shaped denials.
8. Add durable audit, bounded caches, observability, and assemble the CLI pipeline.
9. Build integration, compatibility, and adversarial release gates.
10. Harden performance and produce reproducible release artifacts.

## Implementation Tasks

### Task 1: Bootstrap the repository and prove protocol boundaries

Goal: Establish a buildable, legally clean Go project and retire the highest-risk protocol and mapper-integration unknowns with executable spikes and recorded decisions.

Context:
- The repository is greenfield and the specification requires Apache-2.0 original code, pinned Go/dependencies, iamlive MIT provenance, and no use of unlicensed `iam-agent-proxy` source.
- The first spike must prove both per-run-CA interception of an AWS-like TLS destination and byte-opaque non-AWS CONNECT tunneling without system trust-store changes.
- The iamlive integration form must be selected before mapper implementation so provenance and package boundaries do not have to be reconstructed later.

Files:
- Create: `go.mod`, `go.sum`, `.go-version` — module and exact toolchain/dependency pins.
- Create: `cmd/kordn/main.go`, `internal/app/commands.go` — buildable CLI entry point and command skeleton.
- Create: `Makefile`, `.gitignore`, `.github/workflows/ci.yml` — canonical format, vet, test, race, license, and build gates.
- Create: `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, `CONTRIBUTING.md` — project license, dependency provenance, disclosure process, DCO, and narrow security claim.
- Create: `third_party/iamlive/LICENSE`, `third_party/iamlive/NOTICE`, `third_party/iamlive/UPSTREAM_COMMIT` — exact MIT attribution and selected upstream revision.
- Create: `docs/threat-model.md`, `docs/architecture.md`, `docs/decisions/0001-iamlive-integration.md` — security boundary, one-process architecture, and import-versus-derived mapper decision.
- Create: `test/integration/proxy_spike_test.go`, `test/fixtures/sigv4/` — CONNECT/TLS proof and initial AWS-published SigV4 vectors.

Steps:
- [x] Initialize `github.com/kordn-ai/kordn`, pin an exact stable Go patch, add a minimal command tree, and define reproducible `make fmt`, `make lint`, `make test`, and `make test-race` targets used by CI.
- [x] Add Apache-2.0 licensing, DCO contribution guidance, vulnerability reporting, dependency license scanning, and explicit prohibition on deriving code from `iam-agent-proxy` without a license grant.
- [x] Implement an integration spike that starts a loopback CONNECT proxy, injects a test AWS endpoint classifier, presents a per-run CA leaf trusted only through the child CA setting, and reaches a test upstream without modifying system trust.
- [x] Add a second spike proving a non-AWS HTTPS destination retains its end-to-end server certificate and payload bytes through an opaque CONNECT tunnel.
- [x] Evaluate the pinned iamlive module against the required mapper inputs/outputs, choose import or minimal attributed derivation, populate all provenance files, and record rejected alternatives and the regression gate in ADR 0001.
- [x] Seed SigV4 canonicalization fixtures from AWS-published vectors without implementing production forwarding yet.

Verification:
- `make fmt-check && make lint && make test-race`
- `go test -race ./test/integration -run 'TestProxySpike_(InterceptAWSWithRunCA|TunnelNonAWSOpaque)'`
- `go list -m all` and the configured license-scan target report no unknown or disallowed licenses.

Completion criteria:
- A clean checkout builds `./cmd/kordn` with the pinned toolchain on macOS and Linux CI.
- The test AWS TLS path works only with the generated CA, while the non-AWS TLS certificate remains end-to-end.
- The mapper integration form, exact iamlive revision, copied/imported boundary, notices, and widening-regression strategy are concrete repository artifacts.
- Documentation states that proxy bypass and explicit same-user credential-file access are not prevented by V0.1.

### Task 2: Define strict configuration, schemas, and shared contracts

Goal: Make all startup inputs and cross-package request/decision contracts explicit, strictly validated, and testable before runtime components depend on them.

Context:
- Configuration and policy are one immutable `kordn.dev/v1alpha1` document loaded before the child starts.
- Unknown fields, unsafe ownership/modes, non-loopback listeners, absent explicit profiles, and unsupported policy features must fail startup.
- Shared request types must distinguish protocol, endpoint, payload mode, mapping confidence, resource scope, dependencies, and stable reason codes without stringly typed fallbacks.

Files:
- Create: `internal/config/schema.go`, `internal/config/load.go`, `internal/config/validate.go` — typed configuration, strict YAML loading, path expansion, ownership/mode and semantic validation.
- Create: `internal/config/config_test.go`, `internal/config/testdata/` — valid spec example and malformed/unsafe fixtures.
- Create: `internal/awsrequest/endpoint.go`, `internal/awsrequest/protocol.go`, `internal/awsrequest/types.go` — endpoint, verified/decoded request, protocol, payload, and mapper types.
- Create: `internal/policy/decision.go`, `internal/awserror/reasons.go` — decision types and stable reason-code constants.
- Create: `api/config.schema.json`, `api/audit.schema.json` — versioned machine-readable public contracts.
- Create: `examples/policies/deny-by-default.yaml` — safe configuration generated by `kordn init` later.

Steps:
- [x] Model upstream profile and optional fixed AssumeRole settings; proxy listen/upstream proxy/body limits; policy rules; and audit path/fsync/failure/redaction settings with secure defaults from the spec.
- [x] Implement strict YAML decoding, `apiVersion`/`kind` checks, canonical policy serialization/hash, symlink resolution, current-user ownership checks, rejection of group/world-writable policy files, and normalized path handling.
- [x] Reject non-loopback listeners, absent or ad hoc default profiles, `unknown: allow`, broad unsupported policy operators, invalid STS parameters, invalid body/cache bounds, and unsafe audit/runtime paths before any network or child action.
- [x] Define the Section 11 and 17 interfaces and immutable types in their owning packages, including typed scope kinds `exact`, `set`, `known_global`, `unresolved` and mapping confidence.
- [x] Define all minimum Section 15 reason codes as constants and ensure JSON Schemas constrain enums and reject extra fields consistently with Go decoding.
- [x] Add fixture tests proving the specification example validates, canonical hashes are stable, rule order does not alter policy identity semantics, and every malformed/unsafe case fails deterministically.

Verification:
- `go test -race ./internal/config ./internal/awsrequest ./internal/policy ./internal/awserror`
- Validate `examples/policies/deny-by-default.yaml` against `api/config.schema.json` using the repository's pinned schema-validation command.

Completion criteria:
- The valid spec configuration round-trips to typed values and a stable policy hash without unknown data loss.
- Every security-sensitive invalid input fails before credential resolution, listener creation, or child launch.
- Later packages can implement the published interfaces without redefining endpoint, protocol, mapping, decision, or reason-code concepts.

### Task 3: Implement credential isolation and child supervision

Goal: Resolve the fixed upstream authority ceiling before launch and run a supervised child that can discover only one stable fake credential and Kordn-controlled proxy/CA settings.

Context:
- Kordn's own provider and outbound proxy configuration must be captured before creating the child environment; process-wide AWS/proxy environment must not be mutated.
- V0.1 supports an explicit shared-config profile and at most one fixed optional AssumeRole step, with `GetCallerIdentity` required before launch.
- The root child runs in its own POSIX process group; startup failures never launch it, and fatal post-launch Kordn failures terminate the group.

Files:
- Create: `internal/credentials/provider.go`, `internal/credentials/assume_role.go`, `internal/credentials/identity.go`, `internal/credentials/fake.go` — upstream provider, optional role, preflight identity, and stable random fake credential.
- Create: `internal/runtime/sessiondir.go`, `internal/runtime/env.go`, `internal/runtime/child.go`, `internal/runtime/signals_unix.go` — private run state, synthetic files, environment construction, process groups, signal and exit handling.
- Create: `internal/runtime/credentials_test.go`, `internal/runtime/env_test.go`, `internal/runtime/child_test.go` — isolation, permissions, long-lived credential, argument, and lifecycle tests.
- Modify: `internal/app/commands.go` — enforce mandatory `--` and direct argv handling for `run`.

Steps:
- [ ] Build the AWS SDK for Go v2 provider from the explicit profile, optionally wrap it in one fixed AssumeRole provider, memoize refresh, and reject child-controlled profile/role inputs.
- [ ] Complete SSO/MFA/`credential_process` resolution and one `sts:GetCallerIdentity` preflight before child launch; retain only the provider and non-secret identity metadata.
- [ ] Generate cryptographically random run ID, clearly local fake access key, secret, session token, and Basic proxy credential that remain stable for the run.
- [ ] Create a `0700` per-run directory and `0600` synthetic AWS config/credentials files containing only fake credentials, selected Region, and Kordn CA reference; never modify user AWS files.
- [ ] Construct a dedicated child environment that sets every Section 7 variable, clears web-identity/container/role fallback variables, sets uppercase and lowercase proxy variables consistently, and leaves Kordn's own environment/transport unchanged.
- [ ] Execute the child argv directly, create a POSIX process group, forward interrupt/termination/resize signals, preserve healthy child exit status/signal, implement exits 78/70/126, bounded drain hooks, and abandoned-runtime cleanup.
- [ ] Add a long-lived child fixture that repeatedly inspects standard provider sources and confirms it sees the same fake credential while no real credential appears in environment, synthetic files, logs, or errors.

Verification:
- `go test -race ./internal/credentials ./internal/runtime`
- `go test -race ./internal/runtime -run 'TestChild_(StableFakeCredential|NoRealCredential|ArgvAndExitPropagation|SignalForwarding)'`

Completion criteria:
- Invalid config, unavailable credentials, failed identity preflight, or future proxy-start hook failure prevents child execution.
- The child and standard SDK provider inspection see only one stable fake credential and cannot accidentally fall back through standard metadata/container/web-identity variables.
- Root-child exits and signals propagate as specified; a Kordn safety failure terminates the child group and cleans private run state.

### Task 4: Implement authenticated proxying, endpoint classification, and per-run PKI

Goal: Provide an authenticated loopback proxy that strictly identifies supported AWS TLS destinations, terminates only those connections, and safely tunnels permitted non-AWS traffic.

Context:
- Proxy authentication and fake SigV4 are separate mandatory checks; proxy auth is rejected before destination handling.
- CONNECT authority and inner Host must independently normalize and match. Containment checks such as searching for `amazonaws.com` are forbidden.
- The proxy must not become an SSRF relay, must preserve corporate proxy chaining, and must advertise HTTP/1.1 only on intercepted TLS.

Files:
- Create: `internal/proxy/server.go`, `internal/proxy/connect.go`, `internal/proxy/auth.go`, `internal/proxy/tunnel.go`, `internal/proxy/transport.go`, `internal/proxy/limits.go` — listener, request auth, interception/tunneling, safe dialing, upstream proxy, and parser limits.
- Create: `internal/pki/ca.go`, `internal/pki/leafcache.go` — per-run CA and lazy exact-host leaf certificates.
- Modify: `internal/awsrequest/endpoint.go` — commercial partition regional/global/FIPS/dual-stack classification and normalized endpoint metadata.
- Create: `internal/cache/lru.go` — generic concurrency-safe bounded LRU used first for endpoint and leaf caches.
- Create: `internal/proxy/*_test.go`, `internal/pki/*_test.go`, `internal/awsrequest/endpoint_test.go` — authentication, lookalike, SSRF, certificate, cache, and tunnel tests.

Steps:
- [ ] Bind `127.0.0.1:0` by default, apply conservative header/request limits, require constant-time Basic proxy authentication on every request and CONNECT, and expose no unauthenticated endpoint.
- [ ] Normalize case, trailing dot, port, and IDNA safely; classify exact commercial AWS regional/global and required FIPS/dual-stack fixtures using label boundaries and explicit metadata, with stable negative caching.
- [ ] Validate that CONNECT authority and inner Host agree; reject plaintext AWS requests, unsupported partitions, custom endpoints, and mismatches rather than forwarding.
- [ ] Before any direct or corporate-proxy tunnel, resolve and reject literal or DNS results that are loopback, unspecified, multicast, link-local, metadata, or otherwise prohibited; defend against DNS answer changes during dialing.
- [ ] Tunnel non-AWS HTTPS as opaque bytes without logging paths/query/content and forward non-AWS plaintext only with standard hop-by-hop handling; keep non-AWS destination logging disabled by default.
- [ ] Generate a new per-run CA in private storage, issue short-lived SAN-only exact-host leaves lazily, advertise ALPN `http/1.1`, bound the leaf cache, and remove CA/key material on shutdown or stale-run cleanup.
- [ ] Build a separate outbound transport from the captured parent corporate proxy and system/public roots; prove it never reads child-local proxy variables or disables certificate validation.

Verification:
- `go test -race ./internal/proxy ./internal/pki ./internal/awsrequest ./internal/cache`
- `go test -race ./internal/proxy -run 'TestProxy_(RequiresAuthBeforeLookup|RejectsUnsafeDestinations|TunnelsNonAWSOpaque|InterceptsRecognizedAWS|RejectsHostMismatch)'`

Completion criteria:
- Missing/invalid proxy authentication causes no destination resolution or connection.
- `amazonaws.com.evil.example`, unsupported partitions, unsafe IPs/DNS answers, and CONNECT/Host mismatch never enter AWS interception or unsafe forwarding.
- Recognized AWS TLS is intercepted with the per-run CA over HTTP/1.1; non-AWS certificates and bytes remain end-to-end.
- CA keys and synthetic certificate files have required modes and are cleaned without system trust-store changes.

### Task 5: Verify inbound SigV4 and safely re-sign supported requests

Goal: Authenticate and integrity-check every intercepted AWS request using the run's fake credential, then strip fake material and create a valid upstream SigV4 request without hidden operation retries.

Context:
- Header-based `AWS4-HMAC-SHA256` is the only required V0.1 mode, with default clock skew ±5 minutes.
- Path, query, signed headers, payload hash, endpoint service/Region, key, token, and HMAC must all agree before decoding/mapping.
- Request bodies default to 8 MiB in memory and 64 MiB spooled; unsupported streaming/event modes fail closed.

Files:
- Create: `internal/sigv4/canonical.go`, `internal/sigv4/verify.go`, `internal/sigv4/payload.go`, `internal/sigv4/resign.go` — canonicalization, inbound validation, body lifecycle, and upstream signer.
- Modify: `internal/proxy/transport.go`, `internal/proxy/limits.go` — public-PKI upstream request path, body spool lifecycle, response streaming, and no-retry semantics.
- Create: `internal/sigv4/*_test.go`, `internal/sigv4/*_fuzz_test.go` — AWS vectors, tampering, canonicalization, payload, and parser coverage.
- Extend: `test/fixtures/sigv4/` — header/query/path/token/body and unsupported-mode golden fixtures.
- Create: `test/integration/fakeaws/sigv4.go`, `test/integration/resign_test.go` — known-key signature-validating upstream and fake-material leak assertions.

Steps:
- [ ] Parse and validate fake access key, session token, credential date/Region/service/terminator, signed-header presence, request time, canonical URI/query/headers, payload mode/hash, and final HMAC in constant-time-sensitive comparisons.
- [ ] Cross-check signing service and Region against endpoint classification, including explicitly modeled global rules; classify malformed credentials separately from unsupported signing modes.
- [ ] Reject SigV4a, query presigning, streaming chunks, event streams, anonymous/unrecognized auth, timestamps outside skew, unsupported payload modes, and oversized requests before mapping or upstream I/O.
- [ ] Implement bounded memory buffering and private `0600` spooling with early unlink where supported; allow unchanged streaming only for explicitly modeled `UNSIGNED-PAYLOAD` or precomputed hashes.
- [ ] For allowed-ready requests, remove inbound authorization/token/query signing and proxy/hop-by-hop headers, preserve semantic method/target/parameters/body, refresh date/token, and sign with the current memoized upstream credential via AWS SDK v2 primitives.
- [ ] Forward only to the original recognized AWS hostname with public PKI validation, stream responses, preserve AWS bodies/request IDs, and retry only connection establishment proven to have sent no application bytes.
- [ ] Assert the upstream fixture accepts the new signature and never observes fake access key, token, authorization, proxy auth, or identity-altering forwarding headers.

Verification:
- `go test -race ./internal/sigv4 ./internal/proxy ./test/integration -run 'SigV4|Resign|Payload'`
- `go test ./internal/sigv4 -run '^$' -fuzz=FuzzCanonicalRequest -fuzztime=30s`

Completion criteria:
- Every specified path/query/header/token/time/body tampering case fails before decode/map/forward with the correct stable reason class.
- Valid fake-signed fixture requests are re-signed with the test upstream key and accepted while all fake authentication material is absent upstream.
- Unsupported or oversized payloads fail closed and all spool resources are removed.
- Proxy transport cannot replay an ambiguous mutation or recursively route through itself.

### Task 6: Decode AWS protocols and map complete IAM requirements

Goal: Convert every supported, verified runtime request into a high-confidence and complete set of IAM action/resource/dependency requirements with pinned provenance and fail-closed unknown behavior.

Context:
- Required protocols are AWS JSON 1.0/1.1, AWS Query, EC2 Query, REST-JSON, and supported non-streaming REST-XML.
- Service and operation evidence can come from endpoint metadata, credential scope, target headers, URI templates, and Action fields; disagreement is an error.
- iamlive-derived behavior is not automatically enforcement-grade. Known AWS wildcard scope must remain different from incomplete resource extraction.

Files:
- Create: `internal/awsrequest/decode_json.go`, `internal/awsrequest/decode_query.go`, `internal/awsrequest/decode_restjson.go`, `internal/awsrequest/decode_restxml.go` — bounded protocol decoders.
- Create: `internal/awsrequest/decode_*_test.go`, `test/fixtures/awsrequest/` — protocol and disagreement fixtures.
- Create: `internal/iammap/mapper.go`, `internal/iammap/normalize.go`, `internal/iammap/resources.go`, `internal/iammap/dependencies.go` — mapper boundary, canonical actions/ARNs, resource extraction, and conditional dependencies.
- Create: `internal/iammap/iamliveadapter/adapter.go` and selected attributed adapter files — sole direct iamlive integration boundary.
- Create: `internal/iammap/data/version.go`, `internal/iammap/data/authorization.json`, `internal/iammap/data/generate.go` — pinned AWS authorization snapshot, generation provenance, and exposed versions.
- Create: `internal/iammap/*_test.go`, `internal/iammap/testdata/` — golden mappings and widening regression fixtures.
- Modify: `THIRD_PARTY_NOTICES.md`, `third_party/iamlive/*` — final copied/imported dependency notices and exact revision.

Steps:
- [ ] Decode operation and only the bounded request parameters needed for mapping for all required protocols, retaining typed evidence and rejecting malformed, duplicate, conflicting, or over-limit values.
- [ ] Require independent endpoint/scope/protocol evidence to agree on service, operation, Region, and partition; return no mapping when they disagree.
- [ ] Implement the ADR-selected iamlive adapter behind `IAMMapper`, contain panics/timeouts, normalize canonical IAM action spelling, and expose mapper/iamlive/data versions in every result.
- [ ] Pin the AWS machine-readable Service Authorization Reference snapshot at build time, document/generate it reproducibly, forbid runtime metadata fetches, and add a diff gate that flags newly globalized or broadened mappings.
- [ ] Extract and validate exact ARN or finite ARN sets with partition/Region/account context; emit `known_global` only from authoritative action metadata and `unresolved` for incomplete request-specific scope.
- [ ] Return every modeled IAM action and conditional dependency, including at least one request-aware `iam:PassRole` case; unresolved applicability fails closed rather than omitting the dependency.
- [ ] Add golden fixtures for representative EC2, ECS, STS, S3, CloudWatch, CloudWatch Logs, IAM, Lambda, and DynamoDB requests plus unknown/stale/malformed/panic/timeout cases.

Verification:
- `go test -race ./internal/awsrequest ./internal/iammap`
- Run the mapper-data regeneration/check command and confirm no uncommitted output.
- `go test ./internal/iammap -run 'TestGoldenMappings|TestNoScopeWidening|TestDependentPassRole|TestUnknownFailsClosed'`

Completion criteria:
- Every required protocol maps representative operations to versioned, high-confidence action/resource/dependency sets.
- Exact/set/known-global/unresolved results remain distinguishable in types, fixtures, cache inputs, and serialized evidence.
- Unknown endpoints/operations/resources/dependencies, conflicting evidence, malformed ARNs, timeouts, and panics produce no forwardable result.
- iamlive and AWS data provenance is complete and automated mapping updates cannot silently widen behavior.

### Task 7: Implement immutable policy decisions and AWS-shaped denials

Goal: Evaluate complete IAM requirement sets deterministically and return protocol-native local access denials with stable, non-secret diagnostics.

Context:
- A request is atomic: every action/resource/dependency combination must be allowed, and one explicit deny rejects all of it.
- Known-global actions require resource `*` plus `allowAwsRequiredWildcard: true`; unresolved scope can never be approved.
- Rule ordering is non-semantic, action glob matching is case-insensitive, and resource matching is bytewise case-sensitive in V0.1.

Files:
- Create: `internal/policy/glob.go`, `internal/policy/engine.go` — shared `*`/`?` matcher and deny-by-default evaluator.
- Modify: `internal/policy/decision.go` — complete immutable inputs/results, matched rule IDs, and stable reasons.
- Create: `internal/policy/engine_test.go`, `internal/policy/glob_test.go`, `internal/policy/policy_fuzz_test.go` — precedence, all-requirement, wildcard, ordering, and bounds tests.
- Create: `internal/awserror/encode.go`, `internal/awserror/json.go`, `internal/awserror/xml.go` — AWS JSON, REST-JSON, Query/EC2 Query, and REST-XML/S3 denial encoders.
- Create: `internal/awserror/encode_test.go` — protocol headers/body/status and secret-leak fixtures.

Steps:
- [ ] Implement one bounded glob matcher used by action/resource rules with the specified case semantics and exact Region/account/partition constraints.
- [ ] Reject non-high confidence and unresolved requirements first; evaluate every requirement/resource combination without rule-order dependence; apply explicit deny precedence and require positive allow coverage for all combinations.
- [ ] Require explicit known-global wildcard acknowledgement and ensure an allow for one resource, dependency, Region, account, or partition cannot cover another through cache-key or normalization mistakes.
- [ ] Canonically sort requirement/rule output for stable hashes, decision cache keys, events, and tests without making rule order meaningful.
- [ ] Encode local HTTP 403 responses for AWS JSON 1.0/1.1, REST-JSON, Query/EC2 Query, and REST-XML/S3 with only service, operation, reason code, and opaque event ID.
- [ ] Preserve the distinction between local deny, upstream access denied, and upstream error, and ensure policy denials themselves do not force Kordn's process exit status.
- [ ] Add property/fuzz tests for rule-order invariance, deny dominance, complete requirement coverage, wildcard acknowledgement, and response parseability by representative clients.

Verification:
- `go test -race ./internal/policy ./internal/awserror`
- `go test ./internal/policy -run '^$' -fuzz=FuzzRuleOrderInvariant -fuzztime=30s`

Completion criteria:
- Reordering rules cannot alter a decision; explicit deny always wins and every mapped requirement must have valid allow coverage.
- No policy can convert unresolved scope/dependency or low confidence into allow, and known-global wildcard requires explicit acknowledgement.
- AWS CLI/SDK protocol parsers recognize each local denial as access denied, and denial content contains no policy path, credential data, stack, or request body.

### Task 8: Assemble audit, caches, observability, and the CLI runtime pipeline

Goal: Compose the production verify → decode → map → decide → audit → re-sign pipeline with durable local evidence, bounded concurrency, complete CLI UX, and fail-closed lifecycle behavior.

Context:
- Each request has immutable context; caches and upstream provider are concurrency-safe; one bounded writer goroutine serializes audit.
- A decision is not complete until accepted by the audit queue. Under default failure mode, queue saturation/writer failure blocks new AWS requests.
- `kordn run` is the only protected runtime command, but V0.1 also requires `init`, policy validation, identity, audit query, and version commands.

Files:
- Create: `internal/audit/event.go`, `internal/audit/jsonl.go`, `internal/audit/redact.go`, `internal/audit/summary.go` — schema types, `0600` JSONL writer, centralized redaction, run summary/query support.
- Create: `internal/audit/*_test.go`, `internal/audit/testdata/` — schema, failure/backpressure, durability, secret scanning, and resource-hashing tests.
- Create: `internal/observe/metrics.go`, `internal/observe/metrics_test.go` — in-memory counters/histograms and exit-summary snapshots.
- Modify: `internal/cache/lru.go` — mapping metadata and decision caches with complete keys and observable non-secret stats.
- Modify: `internal/proxy/server.go` — complete per-request pipeline and local/upstream response handling.
- Modify: `internal/app/run.go`, `internal/app/commands.go`, `cmd/kordn/main.go` — startup ordering, shutdown, commands, output, and exits.
- Modify: `api/audit.schema.json`, `examples/policies/deny-by-default.yaml` — final event contract and `init` content.
- Create: `internal/app/*_test.go`, `test/integration/pipeline_test.go` — startup, fail-closed, CLI, request, audit, and shutdown tests.

Steps:
- [ ] Implement all Section 14 event types and fields, append-only `0600` JSONL storage, schema versioning, configurable batch/decision fsync, bounded queue, flush, and writer-failure state.
- [ ] Centralize redaction for logs/audit/errors; remove authorization, proxy auth, tokens, keys, bodies, cookies, presigned signatures, raw environment, and default command arguments; support deterministic resource-name hashing.
- [ ] Add endpoint, leaf, static operation metadata, and decision caches scoped to a run; include mapper version, policy hash, normalized complete requirements, partition, Region, account, and resource identity in relevant keys.
- [ ] Assemble the production pipeline so invalid authentication never maps, denied/unknown requests are audited before AWS-shaped response, allowed requests are audited before forwarding, and audit unavailability causes `audit_unavailable` with no upstream request.
- [ ] Implement request/connection concurrency, bounded mapper timeouts, one shared credential provider, graceful drain/flush timeout, listener closure, child-group termination on fatal safety failure, and cleanup ordering.
- [ ] Implement `init`, `run`, `policy validate`, `identity`, `audit`, and `version`; enforce mandatory `--`; print identity/bypass warning/startup, concise denials, and TTY exit summary while honoring quiet/verbose flags.
- [ ] Add local metrics from Section 22 to `run.ended` and exit output without exposing an HTTP endpoint or credential/resource secrets.
- [ ] Prove the final startup order: validate config/policy → resolve/preflight identity → create run secrets/CA → start audit and proxy → construct environment → launch child; any prerequisite failure leaves the child unexecuted.

Verification:
- `go test -race ./internal/... ./test/integration -run 'Pipeline|Audit|CLI|Startup|Shutdown'`
- Validate emitted fixtures against `api/audit.schema.json` and run the repository secret-scanning test over captured stdout, stderr, audit, and errors.
- `go run ./cmd/kordn init` in an isolated HOME, followed by `go run ./cmd/kordn policy validate --config <isolated-config>`.

Completion criteria:
- Denied, unknown, unauthenticated, unsupported, and audit-failed requests never reach the signature-validating upstream fixture.
- Every accepted AWS decision has one schema-valid audit event; flush completes before healthy exit and no accepted events are silently dropped.
- Cache keys cannot cross policies, mapper versions, resources, Regions, accounts, or partitions and all caches remain bounded under concurrency.
- Every required CLI command and exit code behaves as specified, and `run` is the sole protected launch path.

### Task 9: Build integration, compatibility, and adversarial release gates

Goal: Prove the complete runtime against required producers, protocol/error behaviors, corporate-proxy routing, sequential calls, and documented attacks on macOS and Linux.

Context:
- Deterministic CI uses a recognized injected test endpoint that validates upstream signatures and records every received request; real AWS tests are opt-in and low privilege.
- Release-blocking producers are AWS CLI v2, long-lived boto3/botocore, Terraform AWS provider, AWS SDK for Go v2, Claude Code, and Codex, with exact tested versions recorded.
- Bypass tests document limits; they must not be misrepresented as contained attacks.

Files:
- Create: `test/integration/fakeaws/server.go`, `test/integration/fakeaws/protocols.go`, `test/integration/fakeaws/state.go` — signature validation, modeled responses, request ledger, failures, and stateful sequences.
- Create: `test/integration/security_test.go`, `test/integration/lifecycle_test.go` — no-forward, no-leak, replay, writer/proxy failure, cleanup, and partial execution.
- Create: `test/compatibility/awscli_test.go`, `test/compatibility/boto3_test.go`, `test/compatibility/terraform_test.go`, `test/compatibility/gosdk_test.go`, `test/compatibility/agents_test.go`, `test/compatibility/corporate_proxy_test.go` — pinned producer scenarios.
- Create: `test/compatibility/fixtures/`, `test/compatibility/versions.json` — scripts/configs and exact client/provider versions.
- Create: `test/realaws/realaws_test.go`, `test/realaws/README.md` — opt-in tagged test account contract and disposal controls.
- Create: `docs/compatibility.md` — generated/synchronized matrix, supported endpoints/protocols, explicit limitations, and open-question outcomes.
- Modify: `.github/workflows/ci.yml`, `Makefile` — tagged compatibility, OS/architecture build, and nightly real-AWS jobs.

Steps:
- [ ] Complete the fake AWS server with known real test key validation, AWS JSON/Query/REST response fixtures, request ledger, latency/disconnect/403/429/5xx injection, and stateful sequential resources.
- [ ] Add AWS CLI allow/read/mutation/deny/unknown cases and verify recognizable local denial plus unmodified upstream errors/request IDs.
- [ ] Reuse one boto3 client for at least 30 minutes and one Go SDK v2 client across allowed/denied calls, transparent upstream credential refresh, streaming response, and SDK-owned retry after upstream 429.
- [ ] Run Terraform `init` through opaque registry tunnels, then sandboxed `plan` and narrow `apply` through AWS interception, including a later denied call and accurate partial audit.
- [ ] Add the A-read/B-derived-write/C-denied sequence and prove A/B remain complete, C never reaches upstream, and audit records runtime-resolved resources without claiming rollback.
- [ ] Wrap pinned Claude Code and Codex smoke fixtures that launch AWS CLI and boto3 subprocesses, inherit Kordn settings, preserve non-AWS agent API TLS, and surface local denial to agent and terminal.
- [ ] Test corporate proxy chaining, public PKI validation, proxy reconnection credentials, FIPS/dual-stack/global fixtures, non-AWS tunneling, response streaming, and no recursive local proxy routing.
- [ ] Add adversarial cases for wrong/real key, guessed proxy, replay outside skew, endpoint lookalike, direct-connect/unset proxy, explicit original credential-file read, killed audit writer, and killed proxy; label direct bypass/file access as documented limitations.
- [ ] Generate `docs/compatibility.md` from pinned versions/results and gate macOS/Linux CI plus `amd64`/`arm64` buildability; keep real-account tests credential-gated and destructive-resource bounded.

Verification:
- `make test-integration`
- `make test-compatibility` (or `go test -tags=compat ./test/compatibility/...` after required external clients are installed)
- `go test -tags=realaws ./test/realaws/...` in the dedicated nightly account only.
- CI matrix builds/tests on macOS and Linux and cross-builds all four release targets.

Completion criteria:
- AWS CLI, boto3, Terraform, and Go SDK v2 all use the same proxy and satisfy stable-client, allow/deny, streaming, and error compatibility requirements.
- Claude Code/Codex inheritance smoke tests pass on macOS and Linux with non-AWS TLS remaining opaque.
- Denied/unknown/adversarial requests visible to Kordn do not reach the fake upstream, and direct bypass limitations are explicitly demonstrated and documented.
- Exact client versions and endpoint variants are published from the release-blocking matrix.

### Task 10: Harden performance and produce reproducible releases

Goal: Meet the security, leak, latency, throughput, memory, and legal release gates and publish reproducible signed binaries with accurate user documentation.

Context:
- Cached local processing targets are p50 ≤3 ms, p95 ≤10 ms, p99 ≤25 ms; uncached leaf generation p95 ≤25 ms; throughput ≥500 ordinary requests/s at 100 connections.
- Idle memory must be ≤80 MiB, compatibility memory ≤150 MiB excluding spools, and 10,000 mixed requests must leak no goroutines, file descriptors, or temporary files.
- Release artifacts require checksums, signatures, SBOM, provenance, license report, mapper/data versions, and narrow threat-model wording.

Files:
- Create/extend: `internal/sigv4/*_bench_test.go`, `internal/awsrequest/*_bench_test.go`, `internal/iammap/*_bench_test.go`, `internal/policy/*_bench_test.go`, `internal/audit/*_bench_test.go`, `internal/pki/*_bench_test.go` — required microbenchmarks.
- Create: `test/integration/soak_test.go`, `test/integration/leak_test.go`, `test/integration/performance_test.go` — 10,000-request resource checks and target gates.
- Extend: package `*_fuzz_test.go` files — HTTP parsing, SigV4, decoders, mapper inputs, ARN construction, policy, and redaction fuzzing.
- Create: `.github/workflows/release.yml`, `.goreleaser.yaml` — reproducible cross-platform builds, checksums, signing, SBOM, provenance, and publishing.
- Create: `README.md`, `docs/quickstart.md`, `docs/security-review-checklist.md` — installation, safe example policies, security invariants, authority-ceiling guidance, limits, and review gate.
- Modify: `SECURITY.md`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `docs/threat-model.md`, `docs/architecture.md`, `docs/compatibility.md` — final disclosure, provenance, behavior, and claims.
- Modify: `cmd/kordn/main.go`, `internal/app/commands.go` — complete `version --json` build/dependency/mapper provenance.

Steps:
- [ ] Add benchmarks for canonicalization/verification, re-signing, JSON/Query decoding, extraction, 10/100/1,000-rule policy matching, decision cache hit/miss, JSONL serialization, and leaf generation/cache hit.
- [ ] Add load tests for 100 concurrent connections and at least 500 ordinary requests/s, startup and local latency percentiles, idle/compatibility memory, and bounded audit behavior.
- [ ] Run 10,000 mixed requests and compare goroutines, file descriptors, heap, cache sizes, audit queue, and temp files before/after bounded settling; fail on material leaks.
- [ ] Run race, vet, fuzz-smoke, secret scan, dependency/license vulnerability checks, mapper widening checks, compatibility tests, and security-invariant checklist as release prerequisites.
- [ ] Build reproducible static macOS/Linux `amd64`/`arm64` binaries; attach checksums, signatures, SBOM, build provenance, dependency/license report, and exact mapper/AWS data versions.
- [ ] Document installation, deny-by-default initialization, dedicated limited upstream-role guidance, supported/unsupported compatibility, audit handling, corporate proxy behavior, and the prominent direct-bypass warning.
- [ ] Make `kordn version --json` report binary/toolchain version, commit, target, direct dependencies, iamlive commit/integration form, and AWS authorization-data snapshot without secrets.
- [ ] Reconcile every Section 20 invariant and Section 26 acceptance criterion to an automated test or explicit release checklist item; require a threat-model update and security review for any exception.

Verification:
- `make fmt-check lint test-race test-integration test-compatibility benchmark security-check license-check release-snapshot`
- `go test -run=^$ -bench=. -benchmem ./...`
- `go test -race ./...`
- Run the 10,000-request soak and performance gate on the documented reference developer machine; archive benchmark and pprof summaries with release CI artifacts.
- Install each snapshot artifact in a clean macOS/Linux environment and complete `docs/quickstart.md` without source checkout or system trust-store changes.

Completion criteria:
- All Section 21 target percentiles, throughput, memory, and leak limits pass or the release is blocked pending an explicitly approved spec change.
- All 22 V0.1 acceptance criteria have a passing automated test or named, repeatable release check.
- Release artifacts are reproducible, signed, checksummed, SBOM/provenance complete, and include every required license notice.
- Public documentation accurately promises request-boundary enforcement only and provides no implication of direct-egress or same-user containment.

## Cross-Task Verification

- `make fmt-check lint test-race test-integration test-compatibility security-check license-check`
- `go test -race ./...`
- `go test -run=^$ -bench=. -benchmem ./...`
- Verify `go generate`/mapper-data generation and JSON Schema generation/check commands leave the worktree clean.
- Run a clean-room quickstart on macOS and Linux: initialize deny-by-default config, start `kordn run -- aws sts get-caller-identity`, allow one scoped operation, deny another, inspect schema-valid audit, and confirm no system trust-store modification.
- Run the sequential A/B/C fixture and verify A/B complete, C is locally denied, C is absent from the upstream ledger, and all three outcomes are accurately audited.
- Scan child environment, runtime files, stdout/stderr, logs, audit events, local errors, and fake-upstream captures for fake/real secrets; no prohibited credential or authorization material may appear.
- Confirm exact tested producer versions, mapper version, iamlive commit, AWS authorization snapshot, build provenance, security limitations, and license notices are present in release artifacts and documentation.

## Risks and Mitigations

- Risk: iamlive APIs or data encode policy-generation assumptions that are unsafe for request enforcement.
  Mitigation: Isolate integration behind one adapter, pin exact provenance, preserve typed unresolved scope, add widening golden tests, and fail closed on adapter error/panic/timeout.
- Risk: Endpoint evolution causes false positives that intercept non-AWS TLS or false negatives that bypass visible enforcement.
  Mitigation: Use explicit partition metadata and label-boundary normalization, independently match CONNECT/Host, pin compatibility fixtures, fail closed for AWS-like unsupported forms, and never broaden from substring matching.
- Risk: AWS SDK canonicalization differences reject legitimate clients or allow tampered requests.
  Mitigation: Use AWS-published vectors, cross-client fixtures, fuzz duplicate/path/query cases, validate all signed inputs, and verify re-signed requests with an independent known-key upstream.
- Risk: A corporate proxy creates recursion or weakens TLS verification.
  Mitigation: Capture parent proxy settings before child environment creation, build a separate outbound transport, prohibit local child proxy reuse, and test TLS-inspecting proxy trust explicitly without disabling public PKI checks.
- Risk: Some pinned Terraform, Go, agent, or CRT paths do not honor proxy Basic auth or `AWS_CA_BUNDLE` consistently.
  Mitigation: Make exact-version compatibility tests release-blocking, document unsupported transport variants, and reject/fail closed rather than adding a second runtime architecture.
- Risk: Mapper coverage or conditional dependencies lag AWS service changes.
  Mitigation: Pin authorization data, expose versions, schedule controlled update diffs, test high-value operations and `iam:PassRole`, cache negative results, and deny unknown/unresolved requests.
- Risk: Audit durability/backpressure violates either latency targets or fail-closed guarantees.
  Mitigation: Use a bounded single writer with acceptance acknowledgment and batched fsync by default, support per-decision fsync, benchmark both, and deny when the queue/writer is unavailable.
- Risk: Body buffering/spooling permits memory, disk, or temp-file exhaustion.
  Mitigation: Enforce preconfigured limits before forwarding, use private early-unlinked files, bound concurrent spool bytes, expose non-secret metrics, and include cancellation/leak/oversize tests.
- Risk: Real credentials leak through panic formatting, standard SDK diagnostics, or test logs.
  Mitigation: Centralize redaction, avoid serializing credential objects, use sanitized typed errors, secret-scan every output surface, and exercise fatal/failure paths with sentinel credentials.
- Risk: Same-user hostile code bypasses environment proxying or reads original credential stores.
  Mitigation: Keep the security claim narrow, demonstrate bypasses as limitation tests, recommend a dedicated low-authority upstream role, and defer stronger containment to a separately reviewed OS layer.
- Risk: Public module/brand ownership or third-party licensing blocks release.
  Mitigation: Keep module/name clearance as a pre-release gate, retain exact iamlive notices from Task 1, automate license/SBOM checks, and avoid all unlicensed source derivation.

## Open Questions

- Public repository/module ownership and `Kordn` name clearance must be finalized before the first public artifact; the internal implementation may proceed under the assumed module path.
- Exact FIPS, dual-stack, global, account-based, S3 non-streaming, and client-version coverage is finalized by Task 9 fixtures and published in `docs/compatibility.md`; unsupported forms remain fail-closed.
- The long-term mapping snapshot update cadence, additional request-aware dependent permissions, future SigV4a/presigning, richer policy predicates, process attribution, supervised detach, and OS-level direct-egress enforcement remain post-V0.1 decisions and must not weaken this plan's V0.1 defaults.
