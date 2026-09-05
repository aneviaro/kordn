# Future improvements

## Make failures actionable and protocol-correct

The unsupported-operation path and startup path currently hide information the
user needs to correct the problem:

- A decode failure is reported to AWS CLI using the fallback operation
  `Unknown`, and the fallback protocol is hardcoded to JSON. Query-protocol
  services such as IAM therefore receive an invalid response format and report
  a confusing XML parsing error.
- `kordn run` currently reduces every startup error to `kordn: startup failed`
  and exit status 78. This gives no indication whether the configuration,
  policy, credentials, audit setup, CA, or listener failed.
- A malformed policy may already have a precise validation error internally,
  but that error is not shown by the runtime startup path. Users need the
  failing policy field/rule and a concrete correction or validation command.

### Desired error behavior

- Preserve the detected or authoritative AWS protocol for every local denial.
  IAM Query failures must be valid XML; JSON-protocol failures must remain
  valid JSON.
- Report the actual operation when it can be safely recovered from the
  authenticated request. Use a distinct, stable reason for an operation that
  is valid AWS syntax but unsupported by the local model versus malformed or
  unknown operation evidence.
- Keep local denials machine-readable and compatible with the producer while
  retaining the audit event ID and stable reason code.
- Report startup failures with a phase and specific safe cause, for example:

  ```text
  kordn run: invalid policy: policy.rule[0].actions: iam:ListUsers is not permitted here
  hint: run kordn policy validate --config ~/.kordn/config.yaml
  ```

- Make policy validation errors actionable by identifying the configuration
  path, rule ID or index, invalid value where safe, and the expected form.
  Validation must remain free of credential or secret material.
- Keep exit statuses stable so scripts can distinguish invalid configuration or
  policy from runtime, credential, and upstream failures.

### Acceptance criteria

- An unsupported IAM operation produces a parseable IAM XML error containing a
  useful stable reason and request/event ID.
- `kordn run` exposes the specific invalid-policy error instead of only
  `startup failed`.
- `kordn policy validate` and `kordn run` identify the same policy validation
  failure and provide a remediation hint.
- Error output never includes access keys, secret keys, session tokens,
  external IDs, or other credential material.

## Support an explicitly guarded allow-by-default policy

The policy language currently requires `policy.default: deny`. A future
improvement should allow `policy.default: allow`, but only when the policy
contains at least one explicit deny rule. An allow-by-default policy with no
deny rules would make every successfully mapped operation broadly permitted and
must be rejected as an invalid policy rather than accepted silently.

### Desired behavior

- Accept `policy.default: allow` only when one or more rules have
  `effect: deny`.
- Reject `policy.default: allow` when there are no deny rules, with an
  actionable validation error explaining that an explicit deny rule is
  required.
- Print a clear warning to stderr during both `kordn policy validate` and
  `kordn run` whenever an allow-by-default policy is accepted.
- Emit the startup warning before launching the child process so the operator
  can see that the run is using a broad default.
- Keep unsupported, malformed, or ambiguous AWS requests fail-closed even
  under an allow-by-default policy.
- Do not include credentials or other secret material in the warning.

### Acceptance criteria

- A valid allow-by-default policy with explicit deny rules validates
  successfully and prints a warning.
- The same policy prints a warning during startup before the child is launched.
- An allow-by-default policy without any deny rule fails validation and cannot
  start a protected run.
- Default-deny policies do not print the allow-by-default warning.

## Give agents skills to work with and control policies

Agents should be able to understand and operate Kordn policies without
requiring an operator to translate every policy task into shell commands. Add a
small, explicit set of agent skills for inspecting, explaining, validating,
and safely proposing or applying policy changes.

### Desired behavior

- Expose read-only skills to list the active policy, show its hash and source,
  explain which rule would match a requested AWS operation, and report recent
  policy denials from the audit log.
- Make the agent familiar with Kordn's documented error responses, including
  stable reason codes, protocol-specific error formats, request or event IDs,
  and actionable remediation guidance, so it can accurately explain failures
  and recommend the appropriate policy or configuration change.
- Use a pinned, expanded iamlive mapping engine as the primary source for
  operation-to-IAM-action and dependent-action mappings, rather than manually
  maintaining mappings for every AWS API. Keep Kordn's decoder, resource
  validation, policy enforcement, and fail-closed boundary around it.
- Automate versioned iamlive metadata updates, provenance checks, and
  regression tests so adding a mapped AWS operation normally requires no
  hand-authored action or dependency table entry.
- Allow an agent to draft policy changes in a separate candidate policy rather
  than modifying the active policy implicitly.
- Validate and display the candidate's actionable errors, effective changes,
  affected operations/resources, and resulting policy hash before activation.
- Require explicit operator authorization for any activation, relaxation, or
  removal of policy controls. An agent must never be able to bypass the active
  policy or grant itself additional permissions.
- Apply an authorized policy change atomically to a new run (or at a clearly
  defined safe reload boundary); an in-flight run must retain the policy and
  hash with which it started.
- Record the requesting agent, authorizing operator, candidate and active
  policy hashes, change summary, timestamp, and result in the audit trail.
- Keep the control surface local to the existing `kordn` process and CLI; do
  not add a network control plane or expose policy mutation through intercepted
  AWS traffic.
- Keep policy contents, audit output, and skill responses free of credentials,
  session tokens, and unrelated secret material.

### Acceptance criteria

- An agent can inspect and explain the active policy using a documented skill
  interface without changing it.
- An agent can identify and explain Kordn error responses, distinguish policy
  denials from malformed requests, unsupported operations, configuration
  failures, and upstream failures, and provide the associated remediation
  guidance without exposing secrets.
- AWS operation and dependent-action mappings are sourced from the pinned
  iamlive integration, and adding a mapped operation does not require a
  hand-authored per-API mapping.
- Incomplete or ambiguous iamlive mapping results fail closed rather than being
  converted into broader permissions.
- A proposed policy change is validated before it can be activated, and the
  preview identifies any newly allowed or denied operations.
- Policy activation fails closed when authorization, validation, or atomic
  replacement fails.
- Unauthorized agents cannot weaken, disable, or replace the active policy.
- Every successful or rejected control attempt is auditable and includes the
  relevant policy hashes and authorization result.

## Make proxy checks easy to extend

Adding a new request-safety check currently risks coupling it directly to the
proxy's main request flow. Introduce a small, typed internal check pipeline so
new checks can be implemented, registered, tested, and audited without
rewriting the core proxy handler.

### Desired behavior

- Define a narrow check interface with typed, read-only request context and an
  explicit result: continue or deny with a stable reason code and safe detail.
- Register built-in checks in one composition point and execute them in a
  deterministic order at clearly documented request stages.
- Let checks declare the evidence they require so they cannot run against
  incomplete endpoint, authentication, decoding, mapping, or policy state.
- Stop processing on the first denial and prevent any denied request from
  reaching the upstream transport.
- Treat check errors, invalid results, and panics as local fail-closed denials,
  with enough audit context to diagnose the failing check without exposing
  credentials or request secrets.
- Provide reusable test helpers and contract tests for ordering, required
  evidence, denial responses, audit records, and fail-closed behavior.
- Keep checks compiled into the existing local Kordn binary. Do not introduce
  runtime-loaded plugins, a daemon, or a network control plane.
- Preserve the HTTPS CONNECT boundary: traffic not positively classified as
  AWS remains byte-opaque end-to-end TLS and must not be exposed to checks that
  inspect AWS request contents.

### Acceptance criteria

- A new built-in proxy check can be added and registered without modifying the
  core request-control flow.
- Check order and required inputs are explicit, deterministic, and covered by
  tests.
- A denial, error, panic, or malformed check result fails closed before any
  upstream forwarding and produces a stable, attributable audit reason.
- Existing endpoint classification, SigV4 verification, decoding, IAM mapping,
  policy, audit, and upstream-signing boundaries retain their current
  behavior.
- Non-AWS CONNECT traffic remains unintercepted and unavailable to
  AWS-request checks.

## Add a background AWS authorization mode

Add an explicitly requested background running mode that keeps Kordn active
while the operator uses normal AWS tooling. In this mode, Kordn should
intercept AWS commands routed through its local proxy boundary and perform
authorization before any request is forwarded to AWS. This must remain a single
local `kordn run` process, not a separate daemon or network control plane.

### Desired behavior

- Provide a clearly documented command or flag to start and stop the background
  run, with an unambiguous indication when authorization is active.
- Intercept all positively classified AWS requests that use the configured
  local proxy, rather than only the currently supported service subset.
- Authenticate and decode each request, map it to the corresponding AWS
  action and resource, and evaluate the active policy before forwarding it.
- Fail closed when authentication, operation mapping, resource validation, or
  policy evaluation is missing, malformed, ambiguous, or unavailable.
- Keep non-AWS HTTPS CONNECT traffic byte-opaque and pass it through without
  inspection or AWS authorization.
- Preserve the active policy and policy hash for the lifetime of the run, and
  record authorization decisions, denials, and startup/shutdown events in the
  audit trail without logging credentials or session tokens.
- Make child-process, signal, credential, CA, listener, and upstream failures
  visible and actionable while the background run is active.
- Ensure the mode cannot silently continue without Kordn protection after the
  process exits or loses its listener.

### Acceptance criteria

- An operator can start a background `kordn run` and use standard AWS CLI
  commands through it without additional per-command authorization steps.
- Every positively classified AWS command is authorized before upstream
  forwarding, including operations supported by the complete generated model.
- A denied or unverifiable AWS command never reaches AWS and produces a
  protocol-correct local error plus an audit record.
- Non-AWS CONNECT traffic remains end-to-end opaque and is not subject to AWS
  authorization.
- Stopping or losing the background process makes the protected AWS path
  unavailable rather than bypassing authorization.
- Background-mode logs and audit records contain no credentials or other secret
  material.

## Refactor catalog-backed IAM mapping validation and dependency evaluation

The catalog-backed IAM mapper still mixes catalog validation, wire lookup,
mapping-graph evaluation, and request-dependent dependency extraction. Hot-path
indexes removed repeated request-time catalog scans and copies, but the strict
reference run still reported 322.8 MiB RSS against the 80 MiB ordinary-process
budget. Retained catalog representations, string-based disagreement checks,
boolean certainty, and positional bookkeeping make correctness and memory use
difficult to reason about.

### Desired behavior

- Store pinned API, mapping, and IAM-definition evidence in a compact resident
  representation without retaining duplicate catalog-wide wire and mapping
  graphs after initialization.
- Keep request decoding and mapping on the existing immutable indexes; reducing
  RSS must not reintroduce catalog-scale request work, mutable shared state, or
  request-path locks.
- Centralize static validation of API models, `map.json`, and IAM definitions at
  catalog-load time while retaining fail-closed behavior for missing,
  contradictory, ambiguous, or incomplete evidence.
- Preserve defensive-copy public catalog APIs and every raw evidence occurrence,
  including duplicate API versions, mappings, resources, and dependencies.
- Represent dependent-action occurrences explicitly with tri-state
  applicability. Preserve duplicate and proven-inapplicable occurrences, and
  reject unknown applicability rather than guessing.
- Separate wire resolution, catalog mapping, primary-resource evaluation, and
  dependency evaluation behind narrow, typed interfaces and safe structured
  errors.
- Preserve exact Query/EC2 Query version matching, modeled JSON protocol/target
  checks, REST route and query-binding checks, and all existing endpoint and
  non-AWS interception boundaries.
- Keep the pinned source hash, offline build, single-binary/process architecture,
  and catalog provenance unchanged; do not add lazy network loading or a daemon.
- Ensure request cancellation stops mapping work instead of leaving timed-out
  work running in the background.

### Acceptance criteria

- `KORDN_STRICT_PERFORMANCE=1 make strict-performance` stays within the 80 MiB
  ordinary RSS budget while retaining the Section 21 latency and throughput
  thresholds.
- `KORDN_STRICT_PERFORMANCE=1 make strict-compatibility` stays within the 150 MiB
  compatibility RSS budget.
- Normal mapping requests continue to use indexed catalog data and avoid
  repeated full catalog cloning/scanning.
- Static catalog inconsistencies are detected once with actionable diagnostics;
  no inconsistent mapping is forwarded or authorized.
- Dependency validation compares exact action/resource occurrence multisets and
  retains current conditional-dependency fail-closed semantics.
- Existing golden, ambiguity, malformed-input, fuzz, timeout, allocation, and
  fail-closed tests continue to pass, and the strict performance source files
  and thresholds remain unchanged.
