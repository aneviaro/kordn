# Kordn AI: Local AWS Execution Proxy

## Developer-ready technical specification

**Status:** Draft v0.1  
**Implementation target:** Local-first, open-source release  
**Primary command:** `kordn run -- <command> [args...]`  
**Recommended project license:** Apache License 2.0  
**Initial platforms:** macOS and Linux, `amd64` and `arm64`

---

## 1. Executive summary

Kordn is a local AWS execution security proxy for agentic and automated processes. It launches an arbitrary child process, supplies that process with stable fake AWS credentials, intercepts the AWS HTTPS requests produced by the child and all cooperating descendants, maps each request to its required IAM action and resource set, evaluates a local deny-by-default policy, and either:

- denies the request locally with an AWS-shaped `AccessDenied` response; or
- re-signs the request with a separately held upstream AWS credential and forwards it to AWS.

The enforcement boundary is the AWS request, not the programming language or tool that produced it. AWS CLI, Claude Code, Codex, Python/boto3, Terraform, Go, and other compatible SDK-based programs use the same proxy path.

```mermaid
flowchart LR
    A["kordn run -- <command>"] --> B["Child process and descendants"]
    B -->|"Stable fake AWS credentials<br/>HTTP(S)_PROXY"| C["Local authenticated proxy"]
    C --> D["TLS termination for recognized AWS endpoints"]
    D --> E["Verify fake SigV4 request"]
    E --> F["Map request to IAM requirements"]
    F --> G["Evaluate immutable local policy"]
    G -->|"Deny or unknown"| H["AWS-shaped AccessDenied<br/>No upstream request"]
    G -->|"Allow"| I["Re-sign with upstream ceiling credential"]
    I --> J["AWS"]
    C -->|"Non-AWS destination"| K["Opaque CONNECT tunnel"]
```

The upstream credential is the maximum authority ceiling. The local policy narrows which requests Kordn will forward, but V0.1 does not dynamically create roles or mint a new STS session for every operation.

The core user promise is:

> Kordn gives the protected process no real AWS credential and makes an explicit local policy decision at the AWS request boundary before forwarding any supported AWS operation.

The core limitation is equally important:

> V0.1 is a proxy-based control, not an operating-system sandbox. It cannot prevent a deliberately hostile process from ignoring proxy settings, reading separately available credentials, or opening a direct connection to AWS. Its security guarantee applies to authenticated requests that traverse the Kordn proxy.

---

## 2. Product goals

### 2.1 Required goals

1. Provide one language- and tool-independent execution path:

   ```bash
   kordn run -- <command> [args...]
   ```

2. Work transparently for supported programs that use standard AWS credentials and proxy configuration, including:

   - AWS CLI v2;
   - Python with boto3/botocore;
   - Terraform with the AWS provider;
   - Go programs using AWS SDK for Go v2;
   - long-lived SDK clients;
   - Claude Code, Codex, and similar agent harnesses when their subprocesses inherit the Kordn environment.

3. Give the child one stable fake credential set for the lifetime of the Kordn run. The child must never need to recreate an SDK client because Kordn changes real upstream credentials.

4. Keep real upstream credentials exclusively inside the Kordn parent/proxy process.

5. Identify the concrete AWS service, API operation, IAM action set, and resource scope from the resolved runtime HTTP request.

6. Evaluate a deterministic, local, deny-by-default policy before forwarding.

7. Fail closed when Kordn cannot confidently map or safely re-sign a request.

8. Return an error shape that normal AWS SDKs and the AWS CLI recognize as an access denial.

9. Produce a durable, structured local audit record without recording credentials, authorization headers, session tokens, or request bodies.

10. Reuse iamlive-derived AWS request-to-IAM mapping logic where technically appropriate, while preserving its MIT attribution and independently implementing Kordn-specific authentication, authorization, forwarding, and credential isolation.

11. Keep the normal hot path local. No hosted service, central broker, or per-request remote dependency is part of V0.1.

### 2.2 Success definition

The initial release is successful when the same proxy implementation can transparently protect AWS calls from AWS CLI, a long-lived boto3 client, Terraform, and a Go SDK client; correctly allow and deny mapped operations; never expose the upstream credential to the child; and add low single-digit milliseconds of local processing latency to ordinary control-plane requests.

---

## 3. Non-goals

The following are explicitly outside V0.1:

- a SaaS control plane;
- a customer-hosted Lambda or central credential broker;
- multi-account fleet management;
- centrally managed approvals;
- a second CLI-specific or SDK-specific enforcement mode;
- command parsing or static analysis as an authorization boundary;
- intent inference, LLM-based authorization, runbook management, or SRE planning;
- dynamic creation or modification of IAM roles and policies;
- issuing a newly minimized STS session per AWS request;
- blocking direct network egress at the operating-system level;
- protecting against a child process with full control of the host user account;
- Windows support;
- browser or AWS Console access;
- non-AWS authorization;
- automatic rollback or transactionality across multiple AWS calls;
- transparent support for every AWS signing and streaming variant in the first release.

Possible future work may add OS-level direct-egress prevention, centralized policy and audit, a customer-side broker, additional AWS partitions, approvals, or a signed policy distribution mechanism. These must not change the single AWS-request-boundary architecture.

---

## 4. Terminology

| Term | Definition |
|---|---|
| **Run** | One invocation of `kordn run -- ...`, from startup until the root child exits and the proxy shuts down. |
| **Root child** | The command directly launched by Kordn. |
| **Protected process** | The root child or a descendant that inherits and honors Kordn's fake credentials and proxy configuration. |
| **Fake credential** | A random access key ID, secret key, and session token valid only for authenticating a request to the local Kordn proxy. It has no AWS identity. |
| **Upstream credential** | The real AWS credential resolved by Kordn before child launch and used only inside Kordn to sign allowed upstream requests. |
| **Authority ceiling** | The maximum AWS authority of the configured upstream identity or optional assumed role. Kordn cannot successfully perform an AWS operation outside this authority. |
| **AWS endpoint** | A hostname positively recognized by Kordn as an AWS API endpoint in a supported partition. |
| **IAM requirement** | One IAM action plus its required resource set and any dependent action derived from the concrete AWS request. |
| **Known global scope** | A mapping result where AWS does not support resource-level permissions for the action and IAM therefore requires `Resource: "*"`. |
| **Unresolved scope** | A mapping result where a resource should be scoped but Kordn could not resolve it from the request. This is not equivalent to known global scope. |
| **Local policy** | The immutable policy snapshot loaded before the child is launched. |
| **Fail closed** | Do not forward the request to AWS; emit an audit event and return a local error. |

---

## 5. Threat model

### 5.1 Assets to protect

- real upstream AWS credentials;
- the ability to invoke AWS APIs through the configured upstream identity;
- local policy integrity during a run;
- audit integrity and confidentiality;
- the Kordn certificate-authority private key and fake credential secret;
- the user's AWS resources reachable through the upstream authority ceiling.

### 5.2 In-scope threats

V0.1 is intended to reduce risk from:

- accidental or overbroad AWS operations produced by an AI agent;
- unexpected AWS calls made by scripts, Terraform providers, or SDK libraries;
- a long-running process that later attempts a new AWS operation;
- a protected process accidentally inheriting the user's normal AWS profile or environment credentials;
- a sibling local process attempting to use an unauthenticated open proxy;
- unknown or newly introduced AWS API calls that the bundled mapper cannot resolve;
- mapper failures that would otherwise fall back to wildcard permission assumptions;
- logs leaking AWS access keys, secret keys, session tokens, or SigV4 authorization headers;
- policy changes on disk during a run silently changing the active decision set.

### 5.3 Attacker assumptions

The protected code may be mistaken, prompt-injected, or willing to try actions outside its intended task. It is not assumed to have administrator or root privileges.

The initial security boundary does **not** assume that Kordn can contain a deliberately hostile process that controls the same OS user. A same-user process may be able to inspect files, change its environment, read the user's original AWS configuration directly, attach a debugger, or connect around the proxy.

### 5.4 Explicit bypass limitations

V0.1 does not prevent a child from deliberately:

- ignoring `HTTP_PROXY` or `HTTPS_PROXY`;
- passing custom proxy settings when constructing an SDK client;
- opening a direct TLS connection to an AWS endpoint;
- reading `~/.aws/credentials`, AWS SSO caches, web-identity tokens, or other files by explicit path;
- using hard-coded credentials;
- implementing IMDS, ECS task metadata, or another credential provider directly rather than through the standard SDK chain;
- using a previously generated presigned URL outside Kordn;
- invoking a non-AWS service that later performs AWS actions;
- modifying or disabling application-level TLS/proxy behavior;
- killing Kordn and attempting another execution path.

Environment replacement reduces accidental fallback but is not an OS-enforced isolation boundary.

### 5.5 Security claim

The V0.1 security claim must be worded narrowly:

> For supported AWS requests that use the Kordn fake credential and traverse the authenticated Kordn proxy, Kordn verifies the inbound request, maps it to IAM requirements, applies a deny-by-default local policy, and does not forward denied or unknown requests. Real upstream credentials are not exposed to the protected process by Kordn.

The project documentation must not claim that `kordn run` alone prevents all direct AWS access from adversarial code.

---

## 6. High-level architecture

One `kordn run` process owns the complete runtime:

1. configuration loader;
2. upstream credential resolver;
3. per-run fake credential generator;
4. per-run certificate authority;
5. authenticated loopback HTTP CONNECT proxy;
6. AWS endpoint classifier;
7. inbound SigV4 verifier;
8. AWS protocol decoder;
9. IAM mapper;
10. local policy engine;
11. upstream SigV4 signer and HTTP transport;
12. audit writer;
13. child lifecycle and signal supervisor.

There is no daemon and no network control plane in V0.1.

### 6.1 Required data flow

1. The user invokes:

   ```bash
   kordn run --config ~/.kordn/prod.yaml -- python worker.py
   ```

2. Kordn loads and validates the config and policy.

3. Kordn resolves the configured upstream AWS profile or optional assumed role **before** creating the child environment.

4. Kordn optionally calls `sts:GetCallerIdentity` using the upstream provider to display and audit the authority ceiling identity.

5. Kordn creates:

   - a random run ID;
   - a random fake AWS access key ID, secret key, and session token;
   - a random proxy Basic-auth credential;
   - a per-run CA and leaf-certificate cache;
   - a private runtime directory;
   - a synthetic AWS config and credentials file containing no real credential.

6. Kordn binds a proxy on `127.0.0.1:0`, obtaining an ephemeral port.

7. Kordn launches the child with the environment defined in Section 7.

8. A compatible AWS SDK signs a normal AWS request using the stable fake credential and opens a CONNECT tunnel through Kordn.

9. Kordn authenticates the proxy connection, classifies the destination, and:

   - tunnels non-AWS traffic without TLS interception; or
   - terminates TLS for a recognized AWS endpoint using a generated leaf certificate.

10. For an AWS request, Kordn verifies that the inbound SigV4 access key, session token, signature, signed headers, timestamp, and payload mode are valid for this run.

11. Kordn decodes the concrete service, operation, Region, account context, parameters needed for resource extraction, and signing algorithm.

12. The mapper produces all required IAM action/resource pairs, including known dependent permissions.

13. The policy engine returns `allow` or `deny` with stable reason codes and matched rule IDs.

14. On deny or any unsupported/unknown state, Kordn writes an audit event and returns an AWS-shaped denial. It makes no upstream request.

15. On allow, Kordn obtains the current upstream credential from the internal provider, removes all fake authentication material, signs the normalized request using the upstream credential, and forwards it over a separately authenticated TLS connection to the original AWS endpoint.

16. Kordn streams the AWS response back to the child and records the status, AWS request ID, and timing fields.

---

## 7. Process and environment setup

### 7.1 Command syntax

The only protected runtime entry point is:

```bash
kordn run [kordn flags] -- <command> [args...]
```

Examples:

```bash
kordn run -- aws sts get-caller-identity
kordn run -- python worker.py
kordn run -- terraform apply
kordn run -- claude
kordn run -- codex
kordn run -- go run ./cmd/operator
```

The `--` separator is mandatory. Kordn must pass the child argument vector directly to `exec`; it must not concatenate arguments into a shell command.

### 7.2 Startup ordering

Kordn must complete these operations before spawning the child:

1. parse configuration;
2. validate policy and file ownership/permissions;
3. resolve upstream credential provider;
4. complete any required interactive SSO/MFA flow;
5. optionally verify caller identity;
6. generate the run CA, fake credential, and proxy secret;
7. start the proxy and audit writer;
8. build the child environment;
9. spawn the root child.

If any required step fails, the child must not start.

### 7.3 Child environment

Kordn must set or replace all of the following for the child:

```text
AWS_ACCESS_KEY_ID=<per-run fake access key>
AWS_SECRET_ACCESS_KEY=<per-run fake secret>
AWS_SESSION_TOKEN=<per-run fake session token>
AWS_EC2_METADATA_DISABLED=true
AWS_EC2_METADATA_V1_DISABLED=true
AWS_SHARED_CREDENTIALS_FILE=<private synthetic credentials file>
AWS_CONFIG_FILE=<private synthetic config file>
AWS_PROFILE=kordn
AWS_DEFAULT_PROFILE=kordn
AWS_SDK_LOAD_CONFIG=1
AWS_CA_BUNDLE=<per-run Kordn CA PEM>
HTTP_PROXY=http://<proxy-user>:<proxy-secret>@127.0.0.1:<port>
HTTPS_PROXY=http://<proxy-user>:<proxy-secret>@127.0.0.1:<port>
http_proxy=<same value>
https_proxy=<same value>
NO_PROXY=localhost,127.0.0.1,::1
no_proxy=localhost,127.0.0.1,::1
KORDN_RUN_ID=<run id>
KORDN_ACTIVE=1
```

The lowercase and uppercase proxy variables must be set to the same value because different clients have different precedence behavior. AWS documents `HTTP_PROXY` and `HTTPS_PROXY` as supported AWS CLI proxy configuration, while iamlive uses the same mechanism for AWS CLI and SDK proxy mode.

Kordn must construct a dedicated environment slice for the child. It must not mutate its own process-wide AWS or proxy environment after the upstream provider has been created; doing so could redirect Kordn's credential refresh or outbound transport back into the local proxy.

Kordn must clear, ignore, or replace standard credential providers that could accidentally override the fake environment credential, including:

```text
AWS_WEB_IDENTITY_TOKEN_FILE
AWS_ROLE_ARN
AWS_ROLE_SESSION_NAME
AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
AWS_CONTAINER_CREDENTIALS_FULL_URI
AWS_CONTAINER_AUTHORIZATION_TOKEN
AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE
```

The synthetic shared config must contain only non-secret settings required for compatibility, such as the selected Region and `ca_bundle`. The synthetic credentials file must contain only the fake credential.

Kordn must not modify the user's real `~/.aws/config` or `~/.aws/credentials`.

### 7.4 Original environment handling

Before overwriting proxy and AWS variables, Kordn must capture any parent corporate proxy configuration for use by its own outbound transport. The Kordn outbound transport must never read the child-facing local proxy variables, or it may recursively proxy through itself.

If an upstream corporate proxy is configured, Kordn must chain its outbound AWS TLS connection through that proxy. The corporate proxy must see the final upstream connection, not the fake credential.

### 7.5 Process lifecycle

- Kordn runs the root child in its own process group on POSIX platforms.
- Kordn forwards `SIGINT`, `SIGTERM`, and terminal-resize signals as appropriate.
- The root child's exit status is returned unchanged when Kordn itself remains healthy.
- The proxy remains active until the root child exits.
- After root-child exit, Kordn allows a short configurable drain period, closes listeners, flushes audit events, deletes the runtime directory, and exits.
- Background descendants that outlive the root child are unsupported in V0.1 and lose Kordn connectivity when the run ends.
- Kordn must never silently fall back to launching the child without protection when proxy startup fails.

---

## 8. Proxy and TLS behavior

### 8.1 Listener requirements

- Bind only to `127.0.0.1` by default.
- Use an ephemeral port unless the user explicitly chooses one.
- Require HTTP Basic proxy authentication on every request and CONNECT tunnel.
- Generate a random proxy username and at least 256 bits of random secret material per run.
- Reject missing or invalid proxy authentication before destination handling.
- Apply conservative header and request-size limits.
- Do not expose a PAC file, unauthenticated health endpoint, or LAN listener in V0.1.

The fake SigV4 credential and proxy authentication provide two distinct checks: the proxy secret limits who can open a tunnel, while fake SigV4 validation authenticates and integrity-checks the AWS request.

### 8.2 Destination classification

The proxy must classify the CONNECT authority and inner HTTP `Host` independently.

An AWS request is eligible for interception only when:

- the CONNECT host is an exact recognized AWS endpoint or a valid subdomain of a supported AWS endpoint suffix;
- the inner `Host` matches the CONNECT destination after normalization;
- the destination uses TLS;
- the endpoint parser can determine a supported AWS partition, service, and Region/global scope;
- the hostname passes strict label-boundary and IDNA normalization checks.

String containment checks such as `host.contains("amazonaws.com")` are forbidden. `amazonaws.com.evil.example` must never classify as AWS.

V0.1 must support the standard commercial AWS partition. GovCloud, China, ISO, and ISO-B partitions require separate endpoint fixtures and are not release blockers for V0.1.

Custom AWS endpoint URLs, LocalStack, and arbitrary private endpoints are not treated as AWS in production V0.1. Tests may inject a custom classifier through an internal interface.

### 8.3 Non-AWS traffic

Non-AWS HTTPS CONNECT traffic must be tunneled as opaque bytes. Kordn must not:

- terminate non-AWS TLS;
- inspect request bodies or headers;
- modify non-AWS data;
- apply AWS policy rules;
- log destination paths, query strings, or content.

The audit may record only aggregate tunnel counts and destination hostnames when explicitly enabled. Default behavior is no non-AWS destination logging.

This allows agent API traffic and other HTTPS dependencies to continue through the same inherited proxy settings without trusting the Kordn CA for non-AWS endpoints.

For a non-AWS plaintext HTTP proxy request, Kordn necessarily parses the proxy request line and headers to forward it. It must not apply AWS decoding, log the body or query, or modify content beyond standard hop-by-hop proxy handling. Plaintext HTTP to a recognized AWS endpoint is rejected; Kordn never forwards an AWS API request without upstream TLS.

Before opening any tunnel, Kordn must reject loopback, unspecified, multicast, and link-local metadata destinations when they are addressed through the proxy, including `169.254.169.254`, `169.254.170.2`, and `fd00:ec2::254`. The check must be applied both to literal IP addresses and to resolved DNS results. This does not prevent a hostile child from connecting to those addresses directly; it ensures the Kordn proxy does not itself become a metadata-service or localhost SSRF relay.

### 8.4 Per-run certificate authority

Kordn must generate a new local CA for each run.

- Store the CA private key only in the private runtime directory.
- Directory mode: `0700`.
- Key and synthetic credential files: `0600`.
- Generate leaf certificates lazily per exact AWS hostname.
- Cache leaf certificates in memory for the run.
- Include the requested hostname as a DNS Subject Alternative Name.
- Set a short validity window covering the run plus a small clock-skew allowance.
- Delete the CA key and certificates on normal shutdown.
- Attempt cleanup on startup for abandoned runtime directories older than a conservative threshold.
- Never install the CA into the system trust store.

The child trusts the per-run CA through `AWS_CA_BUNDLE`. AWS SDKs and tools document the `ca_bundle`/`AWS_CA_BUNDLE` setting, and iamlive uses the same mechanism in proxy mode.

### 8.5 HTTP versions

V0.1 terminates and forwards HTTP/1.1. The TLS ALPN configuration must advertise `http/1.1` only for intercepted AWS endpoints so clients fall back cleanly.

HTTP/2-specific AWS clients, event streams, and transports that require AWS CRT HTTP/2 behavior are unsupported until explicitly implemented and tested.

### 8.6 Request size and streaming

The proxy must classify payload handling before reading the full body.

- Ordinary control-plane bodies up to the configured inspection limit may be buffered in memory or spooled to a private temporary file.
- Default maximum in-memory body: 8 MiB.
- Default maximum spooled body: 64 MiB.
- Bodies above supported limits fail closed before upstream forwarding unless the signing mode permits safe unchanged streaming.
- `UNSIGNED-PAYLOAD` may be streamed when supported by the service and signing algorithm.
- A precomputed `x-amz-content-sha256` may permit unchanged streaming, but the upstream signature must use the same payload hash and AWS remains the final payload-integrity verifier.
- Temporary body files must be mode `0600`, unlinked as early as the OS permits, and deleted after the request.

V0.1 must fail closed for SigV4 streaming-chunk signatures such as `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, signed AWS event streams, and other formats that require rewriting a sequence of payload signatures.

### 8.7 No hidden retries

The proxy must not perform application-level retries for AWS operations. The originating AWS SDK owns retry behavior.

The outbound transport may retry only a connection establishment that demonstrably sent no application bytes. It must never retry a mutation after an ambiguous connection failure.

---

## 9. Fake credentials and inbound SigV4 validation

### 9.1 Fake credential properties

For each run, generate:

- one access key ID with a clearly local, non-production prefix and AWS-compatible length;
- one cryptographically random secret key;
- one cryptographically random session token;
- one creation timestamp.

The same fake credential remains stable until the run ends. This is what makes long-lived boto3, Terraform, and Go SDK clients work without recreation.

The fake credential must never be accepted by any service other than the local proxy and has no corresponding principal in AWS.

### 9.2 Supported signing mode

V0.1 requires header-based AWS Signature Version 4 using `AWS4-HMAC-SHA256`.

The inbound verifier must validate:

- access key ID equals the run's fake access key;
- session token equals the run's fake session token;
- credential scope date, Region, service, and terminator are syntactically valid;
- request timestamp is within the configured clock-skew window, default ±5 minutes;
- every header named in `SignedHeaders` is present and canonicalized correctly;
- canonical URI and canonical query string;
- canonical headers;
- payload hash mode;
- final HMAC signature using the fake secret;
- service and Region agree with the recognized endpoint, except for explicitly documented global endpoint rules.

Malformed or invalid inbound signatures must not be mapped or forwarded.

### 9.3 Unsupported signing modes

V0.1 fails closed for:

- SigV4a (`AWS4-ECDSA-P256-SHA256`);
- query-parameter presigning;
- SigV4 streaming chunk signatures;
- unsigned AWS requests unless the service and operation are explicitly modeled as anonymous and policy support is later added;
- unrecognized authentication schemes.

The audit reason must distinguish `unsupported_signing_scheme` from `invalid_signature`.

### 9.4 Re-signing behavior

For an allowed request, the upstream signer must:

1. remove the inbound `Authorization` header;
2. remove the fake `X-Amz-Security-Token`;
3. remove or replace fake/query signing parameters;
4. strip hop-by-hop and proxy headers;
5. preserve the original semantic request method, target, parameters, and payload;
6. set a fresh `X-Amz-Date` unless protocol constraints require preserving the client time;
7. attach the current real upstream session token when present;
8. compute a new canonical request and SigV4 signature using the upstream credential;
9. connect to the original recognized AWS hostname with normal public PKI validation;
10. never forward the fake signature or fake credential identifier.

AWS documents that temporary credentials require `X-Amz-Security-Token` and that volatile proxy headers should not be included in the signature. The signer implementation must follow AWS canonicalization rules exactly rather than using ad hoc header transformations.

---

## 10. Upstream credential and authority ceiling

### 10.1 Supported sources

V0.1 supports one configured upstream source per run:

1. an explicit AWS shared-config profile; or
2. an explicit AWS shared-config profile followed by one optional configured `AssumeRole` step.

There is no per-request role selection and no child-selected profile.

When Kordn performs the optional role step itself, the configuration may additionally specify `externalId`, `sourceIdentity`, `roleSessionName`, and `durationSeconds`. These values are fixed at startup, validated against STS constraints, and never accepted from the child. A shared-config profile that already performs role assumption remains the preferred way to express more complex SSO/MFA role chains.

### 10.2 Resolution requirements

- Resolve the upstream provider before creating the child environment.
- Use the AWS SDK for Go v2 standard credential provider chain inside Kordn.
- Require an explicit profile in the immutable run configuration; do not silently use whichever profile happens to be default and do not permit an ad hoc `kordn run` profile override.
- Complete SSO, MFA, or `credential_process` interaction before launching the child.
- Memoize the provider so refresh occurs inside Kordn.
- Never serialize resolved real credentials to Kordn config, audit files, environment variables, command arguments, IPC responses, or child-accessible files.
- Never include credentials in panic output or debug logging.

### 10.3 Optional role ceiling

If `upstream.assumeRoleArn` is configured, Kordn assumes that role once as its authority ceiling and lets the SDK provider refresh it when needed. The role must be fixed in the immutable startup configuration.

The local proxy policy remains the per-request authorization control. V0.1 does not generate a dynamic session policy for each call.

AWS states that an `AssumeRole` session policy can only narrow the role's identity policy, but also documents policy-evaluation nuances around resource-based policies. The V0.1 proxy must therefore treat the configured upstream role as a coarse ceiling, not claim that a local policy is an AWS-native permission boundary.

### 10.4 Preflight identity

Kordn calls `sts:GetCallerIdentity` with the resolved upstream provider before child launch and records:

- AWS account ID;
- principal ARN;
- user ID;
- profile name;
- optional assumed-role ARN.

The identity is shown to the user before execution unless `--quiet` is set.

If identity preflight fails, the run does not start. An explicit offline mode is outside V0.1.

### 10.5 Ceiling guidance

Documentation must tell users to configure a dedicated, appropriately limited upstream role or profile. Running Kordn with an administrator profile makes the local proxy a high-value holder of administrator authority and increases the effect of any proxy vulnerability or bypass.

---

## 11. AWS request decoding and IAM mapping

### 11.1 Mapper inputs and outputs

The mapper operates on the fully resolved runtime request after inbound SigV4 verification.

Required interface:

```go
type IAMMapper interface {
    Map(ctx context.Context, req *DecodedAWSRequest) (*MappingResult, error)
}

type DecodedAWSRequest struct {
    Partition       string
    EndpointHost    string
    Service         string
    Region          string
    CallerAccountID string
    Protocol        AWSProtocol
    Operation       string
    Method          string
    CanonicalPath   string
    CanonicalQuery  url.Values
    Headers         http.Header
    Parameters      map[string]Value
    PayloadHashMode PayloadHashMode
}

type MappingResult struct {
    Service       string
    Operation     string
    Requirements  []IAMRequirement
    MapperVersion string
    Confidence    MappingConfidence
    Evidence      []MappingEvidence
}

type IAMRequirement struct {
    Action        string
    Resources     []string
    ScopeKind     ScopeKind // exact, set, known_global, unresolved
    Dependent     bool
    ConditionHint map[string][]string
}
```

### 11.2 Protocol decoders

The decoder layer must support the AWS protocols required by the compatibility matrix:

- AWS JSON 1.0 and 1.1, including `X-Amz-Target`;
- AWS Query;
- EC2 Query;
- REST-JSON;
- REST-XML for supported non-streaming requests.

Service/operation detection may use:

- recognized endpoint metadata;
- SigV4 credential scope;
- `X-Amz-Target`;
- HTTP method and modeled URI template;
- query/body `Action` field;
- service-specific modeled request definitions.

No single untrusted request field is sufficient when independent fields disagree. Disagreement is a mapping error and fails closed.

### 11.3 iamlive-derived logic

The implementation should first evaluate whether the required mapper can use iamlive as a pinned Go dependency. If its APIs are not suitable, Kordn may derive and adapt the relevant mapping data and logic.

Requirements for derived use:

- pin the exact upstream commit or release;
- retain the iamlive MIT copyright and permission notice;
- retain notices for any transitively copied mapping data, including `sdk-iam-map` where applicable;
- mark substantially derived files in source headers;
- record the upstream commit in `THIRD_PARTY_NOTICES.md` and build metadata;
- add Kordn-specific tests rather than assuming policy-generation behavior is safe for enforcement;
- keep Kordn's authorization and fail-closed wrapper outside the derived module.

iamlive's proxy mode demonstrates runtime request inspection and resource extraction, but its output must not be treated as automatically enforcement-grade. In particular, Kordn must preserve the distinction between a legitimate AWS-required wildcard resource and an unresolved resource.

### 11.4 AWS machine-readable authorization data

The mapper may supplement the iamlive-derived mapping with AWS's machine-readable Service Authorization Reference, which exposes API operations, IAM actions, resource types, and condition keys.

The build must pin a generated snapshot and expose its version. Runtime network fetching of authorization metadata is forbidden in V0.1.

### 11.5 Multiple and dependent permissions

One AWS API request may authorize more than one IAM action. The mapper must return all actions required by the modeled request.

Examples include conditional `iam:PassRole`, tagging operations, KMS permissions, and service-specific dependent actions. The request is allowed only when every returned requirement is allowed by local policy.

If the mapper knows that a dependent permission may be required but cannot determine whether it applies to the concrete request, the result is unresolved and fails closed.

### 11.6 Resource scope rules

The mapper must emit exactly one of:

- `exact`: one resource ARN;
- `set`: a finite set of resource ARNs;
- `known_global`: AWS does not support resource-level permissions for this action, so `*` is required;
- `unresolved`: resource-level permission should be possible or request-specific scope is unclear, but the mapper could not resolve it.

`unresolved` must never be converted to `*` automatically.

### 11.7 Unknown-call behavior

Any of the following must fail closed without an upstream request:

- unrecognized AWS endpoint;
- unsupported partition;
- service or operation disagreement;
- absent mapper entry;
- unknown dependent permission;
- unresolved resource scope;
- unsupported signing scheme;
- unsupported payload format;
- mapper panic or timeout;
- invalid ARN construction;
- policy input that exceeds configured limits.

The user may not configure `unknown: allow` in V0.1.

---

## 12. Local policy model

### 12.1 Policy properties

The V0.1 policy engine is deliberately small:

- local file;
- loaded once before child launch;
- immutable for the run;
- deny by default;
- explicit deny overrides allow;
- no rule ordering;
- no LLM decisions;
- no raw IAM policy execution;
- no policy fetch from a remote service.

### 12.2 Configuration example

```yaml
apiVersion: kordn.dev/v1alpha1
kind: LocalRunPolicy

upstream:
  profile: kordn-prod-ceiling
  assumeRoleArn: ""
  externalId: ""
  sourceIdentity: ""
  roleSessionName: kordn-local
  durationSeconds: 3600
  region: eu-west-1

proxy:
  listen: 127.0.0.1:0
  nonAwsTraffic: tunnel
  upstreamProxy: inherit
  maxInMemoryBodyBytes: 8388608
  maxSpoolBodyBytes: 67108864

policy:
  default: deny
  rules:
    - id: deny-iam-and-organizations
      effect: deny
      actions:
        - "iam:*"
        - "organizations:*"
      resources:
        - "*"

    - id: allow-ecs-observation
      effect: allow
      actions:
        - "ecs:List*"
        - "ecs:Describe*"
      resources:
        - "*"
      regions:
        - eu-west-1
      allowAwsRequiredWildcard: true

    - id: allow-one-service-update
      effect: allow
      actions:
        - "ecs:UpdateService"
      resources:
        - "arn:aws:ecs:eu-west-1:123456789012:service/prod/checkout"
      regions:
        - eu-west-1

audit:
  path: ~/.kordn/audit/events.jsonl
  fsync: batch
  failureMode: deny
  logResourceArns: true
  hashResourceNames: false
```

### 12.3 Rule schema

```go
type Rule struct {
    ID                       string
    Effect                   Effect // allow or deny
    Actions                 []string
    Resources               []string
    Regions                 []string
    Accounts                []string
    Partitions              []string
    AllowAWSRequiredWildcard bool
}
```

V0.1 supports `*` and `?` glob syntax for action and resource matching. Matching behavior must be documented and implemented once in a shared library:

- IAM action matching is case-insensitive and normalized to the mapper's canonical spelling in events.
- ARN/resource matching is case-sensitive unless AWS defines the corresponding ARN component otherwise; V0.1 uses bytewise case-sensitive matching.
- Region, account, and partition matches are exact.
- An empty constraint list means any value for that dimension.
- `NotAction`, `NotResource`, regular expressions, arbitrary CEL/Rego, and parameter predicates are not supported in V0.1.

### 12.4 Decision algorithm

For each mapped request:

1. Reject if the mapping confidence is not `high`.
2. Reject if any requirement has `ScopeKind=unresolved`.
3. For every requirement/action/resource combination, find all matching rules.
4. If any matching rule has `effect: deny`, deny the entire request.
5. Otherwise require at least one matching `allow` rule for every requirement/resource combination.
6. For `known_global` scope, the matching allow rule must include resource `*` and set `allowAwsRequiredWildcard: true`.
7. If any requirement remains uncovered, deny the entire request.
8. Record all matched rule IDs and one stable decision reason.

No partially authorized AWS request is forwarded.

### 12.5 Policy snapshot integrity

- Resolve symlinks before loading.
- Require the policy file to be owned by the current user.
- Reject a group- or world-writable policy file by default.
- Parse strictly; unknown fields are configuration errors.
- Canonicalize and hash the parsed policy.
- Store `policy_hash` in every audit decision.
- Do not watch or reload the file during a run.

This prevents a child that can edit the source policy file after startup from changing the in-memory policy decision set for the active run.

---

## 13. Caching

All V0.1 caches are in-process and scoped to one run.

### 13.1 Required caches

1. **Endpoint classification cache**
   - Key: normalized hostname.
   - Value: partition/service/Region classification or stable negative result.
   - Bounded LRU.

2. **TLS leaf certificate cache**
   - Key: exact normalized AWS hostname.
   - Value: generated certificate/key pair.
   - Bounded by unique AWS host count.

3. **Static operation metadata cache**
   - Key: mapper version + service + operation.
   - Value: action/resource templates and protocol metadata.
   - Resource extraction still runs for every request.

4. **Policy decision cache**
   - Key: policy hash + mapper version + normalized requirement set + partition + Region + account.
   - Value: decision, rule IDs, and reason code.
   - Bounded LRU, default 10,000 entries.

5. **Upstream credential provider cache**
   - Use the AWS SDK provider's refresh behavior.
   - Never key or cache credentials based on child-controlled profile or role values.

### 13.2 Cache safety

- No cache entry may omit resource identity from a resource-scoped decision.
- Negative and unknown mapping results may be cached.
- Policy decisions do not outlive the run.
- Credential values are never persisted by Kordn.
- Cache statistics are observable but must not contain credential material.
- A policy hash or mapper version change necessarily produces a different key.

---

## 14. Audit event schema

### 14.1 Storage

- JSON Lines, one event per line.
- File mode `0600`.
- Append-only during a run.
- Default location: `~/.kordn/audit/events.jsonl`.
- Each event has `schema_version`.
- Writer failures default to fail closed for new AWS requests.
- The CLI flushes all accepted events before exit.

### 14.2 Request decision event

```json
{
  "schema_version": "kordn.audit/v1",
  "event_id": "evt_01J...",
  "run_id": "run_01J...",
  "timestamp": "2026-08-17T15:04:05.123456Z",
  "event_type": "aws.request.decision",
  "root_process": {
    "pid": 12345,
    "argv0": "python",
    "command_hash": "sha256:..."
  },
  "connection_id": "conn_01J...",
  "request": {
    "host": "ecs.eu-west-1.amazonaws.com",
    "partition": "aws",
    "service": "ecs",
    "operation": "UpdateService",
    "region": "eu-west-1",
    "protocol": "json1.1",
    "method": "POST",
    "payload_bytes": 198
  },
  "iam_requirements": [
    {
      "action": "ecs:UpdateService",
      "resources": [
        "arn:aws:ecs:eu-west-1:123456789012:service/prod/checkout"
      ],
      "scope_kind": "exact",
      "dependent": false
    }
  ],
  "mapping": {
    "confidence": "high",
    "mapper_version": "iamlive-main@<commit>+kordn.1"
  },
  "decision": {
    "result": "allow",
    "reason_code": "all_requirements_allowed",
    "matched_rule_ids": ["allow-one-service-update"],
    "policy_hash": "sha256:..."
  },
  "upstream": {
    "profile": "kordn-prod-ceiling",
    "principal_arn": "arn:aws:sts::123456789012:assumed-role/KordnCeiling/kordn",
    "http_status": 200,
    "aws_request_id": "..."
  },
  "timing_ms": {
    "decode": 0.31,
    "map": 0.62,
    "policy": 0.08,
    "local_total": 1.47,
    "upstream": 54.11
  }
}
```

### 14.3 Event types

V0.1 defines:

- `run.started`;
- `run.ended`;
- `aws.request.decision`;
- `aws.request.forward_error`;
- `proxy.authentication_failed`;
- `proxy.unsupported_request`;
- `audit.writer_failed`;
- `runtime.cleanup_failed`.

### 14.4 Redaction requirements

Never log:

- `Authorization`;
- `Proxy-Authorization`;
- `X-Amz-Security-Token`;
- fake or real access key IDs by default;
- secret keys;
- session tokens;
- request or response bodies;
- cookies;
- presigned query signatures;
- raw environment variables;
- complete child command arguments when they may contain secrets.

Root command logging defaults to `argv0` plus a hash of the full argument vector. An explicit debug option may log a redacted argument vector, but debug mode must still never log authentication material.

Resource ARNs may contain sensitive names. The audit config must support hashing resource identifiers while retaining action, account, Region, and resource type.

### 14.5 Process attribution limitation

Portable per-request descendant PID attribution is not guaranteed through a TCP proxy. V0.1 records the root child PID, run ID, and connection ID. It must not claim that a specific grandchild PID made a request unless a platform-specific implementation proves that mapping.

---

## 15. Error semantics

### 15.1 Local policy denial

For a denied request, Kordn must:

1. generate an audit event ID;
2. write the decision event;
3. emit a concise human-readable message to the controlling terminal unless quiet;
4. return a protocol-compatible AWS access-denied response;
5. avoid any upstream network request.

The response message includes only:

- `Kordn denied the request`;
- stable reason code;
- service and operation;
- opaque event ID.

It must not include the local policy file path, upstream profile secrets, or internal stack traces.

### 15.2 AWS-shaped responses

The error encoder selects the response shape from the decoded AWS protocol:

- **AWS JSON 1.0/1.1:** HTTP 403, `application/x-amz-json-1.0` or `1.1`, `x-amzn-ErrorType: AccessDeniedException`, and a JSON error document.
- **REST-JSON:** HTTP 403 with an `AccessDeniedException` JSON body and `x-amzn-ErrorType`.
- **AWS Query/EC2 Query:** HTTP 403 XML `ErrorResponse` with `Code=AccessDenied`.
- **REST-XML/S3:** HTTP 403 XML `Error` with `Code=AccessDenied`.

Example JSON body:

```json
{
  "__type": "AccessDeniedException",
  "message": "Kordn denied ecs:UpdateService (policy_no_matching_allow); event evt_01J..."
}
```

Example XML body:

```xml
<ErrorResponse>
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>Kordn denied ec2:TerminateInstances (explicit_deny); event evt_01J...</Message>
  </Error>
  <RequestId>evt_01J...</RequestId>
</ErrorResponse>
```

### 15.3 Stable reason codes

At minimum:

```text
explicit_deny
policy_no_matching_allow
aws_required_wildcard_not_approved
unknown_endpoint
unsupported_partition
unknown_operation
mapping_low_confidence
resource_unresolved
dependent_permission_unresolved
invalid_inbound_signature
unsupported_signing_scheme
unsupported_payload_mode
request_too_large
audit_unavailable
upstream_credential_unavailable
upstream_transport_error
internal_fail_closed
```

### 15.4 Upstream errors

An AWS response received after an allowed forward must be returned unmodified except for mandatory hop-by-hop header handling.

The audit must distinguish:

- `local_deny` — Kordn blocked before AWS;
- `upstream_access_denied` — local policy allowed, AWS rejected;
- `upstream_error` — another AWS or transport error.

### 15.5 CLI exit behavior

- On successful startup, the root child's exit status or terminating signal is preserved.
- Configuration/startup failure before child launch: exit `78`.
- Internal Kordn failure after launch that prevents continued safe proxying: terminate the root child process group and exit `70` after audit flush.
- Failure to `exec` the child: exit `126`.
- Policy denials do not directly set Kordn's process exit code; the protected program decides how the AWS error affects its own exit.

---

## 16. CLI and user experience

### 16.1 Commands

```text
kordn init
kordn run [flags] -- <command> [args...]
kordn policy validate [--config PATH]
kordn identity [--profile NAME]
kordn audit [--run RUN_ID] [--json]
kordn version
```

`kordn run` is the only command that launches a protected runtime.

### 16.2 `kordn init`

Creates:

- `~/.kordn/config.yaml` with a deny-by-default example;
- `~/.kordn/audit/` mode `0700`;
- no CA and no credentials.

The generated policy must not contain a broad allow rule.

### 16.3 `kordn run` flags

```text
--config PATH
--quiet
--verbose
--audit-path PATH
--listen 127.0.0.1:0
```

The upstream profile, optional role ARN, Region restrictions, and policy rules must come from the immutable config, not convenient ad hoc flags. Selecting a different security context therefore requires selecting and validating a different config file. The final resolved identity is always printed and audited.

### 16.4 Startup output

```text
Kordn run run_01J...
  command:       python worker.py
  upstream:      kordn-prod-ceiling
  principal:     arn:aws:sts::123456789012:assumed-role/KordnCeiling/kordn
  account:       123456789012
  region:        eu-west-1
  policy:        sha256:ab12...
  proxy:         active on 127.0.0.1:<ephemeral>
  direct bypass: not prevented in local V0.1
```

The bypass line is intentional and should remain until an OS enforcement layer exists.

### 16.5 Denial output

```text
DENIED ec2:TerminateInstances
  resource: arn:aws:ec2:eu-west-1:123456789012:instance/i-0123456789
  reason:   explicit_deny
  rule:     deny-ec2-termination
  event:    evt_01J...
```

### 16.6 Exit summary

When attached to a terminal and not quiet:

```text
Kordn summary run_01J...
  AWS requests:  148
  allowed:       146
  denied:        1
  unsupported:   1
  local p95:     3.8 ms
  audit:         ~/.kordn/audit/events.jsonl
```

---

## 17. Internal APIs and interfaces

The implementation language should be Go to align with iamlive-derived code, provide a single static binary, use mature HTTP/TLS primitives, and share AWS SDK for Go v2 signing and credential providers.

### 17.1 Core interfaces

```go
type EndpointClassifier interface {
    Classify(host string) (AWSEndpoint, error)
}

type InboundAuthenticator interface {
    Verify(ctx context.Context, req *http.Request, endpoint AWSEndpoint) (*VerifiedRequest, error)
}

type AWSRequestDecoder interface {
    Decode(ctx context.Context, req *VerifiedRequest, endpoint AWSEndpoint) (*DecodedAWSRequest, error)
}

type IAMMapper interface {
    Map(ctx context.Context, req *DecodedAWSRequest) (*MappingResult, error)
}

type PolicyEngine interface {
    Evaluate(ctx context.Context, input DecisionInput) Decision
}

type UpstreamCredentials interface {
    Retrieve(ctx context.Context) (aws.Credentials, error)
    Identity() UpstreamIdentity
}

type UpstreamSigner interface {
    Sign(ctx context.Context, req *http.Request, body io.ReadSeeker, endpoint AWSEndpoint, creds aws.Credentials) error
}

type AuditWriter interface {
    Write(ctx context.Context, event AuditEvent) error
    Flush(ctx context.Context) error
}

type ErrorEncoder interface {
    Encode(protocol AWSProtocol, denial Denial) *http.Response
}
```

### 17.2 Decision types

```go
type DecisionResult string

const (
    DecisionAllow DecisionResult = "allow"
    DecisionDeny  DecisionResult = "deny"
)

type DecisionInput struct {
    RunID          string
    Endpoint       AWSEndpoint
    Request        *DecodedAWSRequest
    Mapping        *MappingResult
    PolicyHash     string
    MapperVersion  string
}

type Decision struct {
    Result         DecisionResult
    ReasonCode     string
    MatchedRuleIDs []string
}
```

There is intentionally no `warn`, `learn`, `ask`, or remote-approval result in V0.1.

### 17.3 Concurrency model

- One proxy server accepts concurrent connections.
- Each request has its own immutable decision context.
- Mapping and policy caches are concurrency safe and bounded.
- The upstream credential provider is shared and concurrency safe.
- Audit events are serialized through one writer goroutine.
- If the audit queue reaches its hard bound, new AWS requests fail closed rather than drop events.
- Graceful shutdown has a bounded timeout.

---

## 18. Repository and module layout

```text
kordn/
├── cmd/
│   └── kordn/
│       └── main.go
├── internal/
│   ├── app/
│   │   ├── commands.go
│   │   └── run.go
│   ├── config/
│   │   ├── load.go
│   │   ├── schema.go
│   │   └── validate.go
│   ├── runtime/
│   │   ├── child.go
│   │   ├── env.go
│   │   ├── signals_unix.go
│   │   └── sessiondir.go
│   ├── proxy/
│   │   ├── server.go
│   │   ├── connect.go
│   │   ├── auth.go
│   │   ├── tunnel.go
│   │   ├── transport.go
│   │   └── limits.go
│   ├── pki/
│   │   ├── ca.go
│   │   └── leafcache.go
│   ├── awsrequest/
│   │   ├── endpoint.go
│   │   ├── protocol.go
│   │   ├── decode_json.go
│   │   ├── decode_query.go
│   │   ├── decode_restjson.go
│   │   └── decode_restxml.go
│   ├── sigv4/
│   │   ├── verify.go
│   │   ├── canonical.go
│   │   ├── resign.go
│   │   └── payload.go
│   ├── iammap/
│   │   ├── mapper.go
│   │   ├── normalize.go
│   │   ├── resources.go
│   │   ├── dependencies.go
│   │   ├── data/
│   │   └── iamliveadapter/
│   ├── policy/
│   │   ├── engine.go
│   │   ├── glob.go
│   │   └── decision.go
│   ├── credentials/
│   │   ├── provider.go
│   │   ├── assume_role.go
│   │   └── identity.go
│   ├── awserror/
│   │   ├── encode.go
│   │   ├── json.go
│   │   └── xml.go
│   ├── audit/
│   │   ├── event.go
│   │   ├── jsonl.go
│   │   ├── redact.go
│   │   └── summary.go
│   └── cache/
│       └── lru.go
├── api/
│   ├── config.schema.json
│   └── audit.schema.json
├── test/
│   ├── fixtures/
│   ├── integration/
│   ├── compatibility/
│   └── realaws/
├── docs/
│   ├── threat-model.md
│   ├── compatibility.md
│   └── architecture.md
├── third_party/
│   └── iamlive/
│       ├── LICENSE
│       ├── NOTICE
│       └── UPSTREAM_COMMIT
├── LICENSE
├── NOTICE
├── THIRD_PARTY_NOTICES.md
├── SECURITY.md
├── CONTRIBUTING.md
├── go.mod
└── README.md
```

`internal/iammap/iamliveadapter` is the only package permitted to depend directly on or contain substantially derived iamlive mapper code. This keeps provenance and enforcement review boundaries clear.

---

## 19. Compatibility requirements

### 19.1 Release-blocking compatibility matrix

| Producer | Required scenario | Release expectation |
|---|---|---|
| AWS CLI v2 | `sts get-caller-identity`, one read call, one mutation, one deny | Must pass |
| boto3/botocore | One client reused across allowed and denied requests for at least 3 minutes | Must pass |
| Terraform AWS provider | `init`, `plan`, and a sandboxed `apply` using the same proxy | Must pass |
| AWS SDK for Go v2 | Long-lived client, sequential dependent requests, retry after local deny | Must pass |
| Claude Code | Wrapped process can invoke AWS CLI and boto3 subprocesses through Kordn | Must pass on macOS and Linux |
| Codex | Wrapped process can invoke AWS CLI and boto3 subprocesses through Kordn | Must pass on macOS and Linux |

Release notes must pin the exact tested versions. The implementation must avoid hard-coding behavior to a single minor SDK version.

### 19.2 Required behavioral compatibility

- stable fake credentials work for long-lived clients;
- standard SDK retry logic continues to work;
- response streaming works for supported responses;
- AWS request IDs and service error bodies are preserved;
- `HTTP_PROXY`/`HTTPS_PROXY` inheritance works through child processes;
- non-AWS HTTPS continues through opaque tunnels;
- endpoint variants used by the test matrix, including regional and relevant dual-stack/FIPS endpoints, classify correctly;
- an existing corporate proxy can be chained;
- IPv4 loopback works without a system trust-store change.

### 19.3 Explicitly unsupported in V0.1

- applications that ignore proxy environment variables;
- SDK clients with explicit proxy settings that bypass Kordn;
- SigV4a;
- query-presigned requests;
- SigV4 streaming-chunk uploads;
- AWS event-stream signing;
- AWS CRT transports that cannot fall back to supported HTTP/1.1 behavior;
- arbitrary custom endpoints;
- direct browser usage;
- Windows;
- background workers that intentionally outlive the Kordn root child.

Unsupported cases must produce a clear compatibility error when visible to Kordn. Cases that bypass Kordn entirely are documented limitations.

---

## 20. Security invariants

The implementation and review checklist must enforce these invariants:

1. The proxy listens only on loopback unless a future separately reviewed feature changes this.
2. Every proxy connection requires a per-run random proxy credential.
3. Every intercepted AWS request requires a valid SigV4 signature using the per-run fake credential.
4. The upstream identity is resolved and fixed before child launch.
5. The child never receives a real credential from Kordn.
6. Real credentials are never written to Kordn-managed disk files.
7. Fake authentication headers are never forwarded upstream.
8. Unknown endpoints, operations, resource scopes, dependencies, protocols, payload modes, and signing schemes fail closed.
9. Every mapped IAM requirement must be allowed; one deny rejects the entire request.
10. Legitimate AWS-required wildcard scope and unresolved scope are different types.
11. Explicit deny always overrides allow.
12. The policy snapshot is immutable for the run and identified by hash.
13. Non-AWS TLS is tunneled, not terminated.
14. No denied request is sent upstream.
15. Kordn never falls back to direct AWS execution when the proxy or audit path fails.
16. Authorization, session-token, proxy-authentication, and credential material never enter logs.
17. The Kordn CA is per-run and is never added to the system trust store.
18. Request forwarding uses the original recognized AWS hostname with public PKI verification.
19. The proxy does not add `X-Forwarded-For` or other identity-altering headers to AWS requests.
20. Application-level retries remain owned by the originating SDK.
21. The upstream credential is a coarse authority ceiling; Kordn does not claim to alter AWS IAM policy evaluation.
22. Direct-bypass prevention is not claimed until separately implemented with OS enforcement.
23. The proxy refuses to relay requests to loopback and cloud metadata/link-local destinations.

Any change that weakens an invariant requires a threat-model update and an explicit security review.

---

## 21. Performance targets

Targets are measured on a current developer laptop with an already-resolved upstream credential and exclude AWS network latency.

### 21.1 Startup

- Config, policy, CA, and proxy startup: p50 ≤ 250 ms; p95 ≤ 500 ms.
- Interactive SSO/MFA and first upstream credential resolution are measured separately.
- No more than one caller-identity preflight per run.

### 21.2 Hot path

- Cached endpoint classification + mapping metadata + policy decision:
  - p50 added local latency ≤ 3 ms;
  - p95 ≤ 10 ms;
  - p99 ≤ 25 ms.
- Uncached supported request including leaf certificate generation:
  - p95 added local latency ≤ 25 ms.
- Sustained throughput: at least 500 ordinary control-plane requests/second with 100 concurrent connections.
- Idle memory after startup: ≤ 80 MiB.
- Memory under the compatibility suite: ≤ 150 MiB excluding explicitly spooled request bodies.
- No goroutine, file-descriptor, or temporary-file leak after 10,000 mixed requests.

### 21.3 Audit overhead

- Audit serialization is asynchronous but bounded.
- A decision is not considered complete until accepted by the audit writer queue.
- Default decision-event durability may batch writes, but `audit.fsync: decision` must be supported for tests and high-assurance use.
- If the queue is full or the writer fails under `failureMode: deny`, new AWS requests fail closed.

### 21.4 Benchmarks

Required microbenchmarks:

- SigV4 canonicalization and verification;
- SigV4 re-signing;
- AWS JSON and Query decoding;
- resource extraction;
- policy matching with 10, 100, and 1,000 rules;
- decision-cache hit/miss;
- JSONL audit serialization;
- TLS leaf generation and cache hit.

---

## 22. Observability

V0.1 observability remains local.

### 22.1 Metrics

Maintain in-memory counters and histograms for:

```text
kordn_requests_total{decision,service,operation}
kordn_mapping_failures_total{reason}
kordn_signature_failures_total{reason}
kordn_proxy_auth_failures_total
kordn_upstream_errors_total{class}
kordn_request_local_latency_ms
kordn_request_upstream_latency_ms
kordn_policy_cache_hits_total
kordn_policy_cache_misses_total
kordn_active_connections
kordn_audit_queue_depth
kordn_temp_spool_bytes
```

V0.1 does not expose an unauthenticated metrics HTTP server. Metrics are included in the exit summary and may be written as a `run.ended` audit event.

### 22.2 Logging levels

- `error`: invariant-threatening or fatal conditions;
- `warn`: unsupported request, denied operation, cleanup problem;
- `info`: startup identity, allow/deny summary, exit summary;
- `debug`: normalized non-secret protocol and mapping diagnostics;
- `trace`: not shipped in production builds unless redaction tests cover it.

Debug output must use the same central redaction library as audit events.

### 22.3 Diagnostic bundle

A future `kordn diagnose` may collect config schema version, binary version, mapper version, platform, and redacted recent reason codes. It must never include credentials or raw bodies. It is not required for V0.1 acceptance.

---

## 23. Licensing and provenance

### 23.1 Project license

Use **Apache License 2.0** for original Kordn code.

Reasons:

- permissive commercial and open-source use;
- enterprise-friendly redistribution and embedding;
- explicit contributor patent grant;
- compatible distribution alongside MIT-licensed components when their notices are preserved.

Keep brand names and logos subject to a separate trademark policy. Use Developer Certificate of Origin sign-off for contributions initially; a CLA is not required for V0.1.

### 23.2 iamlive

iamlive is MIT-licensed. Kordn may import, vendor, or derive code from it, subject to preserving the MIT copyright and license notice in copies or substantial portions.

Required files:

- root `LICENSE` containing Apache-2.0 for Kordn-original code;
- root `NOTICE`;
- `THIRD_PARTY_NOTICES.md`;
- `third_party/iamlive/LICENSE` containing the iamlive MIT license;
- `third_party/iamlive/UPSTREAM_COMMIT`;
- any additional notices required by copied mapping dependencies.

Source files substantially derived from iamlive must include a short provenance header identifying the upstream file/commit and MIT license.

### 23.3 iam-agent-proxy

Do not copy, vendor, translate, or create derivative source from `iam-agent-proxy` unless its copyright holder publishes an applicable license or grants explicit written permission.

Publicly described behavior may inform independently designed interfaces and tests, but implementation must be written from this specification, AWS documentation, and permissively licensed sources.

### 23.4 Dependency process

- Run automated license scanning in CI.
- Reject dependencies without a detected and approved license.
- Generate an SBOM for every release.
- Include dependency versions and mapper-data provenance in `kordn version --json`.
- Sign release artifacts and publish checksums.

This specification is technical guidance, not legal advice; a qualified lawyer should review the distribution before the first public release.

---

## 24. Detailed implementation milestones

### Milestone 0 — repository, threat model, and protocol spike

**Deliverables**

- Apache-2.0 repository skeleton;
- `SECURITY.md`, threat model, and bypass statement;
- pinned Go toolchain and CI;
- spike proving an HTTP CONNECT proxy can terminate an AWS CLI TLS connection with a per-run CA and `AWS_CA_BUNDLE`;
- spike proving a non-AWS HTTPS request is tunneled without interception;
- initial SigV4 golden-vector tests.

**Exit criteria**

- `kordn run -- aws sts get-caller-identity` reaches a test upstream through the proxy;
- no system trust-store modification;
- non-AWS TLS certificate remains end-to-end between client and destination.

### Milestone 1 — process supervisor and credential isolation

**Deliverables**

- `kordn run --` argument handling;
- per-run directory and cleanup;
- fake credential generation;
- synthetic AWS config/credentials files;
- environment replacement and metadata-provider disabling;
- proxy Basic authentication;
- signal forwarding and child exit propagation;
- upstream profile resolution before child spawn.

**Exit criteria**

- child sees only fake credentials through standard environment/config inspection;
- long-lived child retains one fake credential for its lifetime;
- real credential is absent from child environment, synthetic files, and logs;
- invalid proxy authentication is rejected.

### Milestone 2 — inbound verification and upstream re-signing

**Deliverables**

- strict AWS endpoint classifier for the commercial partition;
- full supported SigV4 inbound verifier;
- upstream SigV4 signer;
- hop-by-hop header handling;
- protocol-aware response streaming;
- request size/spooling limits;
- unsupported signing/payload fail-closed handling.

**Exit criteria**

- valid fake-signed requests are re-signed with a test upstream key and accepted by the test server;
- altered path, query, signed header, token, timestamp, and body-hash cases are rejected;
- fake `Authorization` and session-token values never reach upstream;
- AWS CLI, boto3, and Go SDK can reuse clients through the proxy.

### Milestone 3 — request decoding and IAM mapper

**Deliverables**

- JSON, Query, EC2 Query, REST-JSON, and REST-XML decoders;
- iamlive adapter or clearly derived mapper module;
- pinned mapping data and license notices;
- resource-scope type distinction;
- dependent permission support;
- mapping confidence and evidence model;
- unknown-call fail-closed behavior.

**Exit criteria**

- golden fixtures map representative EC2, ECS, STS, S3, CloudWatch, CloudWatch Logs, IAM, Lambda, and DynamoDB requests;
- unsupported operation produces no upstream request;
- legitimate required `*` scope is different from unresolved scope;
- at least one conditional `iam:PassRole` case is correctly modeled.

### Milestone 4 — policy engine and AWS-shaped errors

**Deliverables**

- strict YAML schema;
- immutable policy snapshot and hash;
- action/resource/account/Region/partition matching;
- explicit-deny precedence;
- known-global wildcard acknowledgement;
- protocol-specific AccessDenied encoders;
- stable reason codes;
- concise terminal denial output.

**Exit criteria**

- rule-order fuzzing produces identical decisions;
- every requirement must be allowed;
- unknown fields and unsafe policy file permissions fail startup;
- AWS CLI, boto3, Terraform, and Go SDK surface a recognizable access-denied error.

### Milestone 5 — audit, caches, and hardening

**Deliverables**

- JSONL event schema and JSON Schema;
- central redaction library;
- bounded audit queue and fail-closed writer failure mode;
- endpoint, leaf, metadata, and decision caches;
- startup and exit summaries;
- fuzzers for HTTP parsing, canonicalization, mapper input, ARN generation, and policy parsing;
- cleanup and crash-recovery tests.

**Exit criteria**

- secret-scanning tests find no fake or real credentials in logs/audit;
- audit writer failure denies new requests;
- 10,000-request soak has no material resource leak;
- cache keys cannot cross resources, policies, Regions, or accounts.

### Milestone 6 — compatibility suite

**Deliverables**

- AWS CLI integration suite;
- long-lived boto3 suite;
- Terraform plan/apply suite;
- Go SDK v2 suite;
- Claude Code and Codex subprocess-inheritance smoke tests;
- sequential dependency and partial-execution suite;
- corporate-proxy chaining test;
- macOS/Linux and `amd64`/`arm64` CI/release matrix.

**Exit criteria**

- all release-blocking compatibility tests pass;
- unsupported features fail clearly and closed when requests reach Kordn;
- versioned compatibility document is generated from the test matrix.

### Milestone 7 — performance and public release

**Deliverables**

- benchmark suite and pprof profiles;
- signed binaries, checksums, SBOM, and provenance;
- Homebrew or equivalent installation path after binary release works;
- public security disclosure process;
- third-party license audit;
- minimal quickstart and example policies.

**Exit criteria**

- performance targets in Section 21 are met or documented with approved exceptions;
- external contributor can reproduce the build and run the quickstart;
- release artifacts include all required license notices;
- security claims match the threat model and do not imply direct-egress containment.

---

## 25. Test strategy and matrix

### 25.1 Unit tests

#### Endpoint classification

- standard regional endpoint;
- global endpoint;
- dual-stack/FIPS endpoint fixtures;
- uppercase/trailing-dot normalization;
- IDNA edge cases;
- `amazonaws.com.evil.example` rejection;
- CONNECT host and inner Host mismatch;
- unsupported partition;
- custom endpoint rejection.

#### SigV4

- AWS-published canonical request vectors;
- correct fake key/token;
- wrong access key;
- wrong session token;
- missing signed header;
- duplicate header canonicalization;
- encoded path and query edge cases;
- expired/future timestamp;
- tampered payload hash;
- changed method/path/query;
- unsupported SigV4a;
- unsupported presigned query;
- unsupported streaming mode.

#### Mapping

- service and operation detection for every supported protocol;
- API operation with one IAM action;
- API operation with multiple IAM actions;
- conditional dependent action;
- exact ARN;
- finite ARN set;
- known global `*`;
- unresolved resource;
- stale/unknown operation;
- malformed request parameters;
- mapper timeout/panic containment.

#### Policy

- default deny;
- exact allow;
- wildcard action allow;
- exact-resource allow;
- resource-glob allow;
- explicit deny precedence;
- multiple requirements all covered;
- one requirement uncovered;
- known-global action without acknowledgement;
- policy hash stability;
- rule-order independence;
- strict unknown-field rejection;
- unsafe file permissions.

#### Redaction

- real and fake access key patterns;
- secret key;
- session token;
- authorization headers;
- proxy auth;
- presigned query parameters;
- bodies containing credentials;
- panic/error formatting.

### 25.2 Integration test harness

Build an in-process or containerized fake AWS endpoint that:

- has a recognized test endpoint injected through the internal classifier;
- validates the upstream signature using a known real test key;
- returns modeled AWS protocol responses;
- records whether any denied request reached it;
- can inject latency, disconnects, 403s, 429s, and 5xx responses;
- supports sequential stateful fixtures.

Add a separate opt-in nightly test account for real AWS behavior. Real-account tests must use dedicated low-privilege roles and uniquely tagged disposable resources.

### 25.3 Required tool scenarios

#### AWS CLI

1. Allowed `sts:GetCallerIdentity`.
2. Allowed read operation.
3. Allowed resource-scoped mutation in a sandbox account.
4. Explicit local deny.
5. Unknown operation fixture.
6. Verify CLI prints an AWS-recognizable access denial.

#### boto3 long-lived client

```python
ecs = boto3.client("ecs")

# Same client for all calls.
ecs.describe_services(...)
ecs.describe_tasks(...)
ecs.update_service(...)
```

Requirements:

- one fake credential throughout;
- no client recreation;
- each request independently mapped and authorized;
- allow/deny changes by action/resource work with the same client;
- upstream credential refresh remains transparent.

#### Terraform

- `terraform init` succeeds through non-AWS tunnels and registry access;
- AWS provider calls traverse Kordn;
- `terraform plan` succeeds under a read policy;
- a narrowly allowed sandbox `apply` succeeds;
- a later denied call returns a normal provider error;
- audit shows earlier successful calls and denied later call;
- no automatic rollback is claimed.

#### Go SDK v2

- reuse one client across requests;
- standard retry behavior after upstream 429;
- no proxy retry of ambiguous mutation;
- allow and deny resource-scoped calls;
- response streaming for a supported operation.

#### Dependent sequential calls

Stateful test:

1. call A reads a resource identifier;
2. the program derives call B's target from A's response;
3. call B is authorized against the resolved target;
4. call C is denied;
5. A and B remain completed;
6. C never reaches upstream;
7. audit records the partial sequence accurately.

This proves Kordn authorizes runtime-resolved requests without requiring static analysis or client recreation.

#### Claude Code and Codex

- launch each through `kordn run`;
- agent invokes AWS CLI subprocess;
- agent writes and runs a short boto3 script;
- both inherit fake credentials and proxy variables;
- non-AWS agent API traffic remains an opaque tunnel;
- denial is visible to the agent as an AWS access error and to the user as an Kordn terminal event.

### 25.4 Adversarial and limitation tests

- child unsets proxy variables and direct-connects: document that Kordn does not observe the request;
- child explicitly reads the user's original credential file: document the bypass possibility;
- child sends a request with a real access key through Kordn: reject because the inbound key is not the run's fake key;
- sibling process guesses proxy port without proxy secret: reject;
- replay a captured fake-signed request outside timestamp window: reject;
- send non-AWS CONNECT: tunnel without TLS interception;
- attempt AWS endpoint lookalike: tunnel or reject as non-AWS, never treat as AWS;
- kill audit writer: deny new AWS requests;
- kill proxy: child receives connection failure; no direct fallback.

These tests ensure limitations are deliberate and visible rather than accidental claims.

---

## 26. Acceptance criteria for V0.1

The release is acceptable only when all of the following are true:

1. `kordn run -- <command>` is the sole runtime architecture for every supported producer.
2. AWS CLI, boto3, Terraform, and Go SDK v2 all traverse the same local proxy implementation.
3. A long-lived boto3 and Go client work without credential refresh or client recreation caused by Kordn.
4. The child receives only a stable fake credential created for the run.
5. Real upstream credentials do not appear in child environment, Kordn-managed files, stdout/stderr, audit events, or error bodies.
6. Allowed requests are re-signed and accepted by AWS or the signature-validating test upstream.
7. Denied requests do not reach the upstream test server.
8. Unknown endpoint, operation, resource, dependency, protocol, payload, or signing scheme fails closed.
9. The mapper distinguishes known AWS-required wildcard scope from unresolved scope.
10. Every dependent IAM requirement must be allowed.
11. Explicit deny overrides allow and rule order does not matter.
12. The policy is loaded immutably and identified by a stable hash.
13. Local denials are returned in protocol-appropriate AWS error shapes.
14. Upstream AWS errors pass through and are distinguishable in audit.
15. Non-AWS HTTPS is tunneled without decryption.
16. Proxy connections and AWS requests are both authenticated.
17. CA material is per-run, private, and cleaned up.
18. The sequential-call test demonstrates runtime dependency support and accurate partial-execution semantics.
19. The required compatibility matrix passes on macOS and Linux.
20. Hot-path performance meets Section 21 targets.
21. The repository is Apache-2.0, preserves iamlive MIT notices, and contains no unlicensed copied `iam-agent-proxy` code.
22. Documentation prominently states that proxy bypass is not prevented by V0.1.

---

## 27. Open questions

These questions should be resolved through implementation spikes or kept explicit in the compatibility document:

1. **iamlive integration form:** Is the existing Go package clean enough to import, or should Kordn vendor a narrow, attributed mapper/data subset behind its own interface?
2. **Mapping freshness:** How frequently should the pinned AWS/iAM mapping snapshot be updated, and what regression gate prevents a new mapping from widening behavior?
3. **Dependent permissions:** Which services need Kordn-specific request-aware logic beyond the iamlive mapping to model conditional dependencies such as `iam:PassRole`?
4. **Resource ambiguity:** For which high-value actions does iamlive currently emit wildcard because extraction is incomplete rather than because AWS requires it?
5. **Endpoint coverage:** Which FIPS, dual-stack, global, account-based, and new endpoint forms are required for the first release?
6. **CA support:** Do all targeted Terraform and Go provider versions honor `AWS_CA_BUNDLE` consistently when proxy environment variables are used?
7. **Proxy authentication:** Do all release-blocking clients preserve Basic proxy credentials on CONNECT and reconnection?
8. **Corporate proxy chaining:** How should Kordn handle corporate proxies that themselves perform TLS inspection without weakening upstream certificate verification?
9. **Payload handling:** Which non-streaming S3 operations can safely ship in V0.1 without accidentally implying support for streaming SigV4 chunks?
10. **Presigned URLs:** Should a future release re-sign query-presigned requests, or explicitly treat presigning as an authority-bearing artifact outside the proxy's model?
11. **SigV4a:** Can AWS SDK for Go's signer/verifier primitives be reused safely, and which multi-Region services require SigV4a for practical compatibility?
12. **Policy expressiveness:** When are action/resource/Region/account rules insufficient because request parameters change risk without changing IAM action?
13. **Audit durability:** Should default local use prefer one `fsync` per decision, bounded batching, or a configurable durability/performance tradeoff?
14. **Process attribution:** Is portable descendant PID attribution worth platform-specific socket inspection, or is run-level attribution sufficient?
15. **Background descendants:** Should a later version expose an explicit supervised detach mode without adding a second authorization architecture?
16. **Direct bypass:** What is the smallest cross-platform OS enforcement addition that can ensure protected processes reach AWS only through Kordn while preserving the request-boundary design?
17. **Original credential files:** Can a future wrapper hide user AWS config and SSO caches without becoming a full filesystem sandbox?
18. **Upstream role semantics:** Should the first public release require an assumed-role ceiling rather than allow an arbitrary profile identity?
19. **Resource-based policy caveats:** How should documentation explain that AWS resource policies may affect effective permissions beyond the upstream role/session's identity policy?
20. **Name clearance:** Before public release, does `Kordn` require a separate trademark and package-name search due to existing uses in security software?

---

## 28. Normative and implementation references

- [iamlive repository and proxy-mode documentation](https://github.com/iann0036/iamlive) — runtime proxy approach, `HTTP_PROXY`/`HTTPS_PROXY`, `AWS_CA_BUNDLE`, embedded mapping override, and MIT license declaration.
- [iamlive MIT license](https://raw.githubusercontent.com/iann0036/iamlive/main/LICENSE) — copyright and reuse conditions.
- [AWS: Using an HTTP proxy for the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-proxy.html) — supported proxy environment variables and precedence notes.
- [AWS SDKs and Tools: General configuration settings](https://docs.aws.amazon.com/sdkref/latest/guide/feature-gen-config.html) — `ca_bundle` and `AWS_CA_BUNDLE`.
- [AWS SDKs and Tools: AWS access keys](https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html) — standard access-key environment/config settings across SDKs.
- [AWS SDKs and Tools: IMDS credential provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-imds-credentials.html) — `AWS_EC2_METADATA_DISABLED` behavior.
- [AWS: Create a signed AWS API request](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html) — SigV4 canonicalization, temporary session token use, and proxy-mutated header guidance.
- [AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html) — operation-to-action relationships, resource-level permission support, condition keys, and multiple IAM actions per API operation.
- [AWS machine-readable service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html) — programmatic operations, actions, resources, and condition metadata.
- [AWS STS AssumeRole API](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) — credential properties, role/session policy intersection, session limits, and source identity.
- [AWS IAM policy and session evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html) — IAM policy types and resource-policy/session-policy nuances.
- [AWS IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html) — optional build/test validation of generated policy fixtures.

---

## 29. Concise implementation directive

Build Kordn as one local Go binary that launches a child with per-run fake AWS credentials and authenticated proxy settings, terminates TLS only for strictly recognized AWS endpoints, verifies the child's fake SigV4 request, maps the resolved request to high-confidence IAM action/resource requirements, applies an immutable deny-by-default local policy, returns an AWS-shaped denial for any forbidden or unknown request, and re-signs allowed requests with a fixed upstream authority-ceiling credential held only inside Kordn.

Do not add a second CLI-specific path, static-analysis path, remote broker, LLM decision, dynamic IAM creation, or hidden direct fallback to V0.1.
