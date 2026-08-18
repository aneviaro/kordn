# Kordn V0.1 threat model

## Security boundary

Kordn is one local process. It resolves the upstream authority before launch,
creates a per-run fake credential and CA, starts an authenticated loopback
CONNECT proxy, verifies supported AWS requests, maps them to IAM requirements,
and applies an immutable deny-by-default policy before forwarding. The
per-run CA is trusted by the child through `AWS_CA_BUNDLE`; it is never
installed in the system trust store.

The narrow claim is:

> For supported AWS requests that use the Kordn fake credential and traverse the authenticated Kordn proxy, Kordn verifies the inbound request, maps it to IAM requirements, applies a deny-by-default local policy, and does not forward denied or unknown requests. Real upstream credentials are not exposed to the protected process by Kordn.

This claim is deliberately limited to requests visible at that boundary. It
does not claim that `kordn run` prevents all direct AWS access.

## Assets

- real upstream credentials and the authority ceiling;
- local policy integrity and its immutable run snapshot;
- the fake credential and per-run CA private key;
- audit confidentiality/integrity; and
- AWS resources reachable through the upstream authority.

## In-scope failure modes

The first implementation must fail closed for missing proxy authentication,
unsupported or ambiguous AWS endpoints, invalid fake SigV4, unknown mappings,
unresolved resources, policy misses, and audit unavailability. Non-AWS HTTPS
CONNECT is an opaque byte tunnel: Kordn does not terminate TLS, inspect or
rewrite payloads, or apply AWS policy to it. Literal and resolved unsafe proxy
destinations must not become SSRF relays.

The protocol spike in `test/integration/proxy_spike_test.go` proves the two
TLS boundaries independently: a recognized AWS-like endpoint is terminated
with a generated run CA, while a non-AWS server certificate and request/
response bytes pass through unchanged.

## Explicit V0.1 bypasses

Same-user code is not contained. It may ignore or override `HTTP_PROXY` and
`HTTPS_PROXY`, open direct AWS TLS, explicitly read `~/.aws/credentials`, SSO
caches, web-identity files, or other credential sources, use hard-coded
credentials or direct metadata providers, use presigned URLs, modify TLS or
proxy behavior, attach a debugger, or kill Kordn. Descendants that do not
honor the inherited fake credentials and proxy are outside the claim. These
limitations are documented rather than presented as blocked attacks.

Users should configure a dedicated, least-privileged upstream profile or role;
Kordn does not turn an administrator upstream identity into an AWS permission
boundary.
