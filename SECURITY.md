# Security policy

## Scope and claim

Kordn is a local request-boundary control, not an operating-system sandbox.
For supported AWS requests that use the Kordn fake credential and traverse the
authenticated Kordn proxy, Kordn verifies the inbound request, maps it to IAM
requirements, applies a deny-by-default local policy, and does not forward
denied or unknown requests. Real upstream credentials are not exposed to the
protected process by Kordn.

V0.1 does **not** prevent proxy bypass or explicit same-user access to
credential files. A process running as the same user may ignore proxy
variables, open direct AWS connections, read `~/.aws/credentials`, SSO or
web-identity files, use hard-coded credentials or metadata providers, attach a
debugger, or kill Kordn. Kordn must not be described as preventing all direct
AWS access. The CA is per-run and is never installed in a system trust store.

Use a dedicated, least-privileged upstream profile or role. Passing an
administrator profile makes Kordn a holder of that authority; the local policy
is not an AWS-native permission boundary.

## Release security gates

`make security-check` runs format/vet/schema/license/mapper checks and runs
`govulncheck` when installed, reporting it unavailable locally otherwise. The
public release workflow installs and verifies a pinned govulncheck, Syft, and
Cosign version, then runs strict performance and soak tests before creating
checksummed, SBOM-attested and keylessly signed artifacts. Missing release
tools fail that workflow; no local run claims an unavailable scan passed.

## Exceptions

Any exception to a Section 20 invariant or Section 26 acceptance criterion is
release-blocking until the threat model is updated and the exception receives
an explicit security review. The review record must name the exact failed
check, impact, compensating control, owner, and expiry.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in a public issue. Email me
(aliaksandra.neviarouskaya@gmail.com) with a description, affected revision,
reproduction steps, and no credentials or customer data.
