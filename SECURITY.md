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
AWS access.

Use a dedicated, least-privileged upstream profile or role. Passing an
administrator profile makes Kordn a holder of that authority; the local policy
is not an AWS-native permission boundary.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in a public issue. Email me (aliaksandra.neviarouskaya@gmail.com) with a description, affected revision, reproduction steps. Do not attach credentials or customer data.
