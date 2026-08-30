# Runtime architecture

## One process, one boundary

The runtime is one `kordn run` process. Its composition root owns configuration,
upstream credential resolution, fake run identity, per-run PKI, authenticated
loopback proxy, endpoint classification, SigV4 verification, protocol decoding,
IAM mapping, policy, audit, upstream signing/transport, and child supervision.
There is no daemon, remote control plane, SDK-specific path, or static-analysis
authorization path in V0.1.

The protected child receives a stable fake AWS credential, a private synthetic
AWS configuration, proxy variables, and `AWS_CA_BUNDLE`. Kordn captures any
parent corporate proxy settings before constructing that child environment and
uses a separate outbound transport, so it cannot recursively proxy its own
credential refresh through the child-facing listener.

## Protocol split

CONNECT authority and inner `Host` are classified independently. A recognized
commercial AWS endpoint is the only interception candidate and gets a
short-lived, hostname-SAN leaf signed by a newly generated run CA. The CA
private key remains in private run storage and is removed during cleanup; no
system trust store is changed. Non-AWS HTTPS CONNECT is opaque and retains the
server's end-to-end certificate and payload bytes. The executable integration
proof uses an injected positive classifier and test address mapping; production
endpoint classification and SSRF checks are owned by `internal/proxy`.

## Package and legal boundary

Original code is Apache-2.0. The only permitted direct iamlive integration
boundary is `internal/iammap/iamliveadapter`; Kordn-specific authentication,
policy, forwarding, credential isolation, and audit remain outside it. Task 1
records the evaluated upstream revision and selected minimal attributed
mapper-data/logic derivation in ADR 0001 without copying source or adding a
runtime dependency. No source from unlicensed `iam-agent-proxy` is used.

## Startup invariant

Before a child is launched, the composition root validates configuration and
policy, resolves and preflights the upstream identity, creates run secrets and
CA, starts audit and proxy, and constructs the child environment. Any failure
leaves the child unexecuted; no command silently launches an unprotected child.
