# Bootstrap architecture

## One process, one boundary

The target runtime is one `kordn run` process. Its composition root will own
configuration, upstream credential resolution, fake run identity, per-run PKI,
authenticated loopback proxy, endpoint classification, SigV4 verification,
protocol decoding, IAM mapping, policy, audit, upstream signing/transport, and
child supervision. There is no daemon, remote control plane, SDK-specific path,
or static-analysis authorization path in V0.1.

The protected child receives a stable fake AWS credential, a private synthetic
AWS configuration, proxy variables, and `AWS_CA_BUNDLE`. Kordn captures any
parent corporate proxy settings before constructing that child environment and
uses a separate outbound transport, so it cannot recursively proxy its own
credential refresh through the child-facing listener.

## Protocol split

CONNECT authority and inner `Host` will be classified independently. A
recognized commercial AWS endpoint is the only interception candidate and gets
a short-lived, hostname-SAN leaf signed by a newly generated run CA. The CA
private key remains in private run storage and is removed during cleanup; no
system trust store is changed. Non-AWS HTTPS CONNECT is opaque and retains the
server's end-to-end certificate and payload bytes. The Task 1 executable proof
uses an injected positive classifier and test address mapping; production
endpoint classification and SSRF checks are later-owned by `internal/proxy`.

## Package and legal boundary

Original code is Apache-2.0. The only permitted direct iamlive integration
boundary is `internal/iammap/iamliveadapter`; Kordn-specific authentication,
policy, forwarding, credential isolation, and audit remain outside it. Task 1
records the evaluated upstream revision and selected minimal attributed
mapper-data/logic derivation in ADR 0001 without copying source or adding a
runtime dependency. No source from unlicensed `iam-agent-proxy` is used.

## Startup invariant

Before a child can be launched, the eventual composition root must validate
configuration and policy, resolve and preflight the upstream identity, create
run secrets and CA, start audit and proxy, and construct the child environment.
Any failure leaves the child unexecuted. This bootstrap command tree deliberately
returns a clear not-implemented status for runtime commands rather than
silently launching an unprotected child.
