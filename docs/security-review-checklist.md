# V0.1 security and release checklist

Every normative item has a stable ID and a concrete executable check. `make checklist-validation` rejects missing or duplicate IDs; release verification runs that target.

| ID | Normative requirement | Concrete test or command |
|---|---|---|
| S20-01 | loopback-only listener | `TestSecurityAdversarialProxyBoundary and internal/proxy tests` |
| S20-02 | per-run random proxy credential on every connection | `TestSecurityAdversarialProxyBoundary` |
| S20-03 | valid fake-credential SigV4 on every intercepted AWS request | `TestSecurityRealProxyRejectsBadStaleAndForwardsAllowed` |
| S20-04 | upstream identity fixed before child launch | `TestSecurityRealProxyRejectsBadStaleAndForwardsAllowed and runtime credential tests` |
| S20-05 | child never receives real credentials | `TestSecurityExplicitDirectAndCredentialFileLimitations and runtime tests` |
| S20-06 | real credentials never written to managed disk | `TestSecurityRealProxyRejectsBadStaleAndForwardsAllowed and fakeaws ledger tests` |
| S20-07 | fake auth headers never forwarded upstream | `fakeaws protocol tests and security integration` |
| S20-08 | unknown endpoint/operation/resource/dependency/protocol/payload/signing fails closed | `internal/proxy, awsrequest, iammap, policy and sigv4 tests` |
| S20-09 | all mapped IAM requirements allowed conjunctively | `policy engine tests and TestSecurityRealProxyDeniesBeforeUpstream` |
| S20-10 | known AWS wildcard distinct from unresolved scope | `iammap golden and policy scope tests` |
| S20-11 | explicit deny overrides allow | `policy tests TestRuleOrderInvariant` |
| S20-12 | immutable hashed policy snapshot | `config snapshot/hash tests` |
| S20-13 | non-AWS TLS tunneled opaque | `TestSecurityAdversarialProxyBoundary` |
| S20-14 | denied requests absent upstream | `TestSecurityRealProxyDeniesBeforeUpstream and fakeaws ledger` |
| S20-15 | no direct fallback on proxy or audit failure | `TestSecurityAuditWriterFailureStopsForwarding and proxy close tests` |
| S20-16 | credential and auth material absent from logs | `audit redaction tests, secret scan` |
| S20-17 | per-run CA private and absent system trust | `internal/pki tests and release snapshot` |
| S20-18 | recognized AWS hostname and public PKI upstream verification | `fakeaws signature verification and proxy transport tests` |
| S20-19 | no identity-altering forwarding headers | `fakeaws ledger header assertions` |
| S20-20 | SDK owns application retries | `proxy retry and upstream failure tests` |
| S20-21 | upstream credential is authority ceiling only | `security docs and fake AWS authority-ceiling tests` |
| S20-22 | direct bypass prevention not claimed | `TestDirectConnectAndOriginalCredentialReadAreDocumentedOutOfScope` |
| S20-23 | loopback and metadata/link-local relay refused | `proxy destination rejection tests` |

| ID | V0.1 acceptance criterion | Concrete test or command |
|---|---|---|
| AC-01 | kordn run is sole runtime architecture | `runtime command tests` |
| AC-02 | AWS CLI/boto3/Terraform/Go SDK share proxy | ``make test-compatibility` and producer tests` |
| AC-03 | long-lived boto3 and Go clients work | `boto3/Go SDK compatibility tests` |
| AC-04 | child receives stable fake credential | `runtime credential tests` |
| AC-05 | real credentials absent from all stated surfaces | `redaction, file, and error-body tests` |
| AC-06 | allowed requests re-signed and accepted | `resign integration test` |
| AC-07 | denied requests absent test upstream | `security integration and fakeaws ledger` |
| AC-08 | unknown inputs fail closed | `adversarial protocol/mapper tests` |
| AC-09 | wildcard and unresolved scope distinguished | `iammap golden/no-widening tests` |
| AC-10 | dependent IAM requirements conjunctive | `dependent PassRole tests` |
| AC-11 | deny precedence and rule order independence | `policy tests/fuzz-smoke` |
| AC-12 | immutable hashed policy | `config/policy snapshot tests` |
| AC-13 | protocol-appropriate local errors | `awserror protocol tests` |
| AC-14 | upstream errors distinct and audited | `upstream-status integration test` |
| AC-15 | non-AWS HTTPS tunneled | `opaque proxy tunnel test` |
| AC-16 | proxy and AWS auth enforced | `proxy/SigV4 tests` |
| AC-17 | private CA cleanup | `PKI cleanup and release snapshot` |
| AC-18 | A/B/C partial execution semantics | `TestSecurityABCLedgerAndAuditUseTheRealProxyHarness` |
| AC-19 | macOS/Linux matrix | ``make test-compatibility` on release runners` |
| AC-20 | Section 21 hot-path targets | ``KORDN_STRICT_PERFORMANCE=1 make strict-performance`` |
| AC-21 | MIT license and iamlive notices/no copied code | ``make license-check` and snapshot metadata` |
| AC-22 | bypass limitation documented | `docs/security-review-checklist.md and `make security-check`` |

The direct-connect and same-user credential-file statements are documented V0.1 limitations, not containment claims. Release verification has no optional skip path.
