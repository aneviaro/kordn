# Compatibility matrix

The compatibility boundary is the authenticated `kordn run -- <producer>`
request path. The AWS CLI, boto3, Terraform, and Go SDK v2 use the same local
proxy implementation; there is no producer-specific authorization path.

Pinned producer versions are in [`test/compatibility/versions.json`](../test/compatibility/versions.json).
`make test-compatibility` is hermetic and never contacts AWS, downloads
providers, or runs the long boto loop. The external gate sets
`KORDN_EXTERNAL_REQUIRED=1`; a missing exact binary, provider mirror, or agent
is a failure rather than a substitute shim. Source checkouts must include the
submodule and run `make iamlive-init` (also supported after a non-recursive
clone); subsequent checks are offline. GitHub source archives and plain
`go install` are unsupported inputs. Published binaries are standalone and do
not need the checkout or submodule.

| Producer / behavior | Hermetic gate | External required gate |
|---|---|---|
| AWS CLI read, mutation, deny, unknown, upstream status/code/request ID | fixture scenarios | Linux amd64, macOS arm64 |
| Terraform init/plan/apply/later-operation deny and state/partial audit | fixture controls and mirror preflight | Linux amd64, macOS arm64 |
| One long-lived boto3 client and rotating short-lived credentials for at least 3 minutes | preflight only | Linux amd64, macOS arm64; `KORDN_BOTO_LONG_RUN=1` |
| Claude Code and Codex real tool launch | preflight only | Linux amd64, macOS arm64; exact binary, no shim |
| Corporate authenticated parent relay, reconnect, opaque TLS/chunks | local relay tests | Linux amd64, macOS arm64 |
| Adversarial auth/lookalike/killed proxy | local relay tests | Linux amd64, macOS arm64 |

The supported producer boundary is still the positive endpoint classifier. IAM
XML/Query denials remain protocol-native with stable reason/event identifiers;
unsupported, ambiguous, or unresolved catalog evidence is denied locally and is
never forwarded upstream.

Performance is a measured release gate, not a compatibility promise. For a
focused local catalog smoke test, run `make benchmark-hotpath`; it requires the
pinned iamlive catalog and reports allocations as well as timings. To compare
common decoder samples from two refs, run
`./scripts/bench-compare.sh <baseline-ref> <candidate-ref>`; recorded output
files can instead be compared with
`./scripts/bench-compare.sh --files <baseline.txt> <candidate.txt>`. File and ref
comparisons require the separately installed `benchstat` tool; the script does
not download it. CI treats benchmark timings as diagnostic only, while the
structural and allocation tests are deterministic hard gates.

On the documented current Darwin amd64 reference machine run
`KORDN_STRICT_PERFORMANCE=1 make strict-performance` and
`KORDN_STRICT_PERFORMANCE=1 make strict-compatibility`. These strict checks
record actual throughput, p50/p95/p99, RSS, and resource counters. Shared-runner
numbers are not performance guarantees.

## Explicit non-containment limitations

Unset/direct proxy variables permit direct egress, and a child with filesystem
access can read an original credential file. These are limitation tests, not
security claims. Kordn does not install its CA in the system trust store, does
not inspect non-AWS TLS, and cannot contain a same-user process that bypasses
the inherited proxy.
