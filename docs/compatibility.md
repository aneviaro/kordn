# Compatibility matrix

The compatibility boundary is `kordn run -- <producer>`. The fakeAWS fixture
is local TLS and validates the re-signed request, records a forward ledger, and
models state/errors. Ordinary `make test-compatibility` runs only this hermetic
coverage; it never contacts AWS, downloads providers, or runs the 3-minute
boto loop.

Pinned producer versions are in [`test/compatibility/versions.json`](../test/compatibility/versions.json).
The external gate sets `KORDN_EXTERNAL_REQUIRED=1`; missing binaries or a
provider mirror then fail (tests never substitute shims). Claude and Codex
must use their documented `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` settings and
an offline local model fixture; the returned tool call must launch the real
child command.

| Producer / behavior | Hermetic pure gate | External required gate |
|---|---:|---:|
| AWS CLI read, mutation, deny, unknown, upstream status/code/request ID | fixture scenarios (binary required) | Linux amd64, macOS arm64 |
| Terraform init/plan/apply/later-operation deny and state/partial audit | fixture controls and mirror preflight | Linux amd64, macOS arm64; CI dynamically provisions the exact pinned provider mirror/cache |
| One long-lived boto3 client and rotating short-lived credentials for at least 3 minutes | preflight only | Linux amd64, macOS arm64; `KORDN_BOTO_LONG_RUN=1` |
| Claude Code and Codex real tool launch | preflight only | Linux amd64, macOS arm64; exact binary, no shim |
| Corporate authenticated parent relay, reconnect, opaque TLS/chunks | local relay | Linux amd64, macOS arm64 |
| Adversarial auth/lookalike/killed proxy | local relay | Linux amd64, macOS arm64 |

CI has separate pure and external jobs. Pure integration/compatibility tests
run on Linux and macOS in the `amd64` and `arm64` build matrix where runners
exist. The external release gate is intentionally limited to Linux amd64 and
macOS arm64 and reports an unavailable exact producer as a failure.

## Explicit non-containment limitations

Unset/direct proxy variables permit direct egress, and a child with filesystem
access can read an original credential file. These are successful limitation
tests, not security claims. Kordn does not install its CA in the system trust
store, does not inspect non-AWS TLS, and cannot contain a same-user process that
bypasses the inherited proxy.
