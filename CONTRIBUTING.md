# Contributing to Kordn

Thank you for helping improve Kordn. Original Kordn code is licensed under the
MIT License. Read `SECURITY.md` before reporting a vulnerability.

## Development

Use the pinned toolchain in `.go-version` and run the canonical gates before
opening a pull request:

```text
make fmt-check
make lint
make test-race
make license-check
make build
```

Keep the one-process, request-boundary architecture intact. Do not add a
network control plane, an SDK-specific authorization path, or a direct-egress
security claim.

Pull requests should describe security-relevant behavior and include tests for
fail-closed changes. Never include credentials, tokens, private keys, request
bodies, or production audit data in issues, commits, or test fixtures.

If you are bringing the new feature, start with opening a discussion first, to get the approval and the vibe checked.
