# Kordn

Kordn is a local AWS request-boundary proxy. Run a supported command with a
stable fake credential and an authenticated loopback proxy:

```sh
kordn init
kordn run --config ~/.kordn/config.yaml -- aws sts get-caller-identity
```

The default policy is deny-by-default. Configure a dedicated, least-privilege
upstream identity and explicitly allow only the AWS actions and resources the
command needs. Kordn keeps the upstream credential in the parent process and
records redacted, append-only audit events.

## Security boundary

The security claim is intentionally narrow: for supported AWS requests that
use Kordn's fake credential and traverse the authenticated proxy, Kordn
verifies, maps, authorizes, audits, and only then forwards the request. This is
an application-level proxy-boundary control, not an operating-system sandbox.
A same-user process can ignore proxy settings, connect directly, or read an
original credential file. Those documented bypasses are not contained by
`kordn run`; do not run hostile code with access to the same account.

Non-AWS HTTPS is tunneled opaquely. The per-run CA is private and is never
installed in the system trust store. See [docs/quickstart.md](docs/quickstart.md),
[docs/threat-model.md](docs/threat-model.md), and [SECURITY.md](SECURITY.md).
