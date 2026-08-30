# Quickstart

## Initialize and validate

Use an isolated home for a smoke test or a dedicated real home for normal use:

```sh
kordn init
kordn policy validate --config ~/.kordn/config.yaml
kordn version --json
```

Edit the policy with a dedicated, least-privilege upstream profile. Keep the
policy default deny and add complete action/resource rules. The upstream
identity is an authority ceiling; the local policy can only narrow it.

## Protected execution

```sh
kordn run --config ~/.kordn/config.yaml -- aws sts get-caller-identity
```

The separator is mandatory and arguments after it are passed directly, without
a shell. Events are written to the configured private JSONL audit path. Query
the summary with `kordn audit --json`.

Kordn intercepts only recognized commercial AWS TLS endpoints. Other HTTPS
traffic remains byte-opaque. It does not install its per-run CA in a system
trust store and it does not prevent a same-user program from bypassing proxy
environment variables, opening direct AWS connections, or reading original
credential files. These are explicit V0.1 limitations, not containment claims.

Use `make release-snapshot` for an offline static-artifact smoke gate. The
release artifacts include checksums, SBOM/provenance metadata, dependency and
mapper snapshot information, and license notices.
