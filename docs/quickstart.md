# Quickstart

## Initialize and validate

A source checkout must include the pinned sparse iamlive submodule. Clone with
`--recurse-submodules` and run `make iamlive-init`, or run that target after a
non-recursive clone. It is the only network-capable preparation step; use
`GOPROXY=off GOSUMDB=off make iamlive-check` to verify the pin and catalog
offline. GitHub source archives and plain `go install` are unsupported; a
published binary is standalone.

Use an isolated home for a smoke test or a dedicated real home for normal use:

```sh
kordn init
kordn policy validate --config ~/.kordn/config.yaml
kordn version --json
```

Edit the policy with a dedicated, least-privilege upstream profile. Keep the
policy default deny and add complete action/resource rules. The upstream
identity is an authority ceiling; the local policy can only narrow it.

## Example policy and commands

The repository includes a small read-only AWS CLI policy at
[`../examples/policies/aws-cli-read-only.yaml`](../examples/policies/aws-cli-read-only.yaml).
It covers these commands after you replace the example profile and bucket:

```sh
aws sts get-caller-identity
aws s3 ls s3://kordn-example-reports
aws s3 cp s3://kordn-example-reports/reports/latest.csv -
```

Copy it into the Kordn configuration location, then validate it:

```sh
cp examples/policies/aws-cli-read-only.yaml ~/.kordn/config.yaml
kordn policy validate --config ~/.kordn/config.yaml
```

The comments in the example policy are intentionally explanatory. Kordn does
not authorize shell commands; it authorizes the concrete AWS requests they
produce. Add an action/resource rule for every request a command needs.

## Protected execution

```sh
kordn run --config ~/.kordn/config.yaml -- aws sts get-caller-identity
```

The separator is mandatory and arguments after it are passed directly, without
a shell. Events are written to the configured private JSONL audit path. Query
the summary with `kordn audit --json`.

Kordn intercepts only recognized commercial AWS TLS endpoints. Other HTTPS
traffic remains byte-opaque. Catalog operation/resource evidence is neutral;
endpoint activation and authorization are separate boundaries. Unsupported,
ambiguous, or unresolved evidence fails closed without upstream forwarding,
and IAM Query/XML local denials retain protocol-native responses and stable
reason/event identifiers. It does not install its per-run CA in a system
trust store and it does not prevent a same-user program from bypassing proxy
environment variables, opening direct AWS connections, or reading original
credential files. These are explicit V0.1 limitations, not containment claims.

## Audit log example

Audit records are private, append-only JSONL. Query a run summary with:

```sh
kordn audit --run RUN_ID
kordn audit --run RUN_ID --json
```

The full representative file at
[`../examples/audit/events.jsonl`](../examples/audit/events.jsonl) shows a
startup event, an allowed global STS request, a denied S3 request, and the
run summary. Resource names are represented by a run-scoped HMAC in this
example; configure `logResourceArns: true` only when clear-text resource names
are appropriate for the audit file.

Use `make release-snapshot` for an offline static-artifact smoke gate. The
release artifacts include checksums, SBOM/provenance metadata, dependency and
mapper snapshot information, and license notices.
