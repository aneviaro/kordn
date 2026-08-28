# Real AWS contract tests

These tests are **not** part of ordinary CI and never run without an explicit
opt-in. The dedicated nightly job must set `KORDN_REALAWS_OPT_IN=1`, provide an
account and role allowlist, and provide `KORDN_REALAWS_TOKEN` through the CI
secret store. The test checks opt-in before reading any AWS credential or
starting a network client.

Use a low-privilege role that cannot perform destructive operations by default.
Every disposable resource must be prefixed with a unique run identifier and
registered for cleanup. A hard two-minute request timeout and an independent
job timeout are required. No credentials are written to artifacts, logs, or
this repository. Missing opt-in is a safe skip, not a successful AWS run.
