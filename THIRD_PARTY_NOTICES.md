# Third-party notices

Kordn's original code is Apache-2.0. The dependency set is deliberately small
and is checked by `make license-check`; adding a module requires a reviewed
license and an update to this file and `third_party/licenses/`.

## iamlive — MIT

I am using the iamlive revision recorded in
`third_party/iamlive/UPSTREAM_COMMIT`. iamlive is MIT-licensed by Ian Mckay.
The exact MIT text is retained at `third_party/iamlive/LICENSE`, and the
upstream dependency notice is retained at `third_party/iamlive/NOTICE`.
No iamlive source is copied into this task; the package remains an integration
boundary only.

## Go modules

The final module graph is explicitly enumerated by `make license-check`:

| Module | Version | License text |
| --- | --- | --- |
| `go.yaml.in/yaml/v3` | `v3.0.4` | `third_party/licenses/go-yaml-v3/LICENSE` (Apache-2.0 project files and MIT libyaml-derived files) |
| `github.com/santhosh-tekuri/jsonschema/v6` | `v6.0.3` | `third_party/licenses/jsonschema-v6/LICENSE` (Apache-2.0) |
| `github.com/dlclark/regexp2` | `v1.11.0` | `third_party/licenses/regexp2/LICENSE` (MIT) |
| `golang.org/x/text` | `v0.14.0` | `third_party/licenses/x-text/LICENSE` (BSD-3-Clause) |
| `golang.org/x/mod` | `v0.8.0` | `third_party/licenses/x-mod/LICENSE` (BSD-3-Clause) |
| `golang.org/x/sys` | `v0.5.0` | `third_party/licenses/x-sys/LICENSE` (BSD-3-Clause) |
| `golang.org/x/tools` | `v0.6.0` | `third_party/licenses/x-tools/LICENSE` (BSD-3-Clause) |
| `gopkg.in/check.v1` | `v0.0.0-20161208181325-20d25e280405` | `third_party/licenses/check-v1/LICENSE` (BSD-3-Clause) |

`regexp2`, `x/mod`, `x/sys`, `x/tools`, and `check.v1` are transitive module
graph entries retained by the pinned validator/YAML dependency graph. They are
listed so a release does not silently acquire an unreviewed license.

The project does not derive code from unlicensed `iam-agent-proxy`; no such
source is a dependency.
