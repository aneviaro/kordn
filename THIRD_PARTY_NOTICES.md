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

## AWS SDK for Go v2 and Smithy Go — Apache-2.0

Kordn directly imports these pinned AWS SDK for Go v2 components:

| Module | Version | License text |
| --- | --- | --- |
| `github.com/aws/aws-sdk-go-v2` | `v1.37.2` | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/config` | `v1.29.3` | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/credentials` | `v1.17.56` | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/service/sts` | `v1.36.0` | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |

The exact AWS SDK and Smithy Go submodule versions in the final module graph
are listed below. The AWS SDK submodules use the retained Apache-2.0 text at
`third_party/licenses/aws-sdk-v2/LICENSE`; Smithy Go uses the retained
Apache-2.0 text at `third_party/licenses/smithy-go/LICENSE`.

| Module | Version | Directness | License text |
| --- | --- | --- | --- |
| `github.com/aws/aws-sdk-go-v2` | `v1.37.2` | direct | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/config` | `v1.29.3` | direct | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/credentials` | `v1.17.56` | direct | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | `v1.16.26` | indirect | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/internal/configsources` | `v1.4.2` | indirect | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2` | `v2.7.2` | indirect | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/internal/ini` | `v1.8.2` | indirect | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding` | `v1.13.0` | indirect | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/service/internal/presigned-url` | `v1.13.2` | indirect | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/service/sso` | `v1.24.13` | indirect | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | `v1.28.12` | indirect | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/aws-sdk-go-v2/service/sts` | `v1.36.0` | direct | `third_party/licenses/aws-sdk-v2/LICENSE` (Apache-2.0) |
| `github.com/aws/smithy-go` | `v1.22.5` | indirect | `third_party/licenses/smithy-go/LICENSE` (Apache-2.0) |

## Go modules

The remaining exact module graph is explicitly enumerated by
`make license-check`:

| Module | Version | License text |
| --- | --- | --- |
| `github.com/dlclark/regexp2` | `v1.11.0` | `third_party/licenses/regexp2/LICENSE` (MIT) |
| `github.com/santhosh-tekuri/jsonschema/v6` | `v6.0.3` | `third_party/licenses/jsonschema-v6/LICENSE` (Apache-2.0) |
| `go.yaml.in/yaml/v3` | `v3.0.4` | `third_party/licenses/go-yaml-v3/LICENSE` (Apache-2.0 project files and MIT libyaml-derived files) |
| `golang.org/x/crypto` | `v0.19.0` | `third_party/licenses/x-crypto/LICENSE` (BSD-3-Clause) |
| `golang.org/x/mod` | `v0.8.0` | `third_party/licenses/x-mod/LICENSE` (BSD-3-Clause) |
| `golang.org/x/net` | `v0.21.0` | `third_party/licenses/x-net/LICENSE` (BSD-3-Clause plus Go patent grant) |
| `golang.org/x/sys` | `v0.17.0` | `third_party/licenses/x-sys/LICENSE` (BSD-3-Clause) |
| `golang.org/x/term` | `v0.17.0` | `third_party/licenses/x-term/LICENSE` (BSD-3-Clause) |
| `golang.org/x/text` | `v0.14.0` | `third_party/licenses/x-text/LICENSE` (BSD-3-Clause) |
| `golang.org/x/tools` | `v0.6.0` | `third_party/licenses/x-tools/LICENSE` (BSD-3-Clause) |
| `gopkg.in/check.v1` | `v1.0.0-20161208181325-20d25e280405` | `third_party/licenses/check-v1/LICENSE` (BSD-3-Clause) |

The graph above was obtained after `go mod tidy` in a temporary HOME with
`GOPROXY=https://proxy.golang.org,direct` and
`GOSUMDB=sum.golang.org`; checksums are retained in `go.sum`. The license gate
matches every graph entry exactly and rejects an unknown future module.

`regexp2`, `x/mod`, `x/sys`, `x/tools`, and `check.v1` are transitive module
graph entries retained by the pinned validator/YAML dependency graph. They are
listed so a release does not silently acquire an unreviewed license.

The project does not derive code from unlicensed `iam-agent-proxy`; no such
source is a dependency.
