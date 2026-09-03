# Project Guidance

## Architecture and Security Boundaries

- Keep Kordn as one local Go binary and one `kordn run` process; do not introduce a daemon or network control plane.
- Treat non-AWS HTTPS CONNECT traffic as byte-opaque end-to-end TLS. The per-run Kordn CA is for positively classified AWS interception only and must never enter the system trust store.

## AWS Catalog Integration

- Keep `internal/iamlivecatalog` neutral: it parses pinned upstream evidence, while `internal/awsrequest/endpoint.go` remains the positive interception boundary and `internal/iammap` owns authorization and fail-closed decisions.
- Prepare the pinned catalog with `./scripts/init-iamlive-submodule.sh` before catalog-dependent Go commands; use `--check` for read-only validation. An empty gitlink directory can make `git -C` resolve the parent repository, so nested-repository checks must verify both a `.git` marker and the exact top-level path.
- Match AWS Query and EC2 Query catalog records with the exact wire `Version` plus endpoint service and `Action`; repeated operation names across API-version models are expected and must not be guessed or deduplicated across versions.
- Match REST operations with modeled input-shape query bindings as well as service, protocol, method, and URI. Identical method/URI routes can be separated by required query members; unknown or duplicate query evidence must fail closed.
- Treat mapper evidence as occurrence-sensitive: do not deduplicate or collapse raw API, action, resource, or dependency records; compare complete mapping and IAM-definition multisets.
- Model conditional dependencies with tri-state applicability. Retain proven-inapplicable occurrences for graph cardinality, and fail closed when applicability cannot be proven true or false.
- In fake AWS protocol detection, honor `application/x-amz-json-1.0` and `1.1` before interpreting `X-Amz-Target`; real DynamoDB targets such as `DynamoDB_20120810.GetItem` do not contain a `Json10` marker.
- Mapper lookup errors may wrap a specific dependency or resource failure in `unknown operation`; classify the specific fail-closed cause before the generic wrapper, using phrase boundaries so operation names containing words such as `Dependent` are not misclassified.
- At the pinned iamlive revision, Lambda `CreateFunction` requires `lambda:PassCapacityProvider` in the IAM definition but has no matching extraction record in `map.json`; retain this disagreement and deny with `dependent_permission_unresolved` rather than omitting the permission.
