# iamlive provenance

Kordn embeds a neutral catalog derived from the exact iamlive revision
`3ec1a40e560c2f00ec82c50223add810e2567efb` (`v1.1.28`, MIT; Copyright (c) 2021
Ian Mckay). The source is registered as the gitlink
`internal/iamlivecatalog/upstream` and is initialized by
`scripts/init-iamlive-submodule.sh`.

Only these upstream paths are selected and embedded:

- `LICENSE` — SHA256 `d31581bd2e336f59a640f92f386786dea05c2d0930812fe0627b796e49cfc95f`
- `NOTICE` — SHA256 `46898db400fce8eb0a0d43c70d5672582a42c766a5bed5c924a215d56ac11432`
- `iamlivecore/map.json` — SHA256 `f6ab658506c1f21875cc8dd3c4a4ed2191c7eb4e6233c36678c841c3e2b330b4`
- `iamlivecore/iam_definition.json` — SHA256 `2ec6e80322edd149eeff984bcbc67736b3d01f7b75e3abc8734a6a84847b855d`
- `iamlivecore/apis/**/api-2.json` — each selected model is hashed into the
  catalog source digest; the selected set is checked by the sparse-checkout
  initializer.

The Kordn catalog schema is `iamlive-catalog-schema/v2`, and its catalog data
version is `iamlive-catalog/v2@3ec1a40e560c2f00ec82c50223add810e2567efb` plus the
selected-content SHA-256 calculated at load time. `kordn version --json` exposes
these values separately as `upstream_commit`, `selected_content_sha256`,
`catalog_schema`, and `catalog_version`.

The catalog parser is neutral and offline: it preserves API routes, protocol and
signature metadata, SDK aliases, operation/action mappings, plural mappings,
resource templates, conditions, dependent actions, and missing, permissionless,
undocumented, or contradictory evidence. It retains case-variant duplicate
records and makes ambiguous records fail closed at lookup. The migration covers
447 API models (19,543 operations), 19,514 SDK mapping keys, and 20,638 IAM
definitions; the pinned files contain 225 missing and 2 contradictory mapping
agreements, plus 3 explicit permissionless operations and 30 undocumented IAM
definitions. Its digest is deterministic over the four core files, notices, and
every selected API path and byte sequence.

No iamlive runtime, proxy, credential, HTTP, or authorization enforcement code is
copied. Kordn's authorization and fail-closed enforcement remain outside this
upstream parsing boundary. The MIT license and upstream NOTICE apply only to the
selected derived data boundary; Kordn code remains under the repository license.

To reproduce the checkout, clone with submodules and run `make iamlive-init`, or
run that target after a non-recursive clone. It applies and verifies the sparse
patterns and exact gitlink. `make iamlive-check` is read-only and offline; it
checks the pin, selected hashes, licenses, model parsing, and consistency. An
intentional pin update must change the gitlink, this record, selected hashes,
and review the resulting API/model and definition diffs together.
