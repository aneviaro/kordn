# iamlive provenance

Kordn vendors the minimal derived operation/dependency mapper at
`third_party/iamlive/source/mapper.go`. It is derived from the exact upstream
revision `3ec1a40e560c2f00ec82c50223add810e2567efb` (MIT), upstream path
`iamlivecore/logger.go`, symbols `getActions` (lines 485-506) and
`getDependantActions` (lines 458-483). The corresponding Kordn file SHA256 is
`89e3104adadac57a61366d4e1f6baf492f7b38a750254f6d46ffa481da437342`.

The derived `GetActions` contains an independent, explicit table for Kordn's
reviewed supported-operation subset and has no explicit-action override. The
derived `DependentActions` is invoked once for every mapped primary action,
including actions with a proven-empty dependency result. For the narrowed ECS,
EC2, and Lambda role-bearing subset it examines bounded typed request values and
returns PassRole candidates with their concrete role values; uncertainty is
reported rather than treated as empty. Kordn's adapter supplies these values
and its mapper independently cross-checks primary actions against the pinned
AWS SAR/model records and validates exact role ARNs and dependency applicability.
This table narrowing, typed-value adaptation, and fail-closed cross-checking
are Kordn-specific changes from the upstream runtime behavior.

No upstream runtime, HTTP proxy, credential, or lifecycle code is copied.
