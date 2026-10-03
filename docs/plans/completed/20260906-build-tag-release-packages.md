# Build Tag-Triggered Release Packages

## Overview

Make the existing tag-triggered release pipeline reliable on a fresh GitHub Actions runner. A pushed `v*.*.*` tag must pass the existing mandatory release gates, build four static Kordn archives for Linux and macOS on `amd64` and `arm64`, verify the exact package matrix, and attach the packages and existing security metadata to the GitHub release.

The repository already contains most of this pipeline. The primary gap is that both release jobs use fresh checkouts but do not prepare the pinned sparse iamlive catalog required by `go:embed`. The implementation should repair and validate the existing path rather than introduce a second release mechanism.

## Source Spec

- Spec: Current user request: build release packages on tag creation for Linux and macOS.
- Status: Approved, with repository-grounded assumptions below.
- Last reviewed: 2026-09-06

## Repository Context

- `.github/workflows/release.yml` — already triggers on `v*.*.*`, runs mandatory verification, invokes GoReleaser, signs artifacts with Cosign, creates provenance attestations, and uploads a GitHub release.
- `.goreleaser.yaml` — already defines static `kordn` builds for `darwin` and `linux` on `amd64` and `arm64`, packaged as `tar.gz` archives with checksums and archive SBOMs.
- `internal/iamlivecatalog/embed.go` — embeds selected upstream catalog files at compile time, so builds fail when the catalog worktree is absent.
- `scripts/init-iamlive-submodule.sh` — canonical initializer for the exact pinned, sparse iamlive checkout; it must be used instead of a generic recursive submodule checkout.
- `Makefile` — owns `iamlive-check`, offline verification, the four-target `build-matrix`, and the reproducible `release-snapshot` gate.
- `.github/workflows/ci.yml` — establishes the fresh-checkout pattern of running `make iamlive-init` immediately after checkout.
- `SECURITY.md` — requires vulnerability checks, SBOMs, checksums, signatures, and provenance to remain release-blocking.
- `CONTRIBUTING.md` — documents local gates but currently omits the catalog initialization required by a fresh checkout.

## Implementation Constraints

- Keep Kordn as one local Go binary and one `kordn run` process; release work must not introduce a daemon or network control plane.
- Build exactly `darwin/amd64`, `darwin/arm64`, `linux/amd64`, and `linux/arm64` with `CGO_ENABLED=0`.
- Preserve the tag trigger, mandatory verification dependency, pinned action/tool versions, checksums, per-archive SBOMs, keyless signatures, certificates, release metadata, and GitHub build-provenance attestations.
- Prepare the iamlive catalog with `make iamlive-init`; do not use generic recursive submodule checkout because it bypasses the repository’s sparse-selection and validation boundary.
- Download Go modules explicitly before switching release build commands to `GOPROXY=off` and `GOSUMDB=off`.
- Do not publish if catalog validation fails or if the produced archive matrix differs from the four supported targets.

## Assumptions

- “Tag creation” means pushing a semantic-version-like Git tag matching the existing `v*.*.*` trigger.
- “Main platforms” means both Intel and ARM variants of macOS and Linux: four archives total.
- Existing `tar.gz` packaging, GitHub Releases publishing, and artifact-security metadata are retained.
- The existing GoReleaser configuration is authoritative; this change validates its output rather than introducing hand-written cross-compilation or a runner matrix.

## Non-goals

- Windows builds.
- Homebrew, APT, RPM, container images, or other package-manager distribution.
- Apple Developer ID signing or notarization.
- Replacing GoReleaser, Cosign, Syft, or GitHub Releases.
- Changing runtime behavior or the AWS interception/security boundary.

## Task Summary

1. Prepare every release job for deterministic catalog-backed builds.
2. Enforce and document the four-package release contract.

## Implementation Tasks

### Task 1: Prepare release jobs for catalog-backed builds

Goal: Ensure both fresh release-job workspaces contain the exact pinned catalog and all Go dependencies before verification or packaging begins.

Context:
- `verify` and `build-and-publish` run in separate GitHub Actions workspaces; initialization in one job does not prepare the other.
- `internal/iamlivecatalog/embed.go` requires selected files under `internal/iamlivecatalog/upstream` at compile time.
- `make iamlive-init` performs the project-required sparse checkout, while `make iamlive-check` verifies nested-repository identity, revision, sparse patterns, selected-file hashes, aggregate content hash, and catalog tests.

Files:
- Modify: `.github/workflows/release.yml` — initialize and validate catalog input independently in both jobs and prepare the publish job’s module cache.

Steps:
- [x] Add `make iamlive-init` immediately after checkout in both `verify` and `build-and-publish`.
- [x] Keep Go setup and explicit online module preparation ahead of offline gates; add the same explicit module-download/module-graph preparation to `build-and-publish` instead of relying on cache state saved by `verify`.
- [x] Run `make iamlive-check` after Go setup and module preparation in each job so a wrong, incomplete, or non-sparse catalog blocks further work.
- [x] Run the GoReleaser build with `GOPROXY=off` and `GOSUMDB=off` after preparation, preserving the existing pinned GoReleaser and Syft setup.
- [x] Preserve `build-and-publish.needs: verify`, release permissions, pinned action revisions, and every existing security/reproducibility gate.

Verification:
- `make iamlive-init`
- `GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod download`
- `GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go list -m all >/dev/null`
- `make iamlive-check`
- `actionlint .github/workflows/release.yml`

Completion criteria:
- Both release jobs prepare their own catalog checkout before any catalog-dependent Go command.
- A missing, unpinned, non-sparse, or hash-mismatched catalog stops the workflow before package publication.
- The publish job does not depend on cross-job Go cache timing and builds without network module resolution after its explicit preparation step.

### Task 2: Enforce and document the four-package release contract

Goal: Make the workflow fail closed unless GoReleaser produces exactly the supported Linux/macOS archive matrix, and make fresh-checkout preparation visible to contributors.

Context:
- `.goreleaser.yaml` already declares `darwin` and `linux` with `amd64` and `arm64`, but the workflow only checks that checksums and some SBOM files exist.
- A successful GoReleaser process could still leave an incomplete release set unless the artifact manifest is checked before signing and upload.
- `CONTRIBUTING.md` currently starts with catalog-dependent gates without first preparing the pinned catalog.

Files:
- Modify: `.github/workflows/release.yml` — validate GoReleaser’s artifact manifest before metadata generation, signing, attestation, and upload.
- Modify: `CONTRIBUTING.md` — document `make iamlive-init` as the required fresh-checkout preparation step and summarize the tag release contract.
- Reference only: `.goreleaser.yaml` — retain the existing four-target static archive configuration unless implementation reveals a manifest ambiguity that requires an explicit archive name template.

Steps:
- [x] Add a post-GoReleaser validation step that reads `dist/artifacts.json`, selects archive artifacts, and compares the complete `(goos, goarch)` multiset to exactly `darwin/amd64`, `darwin/arm64`, `linux/amd64`, and `linux/arm64`.
- [x] Require every selected archive path to exist and be non-empty; reject missing targets, duplicate target archives, or additional OS/architecture archives before signing.
- [x] Retain the existing checks for `SHA256SUMS` and SBOM files, and keep all archives in the Cosign-signing and GitHub-attestation inputs.
- [x] Confirm the release upload still includes the four archives, checksums, SBOMs, provenance/license metadata, metadata checksums, signatures, and certificates.
- [x] Add `make iamlive-init` before the canonical local gates in `CONTRIBUTING.md` and document that pushing `v*.*.*` creates the four GitHub release archives only after mandatory verification passes.

Verification:
- `goreleaser check`
- With pinned GoReleaser v2.8.2 and Syft v1.18.1 on `PATH`: `goreleaser release --snapshot --skip=publish --clean`
- Run the same `jq`/manifest predicate used by the workflow against `dist/artifacts.json` and confirm it reports exactly four archive tuples.
- `make release-snapshot`
- Inspect each generated archive with `tar -tzf` and confirm it contains the `kordn` binary and the configured README, license, notice, quickstart, and threat-model files.

Completion criteria:
- The workflow cannot reach signing or publishing with fewer or more than the four required target archives.
- Each supported target has one non-empty `tar.gz` archive.
- Existing checksums, SBOMs, signatures, certificates, provenance, license report, and GitHub attestations remain attached to the release.
- A contributor following `CONTRIBUTING.md` can prepare a fresh checkout and understand what a version-tag push publishes.

## Cross-Task Verification

- `make iamlive-init && make iamlive-check`
- `actionlint .github/workflows/ci.yml .github/workflows/release.yml`
- `goreleaser check`
- `make build-matrix`
- `make release-snapshot`
- In a controlled release test after merge, push a valid `v*.*.*` tag and confirm that `mandatory-release-verification` completes before `build-sign-attest-publish`, then verify all four archives and their security metadata on the resulting GitHub release.

## Risks and Mitigations

- Risk: GoReleaser v2.8.2’s `dist/artifacts.json` fields or artifact type spelling differ from an assumed `jq` expression.
  Mitigation: Generate a snapshot with the pinned version, inspect the manifest structure, and test the exact predicate before committing it to the workflow.
- Risk: Initializing only the verification job creates a false sense of safety while the publish job still has an empty submodule directory.
  Mitigation: Initialize and validate the catalog independently in both jobs.
- Risk: Generic Actions submodule checkout fetches excess upstream content or bypasses sparse-selection checks.
  Mitigation: Use only `make iamlive-init` followed by `make iamlive-check`.
- Risk: A Linux cross-build proves macOS compilation but cannot execute the macOS binaries.
  Mitigation: Keep cross-build validation in scope and treat native macOS runtime smoke testing as separate compatibility coverage, not as proof supplied by the Linux release runner.
- Risk: A live tag test creates a public release unexpectedly.
  Mitigation: Perform it only in an approved test/fork context or as the first intentional release; do not create or delete remote tags automatically during implementation verification.

## Open Questions

- None.
