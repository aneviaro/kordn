GO ?= go
BINARY ?= bin/kordn
# Task 10 gates are hermetic: dependencies must already be in the module
# cache, and a gate must never silently fetch code from the network.
export GOPROXY := off
export GOSUMDB := off
GO_FILES := $(shell find cmd internal test -type f -name '*.go' 2>/dev/null)

.PHONY: all iamlive-init iamlive-check fmt fmt-check lint test test-race license license-check schema schema-check checklist-validation build test-integration compatibility-check test-compatibility strict-compatibility test-external build-matrix benchmark benchmark-hotpath fuzz-smoke strict-performance soak-leak soak-leak-race security-check release-snapshot ci clean

all: build

# Initialization is the sole network-capable preparation step. The check target
# is read-only and all Go gates depend on it so a missing or non-reproducible
# catalog fails with an actionable init instruction.
iamlive-init:
	@./scripts/init-iamlive-submodule.sh

iamlive-check:
	@set -eu; path=internal/iamlivecatalog/upstream; \
	test -d "$$path" || { echo 'iamlive catalog absent; run make iamlive-init' >&2; exit 1; }; \
	./scripts/init-iamlive-submodule.sh --check || { echo 'iamlive catalog is not prepared; run make iamlive-init' >&2; exit 1; }; \
	test "$$(git -C "$$path" rev-parse HEAD)" = "$$(cat third_party/iamlive/UPSTREAM_COMMIT)" || { echo 'iamlive pin differs from UPSTREAM_COMMIT; run make iamlive-init' >&2; exit 1; }; \
	for pair in \
		'd31581bd2e336f59a640f92f386786dea05c2d0930812fe0627b796e49cfc95f LICENSE' \
		'46898db400fce8eb0a0d43c70d5672582a42c766a5bed5c924a215d56ac11432 NOTICE' \
		'f6ab658506c1f21875cc8dd3c4a4ed2191c7eb4e6233c36678c841c3e2b330b4 iamlivecore/map.json' \
		'2ec6e80322edd149eeff984bcbc67736b3d01f7b75e3abc8734a6a84847b855d iamlivecore/iam_definition.json'; do \
		set -- $$pair; actual=$$( (command -v sha256sum >/dev/null && sha256sum "$$path/$$2" || shasum -a 256 "$$path/$$2") | awk '{print $$1}' ); \
		test "$$actual" = "$$1" || { echo "selected iamlive hash mismatch: $$2; run make iamlive-init" >&2; exit 1; }; \
	done; \
	aggregate=$$(mktemp "$${TMPDIR:-/tmp}/iamlive-catalog.XXXXXX"); trap 'rm -f "$$aggregate"' EXIT; \
	{ printf 'LICENSE\0'; cat "$$path/LICENSE"; printf 'NOTICE\0'; cat "$$path/NOTICE"; \
	  printf 'iamlivecore/map.json\0'; cat "$$path/iamlivecore/map.json"; \
	  printf 'iamlivecore/iam_definition.json\0'; cat "$$path/iamlivecore/iam_definition.json"; \
	  find "$$path/iamlivecore/apis" -type f -name api-2.json -print | LC_ALL=C sort | while IFS= read -r file; do \
	    rel=$${file#"$$path/"}; printf 'upstream/%s\0' "$$rel"; cat "$$file"; \
	  done; \
	} > "$$aggregate"; \
	actual=$$( (command -v sha256sum >/dev/null && sha256sum "$$aggregate" || shasum -a 256 "$$aggregate") | awk '{print $$1}' ); \
	test "$$actual" = '43e605716ea0ccdaeb625bad52088deece0204ad38e4b6e461e6792a1dd00869' || { echo 'selected iamlive aggregate hash mismatch: API model or selected data changed; run make iamlive-init' >&2; exit 1; }; \
	$(GO) test ./internal/iamlivecatalog -count=1

fmt: iamlive-check
	$(GO) fmt ./...

fmt-check: iamlive-check
	@test -z "$$($(GO)fmt -l $(GO_FILES))" || { echo "gofmt required; run make fmt" >&2; exit 1; }

lint: iamlive-check
	$(GO) vet ./...

test: iamlive-check
	$(GO) test ./...

test-race: iamlive-check
	$(GO) test -race ./...

# Keep schema validation in a named test so the command is deterministic,
# reviewable, and uses the pinned validator dependency rather than a generated
# temporary Go program. The test also runs Config.Load's pinned semantic phase
# for invariants JSON Schema cannot express (such as unique rule IDs and
# cross-field body bounds).
schema: schema-check

schema-check: iamlive-check
	$(GO) test ./internal/config -run '^TestSchemaCheck$$' -count=1

checklist-validation:
	@set -eu; file=docs/security-review-checklist.md; \
	test "$$(grep -oE 'S20-[0-9]{2}' "$$file" | wc -l | tr -d ' ')" = 23; \
	test "$$(grep -oE 'S20-[0-9]{2}' "$$file" | sort -u | wc -l | tr -d ' ')" = 23; \
	test "$$(grep -oE 'AC-[0-9]{2}' "$$file" | wc -l | tr -d ' ')" = 22; \
	test "$$(grep -oE 'AC-[0-9]{2}' "$$file" | sort -u | wc -l | tr -d ' ')" = 22; \
	for n in $$(seq -w 1 23); do grep -q "S20-$$n" "$$file"; done; \
	for n in $$(seq -w 1 22); do grep -q "AC-$$n" "$$file"; done; \
	echo 'checklist-validation: PASS (23 Section 20 invariants, 22 Section 26 criteria)'

# This gate deliberately enumerates every approved module. A new dependency
# requires a reviewed license and attribution before it can enter the build.
license: license-check

license-check: iamlive-check
	@set -eu; \
	modules="$$($(GO) list -m -f '{{.Path}}@{{.Version}}' all)"; \
	for module in $$modules; do \
		case "$$module" in \
			github.com/kordn-ai/kordn@|\
			github.com/aws/aws-sdk-go-v2@v1.37.2|\
			github.com/aws/aws-sdk-go-v2/config@v1.29.3|\
			github.com/aws/aws-sdk-go-v2/credentials@v1.17.56|\
			github.com/aws/aws-sdk-go-v2/feature/ec2/imds@v1.16.26|\
			github.com/aws/aws-sdk-go-v2/internal/configsources@v1.4.2|\
			github.com/aws/aws-sdk-go-v2/internal/endpoints/v2@v2.7.2|\
			github.com/aws/aws-sdk-go-v2/internal/ini@v1.8.2|\
			github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding@v1.13.0|\
			github.com/aws/aws-sdk-go-v2/service/internal/presigned-url@v1.13.2|\
			github.com/aws/aws-sdk-go-v2/service/sso@v1.24.13|\
			github.com/aws/aws-sdk-go-v2/service/ssooidc@v1.28.12|\
			github.com/aws/aws-sdk-go-v2/service/sts@v1.36.0|\
			github.com/aws/smithy-go@v1.22.5|\
			github.com/dlclark/regexp2@v1.11.0|\
			github.com/santhosh-tekuri/jsonschema/v6@v6.0.3|\
			go.yaml.in/yaml/v3@v3.0.4|\
			golang.org/x/crypto@v0.51.0|\
			golang.org/x/mod@v0.37.0|\
			golang.org/x/net@v0.55.0|\
			golang.org/x/sync@v0.21.0|\
			golang.org/x/sys@v0.45.0|\
			golang.org/x/term@v0.43.0|\
			golang.org/x/text@v0.39.0|\
			golang.org/x/tools@v0.47.0|\
			gopkg.in/check.v1@v1.0.0-20161208181325-20d25e280405) ;; \
			*) echo "unreviewed Go module: $$module" >&2; exit 1 ;; \
		esac; \
	done; \
	for license in $$(find third_party/licenses -type f -name LICENSE -print); do \
		test -s "$$license"; \
	done; \
	test -s LICENSE; \
	test -s THIRD_PARTY_NOTICES.md; \
	test -s third_party/iamlive/LICENSE; \
	test -s third_party/iamlive/NOTICE; \
	test -s third_party/iamlive/UPSTREAM_COMMIT; \
	test -s third_party/licenses/aws-sdk-v2/LICENSE; \
	test -s third_party/licenses/go-bsd-3-clause/LICENSE; \
	test -s third_party/licenses/go-yaml-v3/LICENSE; \
	test -s third_party/licenses/x-net/LICENSE; \
	test -s third_party/licenses/x-net/PATENTS; \
	grep -q 'MIT License' LICENSE; \
	grep -q 'Apache License' third_party/licenses/aws-sdk-v2/LICENSE; \
	grep -q 'MIT License' third_party/iamlive/LICENSE; \
	grep -q 'iam-agent-proxy' SECURITY.md CONTRIBUTING.md THIRD_PARTY_NOTICES.md; \
	grep -q 'go-yaml-v3/LICENSE' THIRD_PARTY_NOTICES.md; \
	grep -q 'go-bsd-3-clause/LICENSE' THIRD_PARTY_NOTICES.md; \
	echo "license-check: PASS (runtime licenses; AWS SDK/Smithy provenance recorded)"

build: iamlive-check
	@mkdir -p $$(dirname $(BINARY))
	$(GO) build -trimpath -buildvcs=false -o $(BINARY) ./cmd/kordn

test-integration: iamlive-check
	$(GO) test -race ./test/integration/...

compatibility-check: iamlive-check
	$(GO) test -tags compat ./test/compatibility -run '^TestVersionMatrixAndDocumentation$$' -count=1

test-compatibility: compatibility-check
	$(GO) test -race -tags compat ./test/compatibility

strict-compatibility: iamlive-check
	KORDN_STRICT_PERFORMANCE=1 $(GO) test -tags compat ./test/compatibility -run '^TestCompatibilityPerformance$$' -count=1

# External producer tests are deliberately opt-in. Required mode fails closed
# when an exact binary, provider mirror, or agent producer is absent.
test-external: iamlive-check
	KORDN_EXTERNAL_REQUIRED=1 KORDN_EXTERNAL_TESTS=1 $(GO) test -race -tags compat ./test/compatibility

build-matrix: iamlive-check
	@set -eu; for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; out=$$(mktemp -t kordn-build.XXXXXX); \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -o $$out ./cmd/kordn; rm -f $$out; \
	done

# Run the complete benchmark suite by default. Release performance jobs may
# add their own benchtime/threshold flags, but this target must not hide a
# benchmark by shortening or selectively filtering it.
benchmark: iamlive-check
	$(GO) test -run '^$$' -bench=. -benchmem ./...

# Keep the focused hot-path smoke suite separate from the complete benchmark
# target: these names are the local regression surface for catalog work.
benchmark-hotpath: iamlive-check
	$(GO) test -run '^$$' -bench='^(BenchmarkDecodeQuery|BenchmarkDecodeJSON|BenchmarkWireIndexLookupQueryExact|BenchmarkWireIndexLookupQueryNegative|BenchmarkWireIndexLookupQueryAmbiguous|BenchmarkWireIndexLookupJSONExact|BenchmarkWireIndexLookupJSONAmbiguous)$$' -benchmem ./internal/awsrequest
	$(GO) test -run '^$$' -bench='^BenchmarkLookupRequest$$' -benchmem ./internal/iammap

# Exercise every checked-in fuzz target briefly without downloading a corpus.
# Fuzzing is deterministic and offline when the module cache is already
# populated, as required by the release gate.
fuzz-smoke: iamlive-check
	$(GO) test ./internal/sigv4 -run '^$$' -fuzz FuzzCanonicalRequest -fuzztime=2s
	$(GO) test ./internal/awsrequest -run '^$$' -fuzz FuzzAWSRequestConfiguredDecoder -fuzztime=2s
	$(GO) test ./internal/proxy -run '^$$' -fuzz FuzzSafeIPClassification -fuzztime=2s
	$(GO) test ./internal/audit -run '^$$' -fuzz FuzzAuditRedaction -fuzztime=2s
	$(GO) test ./internal/cache -run '^$$' -fuzz FuzzLRUBounded -fuzztime=2s
	$(GO) test ./internal/iammap -run '^$$' -fuzz FuzzMapperInput -fuzztime=2s
	$(GO) test ./internal/pki -run '^$$' -fuzz FuzzDNSNameValidation -fuzztime=2s
	$(GO) test ./internal/policy -run '^$$' -fuzz FuzzRuleOrderInvariant -fuzztime=2s

strict-performance: iamlive-check
	KORDN_STRICT_PERFORMANCE=1 $(GO) test ./test/integration -run '^TestStrictPerformance$$' -count=1

soak-leak: iamlive-check
	KORDN_SOAK=1 $(GO) test ./test/integration -run '^TestMixedRequestSoak$$' -count=1

soak-leak-race: iamlive-check
	KORDN_SOAK=1 $(GO) test -race ./test/integration -run '^TestMixedRequestSoakRace$$' -count=1

# Static and behavioral release checks. Local security-check may report an
# unavailable vulnerability tool; the release workflow installs its pinned
# copy and treats absence or failure as fatal.
security-check: lint schema-check license-check checklist-validation
	@set -eu; \
	if command -v govulncheck >/dev/null 2>&1; then GOPROXY=off GOSUMDB=off govulncheck ./...; else echo "security-check: govulncheck unavailable locally (release workflow supplies the pinned tool)"; fi; \
	if grep -R -n -E 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' --include='*.go' --exclude='*_test.go' --exclude-dir=.git . >/dev/null; then echo 'possible credential pattern found' >&2; exit 1; fi; \
	grep -R -n -F 'proxy-boundary' README.md docs SECURITY.md >/dev/null; \
	grep -R -n -F 'same-user' README.md docs SECURITY.md >/dev/null; \
	$(GO) test ./internal/iammap -run 'Test(GoldenMappings|NoScopeWidening|DependentPassRole)' -count=1

# Build every release target twice with network access disabled, retain the
# reproducible artifacts, and execute the host artifact through the documented
# init/validation/version quickstart smoke test.
release-snapshot:
	@set -eu; \
	test "$${GOPROXY:-off}" = off || { echo 'release-snapshot requires GOPROXY=off for reproducibility' >&2; exit 1; }; \
	rm -rf dist/release-snapshot .release-snapshot-a .release-snapshot-b; \
	mkdir -p dist/release-snapshot .release-snapshot-a .release-snapshot-b; \
	$(MAKE) --no-print-directory GOPROXY=off GOSUMDB=off iamlive-check license-check schema-check; \
	for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; name=kordn-$${os}-$${arch}; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 GOPROXY=off GOSUMDB=off $(GO) build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o .release-snapshot-a/$$name ./cmd/kordn; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 GOPROXY=off GOSUMDB=off $(GO) build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o .release-snapshot-b/$$name ./cmd/kordn; \
		cmp .release-snapshot-a/$$name .release-snapshot-b/$$name; \
		cp .release-snapshot-a/$$name dist/release-snapshot/$$name; \
	done; \
	host_os=$$(uname -s | tr '[:upper:]' '[:lower:]'); host_arch=$$(uname -m); \
	case "$$host_os" in darwin|linux) ;; *) echo "unsupported host OS $$host_os" >&2; exit 1;; esac; \
	case "$$host_arch" in x86_64) host_arch=amd64;; arm64|aarch64) host_arch=arm64;; *) echo "unsupported host architecture $$host_arch" >&2; exit 1;; esac; \
	name=kordn-$$host_os-$$host_arch; \
	"$$PWD/dist/release-snapshot/$$name" version --json > dist/release-snapshot/version.json; \
	$(GO) version -m "dist/release-snapshot/$$name" > dist/release-snapshot/BUILD-INFO.txt; \
	printf '%s' '{"format":"kordn.release.sbom/v1","generator":"go list -m","dependencies":[' > dist/release-snapshot/sbom.json; \
	$(GO) list -m -f '{"path":"{{.Path}}","version":"{{.Version}}"}' all | awk 'NR > 1 { printf "," } { printf "%s", $$0 } END { print "]}" }' >> dist/release-snapshot/sbom.json; \
	printf '%s\n' '{"format":"kordn.provenance/v1","build":"offline-reproducible","upstream_commit":"3ec1a40e560c2f00ec82c50223add810e2567efb","selected_content_sha256":"43e605716ea0ccdaeb625bad52088deece0204ad38e4b6e461e6792a1dd00869","catalog_schema":"iamlive-catalog-schema/v2","catalog_version":"iamlive-catalog/v2@3ec1a40e560c2f00ec82c50223add810e2567efb","mapper":"kordn-iammap/v3","adapter":"iamlive-derived/v2@3ec1a40e560c2f00ec82c50223add810e2567efb","authorization_data":"iamlive-catalog/v2@3ec1a40e560c2f00ec82c50223add810e2567efb+sha256:43e605716ea0ccdaeb625bad52088deece0204ad38e4b6e461e6792a1dd00869","targets":["darwin/amd64","darwin/arm64","linux/amd64","linux/arm64"]}' > dist/release-snapshot/provenance.json; \
	printf '%s\n' 'MIT-licensed project; reviewed third-party licenses and attributions are included in release archives.' > dist/release-snapshot/LICENSE-REPORT.txt; \
	( cd dist/release-snapshot && if command -v sha256sum >/dev/null 2>&1; then sha256sum kordn-* BUILD-INFO.txt LICENSE-REPORT.txt provenance.json sbom.json version.json > SHA256SUMS && sha256sum -c SHA256SUMS; else shasum -a 256 kordn-* BUILD-INFO.txt LICENSE-REPORT.txt provenance.json sbom.json version.json > SHA256SUMS && shasum -a 256 -c SHA256SUMS; fi ); \
	for file in dist/release-snapshot/kordn-* dist/release-snapshot/SHA256SUMS dist/release-snapshot/BUILD-INFO.txt dist/release-snapshot/LICENSE-REPORT.txt dist/release-snapshot/sbom.json dist/release-snapshot/provenance.json dist/release-snapshot/version.json; do test -s "$$file"; done; \
	smoke_dir=$$(mktemp -d "$${TMPDIR:-/tmp}/kordn-release-smoke.XXXXXX"); smoke_bin="$$smoke_dir/kordn"; cp "dist/release-snapshot/$$name" "$$smoke_bin"; \
	home=$$(mktemp -d "$${TMPDIR:-/tmp}/kordn-home.XXXXXX"); trap 'rm -rf "$$home" "$$smoke_dir" .release-snapshot-a .release-snapshot-b' EXIT INT TERM; \
	HOME="$$home" "$$smoke_bin" init >/dev/null; \
	safe_root="$$HOME/.kordn-release-smoke"; safe_audit="$$safe_root/events.jsonl"; \
	mkdir -p "$$safe_root"; chmod 700 "$$safe_root"; \
	awk -v path="$$safe_audit" '/^  path: / { print "  path: " path; next } { print }' "$$home/.kordn/config.yaml" > "$$home/.kordn/config.checked.yaml"; chmod 600 "$$home/.kordn/config.checked.yaml"; \
	HOME="$$home" "$$smoke_bin" policy validate --config "$$home/.kordn/config.checked.yaml" >/dev/null; \
	HOME="$$home" "$$smoke_bin" version --json | grep -q '"upstream_commit"'; \
	rm -rf "$$safe_root"; \
	echo 'Kordn offline reproducible snapshot: binaries, checksums, SBOM, provenance, license report, and quickstart PASS'

ci: fmt-check lint test-race test-integration license-check schema-check build test-compatibility benchmark fuzz-smoke security-check release-snapshot

clean:
	rm -rf bin coverage.out dist/release-snapshot .release-snapshot-a .release-snapshot-b
