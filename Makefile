GO ?= go
BINARY ?= bin/kordn
GO_FILES := $(shell find cmd internal test -type f -name '*.go' 2>/dev/null)

.PHONY: all fmt fmt-check lint test test-race license-check schema-check build test-integration ci clean

all: build

fmt:
	$(GO) fmt ./...

fmt-check:
	@test -z "$$($(GO)fmt -l $(GO_FILES))" || { echo "gofmt required; run make fmt" >&2; exit 1; }

lint:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Keep schema validation in a named test so the command is deterministic,
# reviewable, and uses the pinned validator dependency rather than a generated
# temporary Go program. The test also runs Config.Load's pinned semantic phase
# for invariants JSON Schema cannot express (such as unique rule IDs and
# cross-field body bounds).
schema-check:
	$(GO) test ./internal/config -run '^TestSchemaCheck$$' -count=1

# This gate deliberately enumerates every approved module. A new dependency
# requires a reviewed license and a notice before it can enter the build.
license-check:
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
			golang.org/x/mod@v0.8.0|\
			golang.org/x/sys@v0.5.0|\
			golang.org/x/text@v0.14.0|\
			golang.org/x/tools@v0.6.0|\
			gopkg.in/check.v1@v1.0.0-20161208181325-20d25e280405) ;; \
			*) echo "unreviewed Go module: $$module" >&2; exit 1 ;; \
		esac; \
	done; \
	for license in $$(find third_party/licenses -type f -name LICENSE -print); do \
		test -s "$$license"; \
	done; \
	test -s LICENSE; \
	test -s NOTICE; \
	test -s THIRD_PARTY_NOTICES.md; \
	test -s third_party/iamlive/LICENSE; \
	test -s third_party/iamlive/NOTICE; \
	test -s third_party/iamlive/UPSTREAM_COMMIT; \
	test -s third_party/licenses/aws-sdk-v2/LICENSE; \
	test -s third_party/licenses/smithy-go/LICENSE; \
	grep -q 'Apache License' LICENSE; \
	grep -q 'Apache License' third_party/licenses/aws-sdk-v2/LICENSE; \
	grep -q 'Apache License' third_party/licenses/smithy-go/LICENSE; \
	grep -q 'MIT License' third_party/iamlive/LICENSE; \
	grep -q 'iam-agent-proxy' SECURITY.md CONTRIBUTING.md THIRD_PARTY_NOTICES.md; \
	grep -q 'go-yaml-v3/LICENSE' THIRD_PARTY_NOTICES.md; \
	grep -q 'jsonschema-v6/LICENSE' THIRD_PARTY_NOTICES.md; \
	echo "license-check: PASS (approved modules; AWS SDK v2/Smithy provenance recorded)"

build:
	@mkdir -p $$(dirname $(BINARY))
	$(GO) build -o $(BINARY) ./cmd/kordn

test-integration:
	$(GO) test -race ./test/integration

ci: fmt-check lint test-race license-check schema-check build

clean:
	rm -rf bin coverage.out
