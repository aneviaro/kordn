GO ?= go
BINARY ?= bin/kordn
GO_FILES := $(shell find cmd internal test -type f -name '*.go' 2>/dev/null)

.PHONY: all fmt fmt-check lint test test-race license-check build test-integration ci clean

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

license-check:
	@set -eu; modules=$$($(GO) list -m all); unexpected=$$(printf '%s\n' "$$modules" | awk 'NR > 1 {print}'); if test -n "$$unexpected"; then echo "unreviewed Go modules:" >&2; echo "$$unexpected" >&2; exit 1; fi; test -s LICENSE; test -s NOTICE; test -s THIRD_PARTY_NOTICES.md; test -s third_party/iamlive/LICENSE; test -s third_party/iamlive/NOTICE; test -s third_party/iamlive/UPSTREAM_COMMIT; grep -q 'Apache License' LICENSE; grep -q 'MIT License' third_party/iamlive/LICENSE; grep -q 'iam-agent-proxy' SECURITY.md CONTRIBUTING.md THIRD_PARTY_NOTICES.md; echo "license-check: PASS (no unreviewed Go modules; Apache-2.0 original code; iamlive MIT provenance recorded)"

build:
	@mkdir -p $$(dirname $(BINARY))
	$(GO) build -o $(BINARY) ./cmd/kordn

test-integration:
	$(GO) test -race ./test/integration

ci: fmt-check lint test-race license-check build

clean:
	rm -rf bin coverage.out
