GO ?= go
GOLANGCI_LINT ?= golangci-lint

.PHONY: build test lint verify fmt tidy release publish-release

build:
	mkdir -p dist
	$(GO) build -o dist/chain-signer-plugin ./cmd/chain-signer-plugin

test:
	$(GO) test ./...

lint:
	$(GOLANGCI_LINT) run

verify: test lint

release:
	@if [ -n "$(VERSION)" ]; then VERSION="$(VERSION)" ./packaging/release.sh; else ./packaging/release.sh; fi

publish-release:
	@if [ -n "$(VERSION)" ]; then VERSION="$(VERSION)" ./packaging/publish_release.sh; else ./packaging/publish_release.sh; fi

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy
