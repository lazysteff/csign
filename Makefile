GO ?= go
GOLANGCI_LINT ?= golangci-lint

.PHONY: build test lint verify fmt tidy

build:
	mkdir -p dist
	$(GO) build -o dist/chain-signer-plugin ./cmd/chain-signer-plugin

test:
	$(GO) test ./...

lint:
	$(GOLANGCI_LINT) run

verify: test lint

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy
