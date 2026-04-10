GO ?= go

.PHONY: build test fmt tidy

build:
	mkdir -p dist
	$(GO) build -o dist/chain-signer-plugin ./cmd/chain-signer-plugin

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy
