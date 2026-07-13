GO ?= go
GOLANGCI_LINT ?= golangci-lint

.PHONY: build test lint lint-backend deps-check verify fmt tidy release publish-release

build:
	mkdir -p dist
	$(GO) build -o dist/chain-signer-plugin ./cmd/chain-signer-plugin

test:
	$(GO) test ./...

lint: lint-backend

lint-backend:
	$(GOLANGCI_LINT) run

deps-check:
	@set -eu; \
	modules="$$( $(GO) list -mod=readonly -m -f '{{if and (not .Main) (not .Indirect)}}{{.Path}}{{end}}' all )"; \
	updates="$$( $(GO) list -mod=readonly -m -u -f '{{if .Update}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' $$modules )"; \
	if [ -n "$$updates" ]; then \
		echo "newer compatible direct dependency releases are available:"; \
		echo "$$updates"; \
		exit 1; \
	fi

verify: deps-check test lint

release:
	@if [ -n "$(VERSION)" ]; then VERSION="$(VERSION)" ./packaging/release.sh; else ./packaging/release.sh; fi

publish-release:
	@if [ -n "$(VERSION)" ]; then VERSION="$(VERSION)" ./packaging/publish_release.sh; else ./packaging/publish_release.sh; fi

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy
