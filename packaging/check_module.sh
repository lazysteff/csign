#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^v2\.[0-9]+\.[0-9]+$ ]]; then
	echo "usage: $0 <stable-v2-version>" >&2
	exit 2
fi

GO="${GO:-go}"
MODULE="github.com/lazysteff/csign/v2"
VERSION="$1"
WORK_DIR="$(mktemp -d /tmp/csign-module-check.XXXXXXXX)"
trap '"$GO" clean -modcache; rm -rf "$WORK_DIR"' EXIT

# Never inherit the checkout's workspace, vendor flags, private-module bypasses,
# or module cache. GOPROXY can be overridden to test a candidate module archive.
export GOENV=off GOWORK=off GO111MODULE=on GOFLAGS=
export GOPATH="$WORK_DIR/gopath" GOMODCACHE="$WORK_DIR/modcache"
export GOPRIVATE= GONOPROXY= GONOSUMDB=
export GOPROXY="${GOPROXY:-https://proxy.golang.org}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"

mkdir "$WORK_DIR/consumer"
cd "$WORK_DIR/consumer"
"$GO" mod init example.com/csign-release-consumer

# A newly pushed tag can take a short time to become visible through the proxy.
for attempt in 1 2 3 4 5; do
	if "$GO" list -m "$MODULE@$VERSION"; then
		break
	fi
	if [[ "$attempt" == 5 ]]; then
		echo "could not resolve $MODULE@$VERSION through $GOPROXY" >&2
		exit 1
	fi
	sleep 10
done

cat > main.go <<'EOF'
package main

import (
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	"github.com/lazysteff/csign/v2/pkg/client"
)

func main() {
	_ = client.NewFromVault(nil, "chain-signer")
	_ = v1.BaseSignRequest{KeyID: "release-check"}
}
EOF

# Fetch the exact published version with no replace directive. Building both
# paths checks public imports and the complete Vault plugin dependency graph.
"$GO" get "$MODULE/pkg/client@$VERSION" "$MODULE/cmd/chain-signer-plugin@$VERSION"
resolved="$("$GO" list -m -f '{{.Path}}@{{.Version}}{{if .Replace}} replaced{{end}}' "$MODULE")"
if [[ "$resolved" != "$MODULE@$VERSION" ]]; then
	echo "unexpected module resolution: $resolved" >&2
	exit 1
fi
"$GO" build -o "$WORK_DIR/client-consumer" .
"$GO" build -o "$WORK_DIR/chain-signer-plugin" "$MODULE/cmd/chain-signer-plugin"
echo "Verified external client and Vault plugin builds for $resolved"
