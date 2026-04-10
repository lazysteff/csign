#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo v0.0.0-dev)}"
OUT_DIR="${ROOT}/dist/${VERSION}"

mkdir -p "${OUT_DIR}"
go build -o "${OUT_DIR}/chain-signer-plugin" "${ROOT}/cmd/chain-signer-plugin"
shasum -a 256 "${OUT_DIR}/chain-signer-plugin" > "${OUT_DIR}/chain-signer-plugin.sha256"
cat > "${OUT_DIR}/version.txt" <<EOF
version=${VERSION}
api_version=v1
EOF
