#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO="${GO:-go}"
MAKE="${MAKE:-make}"

cd "$ROOT"

EMBEDDED_VERSION="$(sed -n 's/^const Version = "\(v[^"]*\)"$/\1/p' internal/version/version.go)"
if [[ -z "$EMBEDDED_VERSION" ]]; then
	echo "could not read embedded version from internal/version/version.go" >&2
	exit 1
fi

VERSION="${VERSION:-$EMBEDDED_VERSION}"
if [[ "$VERSION" != "$EMBEDDED_VERSION" ]]; then
	echo "release version ${VERSION} does not match embedded version ${EMBEDDED_VERSION}" >&2
	exit 1
fi

"${ROOT}/packaging/release_notes.sh" "$VERSION" >/dev/null
"$MAKE" verify

OUT_DIR="${ROOT}/dist/${VERSION}"
mkdir -p "${OUT_DIR}"
"$GO" build -o "${OUT_DIR}/chain-signer-plugin" "${ROOT}/cmd/chain-signer-plugin"
if command -v shasum >/dev/null 2>&1; then
	shasum -a 256 "${OUT_DIR}/chain-signer-plugin" > "${OUT_DIR}/chain-signer-plugin.sha256"
else
	sha256sum "${OUT_DIR}/chain-signer-plugin" > "${OUT_DIR}/chain-signer-plugin.sha256"
fi
cat > "${OUT_DIR}/version.txt" <<EOF
version=${VERSION}
api_version=v1
EOF
