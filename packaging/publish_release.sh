#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-$(sed -n 's/^const Version = "\(v[^"]*\)"$/\1/p' internal/version/version.go)}"
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*$ ]]; then
	echo "invalid release version: ${VERSION}" >&2
	exit 1
fi

BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ "$BRANCH" != "main" ]]; then
	echo "release publishing must run from main; current branch is ${BRANCH}" >&2
	exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
	echo "release publishing requires a clean worktree" >&2
	exit 1
fi

git fetch origin main:refs/remotes/origin/main --tags
if ! git merge-base --is-ancestor origin/main HEAD; then
	echo "origin/main contains commits not present in HEAD" >&2
	exit 1
fi

if git rev-parse --quiet --verify "refs/tags/${VERSION}" >/dev/null; then
	echo "local tag ${VERSION} already exists" >&2
	exit 1
fi

if git ls-remote --exit-code --tags origin "refs/tags/${VERSION}" >/dev/null 2>&1; then
	echo "remote tag ${VERSION} already exists" >&2
	exit 1
fi

"${ROOT}/packaging/release_notes.sh" "$VERSION" >/dev/null
VERSION="$VERSION" "${ROOT}/packaging/release.sh"

git tag -a "$VERSION" -m "$VERSION"
git push origin HEAD:main
git push origin "$VERSION"

cat <<EOF
Pushed ${VERSION}.
The GitHub Actions release workflow will run make verify again before publishing the GitHub release.
EOF
