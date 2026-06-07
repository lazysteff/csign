#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <version>" >&2
	exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$1"

awk -v version="$VERSION" '
	$0 == "## " version || index($0, "## " version " - ") == 1 {
		found = 1
		print
		next
	}
	found && /^## / {
		exit
	}
	found {
		print
	}
	END {
		if (!found) {
			exit 1
		}
	}
' "${ROOT}/CHANGELOG.md"
