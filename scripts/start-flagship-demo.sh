#!/usr/bin/env bash
set -euo pipefail

# This launcher only opens the committed static flagship artifact.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
TARGET="$REPO_ROOT/demo/flagship-refund-boundary-demo.html"

if [[ ! -f "$TARGET" ]]; then
    echo "ERROR: flagship demo is missing: $TARGET" >&2
    echo "Restore demo/flagship-refund-boundary-demo.html from the repository checkout." >&2
    exit 1
fi

if [[ ! -r "$TARGET" ]]; then
    echo "ERROR: flagship demo is not readable: $TARGET" >&2
    exit 1
fi

if command -v xdg-open >/dev/null 2>&1; then
    exec xdg-open "$TARGET"
elif command -v open >/dev/null 2>&1; then
    exec open "$TARGET"
elif command -v gio >/dev/null 2>&1; then
    exec gio open "$TARGET"
else
    echo "ERROR: no local default-browser opener found (tried xdg-open, open, gio)." >&2
    exit 1
fi
