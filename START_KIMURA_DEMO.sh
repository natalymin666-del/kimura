#!/usr/bin/env bash
set -u

PROJECT_ROOT="$(cd -- "$(dirname -- "$0")" && pwd)"
PYTHON="$PROJECT_ROOT/venv/bin/python"
DEMO_MODULE="$PROJECT_ROOT/kimura_assessment/conference_demo.py"
FIREFOX="$(command -v firefox || true)"
OUTPUT_DIR="$PROJECT_ROOT/conference-demo-output"
LAPTOP_REPORT="$OUTPUT_DIR/conference-demo-report.html"

if [[ ! -x "$PYTHON" ]]; then
    echo "ERROR: required project venv Python is missing: $PYTHON" >&2
    exit 1
fi

if [[ ! -f "$DEMO_MODULE" ]]; then
    echo "ERROR: Conference Demo source is missing: $DEMO_MODULE" >&2
    exit 1
fi

if [[ -z "$FIREFOX" ]]; then
    echo "ERROR: Firefox is required to open the laptop report but was not found on PATH." >&2
    exit 1
fi

cd -- "$PROJECT_ROOT" || {
    echo "ERROR: could not enter project directory: $PROJECT_ROOT" >&2
    exit 1
}

"$PYTHON" -m kimura_assessment.conference_demo --output "$OUTPUT_DIR" || {
    echo "ERROR: Conference Demo failed; report was not opened." >&2
    exit 1
}

if [[ ! -f "$LAPTOP_REPORT" ]]; then
    echo "ERROR: expected laptop report was not generated: $LAPTOP_REPORT" >&2
    exit 1
fi

exec "$FIREFOX" --new-window "$LAPTOP_REPORT"
