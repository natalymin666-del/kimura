"""Deterministic, local persistence for safe assessment result metadata."""

from __future__ import annotations

import json
from pathlib import Path

from .results import AssessmentResult


class PersistenceError(ValueError):
    """Raised when persisted assessment data is missing or malformed."""


class AssessmentResultStore:
    """Append and read one safe ``AssessmentResult`` per JSONL line."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, result: AssessmentResult) -> None:
        if not isinstance(result, AssessmentResult):
            raise TypeError("only AssessmentResult objects can be persisted")
        line = result.to_json()
        # Use text append with a fixed newline: one result is one deterministic record.
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")

    def read_all(self) -> list[AssessmentResult]:
        try:
            content = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PersistenceError("assessment results could not be read") from exc
        results: list[AssessmentResult] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                raise PersistenceError(f"assessment result record {line_number} is empty")
            try:
                values = json.loads(line)
                results.append(AssessmentResult.from_dict(values))
            except (json.JSONDecodeError, ValueError) as exc:
                raise PersistenceError(f"assessment result record {line_number} is malformed") from exc
        return results
