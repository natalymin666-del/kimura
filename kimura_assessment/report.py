"""Safe report formatting for persisted assessment result metadata."""

from __future__ import annotations

import json
from typing import Iterable

from .persistence import AssessmentResultStore
from .results import AssessmentResult


def build_report(results: Iterable[AssessmentResult]) -> dict[str, object]:
    """Build a deterministic aggregate report without response content."""

    ordered = sorted(results, key=lambda item: (item.assessment_id, item.execution_number))
    return {
        "schema_version": 1,
        "result_count": len(ordered),
        "assessment_ids": sorted({result.assessment_id for result in ordered}),
        "completed_count": sum(result.status == "completed" for result in ordered),
        "total_response_bytes": sum(result.response_length for result in ordered),
        "results": [result.to_dict() for result in ordered],
    }


def report_from_store(store: AssessmentResultStore) -> dict[str, object]:
    return build_report(store.read_all())


def report_json_from_store(store: AssessmentResultStore) -> str:
    """Return the report in stable JSON form."""

    return json.dumps(report_from_store(store), sort_keys=True)


def write_report(store: AssessmentResultStore, path: str) -> None:
    """Write a deterministic report separately from the JSONL persistence file."""

    from pathlib import Path

    Path(path).write_text(report_json_from_store(store) + "\n", encoding="utf-8", newline="\n")
