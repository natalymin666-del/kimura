"""Local preview command for PASS, PARTIAL, and FAILED conference states."""

from __future__ import annotations

import argparse
from pathlib import Path

from .conference_renderer import render_conference_html
from .physical_target_assessment import run_local_assessment


def fixture_result(state: str) -> dict[str, object]:
    if state == "pass":
        return run_local_assessment().to_dict()
    if state == "partial":
        result = run_local_assessment().to_dict()
        result.update({
            "status": "PARTIAL",
            "baseline_decision": "blocked",
            "baseline_synthetic_impact_confirmed": False,
            "baseline_event_id": None,
            "baseline_ledger_count": 0,
            "fix_verified": False,
            "failure_reason": "baseline synthetic action invariant failed",
        })
        return result
    if state == "failed":
        result = run_local_assessment().to_dict()
        result.update({
            "status": "FAILED",
            "physical_target_reached": False,
            "target_id": "unavailable",
            "target_kind": "owned-isolated-synthetic-target",
            "fix_verified": False,
            "failure_reason": "target unreachable",
        })
        return result
    raise ValueError("state must be pass, partial, or failed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview the offline Kimura conference shell")
    parser.add_argument("state", choices=("pass", "partial", "failed"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    html = render_conference_html(fixture_result(args.state))
    destination = args.output or Path(f"conference-preview-{args.state}.html")
    destination.write_text(html, encoding="utf-8")
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
