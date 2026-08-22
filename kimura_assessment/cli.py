"""Minimal command-line entry point for one authorized assessment interaction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .demo import run_demo
from .demo_v2 import run_demo_v2
from .demo_v3 import run_demo_v3
from .http_adapter import HttpTarget
from .persistence import AssessmentResultStore
from .report import write_report
from .runner import AssessmentRunner
from .schema import AssessmentContract


class AssessmentConfigError(ValueError):
    """Raised when the local CLI configuration cannot be used safely."""


def _load_config(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            values = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssessmentConfigError("assessment configuration could not be read") from exc
    if not isinstance(values, dict):
        raise AssessmentConfigError("assessment configuration must be a JSON object")
    return values


def _build_from_config(values: dict[str, Any]) -> tuple[AssessmentContract, HttpTarget, str, Any]:
    contract_values = values.get("contract")
    target_values = values.get("target")
    if not isinstance(contract_values, dict) or not isinstance(target_values, dict):
        raise AssessmentConfigError("configuration requires contract and target objects")

    try:
        contract = AssessmentContract.from_dict(contract_values)
        target = HttpTarget(
            endpoint=target_values["endpoint"],
            input_path=target_values["input_path"],
            response_path=target_values["response_path"],
            credential_reference=target_values["credential_reference"],
            timeout=target_values.get("timeout", 15.0),
            max_response_bytes=target_values.get("max_response_bytes", 1_048_576),
        )
        input_text = values["input_text"]
        request_json = values.get("request_json", {})
    except (KeyError, TypeError, ValueError) as exc:
        raise AssessmentConfigError("assessment configuration is invalid") from exc

    if not isinstance(input_text, str) or not isinstance(request_json, (dict, list)):
        raise AssessmentConfigError("input_text must be a string and request_json must be an object or array")
    return contract, target, input_text, request_json


def run_config(path: Path, *, persist_path: Path | None = None, report_path: Path | None = None) -> str:
    """Execute one configured interaction and return safe result JSON only."""

    contract, target, input_text, request_json = _build_from_config(_load_config(path))
    result = AssessmentRunner(contract, target).run_result(input_text, request_json)
    if persist_path is not None:
        store = AssessmentResultStore(persist_path)
        store.append(result)
        if report_path is not None:
            write_report(store, report_path)
    return result.to_json()


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        import sys

        argv = sys.argv[1:]
    if argv and argv[0] == "demo":
        return _main_demo(argv[1:])
    if argv and argv[0] == "demo-v2":
        return _main_demo_v2(argv[1:])
    if argv and argv[0] == "demo-v3":
        return _main_demo_v3(argv[1:])

    parser = argparse.ArgumentParser(description="Run one authorized Kimura assessment interaction")
    parser.add_argument("config", type=Path, help="local JSON assessment configuration")
    parser.add_argument("--persist", type=Path, help="append the safe result to a local JSONL file")
    parser.add_argument("--report", type=Path, help="write a safe report from the persisted JSONL results")
    args = parser.parse_args(argv)

    try:
        if args.report is not None and args.persist is None:
            parser.error("--report requires --persist")
        print(run_config(args.config, persist_path=args.persist, report_path=args.report))
    except AssessmentConfigError as exc:
        parser.error(str(exc))
    except Exception:
        # Keep operational failures free of target, request, response, and credential data.
        parser.error("assessment could not be completed")
    return 0


def _main_demo(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run the local Conference Demo v1")
    parser.add_argument("--persist", type=Path, help="append the safe result to a local JSONL file")
    parser.add_argument("--report", type=Path, help="write a safe report from the persisted JSONL results")
    args = parser.parse_args(argv)
    try:
        if args.report is not None and args.persist is None:
            parser.error("--report requires --persist")
        print(run_demo(persist_path=args.persist, report_path=args.report))
    except Exception:
        parser.error("conference demo could not be completed")
    return 0


def _main_demo_v2(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run the local Conference Demo v2")
    parser.add_argument("--persist", type=Path, help="append safe evidence to a local JSONL file")
    parser.add_argument("--report", type=Path, help="write the safe Demo v2 report")
    args = parser.parse_args(argv)
    try:
        if args.report is not None and args.persist is None:
            parser.error("--report requires --persist")
        print(run_demo_v2(persist_path=args.persist, report_path=args.report))
    except Exception:
        parser.error("conference demo v2 could not be completed")
    return 0



def _main_demo_v3(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run the local Kimura Agent Security Assessment Demo v3")
    parser.add_argument("--persist", type=Path, help="append safe evidence to a local JSONL file")
    parser.add_argument("--report", type=Path, help="write the consolidated safe assessment report")
    args = parser.parse_args(argv)
    try:
        if args.report is not None and args.persist is None:
            parser.error("--report requires --persist")
        print(run_demo_v3(persist_path=args.persist, report_path=args.report))
    except Exception:
        parser.error("agent security demo v3 could not be completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
