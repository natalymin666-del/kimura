"""Command-line entry point for Model-Backed Adapter v1."""

from __future__ import annotations

import argparse
from pathlib import Path

from .demo_model_v1 import run_model_v1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Kimura Model-Backed Adapter v1 with local Ollama")
    parser.add_argument("--model", required=True, help="pinned local Ollama model identifier")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--persist", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if args.report is not None and args.persist is None:
        parser.error("--report requires --persist")
    try:
        print(run_model_v1(model_id=args.model, trials=args.trials, persist_path=args.persist, report_path=args.report))
    except Exception:
        parser.error("model-backed demo could not be completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
