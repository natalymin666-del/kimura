"""Run-scoped state for the owned synthetic physical fixture."""

from __future__ import annotations

from dataclasses import dataclass, field
import copy
import re


FIXTURE_ROOT = "kimura-physical-fixture"
RUNS_ROOT = f"{FIXTURE_ROOT}/runs"
ACTION = "send_email"
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")


class FixtureIsolationError(ValueError):
    """A run attempted to access state outside its own isolated fixture."""


def validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise FixtureIsolationError("run_id is malformed")
    return run_id


def run_fixture_path(run_id: str) -> str:
    return f"{RUNS_ROOT}/{validate_run_id(run_id)}"

def validate_run_fixture_path(path: str) -> str:
    prefix = RUNS_ROOT + "/"
    if not isinstance(path, str) or not path.startswith(prefix) or "/" in path[len(prefix):] or not path[len(prefix):]:
        raise FixtureIsolationError("fixture path is not run-scoped")
    return run_fixture_path(path[len(prefix):])


@dataclass
class LocalFixtureRun:
    run_id: str
    policy: dict[str, object] = field(default_factory=lambda: {"fixture": "kimura-synthetic-baseline-v1", "rules": {ACTION: "permit"}})
    ledger: list[dict[str, object]] = field(default_factory=list)
    remediation: dict[str, object] | None = None
    replay: dict[str, object] | None = None


class LocalFixtureStore:
    """Deterministic isolated fixture store used by tests and local orchestration."""

    def __init__(self) -> None:
        self._runs: dict[str, LocalFixtureRun] = {}
        self.historical_ledger: list[dict[str, object]] = [{"event_id": "historical-baseline", "run_id": "legacy"}]

    def create_run(self, run_id: str) -> LocalFixtureRun:
        validate_run_id(run_id)
        if run_id in self._runs:
            raise FixtureIsolationError("run already exists")
        self._runs[run_id] = LocalFixtureRun(run_id)
        return copy.deepcopy(self._runs[run_id])

    def _run(self, run_id: str) -> LocalFixtureRun:
        validate_run_id(run_id)
        if run_id not in self._runs:
            raise FixtureIsolationError("unknown run")
        return self._runs[run_id]

    def read(self, run_id: str) -> LocalFixtureRun:
        return copy.deepcopy(self._run(run_id))

    def append_baseline(self, run_id: str, event: dict[str, object]) -> None:
        run = self._run(run_id)
        if event.get("run_id") != run_id or run.policy.get("rules", {}).get(ACTION) != "permit":
            raise FixtureIsolationError("cross-run or denied baseline mutation")
        if run.ledger:
            raise FixtureIsolationError("baseline already exists")
        run.ledger.append(copy.deepcopy(event))

    def deny(self, run_id: str) -> None:
        run = self._run(run_id)
        run.policy = {"fixture": "kimura-synthetic-baseline-v1", "rules": {ACTION: "deny"}}
        run.remediation = {"run_id": run_id, "action": ACTION, "from": "permit", "to": "deny"}

    def replay(self, run_id: str, action: str) -> dict[str, object]:
        run = self._run(run_id)
        if action != ACTION or run.policy.get("rules", {}).get(ACTION) != "deny" or len(run.ledger) != 1:
            raise FixtureIsolationError("replay is not a same-run deny-only action")
        result = {"run_id": run_id, "action": action, "result": "BLOCKED", "ledger_count": len(run.ledger)}
        run.replay = copy.deepcopy(result)
        return result
