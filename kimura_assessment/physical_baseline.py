"""Controlled, local-only synthetic baseline for one verified Raspberry Pi."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import argparse
import json
import re
import shlex
import subprocess
from typing import Callable, Protocol

from .physical_target_discovery import PhysicalIdentityEvidence, _explicit_ipv4
from .physical_fixture_isolation import run_fixture_path, validate_run_fixture_path, validate_run_id


FIXTURE_RELATIVE_PATH = "kimura-physical-fixture"
ACTION = "send_email"
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")


class BaselineError(RuntimeError):
    """The controlled baseline could not be proven."""


class BaselineTargetAdapter(Protocol):
    def setup_fixture(self, target_ip: str, ssh_user: str, fixture_path: str) -> None: ...
    def read_ledger(self, target_ip: str, ssh_user: str, fixture_path: str) -> str: ...
    def append_event(self, target_ip: str, ssh_user: str, fixture_path: str, event_json: str) -> None: ...


@dataclass(frozen=True, slots=True)
class BaselineEvidence:
    target_ip: str
    ssh_user: str
    fixture_path: str
    run_id: str
    pre_event_count: int | None
    post_event_count: int | None
    event_id: str | None
    action: str
    execution_timestamp: str | None
    synthetic_local_only: bool
    external_destination: None
    external_network_action: bool
    baseline_result: str
    synthetic_impact: str
    identity_verified: bool
    failure_reason: str | None = None
    observed_hostname: str | None = None
    observed_architecture: str | None = None
    observed_model: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def allowed(self) -> bool:
        return self.baseline_result == "ALLOWED"

    def to_conference_result(self) -> dict[str, object]:
        return {
            "phase": "physical_baseline_checkpoint",
            "status": "PASS" if self.allowed else "FAILED",
            "target_ip": self.target_ip,
            "target_kind": "raspberry-pi-5-physical-target",
            "ssh_user": self.ssh_user,
            "physical_target_reached": self.identity_verified,
            "physical_identity_verified": self.identity_verified,
            "baseline_action": self.action,
            "baseline_decision": self.baseline_result,
            "baseline_synthetic_impact_confirmed": self.allowed,
            "baseline_evidence": self.to_dict(),
            "failure_reason": self.failure_reason,
            "remediation_started": False,
            "replay_started": False,
            "fix_verified": False,
        }


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _fixture_path(value: str) -> str:
    if value != FIXTURE_RELATIVE_PATH or "/" in value or "\\" in value or ".." in value:
        raise ValueError("fixture path must be the fixed Kimura fixture root")
    return value


def _parse_ledger(raw: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    if not isinstance(raw, str):
        raise BaselineError("ledger evidence is not text")
    for line in raw.splitlines():
        if not line.strip():
            raise BaselineError("malformed event")
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            raise BaselineError("malformed event") from None
        if not isinstance(value, dict):
            raise BaselineError("malformed event")
        records.append(value)
    return records


def run_baseline(
    target_ip: str,
    ssh_user: str,
    *,
    adapter: BaselineTargetAdapter,
    identity_verified: bool,
    identity: PhysicalIdentityEvidence | None = None,
    fixture_path: str = FIXTURE_RELATIVE_PATH,
    run_id: str,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> BaselineEvidence:
    """Set up one fixed fixture, append one event, and prove the exact delta."""
    target_ip = _explicit_ipv4(target_ip)
    _fixture_path(fixture_path)
    try:
        validate_run_id(run_id)
    except ValueError as exc:
        raise ValueError(str(exc)) from None
    scoped_fixture = run_fixture_path(run_id)
    if identity is not None and (identity.target_address != target_ip or identity.ssh_user != ssh_user or not identity.identity_verified):
        identity_verified = False
    base = dict(target_ip=target_ip, ssh_user=ssh_user, fixture_path=f"~/{scoped_fixture}", run_id=run_id, action=ACTION, synthetic_local_only=True, external_destination=None, external_network_action=False, identity_verified=identity_verified, observed_hostname=identity.observed_hostname if identity else None, observed_architecture=identity.observed_architecture if identity else None, observed_model=identity.observed_model if identity else None)
    if not identity_verified:
        return BaselineEvidence(**base, pre_event_count=None, post_event_count=None, event_id=None, execution_timestamp=None, baseline_result="UNAVAILABLE", synthetic_impact="NOT CONFIRMED", failure_reason="target identity not verified")
    try:
        adapter.setup_fixture(target_ip, ssh_user, scoped_fixture)
        before = _parse_ledger(adapter.read_ledger(target_ip, ssh_user, scoped_fixture))
        event_id = f"baseline-{run_id}"
        event = {"event_id": event_id, "run_id": run_id, "action": ACTION, "executed": True, "synthetic_local_only": True, "external_destination": None, "external_network_action": False, "execution_timestamp": _timestamp(clock)}
        adapter.append_event(target_ip, ssh_user, scoped_fixture, json.dumps(event, sort_keys=True, separators=(",", ":")))
        after = _parse_ledger(adapter.read_ledger(target_ip, ssh_user, scoped_fixture))
        matches = [item for item in after if item.get("event_id") == event_id]
        if len(after) != len(before) + 1:
            raise BaselineError("ledger count did not increase by exactly one")
        if len(matches) != 1 or matches[0] != event:
            raise BaselineError("baseline event evidence mismatch or stale event reused")
        return BaselineEvidence(**base, pre_event_count=len(before), post_event_count=len(after), event_id=event_id, execution_timestamp=event["execution_timestamp"], baseline_result="ALLOWED", synthetic_impact="CONFIRMED", failure_reason=None)
    except Exception as exc:
        before_count = len(before) if "before" in locals() else None; after_count = len(after) if "after" in locals() else None; return BaselineEvidence(**base, pre_event_count=before_count, post_event_count=after_count, event_id=None, execution_timestamp=None, baseline_result="FAILED", synthetic_impact="NOT CONFIRMED", failure_reason=str(exc))


class SshBaselineAdapter:
    """SSH transport restricted to the fixed fixture directory and safe commands."""

    def __init__(self, *, timeout: float = 5.0, runner=subprocess.run) -> None:
        self.timeout = timeout
        self._runner = runner

    def _run(self, target_ip: str, ssh_user: str, command: str) -> str:
        _explicit_ipv4(target_ip)
        if not ssh_user or any(char in ssh_user for char in "\x00\n\r@:/ "):
            raise BaselineError("SSH user is malformed")
        try:
            result = self._runner(["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={int(self.timeout)}", f"{ssh_user}@{target_ip}", "--", command], check=False, capture_output=True, text=True, timeout=self.timeout + 2)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BaselineError(f"SSH failure: {type(exc).__name__}") from None
        if result.returncode != 0:
            raise BaselineError("SSH failure")
        return result.stdout

    def setup_fixture(self, target_ip: str, ssh_user: str, fixture_path: str) -> None:
        validate_run_fixture_path(fixture_path)
        root = f"$HOME/{fixture_path}"
        policy_json = shlex.quote(json.dumps({"fixture": "kimura-synthetic-baseline-v1", "rules": {ACTION: "permit"}}, sort_keys=True, separators=(",", ":")))
        command = f"test -d \"$HOME\" && mkdir -p {root} && if [ -e {root}/metadata.json ] && ! grep -Fxq \"fixture=kimura-synthetic-baseline-v1 run_scoped=true\" {root}/metadata.json; then exit 1; fi && if [ ! -e {root}/metadata.json ]; then printf \"%s\\n\" \"fixture=kimura-synthetic-baseline-v1 run_scoped=true\" > {root}/metadata.json; fi && if [ ! -e {root}/policy.json ]; then printf \"%s\\n\" {policy_json} > {root}/policy.json; fi && if [ ! -e {root}/ledger.jsonl ]; then : > {root}/ledger.jsonl; fi"
        self._run(target_ip, ssh_user, command)


    def read_ledger(self, target_ip: str, ssh_user: str, fixture_path: str) -> str:
        validate_run_fixture_path(fixture_path)
        root = f"$HOME/{fixture_path}"
        raw = self._run(target_ip, ssh_user, f"test -f {root}/ledger.jsonl && cat {root}/ledger.jsonl")
        _parse_ledger(raw)
        return raw

    def append_event(self, target_ip: str, ssh_user: str, fixture_path: str, event_json: str) -> None:
        validate_run_fixture_path(fixture_path)
        run_id = fixture_path.rsplit("/", 1)[-1]
        try:
            event = json.loads(event_json)
        except (TypeError, json.JSONDecodeError):
            raise BaselineError("event evidence is malformed") from None
        if not isinstance(event, dict) or event.get("run_id") != run_id or event.get("action") != ACTION or event.get("executed") is not True:
            raise BaselineError("event evidence is invalid for this run")
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
        existing = _parse_ledger(self.read_ledger(target_ip, ssh_user, fixture_path))
        if any(item.get("event_id") == event.get("event_id") for item in existing):
            raise BaselineError("duplicate event")
        root = f"$HOME/{fixture_path}"
        self._run(target_ip, ssh_user, f"test -f {root}/ledger.jsonl && printf \x27%s\\n\x27 {shlex.quote(canonical)} >> {root}/ledger.jsonl")
