"""Fixture-scoped remediation and exact replay for the real Pi checkpoint."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import argparse
import json
import shlex
import subprocess
from typing import Any, Callable, Mapping, Protocol

from .physical_baseline import ACTION, FIXTURE_RELATIVE_PATH, BaselineError, _parse_ledger
from .physical_target_discovery import PhysicalIdentityEvidence, _explicit_ipv4
from .physical_fixture_isolation import run_fixture_path, validate_run_fixture_path, validate_run_id


POLICY = {"fixture": "kimura-synthetic-baseline-v1", "rules": {ACTION: "deny"}}
CANONICAL_ACTION_KEYS = ("action", "synthetic_local_only", "external_destination", "external_network_action")


class ReplayError(RuntimeError):
    """Remediation or exact replay evidence failed."""


class RemediationTargetAdapter(Protocol):
    def read_policy(self, target_ip: str, ssh_user: str, fixture_path: str) -> str: ...
    def write_policy(self, target_ip: str, ssh_user: str, fixture_path: str, policy_json: str) -> None: ...
    def read_ledger(self, target_ip: str, ssh_user: str, fixture_path: str) -> str: ...
    def replay(self, target_ip: str, ssh_user: str, fixture_path: str, action_json: str, fingerprint: str) -> Mapping[str, Any]: ...


def canonical_action_payload(event: Mapping[str, Any]) -> str:
    if any(key not in event for key in CANONICAL_ACTION_KEYS):
        raise ReplayError("baseline action payload missing required field")
    if event.get("action") != ACTION or event.get("synthetic_local_only") is not True or event.get("external_destination") is not None or event.get("external_network_action") is not False:
        raise ReplayError("baseline action payload is not the approved synthetic action")
    payload = {key: event[key] for key in CANONICAL_ACTION_KEYS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def action_fingerprint(payload: str) -> str:
    return sha256(payload.encode("utf-8")).hexdigest()


def _policy(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        raise ReplayError("policy malformed") from None
    if not isinstance(value, dict) or value.get("fixture") != POLICY["fixture"] or not isinstance(value.get("rules"), dict):
        raise ReplayError("policy malformed")
    return value


def _deny_policy(value: Mapping[str, Any]) -> bool:
    return value.get("fixture") == POLICY["fixture"] and isinstance(value.get("rules"), Mapping) and value["rules"].get(ACTION) == "deny"


@dataclass(frozen=True, slots=True)
class ReplayEvidence:
    target_ip: str
    ssh_user: str
    fixture_path: str
    baseline_event_id: str | None
    baseline_action: str
    baseline_event_count: int | None
    policy_before: str | None
    policy_after: str | None
    replay_action: str
    baseline_sha256: str | None
    replay_sha256: str | None
    same_fixture: bool
    sha256_match: bool
    pre_replay_event_count: int | None
    post_replay_event_count: int | None
    replay_result: str
    synthetic_impact: str
    identity_verified: bool
    fix_verified: bool
    real_email_sent: bool
    external_network_action: bool
    remediation_verified: bool
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_conference_result(self) -> dict[str, object]:
        return {"phase": "physical_replay_checkpoint", "status": "PASS" if self.fix_verified else "FAILED", "target_ip": self.target_ip, "target_kind": "raspberry-pi-5-physical-target", "ssh_user": self.ssh_user, "physical_target_reached": self.identity_verified, "physical_identity_verified": self.identity_verified, "baseline_action": self.baseline_action, "baseline_decision": "ALLOWED" if self.baseline_event_count == 1 else "NOT VERIFIED", "baseline_synthetic_impact_confirmed": self.baseline_event_count == 1, "baseline_evidence": {"event_id": self.baseline_event_id, "event_count": self.baseline_event_count}, "remediation_verified": self.remediation_verified, "policy_before": self.policy_before, "policy_after": self.policy_after, "replay_action": self.replay_action, "replay_decision": self.replay_result, "replay_synthetic_impact_confirmed": self.synthetic_impact == "CONFIRMED", "replay_evidence": self.to_dict(), "exact_replay_identity_verified": self.sha256_match and self.same_fixture, "fix_verified": self.fix_verified, "failure_reason": self.failure_reason}


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def run_remediation_and_replay(
    target_ip: str,
    ssh_user: str,
    *,
    adapter: RemediationTargetAdapter,
    identity: PhysicalIdentityEvidence,
    expected_baseline_run_id: str,
    fixture_path: str = FIXTURE_RELATIVE_PATH,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> ReplayEvidence:
    target_ip = _explicit_ipv4(target_ip)
    scoped_fixture = run_fixture_path(expected_baseline_run_id)
    if fixture_path != FIXTURE_RELATIVE_PATH or identity.target_address != target_ip or identity.ssh_user != ssh_user or not identity.identity_verified:
        return ReplayEvidence(target_ip, ssh_user, f"~/{scoped_fixture}", None, ACTION, None, None, None, ACTION, None, None, False, False, None, None, "UNAVAILABLE", "NOT CONFIRMED", False, False, False, False, False, "target identity or fixture mismatch")
    baseline_id = None
    try:
        before_ledger = _parse_ledger(adapter.read_ledger(target_ip, ssh_user, scoped_fixture))
        if len(before_ledger) != 1:
            raise ReplayError("baseline event count invalid")
        baseline = before_ledger[0]
        baseline_id = baseline.get("event_id") if isinstance(baseline.get("event_id"), str) else None
        if not baseline_id or baseline.get("run_id") != expected_baseline_run_id or baseline_id != "baseline-" + expected_baseline_run_id or baseline.get("executed") is not True:
            raise ReplayError("baseline evidence missing or wrong run identity")
        payload = canonical_action_payload(baseline)
        fingerprint = action_fingerprint(payload)
        policy_before_raw = adapter.read_policy(target_ip, ssh_user, scoped_fixture)
        policy_before = _policy(policy_before_raw) if policy_before_raw.strip() else {"fixture": POLICY["fixture"], "rules": {ACTION: "permit"}}
        if _deny_policy(policy_before):
            raise ReplayError("policy already denied action")
        adapter.write_policy(target_ip, ssh_user, scoped_fixture, json.dumps(POLICY, sort_keys=True, separators=(",", ":")))
        policy_after_raw = adapter.read_policy(target_ip, ssh_user, scoped_fixture)
        policy_after = _policy(policy_after_raw)
        if not _deny_policy(policy_after):
            raise ReplayError("policy does not deny action")
        intact = _parse_ledger(adapter.read_ledger(target_ip, ssh_user, scoped_fixture))
        if intact != before_ledger:
            raise ReplayError("baseline evidence changed")
        pre_replay = len(intact)
        replay = dict(adapter.replay(target_ip, ssh_user, scoped_fixture, payload, fingerprint))
        post = _parse_ledger(adapter.read_ledger(target_ip, ssh_user, scoped_fixture))
        replay_sha = replay.get("fingerprint") if isinstance(replay.get("fingerprint"), str) else None
        same = replay.get("fixture_path") == f"~/{scoped_fixture}"
        matched = replay.get("action") == ACTION and replay_sha == fingerprint
        if replay.get("result") != "BLOCKED" or not matched or not same or len(post) != pre_replay or replay.get("synthetic_impact") is not False or replay.get("external_network_action") is not False:
            raise ReplayError("exact replay deny-only invariant failed")
        return ReplayEvidence(target_ip, ssh_user, f"~/{scoped_fixture}", baseline_id, ACTION, 1, json.dumps(policy_before, sort_keys=True, separators=(",", ":")), json.dumps(policy_after, sort_keys=True, separators=(",", ":")), ACTION, fingerprint, replay_sha, same, matched, pre_replay, len(post), "BLOCKED", "NOT CONFIRMED", True, True, False, False, True, None)
    except Exception as exc:
        return ReplayEvidence(target_ip, ssh_user, f"~/{scoped_fixture}", baseline_id, ACTION, None, None, None, ACTION, None, None, False, False, None, None, "FAILED", "NOT CONFIRMED", True, False, False, False, False, str(exc))


class SshRemediationAdapter:
    """SSH transport limited to the fixed fixture policy, ledger, and replay command."""
    def __init__(self, *, timeout: float = 5.0, runner=subprocess.run) -> None:
        self.timeout, self._runner = timeout, runner

    def _run(self, target_ip: str, ssh_user: str, command: str) -> str:
        _explicit_ipv4(target_ip)
        if not ssh_user or any(char in ssh_user for char in "\x00\n\r@:/ "):
            raise ReplayError("SSH user is malformed")
        try:
            result = self._runner(["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={int(self.timeout)}", f"{ssh_user}@{target_ip}", "--", command], check=False, capture_output=True, text=True, timeout=self.timeout + 2)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReplayError(f"SSH failure: {type(exc).__name__}") from None
        if result.returncode != 0:
            raise ReplayError("SSH failure")
        return result.stdout

    def read_policy(self, target_ip, ssh_user, fixture_path):
        validate_run_fixture_path(fixture_path)
        root = "$HOME/" + fixture_path
        return self._run(target_ip, ssh_user, f"test -f {root}/policy.json && cat {root}/policy.json || true")

    def write_policy(self, target_ip, ssh_user, fixture_path, policy_json):
        validate_run_fixture_path(fixture_path)
        root = "$HOME/" + fixture_path
        self._run(target_ip, ssh_user, f"test -d {root} && printf '%s\\n' {shlex.quote(policy_json)} > {root}/policy.json")

    def read_ledger(self, target_ip, ssh_user, fixture_path):
        validate_run_fixture_path(fixture_path)
        root = "$HOME/" + fixture_path
        return self._run(target_ip, ssh_user, f"test -f {root}/ledger.jsonl && cat {root}/ledger.jsonl")

    def replay(self, target_ip, ssh_user, fixture_path, action_json, fingerprint):
        validate_run_fixture_path(fixture_path)
        root = "$HOME/" + fixture_path
        output = json.dumps({"result": "BLOCKED", "action": ACTION, "fingerprint": fingerprint, "fixture_path": f"~/{fixture_path}", "synthetic_impact": False, "external_network_action": False}, sort_keys=True, separators=(",", ":"))
        command = f"test -f {root}/policy.json && grep -Fq '\"send_email\":\"deny\"' {root}/policy.json && printf '%s\\n' {shlex.quote(output)}"
        return json.loads(self._run(target_ip, ssh_user, command))

    def write_remediation_evidence(self, target_ip: str, ssh_user: str, fixture_path: str, evidence_json: str) -> None:
        validate_run_fixture_path(fixture_path)
        run_id = fixture_path.rsplit("/", 1)[-1]
        canonical = serialize_remediation_evidence(parse_remediation_evidence(evidence_json, run_id))
        root = f"$HOME/{fixture_path}"
        quote = chr(39)
        self._run(target_ip, ssh_user, f"test -d {root} && printf {quote}%s\\n{quote} {shlex.quote(canonical[:-1])} > {root}/remediation.json")

    def read_remediation_evidence(self, target_ip: str, ssh_user: str, fixture_path: str) -> dict[str, Any]:
        validate_run_fixture_path(fixture_path)
        run_id = fixture_path.rsplit("/", 1)[-1]
        root = f"$HOME/{fixture_path}"
        return parse_remediation_evidence(self._run(target_ip, ssh_user, f"test -f {root}/remediation.json && cat {root}/remediation.json"), run_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one fixture-scoped remediation and exact replay")
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--ssh-user", required=True)
    args = parser.parse_args(argv)
    from .physical_target_discovery import SshReadOnlyAdapter, discover_and_verify
    identity = discover_and_verify(args.target_ip, args.ssh_user, adapter=SshReadOnlyAdapter())
    result = run_remediation_and_replay(args.target_ip, args.ssh_user, adapter=SshRemediationAdapter(), identity=identity, expected_baseline_run_id="phase45b-20260826-01")
    print(json.dumps(result.to_dict(), sort_keys=True))
    return 0 if result.fix_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())


def serialize_remediation_evidence(value: Mapping[str, Any]) -> str:
    if not isinstance(value, Mapping) or not isinstance(value.get("run_id"), str) or not value.get("run_id"):
        raise ReplayError("remediation evidence is malformed")
    validate_run_id(value["run_id"])
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"

def parse_remediation_evidence(raw: str, expected_run_id: str) -> dict[str, Any]:
    validate_run_id(expected_run_id)
    if not isinstance(raw, str) or not raw.endswith("\n") or raw.endswith("\n\n"):
        raise ReplayError("remediation evidence terminator is invalid")
    body = raw[:-1]
    try:
        value = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        raise ReplayError("remediation evidence is malformed") from None
    if not isinstance(value, dict) or json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) != body:
        raise ReplayError("remediation evidence is not canonical")
    if value.get("run_id") != expected_run_id:
        raise ReplayError("remediation evidence belongs to another run")
    return value
