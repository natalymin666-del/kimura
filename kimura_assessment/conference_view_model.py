"""Runtime-derived presentation model for the Kimura conference experience."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class ConferenceViewModelError(ValueError):
    """Raised when an assessment result cannot support a truthful presentation."""


@dataclass(frozen=True, slots=True)
class ConferenceViewModel:
    status: str
    display_status: str
    target_id: str
    target_kind: str
    protocol_version: int
    physical_target_reached: bool
    baseline_fixture_id: str | None
    baseline_fixture_sha256: str | None
    action: str | None
    baseline_decision: str | None
    baseline_impact_confirmed: bool
    baseline_event_id: str | None
    baseline_ledger_count: int | None
    remediation_policy_id: str | None
    policy_digest_before: str | None
    policy_digest_after: str | None
    deny_only_verified: bool
    replay_fixture_sha256: str | None
    exact_replay_identity_verified: bool
    replay_target_reached: bool
    replay_decision: str | None
    replay_executed: bool | None
    replay_impact_confirmed: bool
    replay_impact_label: str
    final_ledger_count: int | None
    fix_verified: bool
    failure_reason: str | None
    story: tuple[dict[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "display_status": self.display_status,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "protocol_version": self.protocol_version,
            "physical_target_reached": self.physical_target_reached,
            "baseline_fixture_id": self.baseline_fixture_id,
            "baseline_fixture_sha256": self.baseline_fixture_sha256,
            "action": self.action,
            "baseline_decision": self.baseline_decision,
            "baseline_impact_confirmed": self.baseline_impact_confirmed,
            "baseline_event_id": self.baseline_event_id,
            "baseline_ledger_count": self.baseline_ledger_count,
            "remediation_policy_id": self.remediation_policy_id,
            "policy_digest_before": self.policy_digest_before,
            "policy_digest_after": self.policy_digest_after,
            "deny_only_verified": self.deny_only_verified,
            "replay_fixture_sha256": self.replay_fixture_sha256,
            "exact_replay_identity_verified": self.exact_replay_identity_verified,
            "replay_target_reached": self.replay_target_reached,
            "replay_decision": self.replay_decision,
            "replay_executed": self.replay_executed,
            "replay_impact_confirmed": self.replay_impact_confirmed,
            "replay_impact_label": self.replay_impact_label,
            "final_ledger_count": self.final_ledger_count,
            "fix_verified": self.fix_verified,
            "failure_reason": self.failure_reason,
            "story": [dict(item) for item in self.story],
        }


def _text(result: Mapping[str, Any], field: str, *, required: bool = False) -> str | None:
    value = result.get(field)
    if required and (not isinstance(value, str) or not value):
        raise ConferenceViewModelError(f"result field {field} is required")
    return value if isinstance(value, str) else None


def _bool(result: Mapping[str, Any], field: str) -> bool:
    value = result.get(field)
    if not isinstance(value, bool):
        raise ConferenceViewModelError(f"result field {field} must be boolean")
    return value


def _count(result: Mapping[str, Any], field: str) -> int | None:
    value = result.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConferenceViewModelError(f"result field {field} must be a non-negative integer")
    return value


def _chain_value(result: Mapping[str, Any], stage: str, key: str) -> str | None:
    chain = result.get("evidence_chain", ())
    if not isinstance(chain, (list, tuple)):
        raise ConferenceViewModelError("evidence_chain must be a list")
    for item in chain:
        if isinstance(item, Mapping) and item.get("stage") == stage:
            value = item.get(key)
            return value if isinstance(value, str) else None
    return None


def _story(result: Mapping[str, Any], *, action: str | None, verified: bool) -> tuple[dict[str, str], ...]:
    reached = _bool(result, "physical_target_reached")
    baseline_impact = _bool(result, "baseline_synthetic_impact_confirmed")
    deny_only = _bool(result, "deny_only_verified")
    replay_reached = _bool(result, "replay_target_reached")
    exact = _bool(result, "exact_replay_identity_verified")
    replay_decision = _text(result, "replay_decision")
    replay_executed = result.get("replay_executed")
    replay_impact = _bool(result, "replay_synthetic_impact_confirmed")
    failure = _text(result, "failure_reason")

    def state(done: bool, failed: bool = False) -> str:
        return "failed" if failed else "complete" if done else "pending"

    failure_present = bool(failure)
    return (
        {"key": "discovery", "label": "Discovery", "state": state(reached, failure_present and not reached)},
        {"key": "baseline", "label": "Baseline attack", "state": state(reached and action is not None, failure_present and reached and action is None)},
        {"key": "evidence", "label": "Evidence", "state": state(baseline_impact, failure_present and not baseline_impact)},
        {"key": "remediation", "label": "Remediation", "state": state(deny_only, failure_present and baseline_impact and not deny_only)},
        {"key": "replay", "label": "Exact replay", "state": state(replay_reached and exact, failure_present and deny_only and not replay_reached)},
        {"key": "verification", "label": "Verification", "state": state(verified, failure_present and replay_reached and (replay_decision != "blocked" or replay_executed is not False or replay_impact))},
    )


def derive_view_model(result: Mapping[str, Any]) -> ConferenceViewModel:
    """Validate result shape and derive only presentation state from runtime facts."""

    if not isinstance(result, Mapping):
        raise ConferenceViewModelError("assessment result must be an object")
    status = result.get("status")
    if status not in {"PASS", "PARTIAL", "FAILED"}:
        raise ConferenceViewModelError("assessment result has unsupported status")
    target_id = _text(result, "target_id", required=True)
    target_kind = _text(result, "target_kind", required=True)
    protocol_version = result.get("protocol_version")
    if isinstance(protocol_version, bool) or not isinstance(protocol_version, int):
        raise ConferenceViewModelError("protocol_version must be an integer")

    action = _chain_value(result, "baseline-impact-confirmed", "action")
    baseline_decision = _text(result, "baseline_decision")
    replay_decision = _text(result, "replay_decision")
    replay_executed = result.get("replay_executed")
    if replay_executed is not None and not isinstance(replay_executed, bool):
        raise ConferenceViewModelError("replay_executed must be boolean or null")

    required_pass_facts = (
        status == "PASS"
        and _bool(result, "physical_target_reached")
        and baseline_decision == "allowed"
        and _bool(result, "baseline_synthetic_impact_confirmed")
        and _count(result, "baseline_ledger_count") == 1
        and _bool(result, "deny_only_verified")
        and _bool(result, "exact_replay_identity_verified")
        and _bool(result, "replay_target_reached")
        and replay_decision == "blocked"
        and replay_executed is False
        and _bool(result, "replay_synthetic_impact_confirmed") is False
        and _count(result, "final_ledger_count") == 1
        and _bool(result, "fix_verified")
    )
    fix_verified = _bool(result, "fix_verified")
    display_status = status if status != "PASS" or required_pass_facts else "FAILED"
    if display_status == "PASS":
        replay_label = "NO SYNTHETIC IMPACT"
    elif replay_decision == "blocked" and replay_executed is False and not _bool(result, "replay_synthetic_impact_confirmed"):
        replay_label = "NO SYNTHETIC IMPACT"
    else:
        replay_label = "NOT ESTABLISHED"
    failure_reason = _text(result, "failure_reason")
    if status == "PASS" and not required_pass_facts:
        failure_reason = failure_reason or "result did not satisfy PASS presentation invariants"

    return ConferenceViewModel(
        status=status,
        display_status=display_status,
        target_id=target_id,
        target_kind=target_kind,
        protocol_version=protocol_version,
        physical_target_reached=_bool(result, "physical_target_reached"),
        baseline_fixture_id=_text(result, "baseline_fixture_id"),
        baseline_fixture_sha256=_text(result, "baseline_fixture_sha256"),
        action=action,
        baseline_decision=baseline_decision,
        baseline_impact_confirmed=_bool(result, "baseline_synthetic_impact_confirmed"),
        baseline_event_id=_text(result, "baseline_event_id"),
        baseline_ledger_count=_count(result, "baseline_ledger_count"),
        remediation_policy_id=_text(result, "remediation_policy_id"),
        policy_digest_before=_text(result, "policy_digest_before"),
        policy_digest_after=_text(result, "policy_digest_after"),
        deny_only_verified=_bool(result, "deny_only_verified"),
        replay_fixture_sha256=_text(result, "replay_fixture_sha256"),
        exact_replay_identity_verified=_bool(result, "exact_replay_identity_verified"),
        replay_target_reached=_bool(result, "replay_target_reached"),
        replay_decision=replay_decision,
        replay_executed=replay_executed,
        replay_impact_confirmed=_bool(result, "replay_synthetic_impact_confirmed"),
        replay_impact_label=replay_label,
        final_ledger_count=_count(result, "final_ledger_count"),
        fix_verified=fix_verified and required_pass_facts,
        failure_reason=failure_reason,
        story=_story(result, action=action, verified=required_pass_facts),
    )
