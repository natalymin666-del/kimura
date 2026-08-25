"""Backend-neutral, presentation-only progress events for one assessment run."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Protocol
from uuid import uuid4


class ProgressEventType(StrEnum):
    ASSESSMENT_STARTED = "assessment_started"
    TARGET_VERIFIED = "target_verified"
    BASELINE_VALIDATED = "baseline_validated"
    REMEDIATION_VERIFIED = "remediation_verified"
    REPLAY_IDENTITY_VERIFIED = "replay_identity_verified"
    REPLAY_VALIDATED = "replay_validated"
    CLEANUP_COMPLETED = "cleanup_completed"
    CLEANUP_FAILED = "cleanup_failed"
    FIX_VERIFIED = "fix_verified"
    ASSESSMENT_PARTIAL = "assessment_partial"
    ASSESSMENT_FAILED = "assessment_failed"


_PAYLOAD_FIELDS: dict[ProgressEventType, frozenset[str]] = {
    ProgressEventType.ASSESSMENT_STARTED: frozenset({"assessment_id"}),
    ProgressEventType.TARGET_VERIFIED: frozenset({"target_id", "target_kind", "protocol_version", "policy_digest_before"}),
    ProgressEventType.BASELINE_VALIDATED: frozenset({"fixture_id", "fixture_sha256", "action", "decision", "event_id", "ledger_count"}),
    ProgressEventType.REMEDIATION_VERIFIED: frozenset({"policy_id", "policy_digest_before", "policy_digest_after", "denied_actions"}),
    ProgressEventType.REPLAY_IDENTITY_VERIFIED: frozenset({"attack_id", "fixture_id", "fixture_sha256", "action"}),
    ProgressEventType.REPLAY_VALIDATED: frozenset({"decision", "executed", "synthetic_event_id", "ledger_count", "baseline_ledger_count"}),
    ProgressEventType.CLEANUP_COMPLETED: frozenset({"cleanup_attempted"}),
    ProgressEventType.CLEANUP_FAILED: frozenset({"failure_code"}),
    ProgressEventType.FIX_VERIFIED: frozenset({"baseline_ledger_count", "final_ledger_count"}),
    ProgressEventType.ASSESSMENT_PARTIAL: frozenset({"failure_code", "last_proven_event", "cleanup_completed"}),
    ProgressEventType.ASSESSMENT_FAILED: frozenset({"failure_code", "last_proven_event", "cleanup_completed"}),
}


def _validate_safe_value(value: Any) -> None:
    if value is None or isinstance(value, (bool, int, float, str)):
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_safe_value(item)
        return
    raise TypeError("progress payload contains an unsafe value")


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """One validated, ordered event; sequence is the deterministic clock."""

    run_id: str
    sequence: int
    event_type: ProgressEventType
    payload: dict[str, Any]

    def __post_init__(self) -> None:
        if not self.run_id or not isinstance(self.run_id, str):
            raise ValueError("run_id must be a non-empty string")
        if self.sequence < 1:
            raise ValueError("sequence must be positive")
        allowed = _PAYLOAD_FIELDS[self.event_type]
        if set(self.payload) - allowed:
            raise ValueError("progress payload contains an unapproved field")
        for value in self.payload.values():
            _validate_safe_value(value)

    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "sequence": self.sequence, "event_type": self.event_type.value, "payload": dict(self.payload)}


class ProgressSink(Protocol):
    def __call__(self, event: ProgressEvent) -> None:
        ...


class ProgressEmitter:
    """Best-effort event delivery that cannot affect assessment truth."""

    def __init__(self, sink: ProgressSink | None = None, *, run_id: str | None = None) -> None:
        self._sink = sink
        self.run_id = run_id or uuid4().hex
        self.sequence = 0
        self.sink_failures = 0
        self._emitted_types: set[ProgressEventType] = set()
        self.last_event_type: ProgressEventType | None = None

    def emit(self, event_type: ProgressEventType, payload: Mapping[str, Any]) -> ProgressEvent | None:
        if event_type in self._emitted_types:
            return None
        try:
            event = ProgressEvent(self.run_id, self.sequence + 1, event_type, dict(payload))
        except (TypeError, ValueError):
            self.sink_failures += 1
            return None
        self.sequence = event.sequence
        self._emitted_types.add(event_type)
        self.last_event_type = event_type
        if self._sink is not None:
            try:
                self._sink(event)
            except Exception:
                self.sink_failures += 1
        return event
