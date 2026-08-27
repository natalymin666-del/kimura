"""In-process append-only journal and deterministic snapshot reducer."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Iterable

from .progress_events import ProgressEvent, ProgressEventType


class ProgressJournalError(ValueError):
    """Base error for rejected progress-journal input."""


class ProgressEventConflictError(ProgressJournalError):
    """A sequence was reused for different event content."""


class ProgressEventStaleError(ProgressJournalError):
    """An event is older than the journal's next expected sequence."""


class ProgressEventGapError(ProgressJournalError):
    """An event arrives with a sequence gap."""


class ProgressEventOrderError(ProgressJournalError):
    """An otherwise valid event is illegal for the current run state."""


@dataclass(frozen=True, slots=True)
class ProgressSnapshot:
    """State and evidence derived exclusively from accepted events."""

    run_id: str
    sequence: int
    state: str
    terminal: bool
    evidence: dict[str, dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "sequence": self.sequence,
            "state": self.state,
            "terminal": self.terminal,
            "evidence": deepcopy(self.evidence),
        }


_SUCCESS_ORDER = (
    ProgressEventType.ASSESSMENT_STARTED,
    ProgressEventType.TARGET_VERIFIED,
    ProgressEventType.BASELINE_VALIDATED,
    ProgressEventType.REMEDIATION_VERIFIED,
    ProgressEventType.REPLAY_IDENTITY_VERIFIED,
    ProgressEventType.REPLAY_VALIDATED,
    ProgressEventType.CLEANUP_COMPLETED,
    ProgressEventType.FIX_VERIFIED,
)
_TERMINAL = frozenset({ProgressEventType.ASSESSMENT_PARTIAL, ProgressEventType.ASSESSMENT_FAILED, ProgressEventType.FIX_VERIFIED})


def _canonical_event(event: ProgressEvent) -> ProgressEvent:
    if not isinstance(event, ProgressEvent):
        raise ProgressJournalError("journal accepts only ProgressEvent objects")
    try:
        return ProgressEvent(event.run_id, event.sequence, event.event_type, deepcopy(event.payload))
    except (TypeError, ValueError, KeyError) as exc:
        raise ProgressJournalError(f"malformed progress event: {type(exc).__name__}") from None


def _event_equal(left: ProgressEvent, right: ProgressEvent) -> bool:
    return left.to_dict() == right.to_dict()


def _validate_fix_preconditions(events: list[ProgressEvent], fix_event: ProgressEvent) -> None:
    by_type = {event.event_type: event for event in events}
    required = (ProgressEventType.BASELINE_VALIDATED, ProgressEventType.REMEDIATION_VERIFIED, ProgressEventType.REPLAY_IDENTITY_VERIFIED, ProgressEventType.REPLAY_VALIDATED, ProgressEventType.CLEANUP_COMPLETED)
    if any(event_type not in by_type for event_type in required):
        raise ProgressEventOrderError("fix_verified requires the complete proven history")
    baseline = by_type[ProgressEventType.BASELINE_VALIDATED].payload
    remediation = by_type[ProgressEventType.REMEDIATION_VERIFIED].payload
    replay_identity = by_type[ProgressEventType.REPLAY_IDENTITY_VERIFIED].payload
    replay = by_type[ProgressEventType.REPLAY_VALIDATED].payload
    cleanup = by_type[ProgressEventType.CLEANUP_COMPLETED].payload
    if fix_event.payload != {"baseline_ledger_count": 1, "final_ledger_count": 1}:
        raise ProgressEventOrderError("fix_verified requires expected final ledger evidence")
    if baseline.get("decision") != "allowed" or baseline.get("ledger_count") != 1 or not baseline.get("event_id"):
        raise ProgressEventOrderError("fix_verified requires validated baseline evidence")
    if not remediation.get("policy_id") or remediation.get("policy_digest_before") == remediation.get("policy_digest_after"):
        raise ProgressEventOrderError("fix_verified requires verified remediation")
    if not replay_identity.get("fixture_sha256") or not replay_identity.get("action"):
        raise ProgressEventOrderError("fix_verified requires verified replay identity")
    if replay != {
        "decision": "blocked",
        "executed": True,
        "synthetic_event_id": None,
        "ledger_count": 1,
        "baseline_ledger_count": 1,
    }:
        raise ProgressEventOrderError("fix_verified requires verified replay no-impact evidence")
    if cleanup.get("cleanup_attempted") is not True:
        raise ProgressEventOrderError("fix_verified requires completed cleanup")


def _reduce(run_id: str, events: Iterable[ProgressEvent]) -> ProgressSnapshot | None:
    accepted = list(events)
    if not accepted:
        return None
    if accepted[0].event_type is not ProgressEventType.ASSESSMENT_STARTED:
        raise ProgressEventOrderError("run must start with assessment_started")
    evidence: dict[str, dict[str, Any]] = {}
    previous_success_index = -1
    cleanup_event: ProgressEventType | None = None
    terminal = False
    state = ""
    for position, event in enumerate(accepted):
        if event.run_id != run_id:
            raise ProgressJournalError("event belongs to another run")
        event_type = event.event_type
        if terminal:
            raise ProgressEventOrderError("terminal state cannot be advanced")
        if event_type in _SUCCESS_ORDER:
            index = _SUCCESS_ORDER.index(event_type)
            if event_type is ProgressEventType.CLEANUP_COMPLETED:
                if cleanup_event is not None or previous_success_index < 0:
                    raise ProgressEventOrderError("cleanup_completed is out of order")
            elif index != previous_success_index + 1:
                raise ProgressEventOrderError("success event ordering is invalid")
            if event_type is ProgressEventType.FIX_VERIFIED:
                _validate_fix_preconditions(accepted[:position], event)
            previous_success_index = index
            if event_type is ProgressEventType.CLEANUP_COMPLETED:
                cleanup_event = event_type
            state = event_type.value
            if event_type is ProgressEventType.FIX_VERIFIED:
                terminal = True
        elif event_type is ProgressEventType.CLEANUP_FAILED:
            if previous_success_index >= _SUCCESS_ORDER.index(ProgressEventType.CLEANUP_COMPLETED):
                raise ProgressEventOrderError("cleanup_failed cannot follow cleanup_completed")
            cleanup_event = event_type
            state = event_type.value
        elif event_type in (ProgressEventType.ASSESSMENT_PARTIAL, ProgressEventType.ASSESSMENT_FAILED):
            if cleanup_event is None:
                raise ProgressEventOrderError("terminal assessment event requires cleanup outcome")
            terminal = True
            state = event_type.value
        else:
            raise ProgressJournalError("unknown progress event type")
        evidence[event_type.value] = deepcopy(event.payload)
    return ProgressSnapshot(run_id, accepted[-1].sequence, state, terminal, evidence)


class ProgressJournal:
    """Append-only, per-run event storage with replay-derived snapshots."""

    def __init__(self) -> None:
        self._events: dict[str, list[ProgressEvent]] = {}

    def append(self, event: ProgressEvent) -> ProgressSnapshot:
        canonical = _canonical_event(event)
        run_events = self._events.setdefault(canonical.run_id, [])
        expected = len(run_events) + 1
        if canonical.sequence < expected:
            if canonical.sequence <= len(run_events) and _event_equal(run_events[canonical.sequence - 1], canonical):
                return self.get_latest_snapshot(canonical.run_id)  # type: ignore[return-value]
            if canonical.sequence <= len(run_events):
                raise ProgressEventConflictError("sequence already contains different event content")
            raise ProgressEventStaleError("event sequence is stale")
        if canonical.sequence > expected:
            raise ProgressEventGapError(f"expected sequence {expected}, received {canonical.sequence}")
        candidate = run_events + [canonical]
        snapshot = _reduce(canonical.run_id, candidate)
        if snapshot is None:
            raise ProgressJournalError("event did not produce a snapshot")
        run_events.append(canonical)
        return snapshot

    def get_events(self, run_id: str) -> tuple[ProgressEvent, ...]:
        return tuple(_canonical_event(event) for event in self._events.get(run_id, ()))

    def get_events_after(self, run_id: str, sequence: int) -> tuple[ProgressEvent, ...]:
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ValueError("sequence must be a non-negative integer")
        return tuple(_canonical_event(event) for event in self._events.get(run_id, ())[sequence:])

    def get_latest_snapshot(self, run_id: str) -> ProgressSnapshot | None:
        return _reduce(run_id, self._events.get(run_id, ()))
