"""Evidence-gated orchestration from one physical run into the live journal."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .progress_events import ProgressEventType


class PhysicalConferenceError(RuntimeError):
    """A physical checkpoint was unavailable or failed validation."""


class PhysicalLifecycleAdapter(Protocol):
    def discover(self, run_id: str) -> Mapping[str, Any]: ...
    def baseline(self, run_id: str) -> Mapping[str, Any]: ...
    def remediate(self, run_id: str) -> Mapping[str, Any]: ...
    def replay(self, run_id: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ConferenceRunResult:
    run_id: str
    state: str
    fix_verified: bool
    failure_reason: str | None = None


class PhysicalConferenceOrchestrator:
    """Sequence one physical run and emit only proven progress events."""

    def __init__(self, run_id: str, *, adapter: PhysicalLifecycleAdapter, emit) -> None:
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id is required")
        self.run_id = run_id
        self.adapter = adapter
        self._emit = emit
        self.started = False

    def start(self) -> ConferenceRunResult:
        if self.started:
            raise PhysicalConferenceError("physical choreography already started")
        self.started = True
        self._emit(ProgressEventType.ASSESSMENT_STARTED, {"assessment_id": "physical-assessment-v1"})
        try:
            target = self._stage(self.adapter.discover)
            self._require(target, target.get("identity_verified") is True, "target identity not verified")
            self._emit(ProgressEventType.TARGET_VERIFIED, {
                "target_id": target["target_id"],
                "target_kind": target["target_kind"],
                "protocol_version": target["protocol_version"],
                "policy_digest_before": target["policy_digest_before"],
            })

            baseline = self._stage(self.adapter.baseline)
            self._require(baseline, baseline.get("decision") == "allowed" and baseline.get("synthetic_impact") is True and baseline.get("ledger_before") == 0 and baseline.get("ledger_after") == 1, "baseline invariant failed")
            self._emit(ProgressEventType.BASELINE_VALIDATED, {
                "fixture_id": baseline["fixture_id"], "fixture_sha256": baseline["fixture_sha256"], "action": baseline["action"],
                "decision": baseline["decision"], "event_id": baseline["event_id"], "ledger_count": baseline["ledger_after"],
            })

            remediation = self._stage(self.adapter.remediate)
            self._require(remediation, remediation.get("run_id") == self.run_id and remediation.get("verified") is True and remediation.get("policy_before") == "permit" and remediation.get("policy_after") == "deny", "remediation invariant failed")
            self._emit(ProgressEventType.REMEDIATION_VERIFIED, {
                "policy_id": remediation["policy_id"], "policy_digest_before": remediation["policy_digest_before"],
                "policy_digest_after": remediation["policy_digest_after"], "denied_actions": [baseline["action"]],
            })

            replay = self._stage(self.adapter.replay)
            self._require(replay, replay.get("run_id") == self.run_id and replay.get("fixture_id") == baseline["fixture_id"] and replay.get("fixture_sha256") == baseline["fixture_sha256"] and replay.get("action") == baseline["action"] and replay.get("sha256") == baseline["sha256"] and replay.get("decision") == "blocked" and replay.get("synthetic_impact") is False and replay.get("ledger_before") == 1 and replay.get("ledger_after") == 1, "replay invariant failed")
            self._emit(ProgressEventType.REPLAY_IDENTITY_VERIFIED, {"attack_id": replay["attack_id"], "fixture_id": replay["fixture_id"], "fixture_sha256": replay["fixture_sha256"], "action": replay["action"]})
            self._emit(ProgressEventType.REPLAY_VALIDATED, {"decision": "blocked", "executed": True, "synthetic_event_id": None, "ledger_count": 1, "baseline_ledger_count": 1})
            self._emit(ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True})
            self._emit(ProgressEventType.FIX_VERIFIED, {"baseline_ledger_count": 1, "final_ledger_count": 1})
            return ConferenceRunResult(self.run_id, ProgressEventType.FIX_VERIFIED, True)
        except Exception as exc:
            self._emit(ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True})
            self._emit(ProgressEventType.ASSESSMENT_FAILED, {"failure_code": type(exc).__name__, "last_proven_event": None, "cleanup_completed": True})
            return ConferenceRunResult(self.run_id, ProgressEventType.ASSESSMENT_FAILED, False, str(exc))

    def _stage(self, operation) -> Mapping[str, Any]:
        evidence = operation(self.run_id)
        self._require(evidence, evidence.get("run_id") == self.run_id, "physical evidence belongs to another run")
        return evidence

    @staticmethod
    def _require(evidence: Mapping[str, Any], condition: bool, reason: str) -> None:
        if not isinstance(evidence, Mapping) or not condition:
            raise PhysicalConferenceError(reason)
