"""Generic, provider-neutral independent evidence observer V1.

This module consumes machine-captured structured artifacts.  It has no
transport, request, credential, or target-specific execution
capability.  It deliberately stops at observation statuses; higher-level
boundary verdicts remain in :mod:`boundary_proof`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Mapping

from .boundary_proof import canonical_json, sha256


_DIGEST_LENGTH = 64
_REQUIRED_BINDINGS = (
    "assessment_id", "run_id", "pair_fingerprint", "request_fingerprint",
    "actor_fingerprint", "target_fingerprint", "resource_fingerprint",
)


class ObservationStatus(str, Enum):
    ACCESS_PERMITTED_OBSERVED = "ACCESS_PERMITTED_OBSERVED"
    ACCESS_DENIED_OBSERVED = "ACCESS_DENIED_OBSERVED"
    STATE_CHANGE_CONFIRMED = "STATE_CHANGE_CONFIRMED"
    NO_STATE_CHANGE_CONFIRMED = "NO_STATE_CHANGE_CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != _DIGEST_LENGTH or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    canonical_json(dict(value))
    return dict(value)


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("observation_timestamp must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observation_timestamp is malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError("observation_timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _validate_bindings(bindings: Mapping[str, Any], context: "ObservationContext") -> None:
    values = _mapping(bindings, "evidence_bindings")
    if set(values) != set(_REQUIRED_BINDINGS):
        raise ValueError("evidence bindings are incomplete or contain unexpected fields")
    for name in _REQUIRED_BINDINGS:
        expected = getattr(context, name)
        actual = values[name]
        if name in {"pair_fingerprint", "request_fingerprint", "actor_fingerprint", "target_fingerprint", "resource_fingerprint"}:
            _digest(actual, name)
        if actual != expected:
            raise ValueError(f"evidence binding mismatch: {name}")


def _validate_provenance(provenance: Mapping[str, Any]) -> str:
    values = _mapping(provenance, "capture_provenance")
    capture_id = values.get("capture_id")
    if not isinstance(capture_id, str) or not capture_id:
        raise ValueError("capture provenance requires a capture_id")
    if not isinstance(values.get("captured_by"), str) or not values["captured_by"]:
        raise ValueError("capture provenance requires captured_by")
    if not isinstance(values.get("capture_method"), str) or not values["capture_method"]:
        raise ValueError("capture provenance requires capture_method")
    return capture_id


@dataclass(frozen=True, slots=True)
class ObservationContext:
    assessment_id: str
    run_id: str
    pair_fingerprint: str
    request_fingerprint: str
    actor_fingerprint: str
    target_fingerprint: str
    resource_fingerprint: str
    observation_timestamp: str
    source_type: str

    def __post_init__(self) -> None:
        if not isinstance(self.assessment_id, str) or not self.assessment_id:
            raise ValueError("assessment_id is required")
        if not isinstance(self.run_id, str) or not self.run_id:
            raise ValueError("run_id is required")
        for name in _REQUIRED_BINDINGS[2:]:
            _digest(getattr(self, name), name)
        _timestamp(self.observation_timestamp)
        if self.source_type not in {"KIMURA_CAPTURED", "HUMAN_OBSERVED"}:
            raise ValueError("unsupported source_type")

    @property
    def bindings(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in _REQUIRED_BINDINGS}

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id, "run_id": self.run_id,
            "pair_fingerprint": self.pair_fingerprint,
            "request_fingerprint": self.request_fingerprint,
            "actor_fingerprint": self.actor_fingerprint,
            "target_fingerprint": self.target_fingerprint,
            "resource_fingerprint": self.resource_fingerprint,
            "observation_timestamp": self.observation_timestamp,
            "source_type": self.source_type,
        }


@dataclass(frozen=True, slots=True)
class CapturedResponse:
    status_code: int | None
    normalized_headers_metadata: Mapping[str, Any]
    body_content_digest: str | None
    structured_response_fields: Mapping[str, Any]
    capture_provenance: Mapping[str, Any]
    evidence_bindings: Mapping[str, Any]
    protected_content_digest: str | None = None
    denial_evidence: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.status_code is not None and (isinstance(self.status_code, bool) or not isinstance(self.status_code, int) or not 100 <= self.status_code <= 599):
            raise ValueError("status_code is malformed")
        _mapping(self.normalized_headers_metadata, "normalized_headers_metadata")
        _mapping(self.structured_response_fields, "structured_response_fields")
        if self.body_content_digest is not None:
            _digest(self.body_content_digest, "body_content_digest")
        if self.protected_content_digest is not None:
            _digest(self.protected_content_digest, "protected_content_digest")
        if self.denial_evidence is not None:
            _mapping(self.denial_evidence, "denial_evidence")
        _validate_provenance(self.capture_provenance)

    @property
    def capture_id(self) -> str:
        return _validate_provenance(self.capture_provenance)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "normalized_headers_metadata": dict(self.normalized_headers_metadata),
            "body_content_digest": self.body_content_digest,
            "structured_response_fields": dict(self.structured_response_fields),
            "capture_provenance": dict(self.capture_provenance),
            "evidence_bindings": dict(self.evidence_bindings),
            "protected_content_digest": self.protected_content_digest,
            "denial_evidence": dict(self.denial_evidence or {}),
        }


@dataclass(frozen=True, slots=True)
class StateSnapshot:
    resource_identity: str
    canonical_state_representation: Mapping[str, Any]
    state_digest: str
    capture_provenance: Mapping[str, Any]
    evidence_bindings: Mapping[str, Any]

    def __post_init__(self) -> None:
        _digest(self.resource_identity, "resource_identity")
        state = _mapping(self.canonical_state_representation, "canonical_state_representation")
        if self.state_digest != sha256(state):
            raise ValueError("state_digest does not match canonical state")
        _validate_provenance(self.capture_provenance)

    @property
    def capture_id(self) -> str:
        return _validate_provenance(self.capture_provenance)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_identity": self.resource_identity,
            "canonical_state_representation": dict(self.canonical_state_representation),
            "state_digest": self.state_digest,
            "capture_provenance": dict(self.capture_provenance),
            "evidence_bindings": dict(self.evidence_bindings),
        }


def _canonical_diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    keys = sorted(set(before) | set(after))
    return {key: {"before": before.get(key), "after": after.get(key)}
            for key in keys if before.get(key) != after.get(key)}


@dataclass(frozen=True, slots=True)
class ObservedEffect:
    before_digest: str
    after_digest: str
    changed: bool
    canonical_diff: Mapping[str, Any]
    effect_fingerprint: str

    def __post_init__(self) -> None:
        _digest(self.before_digest, "before_digest")
        _digest(self.after_digest, "after_digest")
        diff = _mapping(self.canonical_diff, "canonical_diff")
        if self.changed != (self.before_digest != self.after_digest) or self.changed != bool(diff):
            raise ValueError("effect change flags do not match evidence")
        expected = sha256({"before_digest": self.before_digest, "after_digest": self.after_digest, "changed": self.changed, "canonical_diff": diff})
        if self.effect_fingerprint != expected:
            raise ValueError("effect_fingerprint does not match effect")

    @classmethod
    def from_snapshots(cls, before: StateSnapshot, after: StateSnapshot) -> "ObservedEffect":
        diff = _canonical_diff(before.canonical_state_representation, after.canonical_state_representation)
        changed = before.state_digest != after.state_digest
        unsigned = {"before_digest": before.state_digest, "after_digest": after.state_digest, "changed": changed, "canonical_diff": diff}
        return cls(before.state_digest, after.state_digest, changed, diff, sha256(unsigned))

    def to_dict(self) -> dict[str, Any]:
        return {"before_digest": self.before_digest, "after_digest": self.after_digest,
                "changed": self.changed, "canonical_diff": dict(self.canonical_diff),
                "effect_fingerprint": self.effect_fingerprint}


@dataclass(frozen=True, slots=True)
class IndependentObservation:
    context: ObservationContext
    response_evidence: CapturedResponse | None
    before_state: StateSnapshot | None
    after_state: StateSnapshot | None
    effect: ObservedEffect | None
    evidence_bindings: Mapping[str, Any]
    confidence: str
    final_observation_status: ObservationStatus
    observation_digest: str

    def __post_init__(self) -> None:
        _validate_bindings(self.evidence_bindings, self.context)
        if self.confidence != "DETERMINISTIC_RULES_ONLY":
            raise ValueError("confidence must be deterministic and non-model-generated")
        if self.final_observation_status in {ObservationStatus.STATE_CHANGE_CONFIRMED, ObservationStatus.NO_STATE_CHANGE_CONFIRMED} and self.effect is None:
            raise ValueError("state status requires effect evidence")
        if not isinstance(self.observation_digest, str) or len(self.observation_digest) != _DIGEST_LENGTH:
            raise ValueError("observation_digest is malformed")

    def to_unsigned(self) -> dict[str, Any]:
        return {
            "context": self.context.to_dict(),
            "response_evidence": self.response_evidence.to_dict() if self.response_evidence else None,
            "before_state": self.before_state.to_dict() if self.before_state else None,
            "after_state": self.after_state.to_dict() if self.after_state else None,
            "effect": self.effect.to_dict() if self.effect else None,
            "evidence_bindings": dict(self.evidence_bindings),
            "confidence": self.confidence,
            "final_observation_status": self.final_observation_status.value,
        }

    def verify(self) -> None:
        if self.observation_digest != sha256(self.to_unsigned()):
            raise ValueError("observation_digest mismatch")

    def to_dict(self) -> dict[str, Any]:
        result = self.to_unsigned()
        result["observation_digest"] = self.observation_digest
        return result


class EvidenceObserverV1:
    """Deterministic observer for supplied evidence; never a network client."""

    VERSION = "observer-v1"

    def __init__(self, *, now: Callable[[], datetime] | None = None, max_age: timedelta = timedelta(minutes=15)):
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._max_age = max_age
        self._seen_capture_ids: set[str] = set()

    def _validate_context(self, context: ObservationContext) -> None:
        if context.source_type != "KIMURA_CAPTURED":
            raise ValueError("evidence is not independently captured")
        observed = _timestamp(context.observation_timestamp)
        now = self._now().astimezone(timezone.utc)
        if observed > now or now - observed > self._max_age:
            raise ValueError("stale or future evidence")

    def _claim(self, *evidence: CapturedResponse | StateSnapshot) -> None:
        ids = [item.capture_id for item in evidence]
        if len(ids) != len(set(ids)) or any(item in self._seen_capture_ids for item in ids):
            raise ValueError("duplicate or replayed evidence")
        self._seen_capture_ids.update(ids)

    def _response(self, context: ObservationContext, response: CapturedResponse) -> None:
        _validate_bindings(response.evidence_bindings, context)
        _validate_provenance(response.capture_provenance)

    def _snapshot(self, context: ObservationContext, snapshot: StateSnapshot) -> None:
        _validate_bindings(snapshot.evidence_bindings, context)
        if snapshot.resource_identity != context.resource_fingerprint:
            raise ValueError("state resource identity mismatch")
        _validate_provenance(snapshot.capture_provenance)

    def _build(self, context, response, before, after, effect, status) -> IndependentObservation:
        bindings = context.bindings
        unsigned = {
            "context": context.to_dict(),
            "response_evidence": response.to_dict() if response else None,
            "before_state": before.to_dict() if before else None,
            "after_state": after.to_dict() if after else None,
            "effect": effect.to_dict() if effect else None,
            "evidence_bindings": bindings,
            "confidence": "DETERMINISTIC_RULES_ONLY",
            "final_observation_status": status.value,
        }
        return IndependentObservation(context, response, before, after, effect, bindings,
                                      "DETERMINISTIC_RULES_ONLY", status, sha256(unsigned))

    def observe_access(self, context: ObservationContext, response: CapturedResponse) -> IndependentObservation:
        self._validate_context(context)
        self._response(context, response)
        self._claim(response)
        fields = response.structured_response_fields
        redirect_target = response.normalized_headers_metadata.get("redirect_target_fingerprint")
        if redirect_target is not None and redirect_target != context.target_fingerprint:
            return self._build(context, response, None, None, None, ObservationStatus.INCONCLUSIVE)
        resource_matches = fields.get("resource_fingerprint") == context.resource_fingerprint
        protected = response.protected_content_digest is not None and resource_matches
        denied = (response.status_code in {401, 403}
                  and isinstance(response.denial_evidence, Mapping)
                  and bool(response.denial_evidence.get("explicit_denial")))
        if protected and response.status_code in {401, 403}:
            status = ObservationStatus.INCONCLUSIVE
        elif protected:
            status = ObservationStatus.ACCESS_PERMITTED_OBSERVED
        elif denied and response.protected_content_digest is None:
            status = ObservationStatus.ACCESS_DENIED_OBSERVED
        else:
            status = ObservationStatus.INCONCLUSIVE
        return self._build(context, response, None, None, None, status)

    def observe_state(self, context: ObservationContext, before: StateSnapshot, after: StateSnapshot) -> IndependentObservation:
        self._validate_context(context)
        self._snapshot(context, before)
        self._snapshot(context, after)
        self._claim(before, after)
        if before.resource_identity != after.resource_identity:
            raise ValueError("before/after resource identity mismatch")
        effect = ObservedEffect.from_snapshots(before, after)
        status = (ObservationStatus.STATE_CHANGE_CONFIRMED if effect.changed
                  else ObservationStatus.NO_STATE_CHANGE_CONFIRMED)
        return self._build(context, None, before, after, effect, status)


def observation_to_proof_capsule_fields(observation: IndependentObservation) -> dict[str, Any]:
    """Return safe fields for an existing Proof Capsule/evidence chain."""
    observation.verify()
    return {
        "observer_version": EvidenceObserverV1.VERSION,
        "observation_digest": observation.observation_digest,
        "input_evidence_digests": [
            sha256(item.to_dict()) for item in (observation.response_evidence, observation.before_state, observation.after_state) if item is not None
        ],
        "pair_fingerprint": observation.context.pair_fingerprint,
        "request_fingerprint": observation.context.request_fingerprint,
        "run_id": observation.context.run_id,
        "provenance": "KIMURA_INDEPENDENTLY_OBSERVED",
        "result": observation.final_observation_status.value,
    }
