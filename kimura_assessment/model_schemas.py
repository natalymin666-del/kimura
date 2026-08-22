"""Safe data contracts for the local model-backed adapter."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any


class ModelValidationError(ValueError):
    """Raised when untrusted model data is malformed."""


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DECISIONS = {"allowed", "blocked", "malformed"}
_OUTCOMES = {"executed", "not_executed", "not_attempted", "error"}


def safe_digest(value: str) -> str:
    if not isinstance(value, str):
        raise ModelValidationError("digest input must be text")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _id(value: str, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ModelValidationError(f"{field} must be a safe identifier")
    return value


@dataclass(frozen=True, slots=True)
class ToolDescription:
    name: str
    description: str
    argument_schema_id: str

    def __post_init__(self) -> None:
        _id(self.name, "tool name")
        _id(self.argument_schema_id, "argument_schema_id")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ModelValidationError("tool description must be non-empty")


@dataclass(frozen=True, slots=True)
class ProposedAction:
    action_name: str
    argument_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.action_name, "action_name")
        if not isinstance(self.argument_keys, tuple) or any(not isinstance(item, str) for item in self.argument_keys):
            raise ModelValidationError("argument_keys must be a tuple of strings")


@dataclass(frozen=True, slots=True)
class ModelSettings:
    model_id: str
    temperature: float = 0.0
    top_p: float | None = None
    seed: int | None = None
    timeout_seconds: float = 30.0
    max_output_tokens: int = 256

    def __post_init__(self) -> None:
        _id(self.model_id, "model_id")
        if not 0.0 <= self.temperature <= 2.0:
            raise ModelValidationError("temperature must be between 0 and 2")
        if self.top_p is not None and not 0.0 < self.top_p <= 1.0:
            raise ModelValidationError("top_p must be between 0 and 1")
        if self.seed is not None and (isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0):
            raise ModelValidationError("seed must be a non-negative integer")
        if self.timeout_seconds <= 0 or self.max_output_tokens <= 0:
            raise ModelValidationError("model timeout and output limit must be positive")


@dataclass(frozen=True, slots=True)
class ModelRequest:
    system_instruction: str
    user_task: str
    retrieved_content: str
    tools: tuple[ToolDescription, ...]
    settings: ModelSettings
    correlation_id: str

    def __post_init__(self) -> None:
        for field in ("system_instruction", "user_task", "retrieved_content"):
            if not isinstance(getattr(self, field), str):
                raise ModelValidationError(f"{field} must be text")
        if not self.tools:
            raise ModelValidationError("at least one synthetic tool description is required")
        _id(self.correlation_id, "correlation_id")


@dataclass(frozen=True, slots=True)
class ModelResponse:
    provider_id: str
    model_id: str
    proposed_action: ProposedAction | None
    proposal_status: str
    finish_reason: str
    response_sha256: str
    response_length: int
    latency_ms: int

    def __post_init__(self) -> None:
        _id(self.provider_id, "provider_id")
        _id(self.model_id, "model_id")
        if not isinstance(self.proposal_status, str) or not self.proposal_status.strip():
            raise ModelValidationError("proposal_status must be non-empty")
        if not isinstance(self.finish_reason, str) or not self.finish_reason.strip():
            raise ModelValidationError("finish_reason must be non-empty")
        if not _DIGEST.fullmatch(self.response_sha256):
            raise ModelValidationError("response_sha256 must be a SHA-256 digest")
        if self.response_length < 0 or self.latency_ms < 0:
            raise ModelValidationError("response length and latency must be non-negative")


@dataclass(frozen=True, slots=True)
class GateDecision:
    attempted: bool
    action_name: str
    decision: str
    policy_id: str
    reason_code: str

    def __post_init__(self) -> None:
        _id(self.action_name, "action_name")
        _id(self.policy_id, "policy_id")
        _id(self.reason_code, "reason_code")
        if self.decision not in _DECISIONS:
            raise ModelValidationError("unsupported gate decision")


@dataclass(frozen=True, slots=True)
class TrialConfig:
    trial_id: str
    seed: int

    def __post_init__(self) -> None:
        _id(self.trial_id, "trial_id")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ModelValidationError("trial seed must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class AgentTrialResult:
    schema_version: int
    trial_id: str
    fixture_id: str
    fixture_sha256: str
    provider_id: str
    model_id: str
    settings_sha256: str
    proposed_action: str | None
    proposal_status: str
    gate_decision: str
    gate_policy_id: str
    synthetic_execution: str
    validated_impact: bool
    audit_event_id: str | None
    provider_response_sha256: str
    provider_response_length: int
    error_class: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ModelValidationError("schema_version must be 1")
        for field in ("trial_id", "fixture_id", "provider_id", "model_id", "proposal_status", "gate_decision", "gate_policy_id", "synthetic_execution"):
            _id(getattr(self, field), field)
        for field in ("fixture_sha256", "settings_sha256", "provider_response_sha256"):
            if not _DIGEST.fullmatch(getattr(self, field)):
                raise ModelValidationError(f"{field} must be a SHA-256 digest")
        if self.proposed_action is not None:
            _id(self.proposed_action, "proposed_action")
        if self.audit_event_id is not None:
            _id(self.audit_event_id, "audit_event_id")
        if self.synthetic_execution not in _OUTCOMES:
            raise ModelValidationError("unsupported synthetic execution outcome")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True, slots=True)
class TrialAggregate:
    trial_count: int
    proposal_count: int
    gate_allowed_count: int
    execution_count: int
    validated_impact_count: int
    outcome: str

    def __post_init__(self) -> None:
        if self.trial_count <= 0:
            raise ModelValidationError("trial_count must be positive")
        values = (self.proposal_count, self.gate_allowed_count, self.execution_count, self.validated_impact_count)
        if any(value < 0 or value > self.trial_count for value in values):
            raise ModelValidationError("trial counts must be within trial_count")
        _id(self.outcome, "outcome")

    @property
    def validated_impact_rate(self) -> float:
        return self.validated_impact_count / self.trial_count

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "validated_impact_rate": self.validated_impact_rate}
