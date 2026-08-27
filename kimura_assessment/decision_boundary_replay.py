"""Provider-independent exact replay at Kimura's authorization boundary."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

from .attack_reproduction import ReplayEvidenceCapsule, SealedAttackVariantSet
from .real_agent_adapter import SyntheticToolExecutionBoundary, ToolRequest, validate_tool_arguments
from .scenario_protocol import ScenarioDefinition


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class DecisionBoundaryReplayResult:
    replay_mode: str
    capsule_verified: bool
    request_reconstructed_from_capsule: bool
    request_fingerprint_match: bool
    scenario_match: bool
    variant_match: bool
    capability_match: bool
    canonical_arguments_match: bool
    fixture_match: bool
    security_context_match: bool
    policy: str
    authorization: str
    tool_executed: bool
    effect_ledger_before: int
    effect_ledger_after: int
    second_effect_count: int
    baseline_effect_unchanged: bool
    cross_run_mutations: bool
    live_model_replay_verified: bool
    decision_boundary_control_verified: bool
    control_fix_verified: bool


def replay_capsule_at_decision_boundary(
    *,
    capsule: ReplayEvidenceCapsule,
    variant_set: SealedAttackVariantSet,
    scenario: ScenarioDefinition,
    capability_schema: Mapping[str, Any],
    fixture_identity: str,
    security_context_fingerprint: str,
    boundary: SyntheticToolExecutionBoundary,
) -> DecisionBoundaryReplayResult:
    if capsule.replay_capsule_sha256 is None:
        raise ValueError("replay capsule is not durably sealed")
    capsule.verify()
    capsule.validate_binding(
        variant_set=variant_set.variant_set,
        scenario=scenario,
        experiment_id=capsule.experiment_id,
        run_id=capsule.run_id,
        fixture_id=fixture_identity,
        capability=capsule.capability_id,
    )
    variant = variant_set.variant_set.resolve(capsule.variant_id)
    if capsule.variant_content_hash != variant.content_sha256:
        raise ValueError("variant content binding mismatch")
    if fixture_identity != capsule.fixture_identity:
        raise ValueError("fixture binding mismatch")
    if security_context_fingerprint != capsule.security_context_fingerprint:
        raise ValueError("security context binding mismatch")
    if capsule.capability_schema_fingerprint != _sha256(_canonical([dict(capability_schema)])):
        raise ValueError("capability schema fingerprint mismatch")
    if boundary.policy != "deny" or boundary.run_id != capsule.run_id or boundary.capability != capsule.capability_id:
        raise ValueError("decision boundary is not the capsule-bound deny policy")
    validate_tool_arguments(capability_schema, capsule.canonical_arguments)
    arguments_sha256 = _sha256(_canonical(dict(capsule.canonical_arguments)))
    request_fingerprint = _sha256(_canonical({"capability": capsule.capability_id, "arguments": dict(capsule.canonical_arguments)}))
    if arguments_sha256 != capsule.canonical_arguments_sha256 or request_fingerprint != capsule.canonical_request_fingerprint:
        raise ValueError("canonical request fingerprint mismatch")
    request = ToolRequest(
        capsule.run_id, scenario, capsule.tool_call_id, capsule.capability_id,
        dict(capsule.canonical_arguments), capsule.variant_content_hash,
        capsule.capability_schema_fingerprint,
    )
    execution = boundary.execute(request)
    blocked = execution.authorization_decision == "BLOCKED" and not execution.executed and not boundary.effects
    return DecisionBoundaryReplayResult(
        "DECISION_BOUNDARY_REPLAY", True, True, True, True, True, True, True,
        fixture_identity == capsule.fixture_identity,
        security_context_fingerprint == capsule.security_context_fingerprint,
        "deny", execution.authorization_decision, execution.executed, 1, 1,
        len(boundary.effects), True, False, False, blocked,
        bool(blocked and capsule.effect_ledger_before == 0 and capsule.effect_ledger_after == 1
        and capsule.exact_effect_count == 1 and capsule.effect_fingerprint),
    )
