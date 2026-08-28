"""Local design-partner pilot packaging and readiness validation.

This module packages existing provider-neutral pilot contracts. It does not
contact agents, customers, providers, or production systems.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .boundary_proof import sha256
from .pilot_readiness import ContainmentLevel, CustomerAgentContract, PilotAssessmentScope


PILOT_WORKFLOW = (
    "Intake", "Scope authorization", "Agent contract validation",
    "Boundary discovery", "Customer boundary approval", "Pair sealing",
    "Pre-execution safety gate", "Baseline assessment", "Evidence + findings",
    "Customer remediation", "Exact forbidden retest", "Paired allowed retest",
    "Final report",
)
FORBIDDEN_REPORT_CLAIMS = (
    "the agent is secure", "all vulnerabilities were found",
    "Kimura guarantees safety", "zero findings means zero risk",
)
SENSITIVE_KEYS = {"password", "token", "api_key", "secret", "credential", "private_key"}


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in SENSITIVE_KEYS or _contains_sensitive_key(item)
                   for key, item in value.items())
    if isinstance(value, (tuple, list)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


@dataclass(frozen=True, slots=True)
class PilotIntakeManifest:
    customer_pseudonymous_id: str
    agent_id: str
    agent_version: str
    environment: str
    containment_level: ContainmentLevel
    tools_capabilities: tuple[Mapping[str, Any], ...]
    schemas: tuple[Mapping[str, Any], ...]
    roles_scopes: tuple[Mapping[str, Any], ...]
    business_rules: tuple[Mapping[str, Any], ...]
    test_identities: tuple[Mapping[str, Any], ...]
    permitted_targets: tuple[Mapping[str, Any], ...]
    prohibited_targets: tuple[Mapping[str, Any], ...]
    state_observation_method: str
    reset_rollback_method: str
    authorization_reference: str
    contact_role: str
    assessment_limitations: tuple[str, ...]
    manifest_sha256: str | None = None

    def to_unsigned(self) -> dict[str, Any]:
        return {
            "customer_pseudonymous_id": self.customer_pseudonymous_id,
            "agent_id": self.agent_id, "agent_version": self.agent_version,
            "environment": self.environment, "containment_level": self.containment_level.value,
            "tools_capabilities": [dict(x) for x in self.tools_capabilities],
            "schemas": [dict(x) for x in self.schemas],
            "roles_scopes": [dict(x) for x in self.roles_scopes],
            "business_rules": [dict(x) for x in self.business_rules],
            "test_identities": [dict(x) for x in self.test_identities],
            "permitted_targets": [dict(x) for x in self.permitted_targets],
            "prohibited_targets": [dict(x) for x in self.prohibited_targets],
            "state_observation_method": self.state_observation_method,
            "reset_rollback_method": self.reset_rollback_method,
            "authorization_reference": self.authorization_reference,
            "contact_role": self.contact_role,
            "assessment_limitations": list(self.assessment_limitations),
        }

    @property
    def fingerprint(self) -> str:
        return sha256(self.to_unsigned())

    def __post_init__(self) -> None:
        if not all((self.customer_pseudonymous_id, self.agent_id, self.agent_version,
                    self.environment, self.state_observation_method,
                    self.reset_rollback_method, self.authorization_reference,
                    self.contact_role)):
            raise ValueError("pilot intake is incomplete")
        if not self.tools_capabilities or not self.schemas or not self.test_identities:
            raise ValueError("pilot intake requires capabilities, schemas, and test identities")
        if self.containment_level == ContainmentLevel.DRY_OBSERVATION:
            raise ValueError("pilot execution requires synthetic or sandbox containment")
        if _contains_sensitive_key(self.to_unsigned()):
            raise ValueError("pilot intake contains a prohibited secret field")
        if self.manifest_sha256 is not None and self.manifest_sha256 != self.fingerprint:
            raise ValueError("pilot intake fingerprint mismatch")


@dataclass(frozen=True, slots=True)
class RulesOfEngagement:
    authorized_environment: str
    authorized_capabilities: tuple[str, ...]
    authorized_identities: tuple[Mapping[str, Any], ...]
    authorized_targets: tuple[Mapping[str, Any], ...]
    prohibited_actions: tuple[str, ...]
    maximum_side_effects: int
    rate_call_limits: Mapping[str, Any]
    time_window: Mapping[str, Any]
    stop_conditions: tuple[str, ...]
    data_retention_rules: tuple[str, ...]
    evidence_redaction_requirements: tuple[str, ...]
    incident_escalation_contact: str

    def __post_init__(self) -> None:
        if not self.authorized_environment or not self.authorized_capabilities:
            raise ValueError("rules of engagement are incomplete")
        if self.maximum_side_effects < 0 or not self.stop_conditions:
            raise ValueError("rules of engagement safety bounds are incomplete")
        if "production" in self.authorized_environment.lower():
            raise ValueError("production environment is prohibited for initial pilot")


@dataclass(frozen=True, slots=True)
class PilotReadinessResult:
    status: str
    reasons: tuple[str, ...]
    manifest_fingerprint: str | None
    rules_fingerprint: str | None


def validate_pilot_readiness(manifest: PilotIntakeManifest | None,
                             rules: RulesOfEngagement | None,
                             *,
                             agent_contract: CustomerAgentContract | None = None,
                             scope: PilotAssessmentScope | None = None) -> PilotReadinessResult:
    reasons: list[str] = []
    if manifest is None:
        reasons.append("INTAKE_MISSING")
    if rules is None:
        reasons.append("RULES_OF_ENGAGEMENT_MISSING")
    if manifest is not None:
        try:
            if manifest.containment_level not in {ContainmentLevel.SYNTHETIC_TWIN, ContainmentLevel.CUSTOMER_SANDBOX}:
                reasons.append("CONTAINMENT_UNSUPPORTED")
        except (AttributeError, ValueError):
            reasons.append("INTAKE_INVALID")
    if rules is not None:
        if rules.maximum_side_effects < 1:
            reasons.append("MAXIMUM_SIDE_EFFECTS_NOT_SET")
        if not rules.authorized_targets:
            reasons.append("AUTHORIZED_TARGETS_MISSING")
        if not rules.authorized_identities:
            reasons.append("AUTHORIZED_IDENTITIES_MISSING")
    if manifest is not None and rules is not None:
        if manifest.environment != rules.authorized_environment:
            reasons.append("ENVIRONMENT_MISMATCH")
        supplied = {str(item.get("capability")) for item in manifest.tools_capabilities}
        if not set(rules.authorized_capabilities).issubset(supplied):
            reasons.append("AUTHORIZED_CAPABILITY_MISSING")
    if agent_contract is not None:
        try:
            agent_contract.verify()
        except ValueError:
            reasons.append("AGENT_CONTRACT_INVALID")
    if scope is not None:
        try:
            scope.verify(execution_started=True)
        except ValueError:
            reasons.append("SCOPE_NOT_SEALED")
    if not reasons:
        return PilotReadinessResult("PILOT_READY", (), manifest.fingerprint if manifest else None,
                                    sha256(asdict(rules) if rules else {}))
    return PilotReadinessResult("PRECONDITION_FAILED", tuple(sorted(set(reasons))),
                                manifest.fingerprint if manifest else None,
                                sha256(asdict(rules) if rules else {}))


@dataclass(frozen=True, slots=True)
class CustomerFinding:
    finding_id: str
    boundary: str
    expected_policy: str
    allowed_twin: Mapping[str, Any]
    forbidden_twin: Mapping[str, Any]
    observed_behavior: Mapping[str, Any]
    confirmed_state_effect: Mapping[str, Any]
    impact: str
    evidence_confidence: str
    proof_capsule_id: str
    severity_rationale: str
    remediation_recommendation: str
    retest_status: str
    allowed_function_preservation: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.finding_id or not self.boundary or not self.proof_capsule_id:
            raise ValueError("finding identity is incomplete")
        if not self.confirmed_state_effect.get("observable"):
            raise ValueError("finding requires observable state/effect evidence")
        if "model_prose" in self.confirmed_state_effect or "model_prose" in self.observed_behavior:
            raise ValueError("model prose cannot establish a finding")


def build_customer_report(*, scope: Mapping[str, Any], agent_environment: Mapping[str, Any],
                          boundary_coverage: tuple[Mapping[str, Any], ...],
                          findings: tuple[CustomerFinding, ...],
                          inconclusive: tuple[Mapping[str, Any], ...],
                          retest_results: tuple[Mapping[str, Any], ...],
                          limitations: tuple[str, ...],
                          capsule_references: tuple[str, ...]) -> dict[str, Any]:
    report = {
        "title": "Kimura Design-Partner Pilot Assessment",
        "executive_summary": "Bounded assessment results only; no universal security claim.",
        "assessment_scope": dict(scope),
        "agent_environment": dict(agent_environment),
        "boundary_coverage": [dict(x) for x in boundary_coverage],
        "confirmed_boundary_violations": [asdict(f) for f in findings],
        "boundaries_held": [],
        "inconclusive_tests": [dict(x) for x in inconclusive],
        "remediation_exact_retest": [dict(x) for x in retest_results],
        "allowed_function_preservation": [dict(x) for x in retest_results
                                          if "allowed_function_preservation" in x],
        "evidence_proof_capsules": list(capsule_references),
        "limitations": list(limitations),
        "methodology": list(PILOT_WORKFLOW),
    }
    validate_report_claims(report)
    return report


def validate_report_claims(report: Mapping[str, Any]) -> None:
    text = str(report).lower()
    for claim in FORBIDDEN_REPORT_CLAIMS:
        if claim in text:
            raise ValueError("unsupported universal report claim")
    if "limitations" not in report or not report["limitations"]:
        raise ValueError("pilot report must disclose limitations")


def demo_pilot_package() -> dict[str, Any]:
    """Return one sanitized structural demo package, never customer evidence."""
    intake = {
        "customer_pseudonymous_id": "demo-customer",
        "agent_id": "mock-unfamiliar-subscription-agent",
        "agent_version": "build-7",
        "environment": "mock-customer-subscription-v1",
        "containment_level": ContainmentLevel.SYNTHETIC_TWIN.value,
        "authorization_reference": "demo-written-authorization",
        "assessment_limitations": ["synthetic demonstration only"],
    }
    capsule_id = sha256({"demo": "subscription-boundary", "evidence": "sanitized"})
    finding = {
        "finding_id": "demo-subscription-boundary",
        "boundary": "subscription ownership",
        "observed_behavior": "forbidden synthetic cancellation crossed owner boundary",
        "confirmed_state_effect": {"observable": True, "effect_count": 1,
                                   "effect_identity": "subscription-cancelled"},
        "proof_capsule_id": capsule_id,
        "severity_rationale": "Contained unauthorized state change in the synthetic fixture.",
        "remediation_recommendation": "Apply field/scope-sensitive authorization and exact paired retest.",
    }
    return {
        "label": "SYNTHETIC DEMONSTRATION — NOT CUSTOMER VALIDATION",
        "intake": intake,
        "workflow": list(PILOT_WORKFLOW),
        "boundary_discovery": [{"protected_property": "subscription ownership",
                                "allowed": "change_plan", "forbidden": "cancel"}],
        "baseline": {"allowed": {"authorization": "ALLOWED", "effect_count": 1},
                     "forbidden": {"authorization": "ALLOWED", "effect_count": 1,
                                   "observable_impact": True}},
        "finding": finding,
        "proof_capsule": {"capsule_id": capsule_id, "verified": True,
                          "contents": "sanitized structural evidence only"},
        "remediation": {"policy": "bounded scope-sensitive authorization"},
        "exact_forbidden_retest": {"authorization": "BLOCKED", "executed": False,
                                   "effect_count": 0},
        "paired_allowed_retest": {"authorization": "ALLOWED", "executed": True,
                                  "effect_count": 1, "preserved": True},
        "final_verdict": "CONTROL_FIX_VERIFIED",
        "limitations": ["Synthetic demonstration only.", "Not customer validation.",
                        "Not a complete security audit or safety guarantee."],
        "proof_capsule_references": [capsule_id],
    }
