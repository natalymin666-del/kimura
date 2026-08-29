"""Provider-neutral preparation contract for an authorized external lab.

Preparation models scope and API evidence only. No network transport, scanner,
credential loader, or external executor is provided here.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .boundary_proof import sha256


SECRET_TERMS = ("password", "token", "api_key", "secret", "credential", "private_key")


def _secret_present(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(k).lower() != "credentials_classification" and any(term in str(k).lower() for term in SECRET_TERMS) or _secret_present(v)
                   for k, v in value.items())
    if isinstance(value, (tuple, list)):
        return any(_secret_present(v) for v in value)
    return False


class ExternalGateStatus(str, Enum):
    AUTHORIZED = "AUTHORIZED_SCOPE_VERIFIED"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True, slots=True)
class ExternalLabAssessmentContract:
    lab_provider: str
    assigned_target: str
    authorization_scope: Mapping[str, Any]
    permitted_protocols_endpoints: tuple[Mapping[str, Any], ...]
    prohibited_targets: tuple[str, ...]
    start_conditions: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    containment_assumptions: tuple[str, ...]
    rate_limits: Mapping[str, Any]
    credentials_classification: str
    evidence_retention_redaction_rules: tuple[str, ...]
    authorized_scope_verified: bool = False
    contract_sha256: str | None = None

    def __post_init__(self) -> None:
        if not all((self.lab_provider, self.assigned_target, self.credentials_classification)):
            raise ValueError("external lab contract identity is incomplete")
        if not self.authorization_scope or not self.permitted_protocols_endpoints:
            raise ValueError("external lab authorization/scope is incomplete")
        if not self.prohibited_targets or not self.start_conditions or not self.stop_conditions:
            raise ValueError("external lab safety conditions are incomplete")
        if not self.containment_assumptions or not self.rate_limits or not self.evidence_retention_redaction_rules:
            raise ValueError("external lab controls are incomplete")
        if _secret_present(self.to_unsigned()):
            raise ValueError("external lab contract contains secret material")
        if self.contract_sha256 is not None and self.contract_sha256 != self.fingerprint:
            raise ValueError("external lab contract fingerprint mismatch")

    def to_unsigned(self) -> dict[str, Any]:
        return {
            "lab_provider": self.lab_provider, "assigned_target": self.assigned_target,
            "authorization_scope": dict(self.authorization_scope),
            "permitted_protocols_endpoints": [dict(x) for x in self.permitted_protocols_endpoints],
            "prohibited_targets": list(self.prohibited_targets),
            "start_conditions": list(self.start_conditions),
            "stop_conditions": list(self.stop_conditions),
            "containment_assumptions": list(self.containment_assumptions),
            "rate_limits": dict(self.rate_limits),
            "credentials_classification": self.credentials_classification,
            "evidence_retention_redaction_rules": list(self.evidence_retention_redaction_rules),
            "authorized_scope_verified": self.authorized_scope_verified,
        }

    @property
    def fingerprint(self) -> str:
        return sha256(self.to_unsigned())

    def verify(self) -> None:
        if self.contract_sha256 is not None and self.contract_sha256 != self.fingerprint:
            raise ValueError("external lab contract fingerprint mismatch")


@dataclass(frozen=True, slots=True)
class ExternalScopeGateResult:
    status: ExternalGateStatus
    reasons: tuple[str, ...]


def verify_external_scope(contract: ExternalLabAssessmentContract,
                          *, target: str, protocol: str, endpoint: str,
                          method: str | None = None, request_count: int = 0) -> ExternalScopeGateResult:
    reasons: list[str] = []
    try:
        contract.verify()
    except ValueError:
        reasons.append("CONTRACT_FINGERPRINT_MISMATCH")
    if not contract.authorized_scope_verified:
        reasons.append("AUTHORIZED_SCOPE_NOT_VERIFIED")
    if contract.contract_sha256 is None:
        reasons.append("CONTRACT_NOT_FINGERPRINT_BOUND")
    if target != contract.assigned_target:
        reasons.append("TARGET_OUTSIDE_DECLARED_SCOPE")
    if target in contract.prohibited_targets:
        reasons.append("PROHIBITED_TARGET")
    permitted = any(item.get("protocol") == protocol and item.get("endpoint") == endpoint
                    and (method is None or item.get("method", method) == method)
                    for item in contract.permitted_protocols_endpoints)
    if not permitted:
        reasons.append("PROTOCOL_OR_ENDPOINT_NOT_PERMITTED")
    max_requests = contract.rate_limits.get("max_requests")
    if isinstance(max_requests, int) and request_count >= max_requests:
        reasons.append("EXCESSIVE_REQUEST_RATE")
    if reasons:
        return ExternalScopeGateResult(ExternalGateStatus.PRECONDITION_FAILED, tuple(sorted(set(reasons))))
    return ExternalScopeGateResult(ExternalGateStatus.AUTHORIZED, ())


def external_kill_conditions(*, target_in_scope: bool, redirect_in_scope: bool,
                             hostname_expected: bool, authorization_unambiguous: bool,
                             within_rate_limit: bool, state_observable: bool,
                             provenance_verified: bool) -> tuple[str, ...]:
    checks = (
        ("TARGET_OUTSIDE_DECLARED_SCOPE", target_in_scope),
        ("REDIRECT_OUTSIDE_SCOPE", redirect_in_scope),
        ("UNEXPECTED_HOSTNAME_OR_IP", hostname_expected),
        ("AUTHORIZATION_AMBIGUOUS", authorization_unambiguous),
        ("EXCESSIVE_REQUEST_RATE", within_rate_limit),
        ("STATE_OR_EFFECT_UNAVAILABLE", state_observable),
        ("EVIDENCE_PROVENANCE_FAILURE", provenance_verified),
    )
    return tuple(name for name, passed in checks if not passed)


@dataclass(frozen=True, slots=True)
class ApiBoundaryAction:
    http_method: str
    endpoint: str
    authenticated_identity: Mapping[str, Any]
    authorization_context: Mapping[str, Any]
    object_resource_identity: Mapping[str, Any]
    canonical_query_parameters: Mapping[str, Any]
    canonical_request_body: Mapping[str, Any]
    expected_permitted_action: Mapping[str, Any]
    forbidden_paired_action: Mapping[str, Any]
    response_metadata: Mapping[str, Any]
    observable_state_effect: Mapping[str, Any]
    action_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.http_method not in {"GET", "POST", "PUT", "PATCH", "DELETE"} or not self.endpoint:
            raise ValueError("API action identity is incomplete")
        if not self.authenticated_identity or not self.object_resource_identity:
            raise ValueError("API identity/resource binding is incomplete")
        if not self.expected_permitted_action or not self.forbidden_paired_action:
            raise ValueError("API action pair is incomplete")
        if not self.observable_state_effect:
            raise ValueError("API observable effect is required")
        if self.action_sha256 is not None and self.action_sha256 != self.fingerprint:
            raise ValueError("API action fingerprint mismatch")

    def to_unsigned(self) -> dict[str, Any]:
        return {
            "http_method": self.http_method, "endpoint": self.endpoint,
            "authenticated_identity": dict(self.authenticated_identity),
            "authorization_context": dict(self.authorization_context),
            "object_resource_identity": dict(self.object_resource_identity),
            "canonical_query_parameters": dict(self.canonical_query_parameters),
            "canonical_request_body": dict(self.canonical_request_body),
            "expected_permitted_action": dict(self.expected_permitted_action),
            "forbidden_paired_action": dict(self.forbidden_paired_action),
            "response_metadata": dict(self.response_metadata),
            "observable_state_effect": dict(self.observable_state_effect),
        }

    @property
    def fingerprint(self) -> str:
        return sha256(self.to_unsigned())


@dataclass(frozen=True, slots=True)
class ExternalEvidenceCapsule:
    lab_scope_fingerprint: str
    target_identity: str
    request: Mapping[str, Any]
    response: Mapping[str, Any]
    authorization_context: Mapping[str, Any]
    observable_effect: Mapping[str, Any]
    causal_provenance: Mapping[str, Any]
    independent_verdict: str
    run_identity: str
    capsule_sha256: str | None = None

    def __post_init__(self) -> None:
        if not self.lab_scope_fingerprint or not self.target_identity or not self.run_identity:
            raise ValueError("external evidence identity is incomplete")
        for value in (self.request, self.response, self.authorization_context,
                      self.observable_effect, self.causal_provenance):
            if not isinstance(value, Mapping):
                raise ValueError("external evidence field is malformed")
        if _secret_present(self.to_unsigned()):
            raise ValueError("external evidence contains secret material")
        if self.capsule_sha256 is not None and self.capsule_sha256 != self.fingerprint:
            raise ValueError("external evidence capsule fingerprint mismatch")

    def to_unsigned(self) -> dict[str, Any]:
        return {"lab_scope_fingerprint": self.lab_scope_fingerprint,
                "target_identity": self.target_identity, "request": dict(self.request),
                "response": dict(self.response), "authorization_context": dict(self.authorization_context),
                "observable_effect": dict(self.observable_effect),
                "causal_provenance": dict(self.causal_provenance),
                "independent_verdict": self.independent_verdict,
                "run_identity": self.run_identity}

    @property
    def fingerprint(self) -> str:
        return sha256(self.to_unsigned())

    def verify(self) -> None:
        if self.capsule_sha256 is not None and self.capsule_sha256 != self.fingerprint:
            raise ValueError("external evidence capsule fingerprint mismatch")


class ExternalTransport(Protocol):
    def send(self, action: ApiBoundaryAction, *, target: str) -> Mapping[str, Any]:
        ...


def execute_external_action(contract: ExternalLabAssessmentContract, action: ApiBoundaryAction,
                            transport: ExternalTransport, *, request_count: int = 0,
                            redirect_target: str | None = None,
                            authorization_unambiguous: bool = True,
                            state_observable: bool = True,
                            assessment_conditions_valid: bool = True) -> tuple[ExternalScopeGateResult, Mapping[str, Any] | None]:
    """Gate before transport; redirect identity is revalidated before any follow-up."""
    gate = verify_external_scope(contract, target=contract.assigned_target, protocol="https",
                                 endpoint=action.endpoint, method=action.http_method,
                                 request_count=request_count)
    if gate.status is not ExternalGateStatus.AUTHORIZED:
        return gate, None
    if not authorization_unambiguous:
        return ExternalScopeGateResult(ExternalGateStatus.PRECONDITION_FAILED, ("AUTHORIZATION_AMBIGUOUS",)), None
    if not state_observable:
        return ExternalScopeGateResult(ExternalGateStatus.PRECONDITION_FAILED, ("STATE_OR_EFFECT_UNAVAILABLE",)), None
    if not assessment_conditions_valid:
        return ExternalScopeGateResult(ExternalGateStatus.PRECONDITION_FAILED, ("ASSESSMENT_CONDITIONS_INVALID_OR_EXPIRED",)), None
    if redirect_target is not None and redirect_target != contract.assigned_target:
        return ExternalScopeGateResult(ExternalGateStatus.PRECONDITION_FAILED,
                                       ("REDIRECT_OUTSIDE_SCOPE",)), None
    return gate, transport.send(action, target=contract.assigned_target)


def validate_external_evidence(*, capsule: ExternalEvidenceCapsule,
                               contract: ExternalLabAssessmentContract,
                               action: ApiBoundaryAction, run_id: str,
                               response_target: str, state_observable: bool = True) -> bool:
    try:
        capsule.verify()
    except ValueError:
        return False
    if capsule.lab_scope_fingerprint != contract.fingerprint:
        return False
    if capsule.target_identity != response_target or response_target != contract.assigned_target:
        return False
    if capsule.run_identity != run_id or capsule.request != action.to_unsigned():
        return False
    if not state_observable or capsule.observable_effect.get("effect_count") is None:
        return False
    if capsule.causal_provenance.get("proven") is not True:
        return False
    return True


def discover_api_boundary_categories(action: ApiBoundaryAction) -> tuple[str, ...]:
    """Generation categories only; this function never assigns a verdict."""
    categories = []
    if action.object_resource_identity.get("owner"):
        categories.append("cross-object/cross-user authorization")
    if action.authorization_context.get("roles") or action.authorization_context.get("scopes"):
        categories.append("privilege/function boundary")
    if action.canonical_request_body:
        categories.append("mass-assignment/state mutation")
    return tuple(categories)


@dataclass(frozen=True, slots=True)
class MockApiLab:
    target: str = "mock-api-lab.local"
    state: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.state is None:
            object.__setattr__(self, "state", {"records": {"r-1": {"owner": "user-a", "status": "open"}}})

    def request(self, action: ApiBoundaryAction) -> Mapping[str, Any]:
        if action.http_method == "GET":
            return {"status": 200, "record": dict(self.state["records"][action.object_resource_identity["id"]])}
        return {"status": 200, "record": dict(self.state["records"][action.object_resource_identity["id"]])}
