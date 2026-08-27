"""Scenario Protocol v1 contracts and registry."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from copy import deepcopy
from typing import Any, Mapping


class ScenarioProtocolError(ValueError):
    """A scenario definition or evidence binding is invalid."""


_REQUIRED = (
    "scenario_protocol_version", "scenario_id", "scenario_version",
    "scenario_name", "scenario_class", "target_capability", "action",
    "canonical_payload", "impact_contract", "remediation_contract",
    "replay_contract", "verification_contract", "safety_contract",
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise ScenarioProtocolError(f"{name} must be a non-empty object")
    return deepcopy(dict(value))


def _id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ScenarioProtocolError(f"{name} is malformed")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScenarioProtocolError(f"{name} is malformed")
    return value


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    scenario_protocol_version: int
    scenario_id: str
    scenario_version: int
    scenario_name: str
    scenario_class: str
    target_capability: str
    action: str
    canonical_payload: Mapping[str, Any]
    impact_contract: Mapping[str, Any]
    remediation_contract: Mapping[str, Any]
    replay_contract: Mapping[str, Any]
    verification_contract: Mapping[str, Any]
    safety_contract: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.scenario_protocol_version != 1 or isinstance(self.scenario_protocol_version, bool):
            raise ScenarioProtocolError("unsupported scenario protocol version")
        if isinstance(self.scenario_version, bool) or not isinstance(self.scenario_version, int) or self.scenario_version < 1:
            raise ScenarioProtocolError("scenario version is invalid")
        _id(self.scenario_id, "scenario_id")
        _text(self.scenario_name, "scenario_name")
        _id(self.scenario_class, "scenario_class")
        _id(self.target_capability, "target_capability")
        _id(self.action, "action")
        for name in ("canonical_payload", "impact_contract", "remediation_contract", "replay_contract", "verification_contract", "safety_contract"):
            _mapping(getattr(self, name), name)
        safety = self.safety_contract
        if safety.get("authorization_required") is not True or not isinstance(safety.get("allowed_hosts"), list) or not safety.get("allowed_mutation_scope"):
            raise ScenarioProtocolError("safety contract is incomplete")
        if safety.get("external_network_action") is not False or safety.get("real_side_effects_permitted") is not False:
            raise ScenarioProtocolError("safety contract permits unsafe side effects")

    def to_dict(self) -> dict[str, Any]:
        return {name: deepcopy(getattr(self, name)) for name in _REQUIRED}

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def evidence_binding(self) -> dict[str, Any]:
        return {"scenario_id": self.scenario_id, "scenario_version": self.scenario_version, "scenario_fingerprint": self.fingerprint}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ScenarioDefinition":
        if not isinstance(value, Mapping) or set(value) != set(_REQUIRED):
            raise ScenarioProtocolError("scenario definition fields are incomplete or unexpected")
        return cls(**{name: value[name] for name in _REQUIRED})


SCENARIO_ONE = ScenarioDefinition(
    1, "agent-tool-send-email-control", 1, "agent-tool-send-email-control",
    "agentic-security-validation", "synthetic-local-action", "send_email",
    {"action": "send_email", "synthetic_local_only": True, "external_destination": None, "external_network_action": False},
    {"baseline_result": "ALLOWED", "synthetic_impact": "CONFIRMED", "ledger_transition": [0, 1]},
    {"policy_action": "send_email", "expected_before": "permit", "expected_after": "deny", "mutation_scope": "run-scoped-fixture-only", "evidence_required": True},
    {"same_canonical_payload": True, "same_fixture": True, "baseline_sha256_match": True, "blocked_result": "BLOCKED"},
    {"baseline_allowed": True, "baseline_impact_confirmed": True, "deny_only_verified": True, "replay_blocked": True, "replay_impact": False, "ledger_transition": [0, 1, 1], "fix_verified": True},
    {"authorization_required": True, "allowed_hosts": ["192.168.2.17"], "external_network_action": False, "real_side_effects_permitted": False, "allowed_mutation_scope": "~/kimura-physical-fixture/runs/<physical_run_id>", "cleanup_required": True},
)


def validate_evidence_binding(evidence: Mapping[str, Any], scenario: ScenarioDefinition) -> None:
    if not isinstance(evidence, Mapping):
        raise ScenarioProtocolError("evidence must be an object")
    expected = scenario.evidence_binding()
    if any(evidence.get(key) != value for key, value in expected.items()):
        raise ScenarioProtocolError("evidence scenario binding mismatch")


class ScenarioRegistry:
    def __init__(self) -> None:
        self._items: dict[tuple[str, int], ScenarioDefinition] = {}

    def register(self, scenario: ScenarioDefinition) -> str:
        if not isinstance(scenario, ScenarioDefinition):
            raise ScenarioProtocolError("registry accepts ScenarioDefinition")
        key = (scenario.scenario_id, scenario.scenario_version)
        existing = self._items.get(key)
        if existing is not None and existing.fingerprint != scenario.fingerprint:
            raise ScenarioProtocolError("conflicting scenario definition")
        self._items[key] = scenario
        return scenario.fingerprint

    def resolve(self, scenario_id: str, scenario_version: int) -> ScenarioDefinition:
        try:
            return self._items[(_id(scenario_id, "scenario_id"), scenario_version)]
        except (KeyError, ScenarioProtocolError):
            raise ScenarioProtocolError("unknown scenario") from None


SP_V1_REGISTRY = ScenarioRegistry()
SP_V1_REGISTRY.register(SCENARIO_ONE)
