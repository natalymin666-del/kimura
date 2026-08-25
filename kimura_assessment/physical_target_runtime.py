"""Bounded synthetic target runtime for the local Physical Target Node v1."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping
from uuid import uuid4

from .physical_target_protocol import (
    PROTOCOL_VERSION,
    TARGET_KIND,
    PhysicalTargetProtocolError,
    sha256_json,
    validate_request,
)
from .red_team_v2 import DEFAULT_REGISTRY


DEFAULT_TARGET_NAME = "kimura-physical-target-node"
DEFAULT_OWNER_LABEL = "kimura-owned-isolated"
DEFAULT_POLICY_ID = "physical-baseline-policy-v1"
DEFAULT_ALLOWED_ACTIONS = frozenset({"send_email"})


@dataclass(frozen=True, slots=True)
class SyntheticFixture:
    attack_id: str
    fixture_id: str
    fixture_sha256: str
    action: str
    source: str
    impact_class: str | None


def _build_default_fixtures() -> dict[tuple[str, str], SyntheticFixture]:
    impact_by_action = {
        "approve_refund": "synthetic-transaction-impact",
        "external_upload": "synthetic-sensitive-egress",
        "send_email": "synthetic-external-action",
        "read_document": None,
    }
    fixtures: dict[tuple[str, str], SyntheticFixture] = {}
    for case in DEFAULT_REGISTRY:
        if case.proposed_action is None:
            continue
        fixtures[(case.attack_id, case.fixture_id)] = SyntheticFixture(
            attack_id=case.attack_id,
            fixture_id=case.fixture_id,
            fixture_sha256=case.fixture_sha256,
            action=case.proposed_action,
            source="untrusted-content",
            impact_class=impact_by_action[case.proposed_action],
        )
    return fixtures


DEFAULT_FIXTURES = _build_default_fixtures()


@dataclass(frozen=True, slots=True)
class TargetConfig:
    """Runtime configuration from which stable target identity is derived."""

    target_name: str = DEFAULT_TARGET_NAME
    owner_label: str = DEFAULT_OWNER_LABEL
    baseline_policy_id: str = DEFAULT_POLICY_ID
    baseline_allowed_actions: frozenset[str] = DEFAULT_ALLOWED_ACTIONS

    @property
    def target_id(self) -> str:
        material = json.dumps(
            {
                "owner_label": self.owner_label,
                "target_name": self.target_name,
                "baseline_policy_id": self.baseline_policy_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        from hashlib import sha256
        return f"physical-target-{sha256(material.encode('utf-8')).hexdigest()[:16]}"


@dataclass(frozen=True, slots=True)
class SyntheticLedgerEvent:
    event_id: str
    request_id: str
    attack_id: str
    fixture_id: str
    fixture_sha256: str
    action: str
    impact_class: str
    policy_id: str
    ledger_sequence: int
    event_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "request_id": self.request_id,
            "attack_id": self.attack_id,
            "fixture_id": self.fixture_id,
            "fixture_sha256": self.fixture_sha256,
            "action": self.action,
            "impact_class": self.impact_class,
            "policy_id": self.policy_id,
            "ledger_sequence": self.ledger_sequence,
            "event_sha256": self.event_sha256,
        }


class PhysicalTargetRuntime:
    """In-memory synthetic target with no real tools or external effects."""

    def __init__(
        self,
        config: TargetConfig | None = None,
        *,
        fixtures: Mapping[tuple[str, str], SyntheticFixture] | None = None,
        node_instance_id: str | None = None,
    ) -> None:
        self.config = config or TargetConfig()
        self.fixtures = dict(fixtures or DEFAULT_FIXTURES)
        self.node_instance_id = node_instance_id or f"instance-{uuid4().hex}"
        self.policy_id = self.config.baseline_policy_id
        self.denied_actions: frozenset[str] = frozenset()
        self._responses: dict[str, tuple[str, dict[str, Any]]] = {}
        self._events: list[SyntheticLedgerEvent] = []
        self._event_by_request: dict[str, SyntheticLedgerEvent] = {}

    @property
    def supported_actions(self) -> tuple[str, ...]:
        return tuple(sorted({fixture.action for fixture in self.fixtures.values()}))

    @property
    def events(self) -> tuple[SyntheticLedgerEvent, ...]:
        return tuple(self._events)

    @property
    def policy_sha256(self) -> str:
        return sha256_json({"denied_actions": sorted(self.denied_actions), "policy_id": self.policy_id})

    def _base(self, request_id: str) -> dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "target_id": self.config.target_id,
            "target_kind": TARGET_KIND,
            "node_instance_id": self.node_instance_id,
        }

    def _error(self, request_id: str, error_code: str) -> dict[str, Any]:
        return {**self._base(request_id), "status": "error", "error_code": error_code, "outcome": "request-rejected"}

    def _check_target(self, request: Mapping[str, Any]) -> None:
        if request.get("target_id") not in (None, self.config.target_id):
            raise PhysicalTargetProtocolError("target_id does not identify this node")

    def _execute(self, request: Mapping[str, Any]) -> dict[str, Any]:
        self._check_target(request)
        key = (request["attack_id"], request["fixture_id"])
        fixture = self.fixtures.get(key)
        if fixture is None:
            return {**self._base(request["request_id"]), "status": "error", "error_code": "unknown-fixture", "outcome": "request-rejected"}
        if request["fixture_sha256"] != fixture.fixture_sha256:
            return {**self._base(request["request_id"]), "status": "error", "error_code": "fixture-digest-mismatch", "outcome": "request-rejected"}
        if request["action"] != fixture.action:
            return {**self._base(request["request_id"]), "status": "error", "error_code": "fixture-action-mismatch", "outcome": "request-rejected"}
        if request["source"] != fixture.source:
            return {**self._base(request["request_id"]), "status": "error", "error_code": "source-mismatch", "outcome": "request-rejected"}
        allowed = request["action"] in self.config.baseline_allowed_actions and request["action"] not in self.denied_actions
        response: dict[str, Any] = {
            **self._base(request["request_id"]),
            "status": "ok",
            "attack_id": fixture.attack_id,
            "fixture_id": fixture.fixture_id,
            "fixture_sha256": fixture.fixture_sha256,
            "action": fixture.action,
            "authorization_decision": "allowed" if allowed else "blocked",
            "executed": allowed,
            "synthetic_event_id": None,
            "impact_class": None,
            "outcome": "synthetic-action-recorded" if allowed else "action-not-allowlisted",
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "ledger_sequence": len(self._events),
        }
        if allowed and fixture.impact_class is not None:
            sequence = len(self._events) + 1
            event_material = {
                "action": fixture.action,
                "attack_id": fixture.attack_id,
                "fixture_id": fixture.fixture_id,
                "fixture_sha256": fixture.fixture_sha256,
                "impact_class": fixture.impact_class,
                "ledger_sequence": sequence,
                "policy_id": self.policy_id,
                "request_id": request["request_id"],
            }
            event = SyntheticLedgerEvent(
                event_id=f"event-{sequence:04d}",
                request_id=request["request_id"],
                attack_id=fixture.attack_id,
                fixture_id=fixture.fixture_id,
                fixture_sha256=fixture.fixture_sha256,
                action=fixture.action,
                impact_class=fixture.impact_class,
                policy_id=self.policy_id,
                ledger_sequence=sequence,
                event_sha256=sha256_json(event_material),
            )
            self._events.append(event)
            self._event_by_request[request["request_id"]] = event
            response.update({"synthetic_event_id": event.event_id, "impact_class": event.impact_class, "ledger_sequence": sequence})
        return response

    def _validate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        self._check_target(request)
        event = self._event_by_request.get(request["observed_request_id"])
        valid = event is not None and event.attack_id == request["attack_id"] and event.fixture_sha256 == request["fixture_sha256"]
        return {
            **self._base(request["request_id"]),
            "status": "ok",
            "attack_id": request["attack_id"],
            "fixture_sha256": request["fixture_sha256"],
            "observed_request_id": request["observed_request_id"],
            "validated": valid,
            "executed": valid,
            "synthetic_event_id": event.event_id if valid else None,
            "impact_class": event.impact_class if valid else None,
            "outcome": "synthetic-impact-validated" if valid else "no-synthetic-impact",
            "ledger_sequence": event.ledger_sequence if valid else len(self._events),
        }

    def _apply_policy(self, request: Mapping[str, Any]) -> dict[str, Any]:
        self._check_target(request)
        requested = frozenset(request["deny_actions"])
        supported = frozenset(self.supported_actions)
        if not requested <= supported:
            return {**self._base(request["request_id"]), "status": "error", "error_code": "unsupported-deny-action", "outcome": "policy-rejected"}
        if not self.denied_actions <= requested:
            return {**self._base(request["request_id"]), "status": "error", "error_code": "policy-broadening-forbidden", "outcome": "policy-rejected"}
        self.denied_actions = requested
        self.policy_id = request["policy_id"]
        return {
            **self._base(request["request_id"]),
            "status": "ok",
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "denied_actions": sorted(self.denied_actions),
            "outcome": "policy-applied",
        }

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any]:
        """Validate and process one request, returning only safe metadata."""

        try:
            request = validate_request(message)
        except (PhysicalTargetProtocolError, TypeError, KeyError):
            request_id = message.get("request_id", "request-invalid") if isinstance(message, Mapping) else "request-invalid"
            if not isinstance(request_id, str) or not request_id or not all(ord(char) < 128 for char in request_id):
                request_id = "request-invalid"
            return self._error(request_id, "invalid-request")

        request_digest = sha256_json(request)
        previous = self._responses.get(request["request_id"])
        if previous is not None:
            previous_digest, previous_response = previous
            if previous_digest != request_digest:
                return self._error(request["request_id"], "request-id-conflict")
            return dict(previous_response)

        try:
            if request["operation"] == "discover":
                if request["expected_target_id"] != self.config.target_id:
                    response = self._error(request["request_id"], "target-identity-mismatch")
                else:
                    response = {
                        **self._base(request["request_id"]),
                        "status": "ok",
                        "runtime": {"target_runtime": "physical-target-runtime-v1"},
                        "capabilities": list(self.supported_actions),
                        "policy_id": self.policy_id,
                        "policy_sha256": self.policy_sha256,
                        "ledger_sequence": len(self._events),
                        "outcome": "target-discovered",
                    }
            elif request["operation"] == "execute":
                response = self._execute(request)
            elif request["operation"] == "validate":
                response = self._validate(request)
            else:
                response = self._apply_policy(request)
        except PhysicalTargetProtocolError:
            response = self._error(request["request_id"], "request-rejected")
        self._responses[request["request_id"]] = (request_digest, dict(response))
        return response


def fixture_for(attack_id: str, fixture_id: str) -> SyntheticFixture:
    """Return a registered fixture for local tests and future adapters."""

    try:
        return DEFAULT_FIXTURES[(attack_id, fixture_id)]
    except KeyError as exc:
        raise KeyError("unknown synthetic fixture") from exc
