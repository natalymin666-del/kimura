"""Versioned, hash-safe JSON protocol for the owned synthetic target node.

This module intentionally contains no network or process-management code.  It
only validates and canonically serializes the bounded messages exchanged by
the Kimura control plane and the physical target node.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Mapping


PROTOCOL_VERSION = 1
TARGET_KIND = "owned-isolated-synthetic-target"
OPERATIONS = frozenset({"discover", "execute", "validate", "apply_policy"})
STATUSES = frozenset({"ok", "error"})
DECISIONS = frozenset({"allowed", "blocked"})

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_BYTES = 64 * 1024


class PhysicalTargetProtocolError(ValueError):
    """Raised when a physical-target protocol message is unsafe or malformed."""


def canonical_json(value: Mapping[str, Any]) -> str:
    """Serialize a protocol object deterministically without retaining secrets."""

    if not isinstance(value, Mapping):
        raise PhysicalTargetProtocolError("protocol message must be an object")
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise PhysicalTargetProtocolError("protocol message is not JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise PhysicalTargetProtocolError("protocol message exceeds size limit")
    return encoded


def sha256_json(value: Mapping[str, Any]) -> str:
    """Return the digest of the canonical representation of a protocol object."""

    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _identifier(value: Any, field: str) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise PhysicalTargetProtocolError(f"{field} must be a safe identifier")


def _digest(value: Any, field: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise PhysicalTargetProtocolError(f"{field} must be a SHA-256 digest")


def _optional_identifier(message: Mapping[str, Any], field: str) -> None:
    if field in message and message[field] is not None:
        _identifier(message[field], field)


def _check_fields(message: Mapping[str, Any], allowed: set[str]) -> None:
    unexpected = set(message) - allowed
    if unexpected:
        raise PhysicalTargetProtocolError(
            "protocol message contains unexpected fields: " + ",".join(sorted(unexpected))
        )


def validate_request(message: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a copy of one control-plane request."""

    if not isinstance(message, Mapping):
        raise PhysicalTargetProtocolError("request must be an object")
    common = {"protocol_version", "request_id", "operation", "assessment_id"}
    operation_fields = {
        "discover": {"expected_target_id"},
        "execute": {"target_id", "attack_id", "fixture_id", "fixture_sha256", "action", "source", "policy_id"},
        "validate": {"target_id", "attack_id", "fixture_sha256", "observed_request_id"},
        "apply_policy": {"target_id", "policy_id", "deny_actions"},
    }
    operation = message.get("operation")
    _check_fields(message, common | operation_fields.get(operation, set()))
    if message.get("protocol_version") != PROTOCOL_VERSION:
        raise PhysicalTargetProtocolError("unsupported protocol_version")
    for field in ("request_id", "assessment_id"):
        _identifier(message.get(field), field)
    if operation not in OPERATIONS:
        raise PhysicalTargetProtocolError("unsupported operation")

    for field in ("expected_target_id", "target_id", "attack_id", "fixture_id", "action", "source", "policy_id", "observed_request_id"):
        _optional_identifier(message, field)
    if operation == "discover":
        _identifier(message.get("expected_target_id"), "expected_target_id")
    elif operation == "execute":
        for field in ("target_id", "attack_id", "fixture_id", "action", "source", "policy_id"):
            _identifier(message.get(field), field)
        _digest(message.get("fixture_sha256"), "fixture_sha256")
    elif operation == "validate":
        for field in ("target_id", "attack_id", "observed_request_id"):
            _identifier(message.get(field), field)
        _digest(message.get("fixture_sha256"), "fixture_sha256")
    elif operation == "apply_policy":
        for field in ("target_id", "policy_id"):
            _identifier(message.get(field), field)
        actions = message.get("deny_actions")
        if not isinstance(actions, list) or any(not isinstance(item, str) for item in actions):
            raise PhysicalTargetProtocolError("deny_actions must be a list of action identifiers")
        for item in actions:
            _identifier(item, "deny_actions item")
        if actions != sorted(set(actions)):
            raise PhysicalTargetProtocolError("deny_actions must be sorted and unique")

    result = dict(message)
    canonical_json(result)
    return result


def validate_response(message: Mapping[str, Any]) -> dict[str, Any]:
    """Validate safe response metadata returned by the physical target."""

    if not isinstance(message, Mapping):
        raise PhysicalTargetProtocolError("response must be an object")
    allowed = {
        "protocol_version", "request_id", "status", "target_id", "target_kind", "node_instance_id",
        "runtime", "capabilities", "policy_id", "policy_sha256", "ledger_sequence", "attack_id",
        "fixture_id", "fixture_sha256", "action", "authorization_decision", "executed", "synthetic_event_id",
        "impact_class", "outcome", "validated", "denied_actions", "observed_request_id", "error_code",
    }
    _check_fields(message, allowed)
    if message.get("protocol_version") != PROTOCOL_VERSION:
        raise PhysicalTargetProtocolError("unsupported protocol_version")
    _identifier(message.get("request_id"), "request_id")
    if message.get("status") not in STATUSES:
        raise PhysicalTargetProtocolError("unsupported response status")
    for field in ("target_id", "target_kind", "node_instance_id", "policy_id", "attack_id", "fixture_id", "action", "outcome", "error_code"):
        _optional_identifier(message, field)
    if "target_kind" in message and message["target_kind"] != TARGET_KIND:
        raise PhysicalTargetProtocolError("unexpected target_kind")
    for field in ("policy_sha256", "fixture_sha256"):
        if field in message and message[field] is not None:
            _digest(message[field], field)
    if "authorization_decision" in message and message["authorization_decision"] not in DECISIONS:
        raise PhysicalTargetProtocolError("unsupported authorization_decision")
    for field in ("executed", "validated"):
        if field in message and not isinstance(message[field], bool):
            raise PhysicalTargetProtocolError(f"{field} must be boolean")
    if "ledger_sequence" in message and (isinstance(message["ledger_sequence"], bool) or not isinstance(message["ledger_sequence"], int) or message["ledger_sequence"] < 0):
        raise PhysicalTargetProtocolError("ledger_sequence must be a non-negative integer")
    if "runtime" in message and not isinstance(message["runtime"], Mapping):
        raise PhysicalTargetProtocolError("runtime must be an object")
    if "capabilities" in message and (not isinstance(message["capabilities"], list) or any(not isinstance(item, str) for item in message["capabilities"])):
        raise PhysicalTargetProtocolError("capabilities must be a list of strings")
    if "denied_actions" in message and (not isinstance(message["denied_actions"], list) or any(not isinstance(item, str) for item in message["denied_actions"])):
        raise PhysicalTargetProtocolError("denied_actions must be a list of strings")
    if "observed_request_id" in message:
        _identifier(message["observed_request_id"], "observed_request_id")
    result = dict(message)
    canonical_json(result)
    return result


def request_json(message: Mapping[str, Any]) -> str:
    """Validate and serialize a request."""

    return canonical_json(validate_request(message))


def response_json(message: Mapping[str, Any]) -> str:
    """Validate and serialize a response."""

    return canonical_json(validate_response(message))
