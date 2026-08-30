"""Generic, local-only authorized evidence capture adapter V1.

The adapter consumes an already sealed request and an already authorized
context.  Its transport is an injected local fixture only; this module has no
network client, scanner, crawler, credential loader, or verdict
engine.  Captured artifacts are suitable inputs to ``observation.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Protocol

from .boundary_proof import canonical_json, sha256
from .observation import CapturedResponse, ObservationContext, StateSnapshot


_DIGEST_LENGTH = 64
_SECRET_KEY_TERMS = (
    "authorization", "cookie", "bearer", "password", "api_key", "apikey",
    "session", "secret", "otp", "credential", "private_key", "access_token",
)


class CaptureError(ValueError):
    """Base class for fail-closed capture errors."""


class CaptureNotAuthorized(CaptureError):
    code = "CAPTURE_NOT_AUTHORIZED"


class CaptureReplayRejected(CaptureError):
    code = "CAPTURE_REPLAY_REJECTED"


class CaptureRedirectRejected(CaptureError):
    code = "CAPTURE_REDIRECT_REJECTED"


class CaptureSecretRejected(CaptureError):
    code = "CAPTURE_SECRET_REJECTED"


class CaptureTransportFailure(CaptureError):
    code = "CAPTURE_TRANSPORT_FAILED"


class CaptureStatus(str, Enum):
    CAPTURED = "CAPTURED"


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != _DIGEST_LENGTH or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is required")
    return value


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    canonical_json(dict(value))
    return dict(value)


def _parse_time(value: Any, name: str) -> datetime:
    parsed = datetime.fromisoformat(_text(value, name).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _secret_key(key: Any) -> bool:
    lowered = str(key).lower().replace("-", "_")
    return any(term in lowered for term in _SECRET_KEY_TERMS)


def _contains_secret(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_secret_key(key) or _contains_secret(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_secret(item) for item in value)
    return False


def _safe_mapping(value: Any, name: str) -> dict[str, Any]:
    result = _mapping(value, name)
    if _contains_secret(result):
        raise CaptureSecretRejected(f"{name} contains secret material")
    return result


@dataclass(frozen=True, slots=True)
class AuthorizedCaptureContext:
    assessment_id: str
    run_id: str
    pair_fingerprint: str
    request_fingerprint: str
    actor_fingerprint: str
    target_fingerprint: str
    resource_fingerprint: str
    authorization_contract_fingerprint: str
    authorization_state: str
    approval_id: str
    capture_nonce: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _text(self.assessment_id, "assessment_id")
        _text(self.run_id, "run_id")
        for name in ("pair_fingerprint", "request_fingerprint", "actor_fingerprint", "target_fingerprint", "resource_fingerprint", "authorization_contract_fingerprint"):
            _digest(getattr(self, name), name)
        if self.authorization_state not in {"AUTHORIZED", "NOT_AUTHORIZED"}:
            raise ValueError("authorization_state is invalid")
        if not isinstance(self.approval_id, str) or not isinstance(self.capture_nonce, str):
            raise ValueError("approval_id and capture_nonce must be text")
        if self.capture_nonce and (len(self.capture_nonce) < 8 or any(c.isspace() for c in self.capture_nonce)):
            raise ValueError("capture_nonce is invalid")
        if _parse_time(self.expires_at, "expires_at") <= _parse_time(self.issued_at, "issued_at"):
            raise ValueError("authorization expiry must follow issuance")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class SealedRequest:
    method_or_action: str
    canonical_target: str
    canonical_resource: str
    canonical_arguments: Mapping[str, Any]
    request_fingerprint: str
    expected_target_identity: str
    redirect_policy: Mapping[str, Any]
    body_digest: str | None = None

    def __post_init__(self) -> None:
        _text(self.method_or_action, "method_or_action")
        _text(self.canonical_target, "canonical_target")
        _text(self.canonical_resource, "canonical_resource")
        _safe_mapping(self.canonical_arguments, "canonical_arguments")
        _digest(self.request_fingerprint, "request_fingerprint")
        _text(self.expected_target_identity, "expected_target_identity")
        _safe_mapping(self.redirect_policy, "redirect_policy")
        if self.body_digest is not None:
            _digest(self.body_digest, "body_digest")
        if self.request_fingerprint != self.computed_fingerprint:
            raise ValueError("request_fingerprint does not match sealed request")

    @property
    def computed_fingerprint(self) -> str:
        return sha256(self.to_unsigned())

    def to_unsigned(self) -> dict[str, Any]:
        return {
            "method_or_action": self.method_or_action,
            "canonical_target": self.canonical_target,
            "canonical_resource": self.canonical_resource,
            "canonical_arguments": dict(self.canonical_arguments),
            "expected_target_identity": self.expected_target_identity,
            "redirect_policy": dict(self.redirect_policy),
            "body_digest": self.body_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        result = self.to_unsigned()
        result["request_fingerprint"] = self.request_fingerprint
        return result


@dataclass(frozen=True, slots=True)
class StateCapture:
    canonical_resource_identity: str
    before_after_marker: str
    state_representation: Mapping[str, Any]
    state_digest: str
    capture_provenance: Mapping[str, Any]

    def __post_init__(self) -> None:
        _digest(self.canonical_resource_identity, "canonical_resource_identity")
        if self.before_after_marker not in {"BEFORE", "AFTER"}:
            raise ValueError("before_after_marker must be BEFORE or AFTER")
        state = _safe_mapping(self.state_representation, "state_representation")
        if self.state_digest != sha256(state):
            raise ValueError("state_digest does not match state_representation")
        _safe_mapping(self.capture_provenance, "capture_provenance")

    def to_observer_snapshot(self, bindings: Mapping[str, Any]) -> StateSnapshot:
        return StateSnapshot(self.canonical_resource_identity, self.state_representation,
                             self.state_digest, self.capture_provenance, bindings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_resource_identity": self.canonical_resource_identity,
            "before_after_marker": self.before_after_marker,
            "state_representation": dict(self.state_representation),
            "state_digest": self.state_digest,
            "capture_provenance": dict(self.capture_provenance),
        }


@dataclass(frozen=True, slots=True)
class CaptureArtifact:
    capture_id: str
    capture_timestamp: str
    assessment_id: str
    run_id: str
    pair_fingerprint: str
    request_fingerprint: str
    actor_fingerprint: str
    target_fingerprint: str
    resource_fingerprint: str
    response_metadata: Mapping[str, Any]
    response_body_digest: str | None
    protected_resource_evidence: Mapping[str, Any] | None
    redirect_chain_metadata: tuple[Mapping[str, Any], ...]
    provenance: Mapping[str, Any]
    artifact_digest: str
    status: CaptureStatus = CaptureStatus.CAPTURED

    def __post_init__(self) -> None:
        _text(self.capture_id, "capture_id")
        _parse_time(self.capture_timestamp, "capture_timestamp")
        _text(self.assessment_id, "assessment_id")
        _text(self.run_id, "run_id")
        _digest(self.pair_fingerprint, "pair_fingerprint")
        for name in ("request_fingerprint", "actor_fingerprint", "target_fingerprint", "resource_fingerprint"):
            _digest(getattr(self, name), name)
        _safe_mapping(self.response_metadata, "response_metadata")
        if self.response_body_digest is not None:
            _digest(self.response_body_digest, "response_body_digest")
        if self.protected_resource_evidence is not None:
            protected = _safe_mapping(self.protected_resource_evidence, "protected_resource_evidence")
            if protected.get("protected_content_digest") is not None:
                _digest(protected["protected_content_digest"], "protected_content_digest")
            if protected.get("structured_response_fields") is not None:
                _mapping(protected["structured_response_fields"], "structured_response_fields")
            if protected.get("denial_evidence") is not None:
                _mapping(protected["denial_evidence"], "denial_evidence")
        if not isinstance(self.redirect_chain_metadata, tuple) or any(not isinstance(x, Mapping) for x in self.redirect_chain_metadata):
            raise ValueError("redirect_chain_metadata must be an immutable tuple of mappings")
        for item in self.redirect_chain_metadata:
            _safe_mapping(item, "redirect_chain_metadata")
        provenance = _safe_mapping(self.provenance, "provenance")
        if provenance.get("capture_id") != self.capture_id or provenance.get("source_type") != "KIMURA_CAPTURED":
            raise CaptureError("capture provenance does not bind artifact")
        if self.artifact_digest != sha256(self.to_unsigned()):
            raise CaptureError("artifact_digest does not match capture artifact")

    def to_unsigned(self) -> dict[str, Any]:
        return {
            "capture_id": self.capture_id, "capture_timestamp": self.capture_timestamp,
            "assessment_id": self.assessment_id, "run_id": self.run_id, "pair_fingerprint": self.pair_fingerprint,
            "request_fingerprint": self.request_fingerprint, "actor_fingerprint": self.actor_fingerprint,
            "target_fingerprint": self.target_fingerprint, "resource_fingerprint": self.resource_fingerprint,
            "response_metadata": dict(self.response_metadata), "response_body_digest": self.response_body_digest,
            "protected_resource_evidence": dict(self.protected_resource_evidence or {}),
            "redirect_chain_metadata": [dict(x) for x in self.redirect_chain_metadata],
            "provenance": dict(self.provenance), "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        result = self.to_unsigned(); result["artifact_digest"] = self.artifact_digest; return result

    def verify(self) -> None:
        if self.artifact_digest != sha256(self.to_unsigned()):
            raise CaptureError("capture artifact digest mismatch")

    def to_observer_response(self, bindings: Mapping[str, Any]) -> CapturedResponse:
        expected = {
            "assessment_id": self.assessment_id, "run_id": self.run_id,
            "pair_fingerprint": self.pair_fingerprint, "request_fingerprint": self.request_fingerprint,
            "actor_fingerprint": self.actor_fingerprint, "target_fingerprint": self.target_fingerprint,
            "resource_fingerprint": self.resource_fingerprint,
        }
        if dict(bindings) != expected:
            raise CaptureError("observer bindings do not match capture artifact")
        protected = self.protected_resource_evidence or {}
        return CapturedResponse(
            status_code=self.response_metadata.get("status_code"),
            normalized_headers_metadata=self.response_metadata.get("headers", {}),
            body_content_digest=self.response_body_digest,
            structured_response_fields=protected.get("structured_response_fields", {}),
            capture_provenance=self.provenance,
            evidence_bindings=bindings,
            protected_content_digest=protected.get("protected_content_digest"),
            denial_evidence=protected.get("denial_evidence"),
        )


class LocalCaptureTransport(Protocol):
    def capture(self, request: SealedRequest, context: AuthorizedCaptureContext) -> Mapping[str, Any]:
        ...


class LocalTransportFixture:
    """Deterministic in-memory transport fixture; never performs I/O."""

    def __init__(self, scenario: Mapping[str, Any]):
        self.scenario = dict(scenario)

    def capture(self, request: SealedRequest, context: AuthorizedCaptureContext) -> Mapping[str, Any]:
        if self.scenario.get("transport_failure"):
            raise OSError("synthetic transport failure")
        return dict(self.scenario)


class EvidenceCaptureAdapterV1:
    VERSION = "capture-adapter-v1"

    def __init__(self, *, authorization_contract_fingerprint: str, assessment_id: str, run_id: str, pair_fingerprint: str, allowed_actor_fingerprints: frozenset[str], now=None):
        self._now = now or (lambda: datetime.now(timezone.utc))
        _digest(authorization_contract_fingerprint, "authorization_contract_fingerprint")
        _text(assessment_id, "assessment_id")
        _text(run_id, "run_id")
        _digest(pair_fingerprint, "pair_fingerprint")
        if not allowed_actor_fingerprints or any((not isinstance(item, str) or len(item) != _DIGEST_LENGTH) for item in allowed_actor_fingerprints):
            raise ValueError("allowed_actor_fingerprints are required")
        self._authorization_contract_fingerprint = authorization_contract_fingerprint
        self._assessment_id = assessment_id
        self._run_id = run_id
        self._pair_fingerprint = pair_fingerprint
        self._allowed_actor_fingerprints = frozenset(allowed_actor_fingerprints)
        self._used_approvals: set[str] = set()
        self._used_nonces: set[str] = set()

    def _authorize(self, context: AuthorizedCaptureContext, request: SealedRequest) -> None:
        if context.assessment_id != self._assessment_id:
            raise CaptureNotAuthorized("assessment_id mismatch")
        if context.run_id != self._run_id:
            raise CaptureNotAuthorized("run_id mismatch")
        if context.pair_fingerprint != self._pair_fingerprint:
            raise CaptureNotAuthorized("pair fingerprint mismatch")
        if context.actor_fingerprint not in self._allowed_actor_fingerprints:
            raise CaptureNotAuthorized("actor is not authorized for this adapter")
        if context.authorization_state != "AUTHORIZED":
            raise CaptureNotAuthorized("authorization state is not AUTHORIZED")
        if context.request_fingerprint != request.request_fingerprint:
            raise CaptureNotAuthorized("request fingerprint mismatch")
        if context.authorization_contract_fingerprint != self._authorization_contract_fingerprint:
            raise CaptureNotAuthorized("authorization contract fingerprint mismatch")
        if context.target_fingerprint != sha256(request.expected_target_identity):
            raise CaptureNotAuthorized("target identity mismatch")
        if context.resource_fingerprint != sha256(request.canonical_resource):
            raise CaptureNotAuthorized("resource identity mismatch")
        now = self._now().astimezone(timezone.utc)
        if now < _parse_time(context.issued_at, "issued_at") or now >= _parse_time(context.expires_at, "expires_at"):
            raise CaptureNotAuthorized("authorization is expired or not yet issued")
        if not context.approval_id or not context.capture_nonce:
            raise CaptureNotAuthorized("approval_id and capture_nonce are required")
        if context.approval_id in self._used_approvals or context.capture_nonce in self._used_nonces:
            raise CaptureReplayRejected("approval or capture nonce was already used")

    def _contain(self, request: SealedRequest, redirect_chain: Any) -> tuple[Mapping[str, Any], ...]:
        if redirect_chain is None:
            return ()
        if not isinstance(redirect_chain, (list, tuple)):
            raise CaptureRedirectRejected("redirect chain is malformed")
        allowed_hosts = request.redirect_policy.get("allowed_target_identities", [request.expected_target_identity])
        allowed_resources = request.redirect_policy.get("allowed_resources", [request.canonical_resource])
        allow_downgrade = request.redirect_policy.get("allow_scheme_downgrade", False)
        result: list[Mapping[str, Any]] = []
        for redirect in redirect_chain:
            item = _safe_mapping(redirect, "redirect")
            if item.get("target_identity") not in allowed_hosts:
                raise CaptureRedirectRejected("redirect target identity is outside sealed target")
            if item.get("resource") not in allowed_resources:
                raise CaptureRedirectRejected("redirect resource is outside sealed resource")
            if item.get("scheme_downgrade") is True and not allow_downgrade:
                raise CaptureRedirectRejected("scheme downgrade is not permitted")
            result.append(item)
        return tuple(result)

    def capture(self, context: AuthorizedCaptureContext, request: SealedRequest, transport: LocalCaptureTransport) -> CaptureArtifact:
        self._authorize(context, request)
        # Consume both one-shot values before invoking even the local fixture;
        # a transport failure cannot be retried under the same approval.
        self._used_approvals.add(context.approval_id)
        self._used_nonces.add(context.capture_nonce)
        try:
            raw = _mapping(transport.capture(request, context), "transport result")
            redirect_chain = self._contain(request, raw.get("redirect_chain", []))
            response_metadata = _safe_mapping(raw.get("response_metadata", {}), "response_metadata")
            protected = raw.get("protected_resource_evidence")
            if protected is not None:
                protected = _safe_mapping(protected, "protected_resource_evidence")
            capture_id = sha256({"approval_id": context.approval_id, "nonce": context.capture_nonce, "run_id": context.run_id})
            common = {
                "capture_id": capture_id,
                "capture_timestamp": self._now().astimezone(timezone.utc).isoformat(),
                "assessment_id": context.assessment_id,
                "run_id": context.run_id,
                "pair_fingerprint": context.pair_fingerprint,
                "request_fingerprint": context.request_fingerprint,
                "actor_fingerprint": context.actor_fingerprint,
                "target_fingerprint": context.target_fingerprint,
                "resource_fingerprint": context.resource_fingerprint,
                "response_metadata": response_metadata,
                "response_body_digest": raw.get("response_body_digest"),
                "protected_resource_evidence": protected or {},
                "redirect_chain_metadata": [dict(item) for item in redirect_chain],
                "provenance": {"adapter_version": self.VERSION, "capture_id": capture_id, "source_type": "KIMURA_CAPTURED", "captured_by": self.VERSION, "capture_method": "in-memory local transport fixture"},
                "status": CaptureStatus.CAPTURED.value,
            }
            artifact = CaptureArtifact(**{**common, "status": CaptureStatus.CAPTURED, "artifact_digest": sha256(common), "redirect_chain_metadata": redirect_chain})
        except CaptureError:
            raise
        except OSError as exc:
            raise CaptureTransportFailure(str(exc)) from exc
        except (TypeError, ValueError) as exc:
            raise CaptureError(str(exc)) from exc
        return artifact


def capture_artifact_to_observation_context(context: AuthorizedCaptureContext) -> ObservationContext:
    return ObservationContext(
        assessment_id=context.assessment_id, run_id=context.run_id,
        pair_fingerprint=context.pair_fingerprint, request_fingerprint=context.request_fingerprint,
        actor_fingerprint=context.actor_fingerprint, target_fingerprint=context.target_fingerprint,
        resource_fingerprint=context.resource_fingerprint,
        observation_timestamp=context.issued_at, source_type="KIMURA_CAPTURED",
    )


def proof_capsule_capture_fields(*, adapter: EvidenceCaptureAdapterV1,
                                 authorization_contract_fingerprint: str,
                                 approval_id: str,
                                 pair_fingerprint: str,
                                 run_id: str,
                                 allowed_capture: CaptureArtifact,
                                 forbidden_capture: CaptureArtifact,
                                 allowed_observation: Any,
                                 forbidden_observation: Any) -> dict[str, Any]:
    """Serialize adapter/observer bindings without deriving a boundary verdict."""
    _digest(authorization_contract_fingerprint, "authorization_contract_fingerprint")
    _digest(pair_fingerprint, "pair_fingerprint")
    _text(approval_id, "approval_id")
    if allowed_capture.request_fingerprint != forbidden_capture.request_fingerprint:
        raise CaptureError("capture pair request mismatch")
    if allowed_capture.target_fingerprint != forbidden_capture.target_fingerprint or allowed_capture.resource_fingerprint != forbidden_capture.resource_fingerprint:
        raise CaptureError("capture pair target/resource mismatch")
    allowed_capture.verify(); forbidden_capture.verify()
    allowed_observation.verify(); forbidden_observation.verify()
    return {
        "adapter_version": adapter.VERSION,
        "authorization_contract_fingerprint": authorization_contract_fingerprint,
        "approval_identity": approval_id,
        "sealed_request_fingerprint": allowed_capture.request_fingerprint,
        "allowed_capture_id": allowed_capture.capture_id,
        "allowed_capture_artifact_digest": allowed_capture.artifact_digest,
        "forbidden_capture_id": forbidden_capture.capture_id,
        "forbidden_capture_artifact_digest": forbidden_capture.artifact_digest,
        "actor_fingerprints": [allowed_capture.actor_fingerprint, forbidden_capture.actor_fingerprint],
        "target_fingerprint": allowed_capture.target_fingerprint,
        "resource_fingerprint": allowed_capture.resource_fingerprint,
        "allowed_observation_digest": allowed_observation.observation_digest,
        "forbidden_observation_digest": forbidden_observation.observation_digest,
        "pair_fingerprint": pair_fingerprint,
        "run_id": run_id,
        "provenance": "KIMURA_INDEPENDENTLY_OBSERVED",
    }
