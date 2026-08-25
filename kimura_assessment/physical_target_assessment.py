"""Laptop-side bounded physical-target assessment orchestration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import argparse
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .physical_target_protocol import (
    PhysicalTargetProtocolError,
    request_json,
    validate_response,
)
from .physical_target_runtime import PhysicalTargetRuntime, TargetConfig, fixture_for


MAX_RESPONSE_BYTES = 64 * 1024
NODE_PATH = "/v1/node"
_HEX_DIGEST = frozenset("0123456789abcdef")


class PhysicalAssessmentError(RuntimeError):
    """Raised for transport, schema, or lifecycle invariant failures."""


class PhysicalTargetTransport(Protocol):
    def request(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        ...


class HttpPhysicalTargetClient:
    """Bounded JSON client for one explicitly configured target endpoint."""

    def __init__(self, endpoint: str, *, timeout: float = 5.0, max_response_bytes: int = MAX_RESPONSE_BYTES):
        parsed = urlsplit(endpoint)
        if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("endpoint must be an explicit HTTP URL without credentials")
        if parsed.path != NODE_PATH or parsed.query or parsed.fragment:
            raise ValueError(f"endpoint path must be exactly {NODE_PATH}")
        if parsed.port is None or not 1 <= parsed.port <= 65535:
            raise ValueError("endpoint must include an explicit valid port")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if not 0 < max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError("max_response_bytes is outside the permitted range")
        self.endpoint = endpoint
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    def request(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            encoded = request_json(payload).encode("utf-8")
            request = Request(self.endpoint, data=encoded, method="POST", headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read(self.max_response_bytes + 1)
            if len(body) > self.max_response_bytes:
                raise PhysicalAssessmentError("target response exceeded configured size limit")
            result = json.loads(body.decode("utf-8"))
            if not isinstance(result, dict):
                raise PhysicalAssessmentError("target response was not an object")
            return validate_response(result)
        except PhysicalAssessmentError:
            raise
        except (PhysicalTargetProtocolError, HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PhysicalAssessmentError(f"target transport or schema failure: {type(exc).__name__}") from None


class InProcessPhysicalTargetClient:
    """Test transport that exercises the same protocol against a local runtime."""

    def __init__(self, runtime: PhysicalTargetRuntime):
        self.runtime = runtime

    def request(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            result = self.runtime.handle(payload)
            return validate_response(result)
        except (PhysicalTargetProtocolError, TypeError, KeyError) as exc:
            raise PhysicalAssessmentError(f"in-process protocol failure: {type(exc).__name__}") from None


@dataclass(frozen=True, slots=True)
class PhysicalAssessmentResult:
    status: str
    target_id: str | None = None
    target_kind: str | None = None
    protocol_version: int | None = None
    physical_target_reached: bool = False
    baseline_fixture_id: str | None = None
    baseline_fixture_sha256: str | None = None
    baseline_decision: str | None = None
    baseline_synthetic_impact_confirmed: bool = False
    baseline_event_id: str | None = None
    baseline_ledger_count: int | None = None
    remediation_policy_id: str | None = None
    policy_digest_before: str | None = None
    policy_digest_after: str | None = None
    deny_only_verified: bool = False
    replay_fixture_sha256: str | None = None
    exact_replay_identity_verified: bool = False
    replay_target_reached: bool = False
    replay_decision: str | None = None
    replay_executed: bool | None = None
    replay_synthetic_impact_confirmed: bool = False
    final_ledger_count: int | None = None
    fix_verified: bool = False
    evidence_chain: tuple[dict[str, Any], ...] = ()
    code_hashes_verified: bool = False
    cleanup_attempted: bool = False
    cleanup_completed: bool = False
    failure_reason: str | None = None
    code_hashes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence_chain"] = [dict(item) for item in self.evidence_chain]
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def verify_code_hashes(expected: Mapping[str, str], observed: Mapping[str, str]) -> tuple[bool, dict[str, str]]:
    """Require the same safe file set and exact lowercase SHA-256 values."""

    if not expected or set(expected) != set(observed):
        return False, dict(observed)
    for values in (expected, observed):
        if any(not isinstance(name, str) or not name for name in values):
            return False, dict(observed)
        if any(not isinstance(value, str) or len(value) != 64 or value != value.lower() or any(char not in _HEX_DIGEST for char in value) for value in values.values()):
            return False, dict(observed)
    return all(expected[name] == observed[name] for name in expected), dict(observed)


class PhysicalTargetOrchestrator:
    """Run the approved fixture lifecycle without duplicating target decisions."""

    def __init__(
        self,
        client: PhysicalTargetTransport,
        *,
        expected_target_id: str,
        expected_hashes: Mapping[str, str],
        observed_hashes: Mapping[str, str],
        cleanup: Callable[[], None] | None = None,
    ) -> None:
        self.client = client
        self.expected_target_id = expected_target_id
        self.expected_hashes = dict(expected_hashes)
        self.observed_hashes = dict(observed_hashes)
        self.cleanup = cleanup or (lambda: None)

    def run(self) -> PhysicalAssessmentResult:
        values: dict[str, Any] = {"code_hashes": dict(self.observed_hashes)}
        evidence: list[dict[str, Any]] = []
        reached = False
        cleanup_attempted = False
        cleanup_completed = False
        failure: str | None = None
        try:
            hashes_ok, hashes = verify_code_hashes(self.expected_hashes, self.observed_hashes)
            values.update({"code_hashes": hashes, "code_hashes_verified": hashes_ok})
            if not hashes_ok:
                raise PhysicalAssessmentError("deployed code hash mismatch")

            fixture = fixture_for("attack-indirect-email-v1", "poisoned-order-note-v1")
            discovery = self._call({
                "protocol_version": 1,
                "request_id": "physical-assessment-discover-01",
                "operation": "discover",
                "assessment_id": "physical-assessment-v1",
                "expected_target_id": self.expected_target_id,
            })
            self._require_target(discovery)
            reached = True
            values.update({
                "target_id": discovery["target_id"],
                "target_kind": discovery["target_kind"],
                "protocol_version": discovery["protocol_version"],
                "physical_target_reached": True,
                "policy_digest_before": discovery.get("policy_sha256"),
                "baseline_fixture_id": fixture.fixture_id,
                "baseline_fixture_sha256": fixture.fixture_sha256,
            })
            evidence.append({"stage": "discovery", "target_id": discovery["target_id"], "policy_sha256": discovery.get("policy_sha256")})

            baseline_request = self._execute_request("physical-assessment-baseline-01", fixture, discovery["policy_id"], discovery["target_id"])
            baseline = self._call(baseline_request)
            self._require_target(baseline)
            if baseline.get("fixture_sha256") != fixture.fixture_sha256 or baseline.get("authorization_decision") != "allowed" or baseline.get("executed") is not True or not baseline.get("synthetic_event_id") or baseline.get("impact_class") is None:
                raise PhysicalAssessmentError("baseline synthetic action invariant failed")
            values.update({
                "baseline_decision": baseline["authorization_decision"],
                "baseline_synthetic_impact_confirmed": True,
                "baseline_event_id": baseline["synthetic_event_id"],
                "baseline_ledger_count": baseline["ledger_sequence"],
            })
            evidence.extend([
                {"stage": "baseline-target-reached", "request_id": baseline_request["request_id"], "target_id": baseline["target_id"]},
                {"stage": "baseline-impact-confirmed", "fixture_sha256": baseline["fixture_sha256"], "action": baseline["action"], "decision": baseline["authorization_decision"], "event_id": baseline["synthetic_event_id"], "policy_sha256": baseline["policy_sha256"]},
            ])

            baseline_validation = self._call({
                "protocol_version": 1,
                "request_id": "physical-assessment-baseline-validate-01",
                "operation": "validate",
                "assessment_id": "physical-assessment-v1",
                "target_id": discovery["target_id"],
                "attack_id": fixture.attack_id,
                "fixture_sha256": fixture.fixture_sha256,
                "observed_request_id": baseline_request["request_id"],
            })
            if baseline_validation.get("validated") is not True or baseline_validation.get("synthetic_event_id") != baseline["synthetic_event_id"]:
                raise PhysicalAssessmentError("baseline synthetic impact validation failed")
            evidence.append({"stage": "baseline-impact-validated", "event_id": baseline_validation["synthetic_event_id"], "ledger_count": baseline_validation["ledger_sequence"]})

            remediation = self._call({
                "protocol_version": 1,
                "request_id": "physical-assessment-remediation-01",
                "operation": "apply_policy",
                "assessment_id": "physical-assessment-v1",
                "target_id": discovery["target_id"],
                "policy_id": "physical-remediation-policy-v1",
                "deny_actions": [fixture.action],
            })
            if remediation.get("denied_actions") != [fixture.action] or remediation.get("policy_sha256") == discovery.get("policy_sha256"):
                raise PhysicalAssessmentError("deny-only remediation invariant failed")
            values.update({
                "remediation_policy_id": remediation["policy_id"],
                "policy_digest_after": remediation["policy_sha256"],
                "deny_only_verified": True,
            })
            evidence.append({"stage": "deny-only-remediation", "policy_id": remediation["policy_id"], "policy_sha256_before": discovery["policy_sha256"], "policy_sha256_after": remediation["policy_sha256"], "denied_actions": remediation["denied_actions"]})

            replay_request = self._execute_request("physical-assessment-replay-01", fixture, remediation["policy_id"], discovery["target_id"])
            replay = self._call(replay_request)
            self._require_target(replay)
            exact = all(replay.get(key) == baseline.get(key) for key in ("fixture_sha256", "action", "attack_id", "fixture_id"))
            if not exact:
                raise PhysicalAssessmentError("exact replay fixture identity mismatch")
            if replay.get("authorization_decision") != "blocked" or replay.get("executed") is not False or replay.get("synthetic_event_id") is not None or replay.get("ledger_sequence") != baseline["ledger_sequence"]:
                raise PhysicalAssessmentError("replay blocking or ledger invariant failed")
            values.update({
                "replay_fixture_sha256": replay["fixture_sha256"],
                "exact_replay_identity_verified": True,
                "replay_target_reached": True,
                "replay_decision": replay["authorization_decision"],
                "replay_executed": replay["executed"],
                "replay_synthetic_impact_confirmed": False,
                "final_ledger_count": replay["ledger_sequence"],
                "fix_verified": True,
            })
            evidence.extend([
                {"stage": "exact-replay-target-reached", "request_id": replay_request["request_id"], "target_id": replay["target_id"]},
                {"stage": "replay-impact-not-confirmed", "fixture_sha256": replay["fixture_sha256"], "decision": replay["authorization_decision"], "executed": replay["executed"], "synthetic_event_id": None, "ledger_count": replay["ledger_sequence"]},
            ])
            replay_validation = self._call({
                "protocol_version": 1,
                "request_id": "physical-assessment-replay-validate-01",
                "operation": "validate",
                "assessment_id": "physical-assessment-v1",
                "target_id": discovery["target_id"],
                "attack_id": fixture.attack_id,
                "fixture_sha256": fixture.fixture_sha256,
                "observed_request_id": replay_request["request_id"],
            })
            if replay_validation.get("validated") is not False or replay_validation.get("synthetic_event_id") is not None or replay_validation.get("ledger_sequence") != baseline["ledger_sequence"]:
                raise PhysicalAssessmentError("replay no-impact validation invariant failed")
            evidence.append({"stage": "replay-no-impact-confirmed", "validated": False, "ledger_count": replay_validation["ledger_sequence"]})
            status = "PASS"
        except (PhysicalAssessmentError, KeyError, TypeError) as exc:
            failure = str(exc)
            status = "PARTIAL" if reached else "FAILED"
        finally:
            cleanup_attempted = True
            try:
                self.cleanup()
                cleanup_completed = True
            except Exception as exc:  # cleanup failure must never become a pass
                failure = f"{failure}; cleanup failed: {type(exc).__name__}" if failure else f"cleanup failed: {type(exc).__name__}"
                status = "PARTIAL" if reached else "FAILED"
        return PhysicalAssessmentResult(status=status, **values, evidence_chain=tuple(evidence), cleanup_attempted=cleanup_attempted, cleanup_completed=cleanup_completed, failure_reason=failure)

    def _call(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            result = self.client.request(payload)
        except Exception as exc:
            if isinstance(exc, PhysicalAssessmentError):
                raise
            raise PhysicalAssessmentError(f"transport failure: {type(exc).__name__}") from None
        if result.get("status") != "ok":
            raise PhysicalAssessmentError(f"target returned {result.get('error_code', 'error')}")
        return result

    def _require_target(self, response: Mapping[str, Any]) -> None:
        if response.get("target_id") != self.expected_target_id or response.get("target_kind") != "owned-isolated-synthetic-target" or response.get("protocol_version") != 1:
            raise PhysicalAssessmentError("target identity or protocol invariant failed")

    @staticmethod
    def _execute_request(request_id: str, fixture: Any, policy_id: str, target_id: str) -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "request_id": request_id,
            "operation": "execute",
            "assessment_id": "physical-assessment-v1",
            "target_id": target_id,
            "attack_id": fixture.attack_id,
            "fixture_id": fixture.fixture_id,
            "fixture_sha256": fixture.fixture_sha256,
            "action": fixture.action,
            "source": fixture.source,
            "policy_id": policy_id,
        }


def run_local_assessment(*, cleanup: Callable[[], None] | None = None) -> PhysicalAssessmentResult:
    """Run a deterministic local lifecycle without network access."""

    runtime = PhysicalTargetRuntime(node_instance_id="instance-local-assessment")
    fixture = fixture_for("attack-indirect-email-v1", "poisoned-order-note-v1")
    hashes = {"physical_target_runtime.py": "0" * 64}
    return PhysicalTargetOrchestrator(InProcessPhysicalTargetClient(runtime), expected_target_id=runtime.config.target_id, expected_hashes=hashes, observed_hashes=hashes, cleanup=cleanup).run()


def _load_manifest(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        values = json.load(handle)
    if not isinstance(values, dict) or not isinstance(values.get("expected"), dict) or not isinstance(values.get("observed"), dict):
        raise ValueError("hash manifest must contain expected and observed objects")
    return dict(values["expected"]), dict(values["observed"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one bounded Kimura physical synthetic-target assessment")
    parser.add_argument("--endpoint", required=True, help=f"explicit HTTP target endpoint ending in {NODE_PATH}")
    parser.add_argument("--target-id", required=True, help="expected owned synthetic target ID")
    parser.add_argument("--hash-manifest", type=Path, required=True, help="JSON object containing expected and observed SHA-256 maps")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        expected, observed = _load_manifest(args.hash_manifest)
        result = PhysicalTargetOrchestrator(
            HttpPhysicalTargetClient(args.endpoint, timeout=args.timeout),
            expected_target_id=args.target_id,
            expected_hashes=expected,
            observed_hashes=observed,
        ).run()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = PhysicalAssessmentResult(status="FAILED", failure_reason=f"configuration failure: {type(exc).__name__}", cleanup_attempted=False, cleanup_completed=False)
    print(result.to_json())
    return 0 if result.status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
