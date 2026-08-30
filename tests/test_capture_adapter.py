"""Synthetic local-only tests for Authorized Evidence Capture Adapter V1."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import unittest

import kimura_assessment.capture_adapter as adapter_module
from kimura_assessment.boundary_proof import sha256
from kimura_assessment.capture_adapter import (
    AuthorizedCaptureContext,
    CaptureArtifact,
    CaptureError,
    CaptureNotAuthorized,
    CaptureRedirectRejected,
    CaptureReplayRejected,
    CaptureSecretRejected,
    CaptureTransportFailure,
    EvidenceCaptureAdapterV1,
    LocalTransportFixture,
    SealedRequest,
    StateCapture,
    proof_capsule_capture_fields,
)
from kimura_assessment.observation import EvidenceObserverV1, ObservationStatus


NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
CONTRACT = hashlib.sha256(b"synthetic-authorization-contract").hexdigest()
PAIR = hashlib.sha256(b"synthetic-pair").hexdigest()
TARGET = "synthetic.target.local"
RESOURCE = "/protected/record"


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def sealed_request(*, target=TARGET, resource=RESOURCE, arguments=None, redirect_policy=None):
    unsigned = {
        "method_or_action": "GET",
        "canonical_target": target,
        "canonical_resource": resource,
        "canonical_arguments": arguments or {},
        "expected_target_identity": target,
        "redirect_policy": redirect_policy or {
            "allowed_target_identities": [target],
            "allowed_resources": [resource],
            "allow_scheme_downgrade": False,
        },
        "body_digest": None,
    }
    return SealedRequest(**unsigned, request_fingerprint=sha256(unsigned))


def context(request, *, run="run-1", actor="actor-a", state="AUTHORIZED", approval="approval-1", nonce="nonce-0001", contract=CONTRACT, issued=None, expires=None):
    issued = issued or NOW - timedelta(seconds=1)
    expires = expires or NOW + timedelta(minutes=5)
    return AuthorizedCaptureContext(
        assessment_id="assessment-1", run_id=run, pair_fingerprint=PAIR,
        request_fingerprint=request.request_fingerprint, actor_fingerprint=digest(actor),
        target_fingerprint=digest(request.expected_target_identity),
        resource_fingerprint=digest(request.canonical_resource),
        authorization_contract_fingerprint=contract, authorization_state=state,
        approval_id=approval, capture_nonce=nonce,
        issued_at=issued.isoformat(), expires_at=expires.isoformat(),
    )


def make_adapter():
    return EvidenceCaptureAdapterV1(authorization_contract_fingerprint=CONTRACT, assessment_id="assessment-1", run_id="run-1", pair_fingerprint=PAIR, allowed_actor_fingerprints=frozenset({digest("actor-a"), digest("actor-b")}), now=lambda: NOW)


def protected_scenario(request, *, denial=False, ambiguous=False, redirect_chain=None):
    if ambiguous:
        return {"response_metadata": {"status_code": 200, "headers": {}}, "response_body_digest": digest("ambiguous")}
    if denial:
        return {
            "response_metadata": {"status_code": 403, "headers": {}},
            "response_body_digest": digest("denial"),
            "protected_resource_evidence": {"denial_evidence": {"explicit_denial": True}},
            "redirect_chain": redirect_chain or [],
        }
    return {
        "response_metadata": {"status_code": 200, "headers": {}},
        "response_body_digest": digest("body"),
        "protected_resource_evidence": {
            "protected_content_digest": digest("protected"),
            "structured_response_fields": {"resource_fingerprint": digest(request.canonical_resource)},
        },
        "redirect_chain": redirect_chain or [],
    }


def capture_and_observe(request, ctx, scenario):
    adapter = make_adapter()
    artifact = adapter.capture(ctx, request, LocalTransportFixture(scenario))
    obs_ctx = __import__("kimura_assessment.capture_adapter", fromlist=["capture_artifact_to_observation_context"]).capture_artifact_to_observation_context(ctx)
    observation = EvidenceObserverV1(now=lambda: NOW).observe_access(obs_ctx, artifact.to_observer_response(obs_ctx.bindings))
    return artifact, observation


def local_pair_verdict(allowed_observation, forbidden_observation):
    if allowed_observation.final_observation_status != ObservationStatus.ACCESS_PERMITTED_OBSERVED:
        return "INCONCLUSIVE"
    if forbidden_observation.final_observation_status == ObservationStatus.ACCESS_DENIED_OBSERVED:
        return "BOUNDARY_HELD"
    if forbidden_observation.final_observation_status == ObservationStatus.ACCESS_PERMITTED_OBSERVED:
        return "BOUNDARY_VIOLATION_CONFIRMED"
    return "INCONCLUSIVE"


class CaptureAdapterV1Tests(unittest.TestCase):
    def setUp(self):
        self.request = sealed_request()
        self.ctx = context(self.request)
        self.adapter = make_adapter()

    def test_local_allowed_and_forbidden_pipeline_and_proof_bindings(self):
        allowed_artifact = self.adapter.capture(self.ctx, self.request, LocalTransportFixture(protected_scenario(self.request)))
        allowed_ctx = __import__("kimura_assessment.capture_adapter", fromlist=["capture_artifact_to_observation_context"]).capture_artifact_to_observation_context(self.ctx)
        allowed_obs = EvidenceObserverV1(now=lambda: NOW).observe_access(allowed_ctx, allowed_artifact.to_observer_response(allowed_ctx.bindings))
        forbidden_ctx = context(self.request, actor="actor-b", approval="approval-2", nonce="nonce-0002")
        forbidden_artifact = self.adapter.capture(forbidden_ctx, self.request, LocalTransportFixture(protected_scenario(self.request, denial=True)))
        forbidden_obs = EvidenceObserverV1(now=lambda: NOW).observe_access(__import__("kimura_assessment.capture_adapter", fromlist=["capture_artifact_to_observation_context"]).capture_artifact_to_observation_context(forbidden_ctx), forbidden_artifact.to_observer_response(__import__("kimura_assessment.capture_adapter", fromlist=["capture_artifact_to_observation_context"]).capture_artifact_to_observation_context(forbidden_ctx).bindings))
        self.assertEqual(allowed_obs.final_observation_status, ObservationStatus.ACCESS_PERMITTED_OBSERVED)
        self.assertEqual(forbidden_obs.final_observation_status, ObservationStatus.ACCESS_DENIED_OBSERVED)
        self.assertEqual((allowed_obs.final_observation_status.value, forbidden_obs.final_observation_status.value), ("ACCESS_PERMITTED_OBSERVED", "ACCESS_DENIED_OBSERVED"))
        fields = proof_capsule_capture_fields(adapter=self.adapter, authorization_contract_fingerprint=CONTRACT, approval_id="approval-1|approval-2", pair_fingerprint=PAIR, run_id="run-1", allowed_capture=allowed_artifact, forbidden_capture=forbidden_artifact, allowed_observation=allowed_obs, forbidden_observation=forbidden_obs)
        self.assertEqual(fields["provenance"], "KIMURA_INDEPENDENTLY_OBSERVED")
        self.assertEqual(fields["pair_fingerprint"], PAIR)

    def test_vulnerable_variant_is_observable_but_adapter_does_not_verdict(self):
        artifact, observation = capture_and_observe(self.request, context(self.request, actor="actor-b", approval="approval-v", nonce="nonce-vvvv"), protected_scenario(self.request))
        self.assertEqual(observation.final_observation_status, ObservationStatus.ACCESS_PERMITTED_OBSERVED)
        self.assertEqual(local_pair_verdict(observation, observation), "BOUNDARY_VIOLATION_CONFIRMED")
        self.assertFalse(hasattr(artifact, "final_verdict"))
        self.assertFalse(hasattr(self.adapter, "derive_verdict"))

    def test_local_higher_level_verifier_derives_held_from_both_captures(self):
        allowed_artifact, allowed_observation = capture_and_observe(self.request, self.ctx, protected_scenario(self.request))
        forbidden_artifact, forbidden_observation = capture_and_observe(self.request, context(self.request, actor="actor-b", approval="approval-held", nonce="nonce-held1"), protected_scenario(self.request, denial=True))
        self.assertEqual(allowed_artifact.request_fingerprint, forbidden_artifact.request_fingerprint)
        self.assertEqual(local_pair_verdict(allowed_observation, forbidden_observation), "BOUNDARY_HELD")

    def test_authorization_mismatches_fail_closed(self):
        cases = (
            replace(self.ctx, authorization_state="NOT_AUTHORIZED"),
            replace(self.ctx, assessment_id="other"),
            replace(self.ctx, run_id="other-run"),
            replace(self.ctx, pair_fingerprint=digest("other-pair")),
            replace(self.ctx, request_fingerprint=digest("other-request")),
            replace(self.ctx, actor_fingerprint=digest("actor-c")),
            replace(self.ctx, target_fingerprint=digest("other-target")),
            replace(self.ctx, resource_fingerprint=digest("other-resource")),
            replace(self.ctx, authorization_contract_fingerprint=digest("other-contract")),
            replace(self.ctx, approval_id=""),
        )
        for bad in cases:
            with self.assertRaises(CaptureNotAuthorized):
                make_adapter().capture(bad, self.request, LocalTransportFixture(protected_scenario(self.request)))

    def test_expired_approval_rejected(self):
        expired = context(self.request, issued=NOW - timedelta(minutes=5), expires=NOW - timedelta(seconds=1))
        with self.assertRaises(CaptureNotAuthorized):
            self.adapter.capture(expired, self.request, LocalTransportFixture(protected_scenario(self.request)))

    def test_approval_and_nonce_are_one_shot(self):
        self.adapter.capture(self.ctx, self.request, LocalTransportFixture(protected_scenario(self.request)))
        with self.assertRaises(CaptureReplayRejected):
            self.adapter.capture(self.ctx, self.request, LocalTransportFixture(protected_scenario(self.request)))
        new_approval_same_nonce = context(self.request, approval="approval-2", nonce=self.ctx.capture_nonce)
        with self.assertRaises(CaptureReplayRejected):
            self.adapter.capture(new_approval_same_nonce, self.request, LocalTransportFixture(protected_scenario(self.request)))

    def test_redirect_target_resource_and_scheme_escape_rejected(self):
        for redirect in (
            {"target_identity": "other.target.local", "resource": RESOURCE},
            {"target_identity": TARGET, "resource": "/unsealed"},
            {"target_identity": TARGET, "resource": RESOURCE, "scheme_downgrade": True},
        ):
            ctx = context(self.request, approval="approval-" + digest(json.dumps(redirect))[:8], nonce="nonce-" + digest(json.dumps(redirect))[:8])
            with self.assertRaises(CaptureRedirectRejected):
                make_adapter().capture(ctx, self.request, LocalTransportFixture(protected_scenario(self.request, redirect_chain=[redirect])))

    def test_secret_bearing_request_or_artifact_rejected(self):
        with self.assertRaises(CaptureSecretRejected):
            sealed_request(arguments={"Authorization": "Bearer secret"})
        with self.assertRaises(CaptureSecretRejected):
            self.adapter.capture(self.ctx, self.request, LocalTransportFixture({"response_metadata": {"headers": {"Set-Cookie": "secret"}}}))
        with self.assertRaises(CaptureSecretRejected):
            CaptureArtifact(sha256("capture"), NOW.isoformat(), "assessment-1", "run-1", PAIR, self.request.request_fingerprint, self.ctx.actor_fingerprint, self.ctx.target_fingerprint, self.ctx.resource_fingerprint, {"authorization": "secret"}, None, None, (), {"adapter_version": "v1", "capture_id": "id", "source_type": "KIMURA_CAPTURED"}, "0" * 64)

    def test_transport_failure_consumes_approval_and_cannot_retry(self):
        with self.assertRaises(CaptureTransportFailure):
            self.adapter.capture(self.ctx, self.request, LocalTransportFixture({"transport_failure": True}))
        with self.assertRaises(CaptureReplayRejected):
            self.adapter.capture(self.ctx, self.request, LocalTransportFixture(protected_scenario(self.request)))

    def test_ambiguous_capture_does_not_become_denial(self):
        _, observation = capture_and_observe(self.request, self.ctx, protected_scenario(self.request, ambiguous=True))
        self.assertEqual(observation.final_observation_status, ObservationStatus.INCONCLUSIVE)

    def test_tampered_artifact_and_substituted_capture_fail_closed(self):
        artifact = self.adapter.capture(self.ctx, self.request, LocalTransportFixture(protected_scenario(self.request)))
        with self.assertRaises(CaptureError):
            replace(artifact, response_body_digest=digest("tampered")).verify()
        other_ctx = context(self.request, actor="actor-b", approval="approval-2", nonce="nonce-0002")
        other = make_adapter().capture(other_ctx, self.request, LocalTransportFixture(protected_scenario(self.request)))
        obs_ctx = __import__("kimura_assessment.capture_adapter", fromlist=["capture_artifact_to_observation_context"]).capture_artifact_to_observation_context(self.ctx)
        with self.assertRaises(ValueError):
            EvidenceObserverV1(now=lambda: NOW).observe_access(obs_ctx, other.to_observer_response(obs_ctx.bindings))

    def test_state_capture_is_canonical_and_machine_bindable(self):
        state = StateCapture(self.ctx.resource_fingerprint, "BEFORE", {"enabled": False}, sha256({"enabled": False}), {"capture_id": "state-before", "captured_by": "fixture", "capture_method": "local"})
        snapshot = state.to_observer_snapshot(self.ctx.__dict__ if False else {
            "assessment_id": self.ctx.assessment_id, "run_id": self.ctx.run_id,
            "pair_fingerprint": self.ctx.pair_fingerprint, "request_fingerprint": self.ctx.request_fingerprint,
            "actor_fingerprint": self.ctx.actor_fingerprint, "target_fingerprint": self.ctx.target_fingerprint,
            "resource_fingerprint": self.ctx.resource_fingerprint,
        })
        self.assertEqual(snapshot.state_digest, sha256({"enabled": False}))
        self.assertEqual(snapshot.resource_identity, self.ctx.resource_fingerprint)

    def test_adapter_is_generic_and_has_no_network_execution(self):
        source = inspect.getsource(adapter_module).lower()
        for forbidden in ("slack", "hackerone", "refund", "grok", "requests", "httpx", "urllib", "socket", "subprocess", "browser"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("boundary_held", source)
        self.assertNotIn("boundary_violation_confirmed", source)

    def test_case_001_remains_unchanged(self):
        from pathlib import Path
        root = Path(__file__).parents[1]
        case = json.loads((root / "evidence/cases/EXTERNAL_BOUNDARY_CASE_001.json").read_text())
        self.assertEqual(case["final_verdict"], "BOUNDARY_HELD")
        self.assertFalse(case["vulnerability_claimed"])
        self.assertEqual(case["evidence_provenance"]["independent_network_verification"], "NONE")
        self.assertEqual(case["pair_fingerprint"], "2a68559340d66f65bd2d3a52d74c06dfa4d8a62f767790d2b88ba2aa7852e083")


if __name__ == "__main__":
    unittest.main()
