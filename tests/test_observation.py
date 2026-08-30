"""Synthetic, local-only fixtures for the generic independent observer V1."""

from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import unittest

import kimura_assessment.observation as observation_module
from kimura_assessment.boundary_proof import sha256
from kimura_assessment.observation import (
    CapturedResponse,
    EvidenceObserverV1,
    ObservationContext,
    ObservationStatus,
    StateSnapshot,
    observation_to_proof_capsule_fields,
)


NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def context(*, run_id="run-1", actor="actor-a", target="target-a", resource="resource-a", timestamp=None):
    return ObservationContext(
        assessment_id="assessment-1", run_id=run_id,
        pair_fingerprint=digest("pair-1"), request_fingerprint=digest("request-1"),
        actor_fingerprint=digest(actor), target_fingerprint=digest(target),
        resource_fingerprint=digest(resource),
        observation_timestamp=(timestamp or NOW.isoformat()), source_type="KIMURA_CAPTURED",
    )


def bindings(ctx):
    return ctx.bindings


def provenance(capture_id):
    return {"capture_id": capture_id, "captured_by": "kimura-observer-v1", "capture_method": "synthetic structured fixture"}


def response(ctx, *, capture_id="response-1", status=200, protected=True, denial=False, fields=None, headers=None):
    return CapturedResponse(
        status_code=status, normalized_headers_metadata=headers or {},
        body_content_digest=digest("body-" + capture_id),
        structured_response_fields=fields or ({"resource_fingerprint": ctx.resource_fingerprint} if protected else {}),
        capture_provenance=provenance(capture_id), evidence_bindings=bindings(ctx),
        protected_content_digest=digest("protected-" + capture_id) if protected else None,
        denial_evidence={"explicit_denial": True, "reason": "access denied"} if denial else None,
    )


def snapshot(ctx, state, capture_id):
    return StateSnapshot(
        resource_identity=ctx.resource_fingerprint,
        canonical_state_representation=state,
        state_digest=sha256(state), capture_provenance=provenance(capture_id),
        evidence_bindings=bindings(ctx),
    )


class ObservationV1Tests(unittest.TestCase):
    def observer(self, **kwargs):
        return EvidenceObserverV1(now=lambda: NOW, **kwargs)

    def test_positive_access_fixture_requires_protected_resource_evidence(self):
        ctx = context()
        result = self.observer().observe_access(ctx, response(ctx, protected=True))
        self.assertEqual(result.final_observation_status, ObservationStatus.ACCESS_PERMITTED_OBSERVED)
        self.assertEqual(result.confidence, "DETERMINISTIC_RULES_ONLY")

    def test_positive_denial_fixture_requires_explicit_denial_and_absence_of_content(self):
        ctx = context()
        result = self.observer().observe_access(ctx, response(ctx, status=403, protected=False, denial=True))
        self.assertEqual(result.final_observation_status, ObservationStatus.ACCESS_DENIED_OBSERVED)

    def test_positive_state_change_fixture(self):
        ctx = context()
        result = self.observer().observe_state(ctx, snapshot(ctx, {"enabled": False}, "before-1"), snapshot(ctx, {"enabled": True}, "after-1"))
        self.assertEqual(result.final_observation_status, ObservationStatus.STATE_CHANGE_CONFIRMED)
        self.assertTrue(result.effect.changed)
        self.assertEqual(result.effect.canonical_diff, {"enabled": {"before": False, "after": True}})

    def test_no_change_fixture(self):
        ctx = context()
        result = self.observer().observe_state(ctx, snapshot(ctx, {"enabled": True}, "before-2"), snapshot(ctx, {"enabled": True}, "after-2"))
        self.assertEqual(result.final_observation_status, ObservationStatus.NO_STATE_CHANGE_CONFIRMED)
        self.assertFalse(result.effect.changed)

    def test_insufficient_access_evidence_is_inconclusive(self):
        ctx = context()
        self.assertEqual(self.observer().observe_access(ctx, response(ctx, protected=False)).final_observation_status, ObservationStatus.INCONCLUSIVE)

    def test_http_403_with_protected_content_is_inconclusive(self):
        ctx = context()
        result = self.observer().observe_access(ctx, response(ctx, status=403, protected=True, denial=True))
        self.assertEqual(result.final_observation_status, ObservationStatus.INCONCLUSIVE)

    def test_model_and_operator_text_cannot_establish_effect(self):
        ctx = context()
        model_claim = response(ctx, protected=False, fields={"model_text": "success"})
        operator_claim = response(ctx, capture_id="response-operator", protected=False, status=403, fields={"operator_text": "denied"})
        self.assertEqual(self.observer().observe_access(ctx, model_claim).final_observation_status, ObservationStatus.INCONCLUSIVE)
        self.assertEqual(self.observer().observe_access(ctx, operator_claim).final_observation_status, ObservationStatus.INCONCLUSIVE)

    def test_cross_run_actor_target_resource_request_and_pair_mismatches_fail_closed(self):
        checks = (
            response(context(run_id="run-2")),
            response(context(actor="actor-b")),
            response(context(target="target-b")),
            response(context(resource="resource-b")),
            response(ObservationContext("assessment-1", "run-1", digest("pair-1"), digest("request-2"), digest("actor-a"), digest("target-a"), digest("resource-a"), NOW.isoformat(), "KIMURA_CAPTURED")),
            response(ObservationContext("assessment-1", "run-1", digest("pair-2"), digest("request-1"), digest("actor-a"), digest("target-a"), digest("resource-a"), NOW.isoformat(), "KIMURA_CAPTURED")),
        )
        current = context()
        for item in checks:
            with self.assertRaises(ValueError):
                self.observer().observe_access(current, item)

    def test_cross_run_before_after_pair_fails_closed(self):
        ctx = context()
        after_ctx = context(run_id="run-2")
        with self.assertRaises(ValueError):
            self.observer().observe_state(ctx, snapshot(ctx, {"v": 1}, "before-3"), snapshot(after_ctx, {"v": 2}, "after-3"))

    def test_stale_evidence_is_rejected(self):
        ctx = context(timestamp=(NOW - timedelta(minutes=16)).isoformat())
        with self.assertRaises(ValueError):
            self.observer().observe_access(ctx, response(ctx))

    def test_missing_and_malformed_provenance_evidence_is_rejected(self):
        ctx = context()
        with self.assertRaises(ValueError):
            response(ctx, capture_id="")
        with self.assertRaises(ValueError):
            CapturedResponse(200, {}, "not-a-digest", {}, {}, bindings(ctx))
        with self.assertRaises(ValueError):
            CapturedResponse(700, {}, None, {}, provenance("bad-status"), bindings(ctx))

    def test_duplicate_or_replayed_evidence_is_rejected(self):
        ctx = context()
        obs = self.observer()
        item = response(ctx, capture_id="unique-response")
        obs.observe_access(ctx, item)
        with self.assertRaises(ValueError):
            obs.observe_access(ctx, item)

    def test_redirect_to_another_target_is_inconclusive(self):
        ctx = context()
        result = self.observer().observe_access(ctx, response(ctx, headers={"redirect_target_fingerprint": digest("other-target")}))
        self.assertEqual(result.final_observation_status, ObservationStatus.INCONCLUSIVE)

    def test_expected_result_and_prior_case_labels_cannot_influence_observation(self):
        ctx = context()
        for claim in ("ACCESS_PERMITTED_OBSERVED", "BOUNDARY_HELD", "PERMITTED"):
            item = response(ctx, capture_id="claim-" + claim, protected=False, fields={"expected_result": claim})
            self.assertEqual(self.observer().observe_access(ctx, item).final_observation_status, ObservationStatus.INCONCLUSIVE)

    def test_human_observed_source_is_not_independently_usable(self):
        ctx = ObservationContext("assessment-1", "run-1", digest("pair-1"), digest("request-1"), digest("actor-a"), digest("target-a"), digest("resource-a"), NOW.isoformat(), "HUMAN_OBSERVED")
        with self.assertRaises(ValueError):
            self.observer().observe_access(ctx, response(ctx))

    def test_proof_capsule_integration_is_serializable_and_bounded(self):
        ctx = context()
        result = self.observer().observe_access(ctx, response(ctx))
        fields = observation_to_proof_capsule_fields(result)
        self.assertEqual(fields["observer_version"], "observer-v1")
        self.assertEqual(fields["provenance"], "KIMURA_INDEPENDENTLY_OBSERVED")
        self.assertEqual(fields["result"], "ACCESS_PERMITTED_OBSERVED")
        json.dumps(fields, sort_keys=True)

    def test_observer_has_no_network_execution_capability(self):
        source = inspect.getsource(observation_module)
        for forbidden in ("requests", "urllib", "httpx", "socket", "send("):
            self.assertNotIn(forbidden, source.lower())
        self.assertFalse(hasattr(EvidenceObserverV1, "send"))


if __name__ == "__main__":
    unittest.main()
