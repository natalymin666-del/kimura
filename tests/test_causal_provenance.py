import json
import unittest
from dataclasses import replace

from kimura_assessment.boundary_proof import BoundaryProofCapsule, BoundaryVerdict, ContainedImpactEvidence, independent_verdict
from kimura_assessment.causal_provenance import CausalProvenance, prove_causal_provenance, validate_causal_provenance
from kimura_assessment.privilege_boundary import build_privilege_baseline, build_privilege_proof_capsule


class CausalProvenanceTests(unittest.TestCase):
    def setUp(self):
        _, _, _, self.allowed, _ = build_privilege_baseline()
        self.request = self.allowed.attempted_action
        self.authorization = {"decision": self.allowed.authorization_decision, "tool_call_id": "tool-1"}
        self.execution = {"executed": True, "tool_call_id": "tool-1"}
        self.effect = {"effect_identity": self.allowed.effect_identity, "effect_count": self.allowed.effect_count}
        self.transition = {"state_before": self.allowed.state_before, "state_after": self.allowed.state_after}
        self.identity = {"run_id": "run-1", "experiment_id": "exp-1"}
        self.provenance = prove_causal_provenance(request=self.request, authorization=self.authorization,
            execution=self.execution, effect=self.effect, state_transition=self.transition,
            run_identity=self.identity, fixture_identity="fixture-1", twin_identity="ALLOWED")

    def test_complete_provenance_validates_and_is_fingerprinted(self):
        self.assertTrue(self.provenance.proven)
        self.assertTrue(validate_causal_provenance(self.provenance, request=self.request, authorization=self.authorization,
            execution=self.execution, effect=self.effect, state_transition=self.transition,
            run_identity=self.identity, fixture_identity="fixture-1", twin_identity="ALLOWED"))
        self.assertNotEqual(self.provenance.fingerprint, replace(self.provenance, proven=False).fingerprint)

    def test_each_missing_or_wrong_link_fails_closed(self):
        cases = [
            ("request_identity", {"request_fingerprint": "wrong"}),
            ("authorization_identity", {"request_fingerprint": "wrong"}),
            ("execution_identity", {"request_fingerprint": "wrong"}),
            ("effect_identity", {"execution_fingerprint": "wrong"}),
            ("state_transition_identity", {"effect_fingerprint": "wrong"}),
        ]
        for field, value in cases:
            bad = replace(self.provenance, **{field: value})
            self.assertFalse(validate_causal_provenance(bad, request=self.request, authorization=self.authorization,
                execution=self.execution, effect=self.effect, state_transition=self.transition,
                run_identity=self.identity, fixture_identity="fixture-1", twin_identity="ALLOWED"))

    def test_cross_run_twin_and_model_claims_fail(self):
        for identity, fixture, twin in (({"run_id": "other", "experiment_id": "exp-1"}, "fixture-1", "ALLOWED"),
                                         (self.identity, "fixture-1", "FORBIDDEN"),
                                         (self.identity, "other-fixture", "ALLOWED")):
            self.assertFalse(validate_causal_provenance(self.provenance, request=self.request, authorization=self.authorization,
                execution=self.execution, effect=self.effect, state_transition=self.transition,
                run_identity=identity, fixture_identity=fixture, twin_identity=twin))
        prose = replace(self.provenance, proven=False, request_identity={"claim": "causal"})
        self.assertFalse(prose.proven)

    def test_capsule_binds_provenance_and_unproven_impact_is_inconclusive(self):
        contract, pair, _, allowed, forbidden = build_privilege_baseline()
        base = build_privilege_proof_capsule(contract, pair, allowed, forbidden)
        capsule = BoundaryProofCapsule(**{**base.to_unsigned(), "causal_provenance": self.provenance.to_dict()})
        capsule.verify()
        self.assertEqual(independent_verdict(forbidden=forbidden, capsule=capsule), BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED)
        unproven = BoundaryProofCapsule(**{**base.to_unsigned(), "causal_provenance": replace(self.provenance, proven=False).to_dict()})
        self.assertEqual(independent_verdict(forbidden=forbidden, capsule=unproven), BoundaryVerdict.INCONCLUSIVE)

    def test_historical_live_artifact_is_readable_and_unchanged(self):
        with open("results/phase-6.2b-live-boundary-proof.json", encoding="utf-8") as handle:
            artifact = json.load(handle)
        self.assertEqual(artifact["experiment_id"], "phase-6.2b-20260828-1")
        self.assertEqual(artifact["attempts"][0]["capsule"]["capsule_sha256"], "8a7ee465ef9242bac144198302d376d6fad74e12c1b8c9b00bc9324d84d5a3bb")
        self.assertNotIn("causal_provenance", artifact["attempts"][0]["capsule"])


if __name__ == "__main__":
    unittest.main()
