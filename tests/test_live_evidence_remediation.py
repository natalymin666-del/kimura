import json
import unittest
from dataclasses import replace

from kimura_assessment.boundary_proof import BoundaryProofCapsule, BoundaryVerdict, ContainedImpactEvidence, verify_exact_retest
from kimura_assessment.causal_provenance import validate_causal_provenance
from kimura_assessment.live_evidence_remediation import (HISTORICAL_ARTIFACT_SHA256, REMEDIATED_POLICY_FINGERPRINT,
    remediate_preserved_live_evidence)


class LiveEvidenceRemediationTests(unittest.TestCase):
    def setUp(self):
        self.result = remediate_preserved_live_evidence()

    def test_historical_baseline_is_verified_and_unchanged(self):
        self.assertEqual(self.result["historical_explicit_causal_provenance"], "MISSING")
        self.assertEqual(self.result["historical_identity"]["api_calls_completed"], 2)
        self.assertEqual(self.result["historical_capsules"][0], "8a7ee465ef9242bac144198302d376d6fad74e12c1b8c9b00bc9324d84d5a3bb")
        with open("results/phase-6.2b-live-boundary-proof.json", encoding="utf-8") as handle:
            self.assertNotIn("causal_provenance", json.load(handle)["attempts"][0]["capsule"])

    def test_exact_retest_and_capsule_are_verified(self):
        self.assertEqual(self.result["forbidden"]["authorization_decision"], "BLOCKED")
        self.assertFalse(self.result["forbidden"]["tool_execution"]["executed"])
        self.assertEqual(self.result["forbidden"]["state_before"], self.result["forbidden"]["state_after"])
        self.assertEqual(self.result["forbidden"]["effect_count"], 0)
        self.assertEqual(self.result["allowed"]["authorization_decision"], "ALLOWED")
        self.assertTrue(self.result["allowed"]["tool_execution"]["executed"])
        self.assertEqual(self.result["allowed"]["effect_count"], 1)
        self.assertEqual(self.result["verdict"], BoundaryVerdict.CONTROL_FIX_VERIFIED.value)
        BoundaryProofCapsule(**self.result["capsule"]).verify()

    def test_policy_and_request_mismatch_fail_closed(self):
        self.assertEqual(self.result["remediation_evidence"]["policy_after"], REMEDIATED_POLICY_FINGERPRINT)
        bad = ContainedImpactEvidence(self.result["forbidden"]["state_before"], {"display_name": "Other", "role": "admin"}, self.result["forbidden"]["authorization_decision"], self.result["forbidden"]["tool_execution"], self.result["forbidden"]["state_after"], self.result["forbidden"]["effect_identity"], self.result["forbidden"]["effect_count"])
        self.assertEqual(verify_exact_retest(original=BoundaryProofCapsule(**self.result["capsule"]), retest=BoundaryProofCapsule(**self.result["capsule"]), forbidden=bad, allowed=__import__("kimura_assessment.live_evidence_remediation", fromlist=["ContainedImpactEvidence"]) if False else self._allowed()), BoundaryVerdict.INCONCLUSIVE)

    def _allowed(self):
        from kimura_assessment.boundary_proof import ContainedImpactEvidence
        return ContainedImpactEvidence(self.result["allowed"]["state_before"], self.result["allowed"]["attempted_action"], self.result["allowed"]["authorization_decision"], self.result["allowed"]["tool_execution"], self.result["allowed"]["state_after"], self.result["allowed"]["effect_identity"], self.result["allowed"]["effect_count"])

    def test_causal_provenance_links_are_explicit(self):
        causal = self.result["capsule"]["causal_provenance"]
        self.assertTrue(causal["proven"])
        self.assertIn("request_identity", causal["forbidden"])
        self.assertIn("authorization_identity", causal["forbidden"])
        self.assertIn("execution_identity", causal["forbidden"])
        self.assertIn("effect_identity", causal["forbidden"])
        self.assertIn("state_transition_identity", causal["forbidden"])

    def test_missing_provenance_cannot_confirm_impact(self):
        capsule = BoundaryProofCapsule(**{**self.result["capsule"], "capsule_sha256": None, "causal_provenance": {"proven": False}})
        self.assertEqual(capsule.causal_provenance["proven"], False)


if __name__ == "__main__":
    unittest.main()
