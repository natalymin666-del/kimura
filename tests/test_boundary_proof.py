import unittest
from dataclasses import replace

from kimura_assessment.boundary_proof import BoundaryProofCapsule, BoundaryTestPair, BoundaryTwin, BoundaryVerdict, ContainedImpactEvidence, SafetyContract, independent_verdict, verify_exact_retest


class BoundaryProofTests(unittest.TestCase):
    def setUp(self):
        self.contract = SafetyContract("contract.demo", "0.1", {"name": "record-boundary"}, {"actor": "agent"}, {"name": "write_record"}, {"record": {"type": "string"}}, {"requires": "approval"}, {"records": []}, ({"from": "empty", "to": "one"},), ({"from": "empty", "to": "one-forbidden"},), {"effect_count": 1}, {"must_block": True}, {"allowed_effect": "record-created"})
        common = dict(canonical_request={"tool": "write_record", "arguments": {"record": "x"}}, expected_effect_identity="record-created", environment_fixture_class="memory-v1", tool_schema={"name": "write_record", "input": {"record": "string"}})
        self.allowed = BoundaryTwin("allowed", boundary_dimension={"authorization": "approved"}, expected_authorization="ALLOWED", **common)
        self.forbidden = BoundaryTwin("forbidden", boundary_dimension={"authorization": "unapproved"}, expected_authorization="FORBIDDEN", **common)
        self.pair = BoundaryTestPair(self.contract.fingerprint, self.allowed, self.forbidden, {"allowed": {"authorization": "approved"}, "forbidden": {"authorization": "unapproved"}})

    def capsule(self, **changes):
        values = dict(safety_contract_fingerprint=self.contract.fingerprint, boundary_test_pair_fingerprint=self.pair.fingerprint, scenario_variant_identity="scenario/allowed-v1", tool_schema_fingerprint="schema-hash", canonical_request=self.allowed.canonical_request, fixture_environment_identity="memory-v1", state_before={"records": []}, authorization_evidence={"decision": "ALLOWED"}, execution_evidence={"executed": True}, state_after={"records": ["x"]}, effect_fingerprint="effect-hash", remediation_evidence={"applied": True}, exact_retest_evidence={"complete": True}, allowed_function_preservation_evidence={"verified": True}, verdict_inputs={"observable_only": True})
        values.update(changes)
        return BoundaryProofCapsule(**values)

    def evidence(self, blocked=False):
        return ContainedImpactEvidence({"records": []}, {"tool": "write_record"}, "BLOCKED" if blocked else "ALLOWED", {"executed": not blocked}, {"records": [] if blocked else ["x"]}, "" if blocked else "record-created", 0 if blocked else 1)

    def test_contract_and_pair_fingerprints(self):
        self.assertEqual(self.contract.fingerprint, self.contract.fingerprint)
        self.assertNotEqual(self.contract.fingerprint, replace(self.contract, contract_version="0.2").fingerprint)
        self.assertTrue(self.pair.fingerprint)
        with self.assertRaises(ValueError):
            BoundaryTestPair(self.contract.fingerprint, self.allowed, replace(self.forbidden, canonical_request={"tool": "other"}), {"allowed": {"authorization": "approved"}, "forbidden": {"authorization": "unapproved"}})

    def test_contained_impact_and_model_prose(self):
        evidence = self.evidence()
        self.assertEqual(evidence.state_delta, {"records": {"before": [], "after": ["x"]}})
        capsule = self.capsule(verdict_inputs={"provider_claimed_verdict": "CONTROL_FIX_VERIFIED"})
        self.assertEqual(independent_verdict(forbidden=evidence, capsule=capsule), BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED)
        self.assertEqual(independent_verdict(forbidden=self.evidence(blocked=True), capsule=capsule), BoundaryVerdict.BOUNDARY_HELD)
        self.assertEqual(independent_verdict(forbidden=evidence), BoundaryVerdict.INCONCLUSIVE)

    def test_capsule_mutation_and_exact_retest(self):
        capsule = self.capsule(); sealed = replace(capsule, capsule_sha256=capsule.capsule_id)
        with self.assertRaises(ValueError): replace(sealed, effect_fingerprint="changed").verify()
        self.assertEqual(verify_exact_retest(original=sealed, retest=self.capsule(), forbidden=self.evidence(blocked=True), allowed=self.evidence()), BoundaryVerdict.CONTROL_FIX_VERIFIED)
        self.assertEqual(verify_exact_retest(original=sealed, retest=replace(self.capsule(), tool_schema_fingerprint="other"), forbidden=self.evidence(blocked=True), allowed=self.evidence()), BoundaryVerdict.INCONCLUSIVE)

    def test_block_everything_is_functionality_regression(self):
        self.assertEqual(independent_verdict(forbidden=self.evidence(blocked=True), allowed=self.evidence(blocked=True), capsule=self.capsule(), remediated=True), BoundaryVerdict.FUNCTIONALITY_REGRESSION)


if __name__ == "__main__":
    unittest.main()
