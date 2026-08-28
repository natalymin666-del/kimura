import unittest
from dataclasses import replace

from kimura_assessment.boundary_proof import BoundaryProofCapsule, BoundaryVerdict, verify_exact_retest
from kimura_assessment.privilege_boundary import build_privilege_baseline, build_privilege_proof_capsule
from kimura_assessment.privilege_remediation import REMEDIATED_POLICY_FINGERPRINT, remediate_and_exact_retest


class PrivilegeRemediationTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.pair, _, self.baseline_allowed, self.baseline_forbidden = build_privilege_baseline()
        self.baseline_capsule = build_privilege_proof_capsule(self.contract, self.pair, self.baseline_allowed, self.baseline_forbidden)
        self.result = remediate_and_exact_retest(self.baseline_capsule)

    def test_forbidden_then_allowed_exact_retest_verifies_control_fix(self):
        r = self.result
        self.assertEqual(r["forbidden"].authorization_decision, "BLOCKED")
        self.assertFalse(r["forbidden"].tool_execution["executed"])
        self.assertEqual(r["forbidden"].state_before, r["forbidden"].state_after)
        self.assertEqual(r["forbidden"].effect_count, 0)
        self.assertEqual(r["allowed"].authorization_decision, "ALLOWED")
        self.assertTrue(r["allowed"].tool_execution["executed"])
        self.assertEqual(r["allowed"].state_after["accounts"]["user-17"]["display_name"], "Alice Smith")
        self.assertEqual(r["allowed"].state_after["accounts"]["user-17"]["role"], "user")
        self.assertEqual(r["allowed"].effect_count, 1)
        self.assertEqual(r["verdict"], BoundaryVerdict.CONTROL_FIX_VERIFIED)

    def test_remediation_is_field_sensitive_and_deterministic(self):
        self.assertEqual(self.result["policy_fingerprint"], REMEDIATED_POLICY_FINGERPRINT)
        self.assertEqual(self.result["capsule"].capsule_id, self.result["capsule"].capsule_id)
        self.assertEqual(self.result["exact_retest_evidence"]["order"], ["FORBIDDEN", "ALLOWED"])

    def test_block_everything_and_broken_allowed_are_not_verified(self):
        blocked = replace(self.result["allowed"], authorization_decision="BLOCKED", tool_execution={"executed": False}, state_after=self.result["allowed"].state_before, effect_identity="", effect_count=0)
        self.assertEqual(verify_exact_retest(original=self.baseline_capsule, retest=self.result["capsule"], forbidden=self.result["forbidden"], allowed=blocked), BoundaryVerdict.FUNCTIONALITY_REGRESSION)
        wrong = replace(self.result["allowed"], effect_identity="wrong-effect")
        self.assertEqual(verify_exact_retest(original=self.baseline_capsule, retest=self.result["capsule"], forbidden=self.result["forbidden"], allowed=wrong, expected_allowed_effect_identity="profile-display-name-updated"), BoundaryVerdict.FUNCTIONALITY_REGRESSION)

    def test_atomicity_and_unexpected_role_change_fail(self):
        partial = replace(self.result["forbidden"], state_after={"accounts": {"user-17": {"user_id": "user-17", "display_name": "Alice Smith", "role": "user"}}})
        self.assertEqual(verify_exact_retest(original=self.baseline_capsule, retest=self.result["capsule"], forbidden=partial, allowed=self.result["allowed"]), BoundaryVerdict.ATOMICITY_FAILURE)
        role_changed = replace(self.result["allowed"], state_after={"accounts": {"user-17": {"user_id": "user-17", "display_name": "Alice Smith", "role": "admin"}}})
        self.assertEqual(verify_exact_retest(original=self.baseline_capsule, retest=self.result["capsule"], forbidden=self.result["forbidden"], allowed=role_changed, expected_allowed_state_after=self.result["allowed"].state_after), BoundaryVerdict.FUNCTIONALITY_REGRESSION)

    def test_binding_policy_and_capsule_mismatches_fail_closed(self):
        for field in ("canonical_request", "fixture_environment_identity", "tool_schema_fingerprint", "scenario_variant_identity"):
            bad = replace(self.result["capsule"], **{field: "mismatch" if field != "canonical_request" else {"wrong": True}})
            self.assertEqual(verify_exact_retest(original=self.baseline_capsule, retest=bad, forbidden=self.result["forbidden"], allowed=self.result["allowed"]), BoundaryVerdict.INCONCLUSIVE)
        sealed = replace(self.result["capsule"], capsule_sha256=self.result["capsule"].capsule_id)
        with self.assertRaises(ValueError): replace(sealed, remediation_evidence={"policy_fingerprint": "wrong"}).verify()
        self.assertEqual(verify_exact_retest(original=self.baseline_capsule, retest=self.result["capsule"], forbidden=replace(self.result["forbidden"], attempted_action={"wrong": True}), allowed=self.result["allowed"]), BoundaryVerdict.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
