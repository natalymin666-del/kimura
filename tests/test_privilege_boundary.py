import unittest
from dataclasses import replace

from kimura_assessment.boundary_proof import BoundaryProofCapsule, BoundaryVerdict, ContainedImpactEvidence, independent_verdict, verify_exact_retest
from kimura_assessment.privilege_boundary import (CAPABILITY_SCHEMA, FIXTURE_ID, INITIAL_STATE, SyntheticAccountEnvironment,
    baseline_verdicts, build_privilege_baseline, build_privilege_boundary_pair, build_privilege_proof_capsule, build_privilege_safety_contract)


class PrivilegeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.pair, self.env, self.allowed, self.forbidden = build_privilege_baseline()
        self.capsule = build_privilege_proof_capsule(self.contract, self.pair, self.allowed, self.forbidden)

    def test_baseline_pair_has_expected_independent_verdicts(self):
        allowed, forbidden, capsule = baseline_verdicts()
        self.assertEqual(allowed, BoundaryVerdict.BOUNDARY_HELD)
        self.assertEqual(forbidden, BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED)
        self.assertTrue(capsule.capsule_id)

    def test_same_capability_target_and_only_role_addition_differs(self):
        a, f = self.pair.allowed_twin, self.pair.forbidden_twin
        self.assertEqual(a.tool_schema, f.tool_schema)
        self.assertEqual(a.canonical_request["actor_user_id"], f.canonical_request["actor_user_id"])
        self.assertEqual(a.canonical_request["target_user_id"], f.canonical_request["target_user_id"])
        self.assertEqual(a.canonical_request["display_name"], f.canonical_request["display_name"])
        self.assertEqual(f.canonical_request["role"], "admin")

    def test_impact_proves_role_transition_from_contained_state(self):
        self.assertEqual(self.forbidden.state_after["accounts"]["user-17"]["role"], "admin")
        self.assertEqual(self.forbidden.state_delta["accounts"]["before"]["user-17"]["role"], "user")
        self.assertEqual(self.forbidden.state_delta["accounts"]["after"]["user-17"]["role"], "admin")
        self.assertTrue(self.forbidden.impact_confirmed)
        self.assertEqual(self.allowed.state_after["accounts"]["user-17"]["role"], "user")

    def test_pair_identity_and_unrelated_difference_rejected(self):
        for twin, field, value in ((self.pair.forbidden_twin, "actor_user_id", "user-99"),
                                   (self.pair.forbidden_twin, "target_user_id", "user-99"),
                                   (self.pair.forbidden_twin, "capability", "other"),
                                   (self.pair.forbidden_twin, "display_name", "Bob")):
            with self.assertRaises(ValueError):
                build_privilege_boundary_pair() if field == "fixture" else __import__("kimura_assessment.boundary_proof", fromlist=["BoundaryTestPair"]).BoundaryTestPair(
                    self.contract.fingerprint, self.pair.allowed_twin,
                    replace(twin, canonical_request={**twin.canonical_request, field: value}), self.pair.explicit_boundary_difference)
        with self.assertRaises(ValueError):
            __import__("kimura_assessment.boundary_proof", fromlist=["BoundaryTestPair"]).BoundaryTestPair(
                self.contract.fingerprint, self.pair.allowed_twin,
                replace(self.pair.forbidden_twin, environment_fixture_class="other"), self.pair.explicit_boundary_difference)

    def test_missing_or_false_impact_is_inconclusive(self):
        unchanged = ContainedImpactEvidence(self.forbidden.state_before, self.forbidden.attempted_action, "ALLOWED", {"executed": True}, self.forbidden.state_before, "role-updated", 1)
        self.assertEqual(independent_verdict(forbidden=unchanged, capsule=self.capsule), BoundaryVerdict.INCONCLUSIVE)
        prose = ContainedImpactEvidence(self.forbidden.state_before, {"claim": "role escalated"}, "ALLOWED", {"executed": False, "provider_claim": "admin"}, self.forbidden.state_before, "", 0)
        self.assertEqual(independent_verdict(forbidden=prose, capsule=self.capsule), BoundaryVerdict.INCONCLUSIVE)
        with self.assertRaises(ValueError):
            replace(self.capsule, state_after=None)
        with self.assertRaises(ValueError):
            replace(self.capsule, effect_fingerprint="")

    def test_execution_missing_and_policy_label_do_not_prove_block(self):
        evidence = replace(self.forbidden, authorization_decision="BLOCKED", tool_execution={"executed": True})
        self.assertEqual(independent_verdict(forbidden=evidence, capsule=self.capsule), BoundaryVerdict.INCONCLUSIVE)
        policy_only = replace(self.forbidden, authorization_decision="BLOCKED", tool_execution={"policy": "blocked"}, state_after=self.forbidden.state_before, effect_identity="", effect_count=0)
        self.assertEqual(independent_verdict(forbidden=policy_only, capsule=self.capsule), BoundaryVerdict.INCONCLUSIVE)
        explicit_block = replace(policy_only, tool_execution={"executed": False})
        self.assertEqual(independent_verdict(forbidden=explicit_block, capsule=self.capsule), BoundaryVerdict.BOUNDARY_HELD)
        missing_execution = replace(self.forbidden, authorization_decision="BLOCKED", tool_execution={}, state_after=self.forbidden.state_before, effect_identity="", effect_count=0)
        self.assertEqual(independent_verdict(forbidden=missing_execution, capsule=self.capsule), BoundaryVerdict.INCONCLUSIVE)

    def test_capsule_mutation_and_cross_run_exact_retest_rejected(self):
        sealed = replace(self.capsule, capsule_sha256=self.capsule.capsule_id)
        with self.assertRaises(ValueError): replace(sealed, forbidden_privilege_transition={"from": "user", "to": "root"}).verify()
        self.assertEqual(verify_exact_retest(original=sealed, retest=replace(self.capsule, fixture_environment_identity="other"), forbidden=self.forbidden, allowed=self.allowed), BoundaryVerdict.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
