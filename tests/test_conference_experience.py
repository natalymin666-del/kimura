import unittest

from kimura_assessment.conference_preview import fixture_result
from kimura_assessment.conference_view_model import ConferenceViewModelError, derive_view_model
from kimura_assessment.physical_target_assessment import run_local_assessment


class ConferenceViewModelTests(unittest.TestCase):
    def test_pass_derives_verified_state(self):
        vm = derive_view_model(run_local_assessment().to_dict())
        self.assertEqual(vm.display_status, "PASS")
        self.assertTrue(vm.fix_verified)
        self.assertEqual(vm.replay_impact_label, "NO SYNTHETIC IMPACT")

    def test_partial_and_failed_never_derive_fix_verified(self):
        for state in ("partial", "failed"):
            vm = derive_view_model(fixture_result(state))
            self.assertEqual(vm.display_status, state.upper())
            self.assertFalse(vm.fix_verified)

    def test_pass_with_broken_invariant_is_downgraded(self):
        result = run_local_assessment().to_dict()
        result["final_ledger_count"] = 2
        vm = derive_view_model(result)
        self.assertEqual(vm.display_status, "FAILED")
        self.assertFalse(vm.fix_verified)

    def test_missing_required_identity_is_rejected(self):
        result = run_local_assessment().to_dict()
        del result["target_id"]
        with self.assertRaises(ConferenceViewModelError):
            derive_view_model(result)

    def test_changed_runtime_values_flow_into_view_model(self):
        result = run_local_assessment().to_dict()
        result["target_id"] = "physical-target-changed"
        result["baseline_event_id"] = "event-changed"
        result["baseline_ledger_count"] = 7
        result["final_ledger_count"] = 7
        result["baseline_fixture_sha256"] = "f" * 64
        result["replay_fixture_sha256"] = "f" * 64
        result["evidence_chain"][0]["target_id"] = "physical-target-changed"
        vm = derive_view_model(result)
        self.assertEqual(vm.target_id, "physical-target-changed")
        self.assertEqual(vm.baseline_event_id, "event-changed")
        self.assertEqual(vm.baseline_ledger_count, 7)
        self.assertEqual(vm.baseline_fixture_sha256, "f" * 64)


if __name__ == "__main__":
    unittest.main()
