import json
import unittest

from kimura_assessment.agent_wrapper import AgentPolicy
from kimura_assessment.calibration import calibration_json, run_calibration_suite
from kimura_assessment.model_schemas import ModelResponse, ProposedAction, safe_digest
from kimura_assessment.model_scenarios import CALIBRATION_FIXTURES, CONTROL_FIXTURES


class ProposalProvider:
    provider_id = "fake-local"
    model_id = "fake-model"

    def complete(self, request):
        return ModelResponse(
            "fake-local", "fake-model", ProposedAction("send_email", ("body",)),
            "valid", "complete", safe_digest("provider-only"), 12, 0,
        )


class SafeTextProvider:
    provider_id = "fake-local"
    model_id = "fake-model"

    def complete(self, request):
        return ModelResponse(
            "fake-local", "fake-model", None, "valid", "complete",
            safe_digest("benign-response"), 8, 0,
        )


class CalibrationTests(unittest.TestCase):
    def test_fixture_identity_and_hashes_are_stable(self):
        self.assertEqual(len(CALIBRATION_FIXTURES), 6)
        self.assertEqual(
            [fixture.fixture_id for fixture in CALIBRATION_FIXTURES],
            [fixture.fixture_id for fixture in CALIBRATION_FIXTURES],
        )
        self.assertEqual(
            [fixture.fixture_sha256 for fixture in CALIBRATION_FIXTURES],
            [fixture.fixture_sha256 for fixture in CALIBRATION_FIXTURES],
        )
        self.assertEqual(len({fixture.fixture_sha256 for fixture in CALIBRATION_FIXTURES}), 6)

    def test_aggregation_separates_proposal_gate_and_validated_impact(self):
        baseline = run_calibration_suite(ProposalProvider(), model_id="fake-model", trials=3, fixtures=CALIBRATION_FIXTURES[:1])
        blocked = run_calibration_suite(
            ProposalProvider(), model_id="fake-model", trials=3, fixtures=CALIBRATION_FIXTURES[:1],
            policy=AgentPolicy("deny-untrusted-actions-v1", True),
        )
        self.assertEqual(baseline[0].proposed_action_count, 3)
        self.assertEqual(baseline[0].allowed_action_count, 3)
        self.assertEqual(baseline[0].validated_impact_count, 3)
        self.assertEqual(baseline[0].classification, "stable")
        self.assertEqual(blocked[0].proposed_action_count, 3)
        self.assertEqual(blocked[0].allowed_action_count, 0)
        self.assertEqual(blocked[0].validated_impact_count, 0)
        self.assertEqual(blocked[0].classification, "no-impact")

    def test_suite_aggregates_each_fixture_across_all_trials(self):
        results = run_calibration_suite(ProposalProvider(), model_id="fake-model", trials=2)
        self.assertEqual(len(results), len(CALIBRATION_FIXTURES))
        self.assertEqual({item.fixture_id for item in results}, {item.fixture_id for item in CALIBRATION_FIXTURES})
        self.assertTrue(all(item.trial_count == 2 for item in results))
        self.assertTrue(all(item.proposed_action_count == 2 for item in results))
        self.assertTrue(all(item.allowed_action_count == 2 for item in results))
        self.assertTrue(all(item.validated_impact_count == 2 for item in results))

    def test_malicious_text_alone_cannot_create_validated_finding(self):
        results = run_calibration_suite(SafeTextProvider(), model_id="fake-model", trials=2, fixtures=CALIBRATION_FIXTURES[:1])
        self.assertEqual(results[0].proposed_action_count, 0)
        self.assertEqual(results[0].allowed_action_count, 0)
        self.assertEqual(results[0].validated_impact_count, 0)

    def test_calibration_output_contains_no_fixture_text_or_raw_response(self):
        results = run_calibration_suite(ProposalProvider(), model_id="fake-model", trials=1, fixtures=CALIBRATION_FIXTURES[:1])
        encoded = calibration_json(results)
        self.assertNotIn(CALIBRATION_FIXTURES[0].retrieved_content, encoded)
        self.assertNotIn("provider-only", encoded)
        self.assertNotIn("synthetic recipient", encoded)
        self.assertEqual(json.loads(encoded)[0]["fixture_id"], CALIBRATION_FIXTURES[0].fixture_id)

    def test_controls_are_separate_from_adversarial_calibration(self):
        self.assertEqual(len(CONTROL_FIXTURES), 2)
        self.assertTrue({item.fixture_id for item in CONTROL_FIXTURES}.isdisjoint(
            {item.fixture_id for item in CALIBRATION_FIXTURES}
        ))

    def test_positive_and_negative_controls_use_normal_aggregation(self):
        positive = run_calibration_suite(ProposalProvider(), model_id="fake-model", trials=2, fixtures=CONTROL_FIXTURES[:1])
        negative = run_calibration_suite(SafeTextProvider(), model_id="fake-model", trials=2, fixtures=CONTROL_FIXTURES[1:])
        self.assertEqual(positive[0].proposed_action_count, 2)
        self.assertEqual(negative[0].proposed_action_count, 0)


if __name__ == "__main__":
    unittest.main()
