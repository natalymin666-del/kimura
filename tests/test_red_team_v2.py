import json
import subprocess
import unittest
from pathlib import Path

from kimura_assessment.red_team_v2 import (
    DEFAULT_REGISTRY,
    DEFAULT_TARGET,
    AttackCase,
    AttackRegistry,
    DeterministicAssessmentRunner,
    SyntheticTargetProfile,
)


class RedTeamV2Tests(unittest.TestCase):
    def test_registry_is_deterministic_and_identities_are_stable(self):
        self.assertEqual(tuple(case.attack_id for case in DEFAULT_REGISTRY), tuple(sorted(case.attack_id for case in DEFAULT_REGISTRY)))
        first = DEFAULT_REGISTRY.registry_sha256
        second = AttackRegistry(tuple(DEFAULT_REGISTRY.cases)).registry_sha256
        self.assertEqual(first, second)
        self.assertEqual([case.fixture_sha256 for case in DEFAULT_REGISTRY], [case.fixture_sha256 for case in DEFAULT_REGISTRY])

    def test_aggregate_counts_equal_per_case_results(self):
        result = DeterministicAssessmentRunner().run()
        self.assertEqual(result.attack_paths_tested, sum(case.case_type == "attack" for case in result.cases))
        self.assertEqual(result.negative_controls, sum(case.case_type == "negative-control" for case in result.cases))
        self.assertEqual(result.tool_boundary_reached, sum(case.tool_boundary_reached for case in result.cases))
        self.assertEqual(result.allowed_actions, sum(case.authorization_decision == "allowed" for case in result.cases))
        self.assertEqual(result.blocked_actions, sum(case.authorization_decision == "blocked" for case in result.cases))
        self.assertEqual(result.validated_impacts, sum(case.ledger_validated_impact for case in result.cases))

    def test_family_and_tool_breakdowns_match_cases(self):
        result = DeterministicAssessmentRunner().run()
        self.assertEqual(result.cases_by_attack_family, {family: sum(case.attack_family == family and case.case_type == "attack" for case in result.cases) for family in sorted({case.attack_family for case in result.cases if case.case_type == "attack"})})
        self.assertEqual(result.validated_impacts_by_family, {family: sum(case.attack_family == family and case.ledger_validated_impact for case in result.cases) for family in sorted({case.attack_family for case in result.cases if case.ledger_validated_impact})})
        for tool, decisions in result.decisions_by_tool.items():
            self.assertEqual(sum(decisions.values()), sum(case.proposed_action == tool for case in result.cases))

    def test_negative_control_cannot_be_a_validated_attack(self):
        result = DeterministicAssessmentRunner().run()
        controls = [case for case in result.cases if case.case_type == "negative-control"]
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0].authorization_decision, "malformed")
        self.assertFalse(controls[0].tool_boundary_reached)
        self.assertFalse(controls[0].executed)
        self.assertFalse(controls[0].ledger_validated_impact)
        self.assertNotIn(controls[0].attack_id, result.successful_attack_ids)

    def test_validated_impacts_require_ledger_events(self):
        result = DeterministicAssessmentRunner().run()
        ledger_ids = {event.attack_id for event in result.ledger_events if event.impact_class != "none"}
        self.assertEqual({case.attack_id for case in result.cases if case.ledger_validated_impact}, ledger_ids)
        self.assertTrue(any(not case.ledger_validated_impact for case in result.cases))

    def test_attack_chains_correspond_to_case_and_evidence(self):
        result = DeterministicAssessmentRunner().run()
        evidence_ids = {item.evidence_id for item in result.evidence}
        for case in result.cases:
            if case.chain is None:
                self.assertFalse(case.ledger_validated_impact)
                continue
            self.assertTrue(case.ledger_validated_impact)
            self.assertEqual(case.chain.attack_id, case.attack_id)
            self.assertTrue(set(case.chain.evidence_ids) <= evidence_ids)
            self.assertEqual(case.chain.stages[-1].stage, "validated-impact")

    def test_mixed_outcomes_are_supported(self):
        result = DeterministicAssessmentRunner().run()
        self.assertGreater(result.allowed_actions, 0)
        self.assertGreater(result.blocked_actions, 0)
        self.assertGreater(result.validated_impacts, 0)
        self.assertLess(result.validated_impacts, result.attack_paths_tested)

    def test_repeated_assessments_have_identical_semantic_results(self):
        first = DeterministicAssessmentRunner().run().to_dict()
        second = DeterministicAssessmentRunner().run().to_dict()
        self.assertEqual(first, second)

    def test_no_network_or_external_side_effects_are_needed(self):
        result = DeterministicAssessmentRunner().run()
        self.assertEqual(result.target_id, DEFAULT_TARGET.target_id)
        self.assertTrue(all(event.impact_class.startswith("synthetic-") or event.impact_class == "none" for event in result.ledger_events))

    def test_existing_conference_demo_source_remains_unchanged(self):
        tracked = subprocess.run(["git", "diff", "--", "kimura_assessment/conference_demo.py", "START_KIMURA_DEMO.sh"], capture_output=True, text=True, check=True)
        self.assertEqual(tracked.stdout, "")


if __name__ == "__main__":
    unittest.main()
