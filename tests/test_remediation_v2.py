import unittest
from dataclasses import replace

from kimura_assessment.remediation_v2 import RemediationPolicy, RemediationVerifier
from kimura_assessment.red_team_v2 import DEFAULT_REGISTRY


class RemediationV2Tests(unittest.TestCase):
    def test_replay_set_is_selected_from_runtime_successes(self):
        result = RemediationVerifier().verify()
        self.assertEqual(result.successful_attack_ids, result.initial.successful_attack_ids)
        self.assertEqual(set(result.replayed_attack_ids), set(result.successful_attack_ids))

    def test_remediation_changes_authorization_and_blocks_impact(self):
        result = RemediationVerifier().verify()
        self.assertTrue(result.initial.allowed_actions >= 1)
        self.assertEqual(result.initial_validated_impacts, 1)
        self.assertEqual(result.post_remediation_allowed, 0)
        self.assertEqual(result.post_remediation_blocked, 1)
        self.assertEqual(result.post_remediation_validated_impacts, 0)
        self.assertTrue(result.remediation_verified)

    def test_exact_replay_identity_is_verified(self):
        result = RemediationVerifier().verify()
        self.assertEqual(result.exact_replays_verified, len(result.successful_attack_ids))
        for link in result.evidence_links:
            self.assertTrue(link.identity_verified)
            self.assertNotEqual(link.original_evidence_id, link.replay_evidence_id)
            self.assertEqual(link.original_fixture_sha256, link.replay_fixture_sha256)
            self.assertEqual(link.final_status, "verified")

    def test_missing_replay_cannot_verify_remediation(self):
        result = RemediationVerifier().verify(replay_cases=())
        self.assertFalse(result.remediation_verified)
        self.assertEqual(result.replayed_attack_ids, ())
        self.assertEqual(result.exact_replays_verified, 0)
        self.assertIsNone(result.evidence_links[0].replay_evidence_id)

    def test_identity_mismatch_cannot_verify_remediation(self):
        verifier = RemediationVerifier()
        initial = verifier.verify().initial
        successful_id = initial.successful_attack_ids[0]
        original = next(case for case in DEFAULT_REGISTRY if case.attack_id == successful_id)
        altered = replace(original, untrusted_content=original.untrusted_content + " altered")
        result = verifier.verify(replay_cases=(altered,))
        self.assertFalse(result.evidence_links[0].identity_verified)
        self.assertFalse(result.remediation_verified)
        self.assertNotEqual(result.evidence_links[0].original_fixture_sha256, result.evidence_links[0].replay_fixture_sha256)

    def test_remaining_impact_keeps_verification_false(self):
        result = RemediationVerifier().verify(remediation_policy=RemediationPolicy("no-op-policy", frozenset()))
        self.assertEqual(result.post_remediation_allowed, 1)
        self.assertEqual(result.post_remediation_validated_impacts, 1)
        self.assertFalse(result.remediation_verified)

    def test_evidence_linkage_contains_original_policy_replay_and_status(self):
        result = RemediationVerifier().verify()
        link = result.evidence_links[0]
        self.assertEqual(link.original_evidence_id, next(case.evidence_id for case in result.initial.cases if case.attack_id == link.attack_id))
        self.assertEqual(link.remediation_policy_id, result.remediation_policy.policy_id)
        self.assertIn(link.replay_evidence_id, {item.evidence_id for item in result.replay.evidence})
        self.assertEqual(link.final_status, "verified")

    def test_repeated_verification_is_deterministic(self):
        first = RemediationVerifier().verify().to_dict()
        second = RemediationVerifier().verify().to_dict()
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
