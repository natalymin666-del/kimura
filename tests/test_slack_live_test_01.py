"""Offline dry-run tests for Slack boundary test #1."""

import hashlib
import json
import unittest
from pathlib import Path


SPEC_PATH = Path(__file__).parents[1] / "external_targets" / "slack_live_test_01.json"
CONTRACT_PATH = Path(__file__).parents[1] / "external_targets" / "slack_hackerone_scope.json"
UNKNOWN = "UNKNOWN"


def load_spec():
    return json.loads(SPEC_PATH.read_text(encoding="utf-8"))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sealed_pair_digest(spec):
    return digest(spec["paired_test"])


def request_digest(twin):
    return digest({"action": twin["action"], "arguments": twin["arguments"]})


def dry_run_execution_allowed(spec, *, human_approval=False, policy_rechecked=False, semantics_confirmed=False):
    gate = spec["execution_gate"]
    return (
        False
        and gate["fail_closed"]
        and gate["authorized_scope_verified"]
        and gate["live_execution_allowed"]
        and human_approval
        and policy_rechecked
        and semantics_confirmed
    )


def verdict_from_observation(*, http_success, state_changed, model_prose=False, state_observed=True):
    if not state_observed or model_prose:
        return "INCONCLUSIVE"
    if http_success and state_changed:
        return "BOUNDARY_VIOLATION_CONFIRMED"
    if not http_success and not state_changed:
        return "BOUNDARY_HELD"
    return "INCONCLUSIVE"


class SlackLiveTest01Tests(unittest.TestCase):
    def setUp(self):
        self.spec = load_spec()
        self.gate = self.spec["execution_gate"]

    def test_dry_run_cannot_execute_live(self):
        self.assertEqual(self.spec["phase"], "SEALED_DRY_RUN")
        self.assertFalse(self.gate["authorized_scope_verified"])
        self.assertFalse(self.gate["live_execution_allowed"])
        self.assertFalse(dry_run_execution_allowed(self.spec, human_approval=True, policy_rechecked=True, semantics_confirmed=True))

    def test_only_two_declared_identities_are_permitted(self):
        self.assertEqual(set(self.gate["declared_identity_labels_only"]), {"TEST_IDENTITY_A", "TEST_IDENTITY_B"})
        self.assertEqual(set(self.spec["declared_test_identities"]), {"A", "B"})
        for identity in self.spec["declared_test_identities"].values():
            self.assertTrue(identity["controlled_by_researcher"])

    def test_real_user_and_third_party_targets_are_rejected(self):
        self.assertFalse(self.spec["workspace"]["real_users_permitted"])
        self.assertFalse(self.spec["candidate_boundary"]["third_party_interaction"])
        self.assertTrue(self.gate["no_real_user_effect_required"])
        self.assertTrue(self.gate["no_third_party_effect_required"])

    def test_autonomous_execution_and_multiple_attempts_are_rejected(self):
        self.assertFalse(self.gate["autonomous_execution_allowed"])
        self.assertTrue(self.gate["single_attempt_only"])

    def test_missing_human_policy_and_semantics_confirmation_fail_closed(self):
        self.assertTrue(self.gate["human_approval_required"])
        self.assertTrue(self.gate["current_policy_recheck_required"])
        self.assertFalse(self.gate["permission_semantics_confirmation_required"])
        self.assertFalse(self.spec["candidate_boundary"]["PERMISSION_SEMANTICS_REQUIRES_HUMAN_CONFIRMATION"])
        self.assertTrue(self.spec["candidate_boundary"]["permission_semantics_confirmed_from_human_observed_ui"])
        self.assertFalse(dry_run_execution_allowed(self.spec, human_approval=False, policy_rechecked=False, semantics_confirmed=False))

    def test_unknown_state_semantics_are_inconclusive(self):
        result = verdict_from_observation(http_success=True, state_changed=False, state_observed=False)
        self.assertEqual(result, "INCONCLUSIVE")
        self.assertEqual(self.spec["candidate_boundary"]["s0_baseline"]["analytics_visibility"], "Everyone, except guests (default)")

    def test_http_success_alone_and_model_prose_cannot_confirm_violation(self):
        self.assertEqual(verdict_from_observation(http_success=True, state_changed=False), "INCONCLUSIVE")
        self.assertEqual(verdict_from_observation(http_success=True, state_changed=True, model_prose=True), "INCONCLUSIVE")

    def test_confirmed_state_change_is_required_for_violation(self):
        self.assertEqual(verdict_from_observation(http_success=True, state_changed=True), "BOUNDARY_VIOLATION_CONFIRMED")
        self.assertEqual(verdict_from_observation(http_success=False, state_changed=False), "BOUNDARY_HELD")

    def test_generator_model_verifier_and_scope_facts_cannot_expand_or_override(self):
        self.assertIn("No generator, model, verifier, renderer", self.gate["override_authority"])
        self.assertFalse(dry_run_execution_allowed(self.spec))
        self.assertEqual(self.spec["target"], "slack.com")
        self.assertEqual(self.spec["workspace"]["reference"], "bimbo")

    def test_pair_and_request_fingerprints_bind_exact_pre_execution_spec(self):
        self.assertEqual(self.spec["pair_fingerprint"], sealed_pair_digest(self.spec))
        self.assertEqual(self.spec["individual_request_fingerprints"]["allowed_twin"], request_digest(self.spec["paired_test"]["allowed_twin"]))
        self.assertEqual(self.spec["individual_request_fingerprints"]["forbidden_twin"], request_digest(self.spec["paired_test"]["forbidden_twin"]))
        self.assertEqual(self.spec["paired_test"]["allowed_twin"]["action"], self.spec["paired_test"]["forbidden_twin"]["action"])
        self.assertEqual(self.spec["paired_test"]["allowed_twin"]["arguments"], self.spec["paired_test"]["forbidden_twin"]["arguments"])
        self.assertEqual(self.spec["paired_test"]["invariants"][-1], "only actor identity/authorization differs")

    def test_proof_capsule_contains_final_human_observed_evidence(self):
        capsule = self.spec["proof_capsule"]
        self.assertEqual(capsule["state"], "COMPLETED_HUMAN_OBSERVED_EVIDENCE")
        self.assertIn("no independent network/API verification", capsule["execution_claim"])
        self.assertEqual(capsule["final_verdict"], "BOUNDARY_HELD")
        self.assertTrue(capsule["human_observed_evidence"])
        self.assertTrue(capsule["locally_verified_integrity"])
        self.assertFalse(capsule["independent_network_verification"])
        self.assertEqual(capsule["pair_fingerprint"], self.spec["pair_fingerprint"])

    def test_fixture_setup_is_separate_from_access_observations(self):
        self.assertTrue(self.spec["candidate_boundary"]["configuration_setup_not_a_vulnerability_test"])
        self.assertEqual(self.spec["candidate_boundary"]["s0_baseline"]["analytics_visibility"], "Everyone, except guests (default)")
        self.assertEqual(self.spec["candidate_boundary"]["s1_intended_fixture_state"]["analytics_visibility"], "Workspace Owner and Admins only")
        self.assertFalse(self.spec["candidate_boundary"]["s1_intended_fixture_state"]["setup_execution_allowed_now"])
        self.assertEqual(self.gate["separate_approval_stages"], [
            "S1 fixture setup: Owner changes S0 to S1",
            "S2 Owner allowed access observation",
            "S2 Member forbidden access observation",
        ])

    def test_human_observed_s1_is_recorded_without_claiming_verification(self):
        fixture = self.spec["candidate_boundary"]["s1_observed_fixture_state"]
        self.assertEqual(fixture["state"], "HUMAN_OBSERVED_FIXTURE_STATE")
        self.assertEqual(fixture["previous_s0"], "Everyone, except guests (default)")
        self.assertEqual(fixture["observed_s1"], "Workspace Owner and Admins only")
        self.assertEqual(fixture["slack_ui_confirmation"], "Saved")
        self.assertEqual(fixture["performed_manually_by"], "TEST_IDENTITY_A")
        self.assertFalse(fixture["independent_verification"])
        self.assertFalse(fixture["vulnerability_claim"])
        self.assertTrue(fixture["owner_analytics_access_observation_performed"])
        self.assertTrue(fixture["member_analytics_access_observation_performed"])
        self.assertEqual(fixture["owner_access_result"], "PERMITTED")
        self.assertTrue(fixture["owner_observation"]["performed_exactly_once_manually"])
        self.assertEqual(fixture["member_access_result"], "DENIED")
        self.assertFalse(fixture["protected_resource_accessible_to_member"])
        self.assertTrue(fixture["member_observation"]["performed_exactly_once_manually"])
        self.assertEqual(self.spec["current_verdict"], "BOUNDARY_HELD")

    def test_completed_pair_has_no_next_observation_and_no_live_execution(self):
        next_step = self.spec["next_step"]
        self.assertEqual(next_step["name"], "NONE - paired observations complete")
        self.assertFalse(next_step["execution_allowed_now"])
        self.assertFalse(self.gate["live_execution_allowed_for_member_forbidden_twin"])
        self.assertFalse(self.gate["live_execution_allowed"])

    def test_old_display_name_boundary_is_retired_and_not_active(self):
        retired = self.spec["retired_boundary"]
        self.assertEqual(retired["status"], "RETIRED_OBSOLETE")
        self.assertTrue(retired["must_not_be_used"])
        self.assertNotEqual(retired["old_pair_fingerprint"], self.spec["pair_fingerprint"])
        self.assertEqual(self.spec["candidate_boundary"]["action"], "view_workspace_analytics")

    def test_scope_contract_fingerprint_is_bound_without_network(self):
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(self.spec["pre_execution_evidence"]["policy_contract_fingerprint"], contract["policy_fingerprint"]["value"])
        self.assertEqual(self.spec["target"], contract["target"])

