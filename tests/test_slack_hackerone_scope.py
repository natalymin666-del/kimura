"""Pure offline tests for the Slack HackerOne preparation contract."""

import hashlib
import json
import unittest
from pathlib import Path


CONTRACT_PATH = Path(__file__).parents[1] / "external_targets" / "slack_hackerone_scope.json"
UNKNOWN = "UNKNOWN"


def load_contract():
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def normalized_contract_without_fingerprint(contract):
    value = json.loads(json.dumps(contract))
    value["policy_fingerprint"]["value"] = "TO_BE_FILLED"
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def execution_gate_allows(contract, *, human_approval=False, policy_rechecked=False):
    gate = contract["execution_gate"]
    required = gate["mandatory_fields"]
    return (
        gate["fail_closed"]
        and gate["authorized_scope_verified"]
        and gate["live_execution_allowed"]
        and required["exact_self_controlled_test_account_identity"] not in (UNKNOWN, None, "")
        and required["dedicated_test_workspace_or_team_identified"] not in (UNKNOWN, None, "")
        and required["second_test_account_or_team_if_boundary_requires_it"] not in (UNKNOWN, None, "")
        and required["exact_allowed_action"] not in (UNKNOWN, None, "")
        and required["exact_forbidden_near_miss_action"] not in (UNKNOWN, None, "")
        and required["no_real_user_or_real_user_data_effect_confirmed"] is True
        and required["request_count_explicitly_bounded"] is True
        and required["human_approval_for_exact_test"] is True
        and human_approval
        and required["current_hackerone_policy_rechecked_immediately_before_execution"] is True
        and policy_rechecked
    )


class SlackHackerOneScopeContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = load_contract()
        self.gate = self.contract["execution_gate"]
        self.required = self.gate["mandatory_fields"]

    def test_contract_fingerprint_is_local_and_deterministic(self):
        expected = hashlib.sha256(normalized_contract_without_fingerprint(self.contract)).hexdigest()
        self.assertEqual(self.contract["policy_fingerprint"]["label"], "LOCAL_SCOPE_CONTRACT_FINGERPRINT")
        self.assertEqual(self.contract["policy_fingerprint"]["value"], expected)
        self.assertTrue(self.contract["source_policy_not_cryptographically_captured"])

    def test_in_scope_and_bounty_eligible_cannot_authorize(self):
        self.assertEqual(self.contract["scope_status"], "IN_SCOPE")
        self.assertTrue(self.contract["bounty_eligible"])
        self.assertFalse(execution_gate_allows(self.contract))

    def test_automation_and_unsafe_automation_classes_are_rejected(self):
        for field in ("automation_permission", "autonomous_attack_generation", "mass_scanning", "fuzzing", "enumeration"):
            self.assertFalse(self.contract[field], field)
        self.assertTrue(self.contract["manual_human_controlled_testing"])

    def test_real_user_access_and_harmful_actions_are_rejected(self):
        self.assertTrue(self.contract["test_accounts_required"])
        self.assertFalse(self.contract["real_user_data_permission"])
        self.assertFalse(self.contract["real_user_interaction_permission"])
        self.assertFalse(self.contract["harmful_state_change_permission"])
        self.assertIn("DDoS", self.contract["known_policy_rules"]["harmful_actions_prohibited"])

    def test_unknown_fields_remain_unknown(self):
        for field in (
            "exact_request_rate_limits", "slack_api_scope",
            "exact_permitted_cross_team_action_classes",
            "exact_test_account_creation_procedure",
            "exact_permitted_state_changing_actions",
        ):
            self.assertEqual(self.contract[field], UNKNOWN, field)

    def test_missing_dedicated_identity_and_boundary_pair_fail_closed(self):
        self.assertEqual(self.required["exact_self_controlled_test_account_identity"], UNKNOWN)
        self.assertEqual(self.required["dedicated_test_workspace_or_team_identified"], UNKNOWN)
        self.assertEqual(self.required["second_test_account_or_team_if_boundary_requires_it"], UNKNOWN)
        self.assertFalse(execution_gate_allows(self.contract))

    def test_missing_human_approval_and_policy_recheck_fail_closed(self):
        self.assertFalse(self.required["human_approval_for_exact_test"])
        self.assertFalse(self.required["current_hackerone_policy_rechecked_immediately_before_execution"])
        self.assertFalse(execution_gate_allows(self.contract, human_approval=True, policy_rechecked=True))

    def test_model_generator_verifier_and_scope_facts_cannot_override_gate(self):
        self.assertTrue(self.gate["fail_closed"])
        self.assertIn("No generator, model, verifier, renderer, or scope fact", self.gate["override_authority"])
        self.assertFalse(execution_gate_allows(self.contract))

    def test_current_state_and_flags_are_pre_execution_only(self):
        self.assertEqual(self.contract["human_approval_model"]["current_state"], "POLICY_REVIEW_REQUIRED")
        self.assertFalse(self.gate["authorized_scope_verified"])
        self.assertFalse(self.gate["live_execution_allowed"])

    def test_only_exact_human_approval_after_all_fields_resolve_can_progress(self):
        ready = json.loads(json.dumps(self.contract))
        required = ready["execution_gate"]["mandatory_fields"]
        required.update({
            "exact_self_controlled_test_account_identity": "controlled Slack test account",
            "dedicated_test_workspace_or_team_identified": "dedicated controlled test workspace",
            "second_test_account_or_team_if_boundary_requires_it": "second controlled test team",
            "exact_allowed_action": "explicitly approved manual validation",
            "exact_forbidden_near_miss_action": "the closest unapproved state-changing action",
            "no_real_user_or_real_user_data_effect_confirmed": True,
            "request_count_explicitly_bounded": True,
            "human_approval_for_exact_test": True,
            "current_hackerone_policy_rechecked_immediately_before_execution": True,
        })
        ready["execution_gate"]["authorized_scope_verified"] = True
        ready["execution_gate"]["live_execution_allowed"] = True
        self.assertFalse(execution_gate_allows(ready, human_approval=False, policy_rechecked=True))
        self.assertTrue(execution_gate_allows(ready, human_approval=True, policy_rechecked=True))
