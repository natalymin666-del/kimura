"""Offline immutability and provenance tests for external Case #001."""

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
CASE_PATH = ROOT / "evidence" / "cases" / "EXTERNAL_BOUNDARY_CASE_001.json"
SOURCE_PATH = ROOT / "external_targets" / "slack_live_test_01.json"
INDEX_PATH = ROOT / "evidence" / "external_boundary_benchmark_index.json"
PAIR = "2a68559340d66f65bd2d3a52d74c06dfa4d8a62f767790d2b88ba2aa7852e083"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def case_digest(case):
    value = json.loads(json.dumps(case))
    value["immutability"]["case_digest"] = "TO_BE_FILLED"
    return hashlib.sha256(canonical(value)).hexdigest()


class ExternalBoundaryCase001Tests(unittest.TestCase):
    def setUp(self):
        self.case = load(CASE_PATH)
        self.source = load(SOURCE_PATH)
        self.index = load(INDEX_PATH)

    def test_case_digest_is_locally_valid(self):
        self.assertEqual(self.case["immutability"]["case_digest"], case_digest(self.case))

    def test_pair_fingerprint_cannot_change(self):
        self.assertEqual(self.case["pair_fingerprint"], PAIR)
        self.assertEqual(self.case["pair_fingerprint"], self.source["pair_fingerprint"])

    def test_allowed_and_forbidden_actors_cannot_be_swapped(self):
        self.assertEqual(self.case["actors"]["allowed"]["role"], "Primary Workspace Owner")
        self.assertEqual(self.case["actors"]["forbidden"]["role"], "Regular Member")
        self.assertNotEqual(self.case["actors"]["allowed"]["identity_reference"], self.case["actors"]["forbidden"]["identity_reference"])

    def test_s1_and_verdict_are_frozen(self):
        self.assertEqual(self.case["fixture_state"]["s1"], "Workspace Owner and Admins only")
        self.assertEqual(self.case["final_verdict"], "BOUNDARY_HELD")
        self.assertNotEqual(self.case["final_verdict"], "BOUNDARY_VIOLATION_CONFIRMED")

    def test_human_observed_cannot_become_independently_verified(self):
        self.assertEqual(self.case["allowed_observation"]["evidence_type"], "HUMAN_OBSERVED")
        self.assertEqual(self.case["forbidden_observation"]["evidence_type"], "HUMAN_OBSERVED")
        self.assertFalse(self.case["fixture_state"]["independent_verification"])
        self.assertEqual(self.case["evidence_provenance"]["independent_network_verification"], "NONE")

    def test_missing_evidence_is_explicit_not_silently_filled(self):
        self.assertEqual(self.case["timestamps"]["fixture_and_observation_timestamps"], "NOT_SUPPLIED_BY_OPERATOR")
        self.assertEqual(self.case["evidence_provenance"]["independent_network_verification"], "NONE")

    def test_vulnerability_claim_remains_false(self):
        self.assertFalse(self.case["authorization_bypass_found"])
        self.assertFalse(self.case["vulnerability_claimed"])

    def test_source_assessment_and_case_are_provenance_linked(self):
        source_bytes = SOURCE_PATH.read_bytes()
        source_sha = hashlib.sha256(source_bytes).hexdigest()
        self.assertEqual(self.case["evidence_provenance"]["source_assessment_reference"], "external_targets/slack_live_test_01.json")
        self.assertEqual(self.case["evidence_provenance"]["source_assessment_sha256"], source_sha)
        self.assertEqual(self.case["evidence_provenance"]["source_proof_capsule_fingerprint"], self.source["proof_capsule"]["capsule_fingerprint"])

    def test_case_digest_changes_when_security_field_changes(self):
        altered = json.loads(json.dumps(self.case))
        altered["forbidden_observation"]["protected_analytics_content_accessible"] = True
        self.assertNotEqual(case_digest(altered), self.case["immutability"]["case_digest"])

    def test_future_assessments_cannot_overwrite_case_001(self):
        self.assertTrue(self.case["immutability"]["append_only_case_id"])
        self.assertTrue(self.case["immutability"]["future_assessments_must_not_overwrite_case_001"])
        self.assertEqual(self.index["case_count"], 1)
        self.assertEqual([item["case_id"] for item in self.index["cases"]], ["EXTERNAL_BOUNDARY_CASE_001"])
        self.assertFalse(self.index["fake_cases_added"])

    def test_benchmark_index_has_no_one_case_success_rate(self):
        self.assertEqual(self.index["success_rate"], "NOT_CALCULATED_FROM_ONE_CASE")
        self.assertEqual(self.index["cases"][0]["result"], "BOUNDARY_HELD")
        self.assertEqual(self.index["cases"][0]["evidence_level"], "HUMAN_OBSERVED; locally integrity-checked; no independent network verification")

