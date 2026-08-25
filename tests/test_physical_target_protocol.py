import unittest

from kimura_assessment.physical_target_protocol import (
    PROTOCOL_VERSION,
    TARGET_KIND,
    PhysicalTargetProtocolError,
    request_json,
    response_json,
    sha256_json,
    validate_request,
    validate_response,
)


class PhysicalTargetProtocolTests(unittest.TestCase):
    def execute_request(self):
        return {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": "request-01",
            "operation": "execute",
            "assessment_id": "assessment-01",
            "target_id": "target-01",
            "attack_id": "attack-01",
            "fixture_id": "fixture-01",
            "fixture_sha256": "a" * 64,
            "action": "send_email",
            "source": "untrusted-content",
            "policy_id": "policy-01",
        }

    def test_request_round_trip_is_canonical(self):
        request = self.execute_request()
        encoded = request_json(request)
        self.assertEqual(encoded, request_json(validate_request(request)))
        self.assertEqual(sha256_json(request), sha256_json(validate_request(request)))
        self.assertIn('"operation":"execute"', encoded)

    def test_all_operations_have_bounded_shapes(self):
        requests = [
            {"protocol_version": 1, "request_id": "r-1", "operation": "discover", "assessment_id": "a-1", "expected_target_id": "t-1"},
            self.execute_request(),
            {"protocol_version": 1, "request_id": "r-2", "operation": "validate", "assessment_id": "a-1", "target_id": "t-1", "attack_id": "attack-01", "fixture_sha256": "b" * 64, "observed_request_id": "request-01"},
            {"protocol_version": 1, "request_id": "r-3", "operation": "apply_policy", "assessment_id": "a-1", "target_id": "t-1", "policy_id": "policy-02", "deny_actions": ["send_email"]},
        ]
        for request in requests:
            self.assertIsInstance(validate_request(request), dict)

    def test_request_rejects_unknown_fields_and_bad_fixture_digest(self):
        request = self.execute_request()
        request["raw_content"] = "must not cross the boundary"
        with self.assertRaises(PhysicalTargetProtocolError):
            validate_request(request)
        request = self.execute_request()
        request["fixture_sha256"] = "not-a-digest"
        with self.assertRaises(PhysicalTargetProtocolError):
            validate_request(request)

    def test_policy_actions_must_be_sorted_and_unique(self):
        request = {
            "protocol_version": 1, "request_id": "r-1", "operation": "apply_policy", "assessment_id": "a-1",
            "target_id": "t-1", "policy_id": "p-1", "deny_actions": ["send_email", "send_email"],
        }
        with self.assertRaises(PhysicalTargetProtocolError):
            validate_request(request)

    def test_response_round_trip_and_target_kind(self):
        response = {
            "protocol_version": 1,
            "request_id": "request-01",
            "status": "ok",
            "target_id": "target-01",
            "target_kind": TARGET_KIND,
            "node_instance_id": "instance-01",
            "attack_id": "attack-01",
            "fixture_id": "fixture-01",
            "fixture_sha256": "a" * 64,
            "action": "send_email",
            "authorization_decision": "allowed",
            "executed": True,
            "synthetic_event_id": "event-01",
            "impact_class": "synthetic-external-action",
            "outcome": "synthetic-action-recorded",
            "policy_id": "policy-01",
            "policy_sha256": "b" * 64,
            "ledger_sequence": 1,
        }
        self.assertEqual(response_json(response), response_json(validate_response(response)))

    def test_response_rejects_real_or_unbounded_payload_fields(self):
        response = {"protocol_version": 1, "request_id": "request-01", "status": "ok", "target_id": "target-01", "target_kind": TARGET_KIND, "raw_response": "not permitted"}
        with self.assertRaises(PhysicalTargetProtocolError):
            validate_response(response)

    def test_response_requires_runtime_protocol_identity(self):
        response = {"protocol_version": 1, "request_id": "request-01", "status": "ok", "target_id": "target-01", "target_kind": "production-target"}
        with self.assertRaises(PhysicalTargetProtocolError):
            validate_response(response)


if __name__ == "__main__":
    unittest.main()
