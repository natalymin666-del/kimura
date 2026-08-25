import json
import threading
import unittest

from kimura_assessment.physical_target_assessment import (
    HttpPhysicalTargetClient,
    InProcessPhysicalTargetClient,
    PhysicalAssessmentResult,
    PhysicalAssessmentError,
    PhysicalTargetOrchestrator,
    run_local_assessment,
    verify_code_hashes,
)
from kimura_assessment.physical_target_runtime import PhysicalTargetRuntime, TargetConfig, fixture_for
from kimura_assessment.physical_target_server import create_server


HASHES = {"physical_target_runtime.py": "a" * 64, "physical_target_server.py": "b" * 64}


class FaultClient:
    def __init__(self, runtime, fault=None):
        self.client = InProcessPhysicalTargetClient(runtime)
        self.fault = fault

    def request(self, payload):
        result = self.client.request(payload)
        return self.fault(payload, result) if self.fault else result


def orchestrator(runtime, client=None, cleanup=None, expected_hashes=None, observed_hashes=None):
    return PhysicalTargetOrchestrator(
        client or InProcessPhysicalTargetClient(runtime),
        expected_target_id=runtime.config.target_id,
        expected_hashes=expected_hashes or HASHES,
        observed_hashes=observed_hashes or HASHES,
        cleanup=cleanup,
    )


class PhysicalTargetAssessmentTests(unittest.TestCase):
    def test_complete_pass_lifecycle_has_semantic_result(self):
        result = run_local_assessment()
        values = result.to_dict()
        self.assertEqual(result.status, "PASS")
        self.assertTrue(result.physical_target_reached)
        self.assertEqual(result.baseline_fixture_id, "poisoned-order-note-v1")
        self.assertEqual(result.baseline_decision, "allowed")
        self.assertTrue(result.baseline_synthetic_impact_confirmed)
        self.assertEqual(result.baseline_event_id, "event-0001")
        self.assertEqual(result.baseline_ledger_count, 1)
        self.assertTrue(result.deny_only_verified)
        self.assertTrue(result.exact_replay_identity_verified)
        self.assertTrue(result.replay_target_reached)
        self.assertEqual(result.replay_decision, "blocked")
        self.assertFalse(result.replay_executed)
        self.assertFalse(result.replay_synthetic_impact_confirmed)
        self.assertEqual(result.final_ledger_count, 1)
        self.assertTrue(result.fix_verified)
        self.assertEqual(values["replay_synthetic_impact_confirmed"], False)
        self.assertIn("replay-impact-not-confirmed", [item["stage"] for item in values["evidence_chain"]])

    def test_unreachable_target_is_failed_and_cleanup_is_attempted(self):
        calls = []
        class Unreachable:
            def request(self, _payload):
                raise PhysicalAssessmentError("target transport or schema failure: URLError")
        result = PhysicalTargetOrchestrator(Unreachable(), expected_target_id="target-01", expected_hashes=HASHES, observed_hashes=HASHES, cleanup=lambda: calls.append("cleanup")).run()
        self.assertEqual(result.status, "FAILED")
        self.assertIn("URLError", result.failure_reason)
        self.assertEqual(calls, ["cleanup"])
        self.assertTrue(result.cleanup_completed)

    def test_wrong_target_identity_is_failed(self):
        runtime = PhysicalTargetRuntime(node_instance_id="i-1")
        def wrong_identity(payload, result):
            if payload["operation"] == "discover":
                result = dict(result)
                result["target_id"] = "physical-target-wrong"
            return result
        result = orchestrator(runtime, FaultClient(runtime, wrong_identity)).run()
        self.assertEqual(result.status, "FAILED")
        self.assertIn("identity", result.failure_reason)

    def test_deployed_hash_mismatch_fails_before_discovery(self):
        runtime = PhysicalTargetRuntime(node_instance_id="i-1")
        calls = []
        class Recording:
            def request(self, payload):
                calls.append(payload)
                return InProcessPhysicalTargetClient(runtime).request(payload)
        result = orchestrator(runtime, Recording(), expected_hashes=HASHES, observed_hashes={**HASHES, "extra.py": "c" * 64}).run()
        self.assertEqual(result.status, "FAILED")
        self.assertIn("hash mismatch", result.failure_reason)
        self.assertEqual(calls, [])
        self.assertFalse(result.code_hashes_verified)

    def test_baseline_unexpectedly_blocked_is_partial(self):
        runtime = PhysicalTargetRuntime(TargetConfig(baseline_allowed_actions=frozenset()))
        result = orchestrator(runtime).run()
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("baseline", result.failure_reason)
        self.assertFalse(result.baseline_synthetic_impact_confirmed)

    def test_missing_baseline_event_is_partial(self):
        runtime = PhysicalTargetRuntime(node_instance_id="i-1")
        def missing_event(payload, result):
            if payload["operation"] == "validate" and payload["request_id"].endswith("baseline-validate-01"):
                result = dict(result)
                result["validated"] = False
                result["synthetic_event_id"] = None
            return result
        result = orchestrator(runtime, FaultClient(runtime, missing_event)).run()
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("baseline synthetic impact validation", result.failure_reason)

    def test_unchanged_remediation_digest_is_partial(self):
        runtime = PhysicalTargetRuntime(node_instance_id="i-1")
        unchanged_digest = runtime.policy_sha256
        def unchanged(payload, result):
            if payload["operation"] == "apply_policy":
                result = dict(result)
                result["policy_sha256"] = unchanged_digest
            return result
        result = orchestrator(runtime, FaultClient(runtime, unchanged)).run()
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("remediation", result.failure_reason)

    def test_remediation_broadening_is_partial(self):
        runtime = PhysicalTargetRuntime(node_instance_id="i-1")
        def broadened(payload, result):
            if payload["operation"] == "apply_policy":
                result = dict(result)
                result["denied_actions"] = []
            return result
        result = orchestrator(runtime, FaultClient(runtime, broadened)).run()
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("remediation", result.failure_reason)

    def test_replay_fixture_identity_mismatch_is_partial(self):
        runtime = PhysicalTargetRuntime(node_instance_id="i-1")
        def mismatch(payload, result):
            if payload["operation"] == "execute" and "replay" in payload["request_id"]:
                result = dict(result)
                result["fixture_sha256"] = "f" * 64
            return result
        result = orchestrator(runtime, FaultClient(runtime, mismatch)).run()
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("fixture identity", result.failure_reason)

    def test_replay_unexpectedly_allowed_is_partial(self):
        runtime = PhysicalTargetRuntime(node_instance_id="i-1")
        def allowed(payload, result):
            if payload["operation"] == "execute" and "replay" in payload["request_id"]:
                result = dict(result)
                result["authorization_decision"] = "allowed"
                result["executed"] = True
                result["synthetic_event_id"] = "event-0002"
            return result
        result = orchestrator(runtime, FaultClient(runtime, allowed)).run()
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("replay blocking", result.failure_reason)

    def test_replay_second_event_is_partial(self):
        runtime = PhysicalTargetRuntime(node_instance_id="i-1")
        def second_event(payload, result):
            if payload["operation"] == "execute" and "replay" in payload["request_id"]:
                result = dict(result)
                result["ledger_sequence"] = 2
                result["synthetic_event_id"] = "event-0002"
            return result
        result = orchestrator(runtime, FaultClient(runtime, second_event)).run()
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("ledger", result.failure_reason)

    def test_malformed_response_is_failed(self):
        class Malformed:
            def request(self, _payload):
                return {"status": "ok"}
        result = orchestrator(PhysicalTargetRuntime(), Malformed()).run()
        self.assertEqual(result.status, "FAILED")
        self.assertIn("identity", result.failure_reason)

    def test_timeout_is_failed_and_cleanup_is_completed(self):
        calls = []
        class Timeout:
            def request(self, _payload):
                raise TimeoutError("read timeout")
        result = orchestrator(PhysicalTargetRuntime(), Timeout(), cleanup=lambda: calls.append(True)).run()
        self.assertEqual(result.status, "FAILED")
        self.assertEqual(calls, [True])
        self.assertTrue(result.cleanup_completed)

    def test_hash_verification_requires_exact_safe_manifest(self):
        self.assertEqual(verify_code_hashes(HASHES, HASHES)[0], True)
        self.assertEqual(verify_code_hashes(HASHES, {"physical_target_runtime.py": "a" * 64})[0], False)
        self.assertEqual(verify_code_hashes(HASHES, {**HASHES, "bad": "not-a-hash"})[0], False)

    def test_result_serialization_is_deterministic(self):
        first = run_local_assessment().to_json()
        second = run_local_assessment().to_json()
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["status"], "PASS")


class PhysicalTargetHTTPClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = PhysicalTargetRuntime(node_instance_id="http-client-instance")
        cls.server = create_server(cls.runtime, "127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_client_exercises_local_http_transport(self):
        client = HttpPhysicalTargetClient(f"http://127.0.0.1:{self.server.server_port}/v1/node", timeout=1)
        response = client.request({"protocol_version": 1, "request_id": "http-discover-01", "operation": "discover", "assessment_id": "assessment-01", "expected_target_id": self.runtime.config.target_id})
        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["target_id"], self.runtime.config.target_id)

    def test_client_rejects_unbounded_or_implicit_endpoints(self):
        with self.assertRaises(ValueError):
            HttpPhysicalTargetClient("https://127.0.0.1:1/v1/node")
        with self.assertRaises(ValueError):
            HttpPhysicalTargetClient("http://127.0.0.1/v1/node")
        with self.assertRaises(ValueError):
            HttpPhysicalTargetClient("http://127.0.0.1:1/other")


if __name__ == "__main__":
    unittest.main()
