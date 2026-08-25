import json
import socket
import subprocess
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from kimura_assessment.physical_target_protocol import TARGET_KIND, validate_response
from kimura_assessment.physical_target_runtime import PhysicalTargetRuntime, TargetConfig, fixture_for
from kimura_assessment.physical_target_server import NODE_PATH, create_server


def protocol_request(operation, request_id, **values):
    return {
        "protocol_version": 1,
        "request_id": request_id,
        "operation": operation,
        "assessment_id": "assessment-01",
        **values,
    }


class PhysicalTargetRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.runtime = PhysicalTargetRuntime(node_instance_id="instance-test-01")
        self.fixture = fixture_for("attack-indirect-email-v1", "poisoned-order-note-v1")

    def execute(self, request_id="execute-01"):
        return self.runtime.handle(protocol_request(
            "execute", request_id,
            target_id=self.runtime.config.target_id,
            attack_id=self.fixture.attack_id,
            fixture_id=self.fixture.fixture_id,
            fixture_sha256=self.fixture.fixture_sha256,
            action=self.fixture.action,
            source=self.fixture.source,
            policy_id=self.runtime.policy_id,
        ))

    def test_discovery_uses_runtime_identity_and_owned_target_kind(self):
        result = self.runtime.handle(protocol_request("discover", "discover-01", expected_target_id=self.runtime.config.target_id))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["target_kind"], TARGET_KIND)
        self.assertEqual(result["node_instance_id"], "instance-test-01")
        self.assertRegex(result["target_id"], r"^physical-target-[0-9a-f]{16}$")
        self.assertEqual(result["capabilities"], sorted(result["capabilities"]))

    def test_target_identity_changes_with_runtime_configuration(self):
        first = PhysicalTargetRuntime(TargetConfig(target_name="node-a"), node_instance_id="i-1")
        second = PhysicalTargetRuntime(TargetConfig(target_name="node-b"), node_instance_id="i-2")
        self.assertNotEqual(first.config.target_id, second.config.target_id)

    def test_valid_baseline_action_creates_one_bounded_event(self):
        result = self.execute()
        self.assertEqual(result["authorization_decision"], "allowed")
        self.assertTrue(result["executed"])
        self.assertEqual(result["impact_class"], "synthetic-external-action")
        self.assertEqual(len(self.runtime.events), 1)
        event = self.runtime.events[0]
        self.assertEqual(event.request_id, "execute-01")
        self.assertEqual(event.fixture_sha256, self.fixture.fixture_sha256)
        self.assertEqual(event.event_id, result["synthetic_event_id"])
        self.assertEqual(len(event.event_sha256), 64)

    def test_unknown_operation_rejected(self):
        result = self.runtime.handle(protocol_request("unknown-operation", "unknown-op-01"))
        self.assertEqual(result["error_code"], "invalid-request")
        self.assertEqual(len(self.runtime.events), 0)

    def test_unknown_fixture_and_mismatch_are_rejected_before_decision(self):
        unknown = self.runtime.handle(protocol_request(
            "execute", "unknown-01", target_id=self.runtime.config.target_id,
            attack_id="unknown-attack", fixture_id="unknown-fixture", fixture_sha256="a" * 64,
            action="send_email", source="untrusted-content", policy_id=self.runtime.policy_id,
        ))
        self.assertEqual(unknown["error_code"], "unknown-fixture")
        mismatch = self.runtime.handle(protocol_request(
            "execute", "mismatch-01", target_id=self.runtime.config.target_id,
            attack_id=self.fixture.attack_id, fixture_id=self.fixture.fixture_id,
            fixture_sha256=self.fixture.fixture_sha256, action="read_document",
            source=self.fixture.source, policy_id=self.runtime.policy_id,
        ))
        self.assertEqual(mismatch["error_code"], "fixture-action-mismatch")
        self.assertEqual(len(self.runtime.events), 0)

    def test_invalid_fixture_digest_is_rejected_by_protocol(self):
        result = self.runtime.handle(protocol_request(
            "execute", "bad-digest-01", target_id=self.runtime.config.target_id,
            attack_id=self.fixture.attack_id, fixture_id=self.fixture.fixture_id,
            fixture_sha256="not-a-digest", action=self.fixture.action,
            source=self.fixture.source, policy_id=self.runtime.policy_id,
        ))
        self.assertEqual(result["error_code"], "invalid-request")
        self.assertEqual(len(self.runtime.events), 0)

    def test_duplicate_request_id_is_idempotent_and_conflicts_are_rejected(self):
        first = self.execute()
        duplicate = self.execute()
        self.assertEqual(first, duplicate)
        self.assertEqual(len(self.runtime.events), 1)
        altered = protocol_request(
            "execute", "execute-01", target_id=self.runtime.config.target_id,
            attack_id=self.fixture.attack_id, fixture_id=self.fixture.fixture_id,
            fixture_sha256=self.fixture.fixture_sha256, action="read_document",
            source=self.fixture.source, policy_id=self.runtime.policy_id,
        )
        self.assertEqual(self.runtime.handle(altered)["error_code"], "request-id-conflict")
        self.assertEqual(len(self.runtime.events), 1)

    def test_remediation_is_deny_only_and_changes_policy_digest(self):
        baseline_digest = self.runtime.policy_sha256
        denied = self.runtime.handle(protocol_request(
            "apply_policy", "policy-01", target_id=self.runtime.config.target_id,
            policy_id="physical-remediation-policy-v1", deny_actions=["send_email"],
        ))
        self.assertEqual(denied["status"], "ok")
        self.assertNotEqual(denied["policy_sha256"], baseline_digest)
        broadening = self.runtime.handle(protocol_request(
            "apply_policy", "policy-02", target_id=self.runtime.config.target_id,
            policy_id="physical-broadened-policy-v1", deny_actions=[],
        ))
        self.assertEqual(broadening["error_code"], "policy-broadening-forbidden")
        self.assertEqual(self.runtime.denied_actions, frozenset({"send_email"}))

    def test_blocked_action_creates_no_event_and_exact_replay_is_verifiable(self):
        baseline = self.execute("baseline-execute-01")
        baseline_validation = self.runtime.handle(protocol_request(
            "validate", "baseline-validate-01", target_id=self.runtime.config.target_id,
            attack_id=self.fixture.attack_id, fixture_sha256=self.fixture.fixture_sha256,
            observed_request_id="baseline-execute-01",
        ))
        self.assertTrue(baseline_validation["validated"])
        self.runtime.handle(protocol_request(
            "apply_policy", "remediation-01", target_id=self.runtime.config.target_id,
            policy_id="physical-remediation-policy-v1", deny_actions=["send_email"],
        ))
        replay = self.execute("replay-execute-01")
        self.assertEqual(replay["fixture_sha256"], baseline["fixture_sha256"])
        self.assertEqual(replay["action"], baseline["action"])
        self.assertEqual(replay["authorization_decision"], "blocked")
        self.assertFalse(replay["executed"])
        self.assertIsNone(replay["synthetic_event_id"])
        replay_validation = self.runtime.handle(protocol_request(
            "validate", "replay-validate-01", target_id=self.runtime.config.target_id,
            attack_id=self.fixture.attack_id, fixture_sha256=self.fixture.fixture_sha256,
            observed_request_id="replay-execute-01",
        ))
        self.assertFalse(replay_validation["validated"])
        self.assertEqual(len(self.runtime.events), 1)

    def test_runtime_responses_are_protocol_valid(self):
        responses = [
            self.runtime.handle(protocol_request("discover", "d-01", expected_target_id=self.runtime.config.target_id)),
            self.execute(),
        ]
        for response in responses:
            self.assertEqual(validate_response(response), response)

    def test_no_subprocess_or_outbound_network_api_is_used_by_runtime(self):
        original_socket = socket.socket
        original_popen = subprocess.Popen
        socket.socket = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("runtime opened a socket"))
        subprocess.Popen = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("runtime opened a subprocess"))
        try:
            self.runtime.handle(protocol_request("discover", "safe-01", expected_target_id=self.runtime.config.target_id))
            self.execute("safe-02")
        finally:
            socket.socket = original_socket
            subprocess.Popen = original_popen


class PhysicalTargetHTTPIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = PhysicalTargetRuntime(node_instance_id="instance-http-01")
        cls.server = create_server(cls.runtime, "127.0.0.1", 0)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}{NODE_PATH}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def post(self, payload, *, content_type="application/json", path=NODE_PATH):
        body = json.dumps(payload).encode("utf-8")
        request_obj = Request(f"http://127.0.0.1:{self.server.server_port}{path}", data=body, method="POST", headers={"Content-Type": content_type})
        try:
            with urlopen(request_obj, timeout=2) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_actual_local_http_transport_baseline_remediation_exact_replay(self):
        fixture = fixture_for("attack-indirect-email-v1", "poisoned-order-note-v1")
        target_id = self.runtime.config.target_id
        status, discovery = self.post(protocol_request("discover", "http-discover-01", expected_target_id=target_id))
        self.assertEqual(status, 200)
        self.assertEqual(discovery["node_instance_id"], "instance-http-01")
        baseline = protocol_request(
            "execute", "http-baseline-01", target_id=target_id, attack_id=fixture.attack_id,
            fixture_id=fixture.fixture_id, fixture_sha256=fixture.fixture_sha256,
            action=fixture.action, source=fixture.source, policy_id=self.runtime.policy_id,
        )
        status, result = self.post(baseline)
        self.assertEqual(status, 200)
        self.assertTrue(result["executed"])
        status, policy = self.post(protocol_request(
            "apply_policy", "http-remediation-01", target_id=target_id,
            policy_id="physical-remediation-policy-v1", deny_actions=["send_email"],
        ))
        self.assertEqual(status, 200)
        replay = protocol_request(
            "execute", "http-replay-01", target_id=target_id, attack_id=fixture.attack_id,
            fixture_id=fixture.fixture_id, fixture_sha256=fixture.fixture_sha256,
            action=fixture.action, source=fixture.source, policy_id=policy["policy_id"],
        )
        status, result = self.post(replay)
        self.assertEqual(status, 200)
        self.assertEqual(result["authorization_decision"], "blocked")
        self.assertFalse(result["executed"])
        self.assertEqual(len(self.runtime.events), 1)

    def test_malformed_json_oversized_body_wrong_content_type_and_endpoint(self):
        malformed_request = Request(self.url, data=b"{bad", method="POST", headers={"Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as context:
            urlopen(malformed_request, timeout=2)
        self.assertEqual(context.exception.code, 400)
        status, response = self.post({}, content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(response["error_code"], "unsupported-content-type")
        large = b"x" * (64 * 1024 + 1)
        large_request = Request(self.url, data=large, method="POST", headers={"Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as context:
            urlopen(large_request, timeout=2)
        self.assertEqual(context.exception.code, 413)
        status, response = self.post({}, path="/not-the-node")
        self.assertEqual(status, 404)
        self.assertEqual(response["error_code"], "unsupported-endpoint")
        get_request = Request(self.url, method="GET")
        with self.assertRaises(HTTPError) as context:
            urlopen(get_request, timeout=2)
        self.assertEqual(context.exception.code, 405)


if __name__ == "__main__":
    unittest.main()
