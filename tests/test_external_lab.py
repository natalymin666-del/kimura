import unittest
from dataclasses import replace

from kimura_assessment.external_lab import (
    ApiBoundaryAction, ExternalEvidenceCapsule, ExternalGateStatus,
    ExternalLabAssessmentContract, MockApiLab, discover_api_boundary_categories, execute_external_action, validate_external_evidence,
    external_kill_conditions, verify_external_scope,
)


class ExternalLabTests(unittest.TestCase):
    def setUp(self):
        self.contract = ExternalLabAssessmentContract(
            "synthetic-lab", "mock-api-lab.local",
            {"written_authorization": "auth-1", "scope": "mock-only"},
            ({"protocol": "https", "endpoint": "/records/r-1", "method": "GET"},),
            ("production", "other-host"),
            ("written authorization", "local mock only"),
            ("scope mismatch", "unexpected effect"),
            ("synthetic fixture only",), {"max_requests": 2},
            "no credentials permitted",
            ("retain redacted structural evidence",),
            True)
        self.contract = replace(self.contract, contract_sha256=self.contract.fingerprint)
        self.action = ApiBoundaryAction(
            "GET", "/records/r-1", {"user_id": "user-a"},
            {"roles": ("reader",), "scopes": ("record:self",)},
            {"id": "r-1", "owner": "user-a"}, {"include": "status"},
            {"fields": ["status"]}, {"read": "own-record"},
            {"read": "other-record"}, {"status": 200},
            {"state_before_after": True})

    def test_scope_gate_fail_closed(self):
        self.assertEqual(verify_external_scope(self.contract, target="mock-api-lab.local", protocol="https", endpoint="/records/r-1").status, ExternalGateStatus.AUTHORIZED)
        self.assertEqual(verify_external_scope(self.contract, target="other-host", protocol="https", endpoint="/records/r-1").status, ExternalGateStatus.PRECONDITION_FAILED)
        not_verified = replace(self.contract, authorized_scope_verified=False, contract_sha256=None)
        self.assertIn("AUTHORIZED_SCOPE_NOT_VERIFIED", verify_external_scope(not_verified, target="mock-api-lab.local", protocol="https", endpoint="/records/r-1").reasons)
        self.assertIn("EXCESSIVE_REQUEST_RATE", verify_external_scope(self.contract, target="mock-api-lab.local", protocol="https", endpoint="/records/r-1", request_count=2).reasons)
        unsealed = replace(self.contract, contract_sha256=None)
        self.assertIn("CONTRACT_NOT_FINGERPRINT_BOUND", verify_external_scope(unsealed, target="mock-api-lab.local", protocol="https", endpoint="/records/r-1").reasons)

    def test_api_action_discovery_and_mock(self):
        self.assertIn("cross-object/cross-user authorization", discover_api_boundary_categories(self.action))
        self.assertIn("mass-assignment/state mutation", discover_api_boundary_categories(self.action))
        self.assertEqual(MockApiLab().request(self.action)["status"], 200)

    def test_capsule_redaction_and_mutation(self):
        cap=ExternalEvidenceCapsule(self.contract.fingerprint, self.contract.assigned_target,
            {"method":"GET"}, {"status":200}, {"decision":"ALLOW"},
            {"effect_count":1}, {"proven":True}, "INCONCLUSIVE", "run-1")
        cap.verify()
        with self.assertRaises(ValueError):
            ExternalEvidenceCapsule(self.contract.fingerprint, self.contract.assigned_target,
                {"token":"secret"}, {"status":200}, {}, {}, {}, "INCONCLUSIVE", "run-1")
        with self.assertRaises(ValueError):
            replace(cap, response={"status":500}, capsule_sha256=cap.fingerprint)

    def test_kill_conditions(self):
        reasons=external_kill_conditions(target_in_scope=False, redirect_in_scope=True, hostname_expected=True, authorization_unambiguous=True, within_rate_limit=True, state_observable=True, provenance_verified=True)
        self.assertEqual(reasons, ("TARGET_OUTSIDE_DECLARED_SCOPE",))


    def test_transport_is_never_called_before_valid_scope(self):
        class RecordingTransport:
            def __init__(self): self.calls = 0
            def send(self, action, *, target):
                self.calls += 1
                return {"status": 200}
        transport = RecordingTransport()
        gate, response = execute_external_action(self.contract, self.action, transport, request_count=0)
        self.assertEqual(gate.status, ExternalGateStatus.AUTHORIZED)
        self.assertEqual(response, {"status": 200})
        self.assertEqual(transport.calls, 1)
        for kwargs in (
            {"request_count": 2},
            {"redirect_target": "unexpected-host"},
            {"authorization_unambiguous": False},
            {"state_observable": False},
            {"assessment_conditions_valid": False},
        ):
            transport = RecordingTransport()
            gate, response = execute_external_action(self.contract, self.action, transport, **kwargs)
            self.assertEqual(gate.status, ExternalGateStatus.PRECONDITION_FAILED)
            self.assertIsNone(response)
            self.assertEqual(transport.calls, 0)
        bad_method = replace(self.action, http_method="POST")
        transport = RecordingTransport()
        gate, response = execute_external_action(self.contract, bad_method, transport)
        self.assertEqual(gate.status, ExternalGateStatus.PRECONDITION_FAILED)
        self.assertEqual(transport.calls, 0)

    def test_cross_target_run_and_unobservable_evidence_rejected(self):
        cap=ExternalEvidenceCapsule(self.contract.fingerprint, self.contract.assigned_target,
            self.action.to_unsigned(), {"status":200}, {"decision":"ALLOW"},
            {"effect_count":1}, {"proven":True}, "INCONCLUSIVE", "run-1")
        self.assertTrue(validate_external_evidence(capsule=cap, contract=self.contract, action=self.action, run_id="run-1", response_target="mock-api-lab.local"))
        self.assertFalse(validate_external_evidence(capsule=cap, contract=self.contract, action=self.action, run_id="run-2", response_target="mock-api-lab.local"))
        self.assertFalse(validate_external_evidence(capsule=cap, contract=self.contract, action=self.action, run_id="run-1", response_target="other-host"))
        self.assertFalse(validate_external_evidence(capsule=cap, contract=self.contract, action=self.action, run_id="run-1", response_target="mock-api-lab.local", state_observable=False))
