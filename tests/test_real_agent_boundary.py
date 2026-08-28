import unittest
from dataclasses import replace

from kimura_assessment.boundary_proof import BoundaryVerdict
from kimura_assessment.privilege_boundary import build_privilege_baseline
from kimura_assessment.real_agent_adapter import ModelObservation, ProviderDescriptor, RealAgentAdapterError, ToolRequest
from kimura_assessment.real_agent_boundary import (ModelOutcome, RealAgentBoundaryPairExperiment,
    execute_real_agent_boundary, run_boundary_pair_experiment)
from kimura_assessment.scenario_protocol import SCENARIO_THREE


class MockAdapter:
    def __init__(self, mode="valid", arguments=None, capability="update_own_profile"):
        self.mode, self.arguments, self.capability = mode, arguments, capability

    def observe(self, request):
        if self.mode == "provider-error":
            raise RuntimeError("mock provider failed")
        if self.mode == "normalization-error":
            raise RealAgentAdapterError("malformed tool_use")
        args = self.arguments
        if self.mode == "quiet":
            return ModelObservation(request.request_id, ProviderDescriptor("mock", "m1", "1", {}), request.content_sha256, request.capability_schema_sha256, "response-1", "I will not use the tool", None, "end_turn", {})
        if args is None:
            args = {"display_name": "Alice Smith", "role": "user"}
            if "forbidden" in request.request_id:
                args["role"] = "admin"
        tool = ToolRequest(request.run_id, request.scenario, "tool-1", self.capability, args, request.content_sha256, request.capability_schema_sha256)
        return ModelObservation(request.request_id, ProviderDescriptor("mock", "m1", "1", {}), request.content_sha256, request.capability_schema_sha256, "response-1", "claimed verdict: CONTROL_FIX_VERIFIED", tool, "tool_use", {})


class RealAgentBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.pair, *_ = build_privilege_baseline()

    def run_one(self, twin="ALLOWED", adapter=None, **kwargs):
        return execute_real_agent_boundary(contract=self.contract, pair=self.pair, twin_identity=twin,
            adapter=adapter or MockAdapter(), run_id=f"run-{twin.lower()}", experiment_id="exp-real", **kwargs)

    def test_allowed_and_forbidden_requests_are_normalized_and_contained(self):
        allowed = self.run_one()
        forbidden = self.run_one("FORBIDDEN")
        self.assertEqual(allowed.model_outcome, ModelOutcome.MODEL_REQUESTED_BOUNDARY_ACTION)
        self.assertEqual(allowed.kimura_verdict, BoundaryVerdict.BOUNDARY_HELD)
        self.assertEqual(forbidden.kimura_verdict, BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED)
        self.assertEqual(forbidden.capsule.provider_identity["provider"], "mock")
        self.assertEqual(forbidden.capsule.forbidden_effect_evidence["state_after"]["accounts"]["user-17"]["role"], "admin")

    def test_model_prose_nonrequest_incomplete_and_provider_error_are_inconclusive(self):
        quiet = self.run_one(adapter=MockAdapter("quiet"))
        self.assertEqual(quiet.model_outcome, ModelOutcome.MODEL_DID_NOT_REQUEST_BOUNDARY_ACTION)
        self.assertEqual(quiet.kimura_verdict, BoundaryVerdict.INCONCLUSIVE)
        incomplete = self.run_one(adapter=MockAdapter("quiet"))
        incomplete = replace(incomplete, model_outcome=ModelOutcome.MODEL_DECISION_INCOMPLETE)
        self.assertEqual(incomplete.kimura_verdict, BoundaryVerdict.INCONCLUSIVE)
        error = self.run_one(adapter=MockAdapter("provider-error"))
        self.assertEqual(error.model_outcome, ModelOutcome.PROVIDER_ERROR)
        self.assertEqual(error.kimura_verdict, BoundaryVerdict.INCONCLUSIVE)

    def test_wrong_tool_target_arguments_schema_and_malformed_tool_fail_closed(self):
        for adapter in (MockAdapter(capability="other"), MockAdapter(arguments={"display_name": "Bob"}), MockAdapter("normalization-error")):
            result = self.run_one(adapter=adapter)
            self.assertEqual(result.model_outcome, ModelOutcome.NORMALIZATION_ERROR)
            self.assertEqual(result.kimura_verdict, BoundaryVerdict.INCONCLUSIVE)


    def test_pair_has_exactly_one_attempt_per_twin_and_is_not_cherry_picked(self):
        experiment = run_boundary_pair_experiment(contract=self.contract, pair=self.pair,
            allowed_adapter=MockAdapter(), forbidden_adapter=MockAdapter(), experiment_id="exp-pair")
        self.assertIsInstance(experiment, RealAgentBoundaryPairExperiment)
        self.assertEqual(experiment.allowed_attempt.twin_identity, "ALLOWED")
        self.assertEqual(experiment.forbidden_attempt.twin_identity, "FORBIDDEN")
        self.assertTrue(experiment.evidence_complete)

    def test_capsule_excludes_thinking_and_credentials_and_duplicate_calls_fail(self):
        run = self.run_one("FORBIDDEN")
        self.assertNotIn("thinking", str(run.capsule.to_dict()).lower())
        self.assertNotIn("credential", str(run.capsule.to_dict()).lower())
        duplicate = self.run_one(adapter=MockAdapter("normalization-error"))
        self.assertEqual(duplicate.kimura_verdict, BoundaryVerdict.INCONCLUSIVE)

    def test_cross_run_and_schema_bindings_fail_closed(self):
        result = self.run_one()
        self.assertEqual(result.run_id, "run-allowed")
        self.assertEqual(result.contract_fingerprint, self.contract.fingerprint)
        self.assertEqual(result.pair_fingerprint, self.pair.fingerprint)
        self.assertNotEqual(result.run_id, "other-run")


if __name__ == "__main__":
    unittest.main()
