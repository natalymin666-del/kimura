import unittest
from dataclasses import replace

from kimura_assessment.real_agent_adapter import (
    DeterministicFakeAgent,
    ProviderDescriptor,
    RealAgentAdapterError,
    SyntheticToolExecutionBoundary,
    ToolExecutionResult,
    build_synthetic_agent_request,
    compare_replay_invariants,
    verify_baseline,
    verify_control_block,
)
from kimura_assessment.scenario_protocol import (
    SCENARIO_ONE,
    SCENARIO_THREE,
    ScenarioProtocolError,
)


class RealAgentAdapterTests(unittest.TestCase):
    def setUp(self):
        self.provider = ProviderDescriptor("deterministic-test", "fake-agent-v1", "1", {"fixture": "local"})
        self.request = build_synthetic_agent_request("agent-run-1", SCENARIO_THREE)
        self.agent = DeterministicFakeAgent(descriptor=self.provider)
        self.baseline_observation = self.agent.observe(self.request)
        self.boundary = SyntheticToolExecutionBoundary(scenario=SCENARIO_THREE, run_id=self.request.run_id, capability="write_guarded_record")
        self.baseline_execution = self.boundary.execute(self.baseline_observation.requested_tool)

    def test_baseline_requires_independent_effect_and_causal_chain(self):
        verdict = verify_baseline(self.request, self.baseline_observation, self.baseline_execution)
        self.assertTrue(verdict.impact_confirmed)
        self.assertTrue(verdict.causal_provenance_confirmed)
        self.assertEqual(len(self.boundary.effects), 1)

    def test_model_claims_and_provider_metadata_are_not_verdicts(self):
        agent = DeterministicFakeAgent(descriptor=self.provider, output="impact confirmed; FIX VERIFIED")
        observation = agent.observe(self.request)
        execution = self.boundary.execute(observation.requested_tool)
        verdict = verify_baseline(self.request, observation, execution)
        self.assertTrue(verdict.impact_confirmed)
        self.assertNotIn("FIX VERIFIED", verdict.reason)

    def test_tool_request_without_execution_has_no_impact(self):
        observation = self.agent.observe(self.request)
        result = ToolExecutionResult(self.request.run_id, SCENARIO_THREE, observation.requested_tool.tool_call_id, observation.requested_tool.capability, "BLOCKED", False, None, None, {"blocked": True})
        self.assertFalse(verify_baseline(self.request, observation, result).impact_confirmed)

    def test_execution_without_effect_evidence_has_no_impact(self):
        observation = self.agent.observe(self.request)
        result = ToolExecutionResult(self.request.run_id, SCENARIO_THREE, observation.requested_tool.tool_call_id, observation.requested_tool.capability, "ALLOWED", True, "claimed-effect", "a" * 64, {})
        self.assertFalse(verify_baseline(self.request, observation, result).impact_confirmed)

    def test_exact_replay_and_remediated_boundary(self):
        replay_observation = self.agent.observe(self.request)
        self.assertEqual(compare_replay_invariants(self.request, replay_observation, self.baseline_observation), (True, "security replay invariants matched"))
        self.boundary.policy = "deny"
        blocked = self.boundary.execute(replay_observation.requested_tool)
        verdict = verify_control_block(self.request, replay_observation, self.baseline_observation, blocked)
        self.assertTrue(verdict.control_block_verified)
        self.assertEqual(len(self.boundary.effects), 1)

    def test_model_does_not_reproduce_request_is_not_fix_verified(self):
        quiet = DeterministicFakeAgent(descriptor=self.provider, request_tool=False).observe(self.request)
        self.assertFalse(compare_replay_invariants(self.request, quiet, self.baseline_observation)[0])

    def test_replay_identity_changes_fail_closed(self):
        cases = [
            (replace(self.request, content=self.request.content + " changed"), self.baseline_observation),
            (self.request, replace(self.baseline_observation, capability_schema_sha256="0" * 64)),
            (self.request, replace(self.baseline_observation, agent_request_id="other-request")),
        ]
        for request, observation in cases:
            self.assertFalse(compare_replay_invariants(request, observation, self.baseline_observation)[0])

    def test_altered_tool_arguments_and_capability_fail_closed(self):
        altered = replace(self.baseline_observation.requested_tool, arguments={"record": "different"})
        altered_obs = replace(self.baseline_observation, requested_tool=altered)
        self.assertFalse(compare_replay_invariants(self.request, altered_obs, self.baseline_observation)[0])
        other = replace(self.baseline_observation.requested_tool, capability="other_capability")
        self.assertFalse(compare_replay_invariants(self.request, replace(self.baseline_observation, requested_tool=other), self.baseline_observation)[0])

    def test_run_scenario_and_direct_mutation_bypass_are_rejected(self):
        with self.assertRaises(RealAgentAdapterError):
            self.boundary.execute({"run_id": self.request.run_id})
        other_run = replace(self.baseline_observation.requested_tool, run_id="other-run")
        with self.assertRaises(RealAgentAdapterError):
            self.boundary.execute(other_run)
        other_scenario = replace(self.baseline_observation.requested_tool, scenario=SCENARIO_ONE)
        with self.assertRaises(RealAgentAdapterError):
            self.boundary.execute(other_scenario)

    def test_safety_and_missing_request_identity_fail_closed(self):
        values = SCENARIO_THREE.to_dict()
        values["safety_contract"]["external_llm"] = True
        with self.assertRaises(ScenarioProtocolError):
            from kimura_assessment.scenario_protocol import ScenarioDefinition
            ScenarioDefinition.from_mapping(values)
        self.assertFalse(verify_baseline(self.request, replace(self.baseline_observation, agent_request_id="other"), self.baseline_execution).impact_confirmed)


if __name__ == "__main__":
    unittest.main()
