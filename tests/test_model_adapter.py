import json
import unittest
from unittest.mock import patch

from kimura_assessment.action_gate import ActionGate
from kimura_assessment.agent_wrapper import AgentPolicy, ModelBackedAgent
from kimura_assessment.model_schemas import ModelResponse, ProposedAction, TrialConfig, safe_digest
from kimura_assessment.model_scenarios import MODEL_V1_FIXTURE
from kimura_assessment.ollama_adapter import OllamaProvider, OllamaReadinessError


class FakeProvider:
    provider_id = "fake-local"
    model_id = "fake-model"

    def complete(self, request):
        return ModelResponse("fake-local", "fake-model", ProposedAction("send_email", ("body",)), "valid", "complete", safe_digest("raw provider response"), 21, 0)


class ModelAdapterTests(unittest.TestCase):
    def test_gate_is_independent_from_model_proposal(self):
        proposal = ProposedAction("send_email", ("body",))
        self.assertEqual(ActionGate(policy_id="baseline-permissive-v1", allowed_actions=frozenset({"send_email"}), require_trusted_source=False).evaluate(proposal, source_trusted=False).decision, "allowed")
        self.assertEqual(ActionGate(policy_id="deny-untrusted-actions-v1", allowed_actions=frozenset({"send_email"}), require_trusted_source=True).evaluate(proposal, source_trusted=False).decision, "blocked")

    def test_model_wrapper_executes_only_after_gate_and_replays_fixture(self):
        agent = ModelBackedAgent(FakeProvider())
        trials = tuple(TrialConfig(f"trial-{index}", index) for index in range(3))
        baseline, before = agent.run_trials(MODEL_V1_FIXTURE, AgentPolicy("baseline-permissive-v1", False), trials)
        retest, after = agent.run_trials(MODEL_V1_FIXTURE, AgentPolicy("deny-untrusted-actions-v1", True), tuple(TrialConfig(f"retest-{index}", index) for index in range(3)))
        self.assertEqual(before.outcome, "stable-vulnerable")
        self.assertEqual(before.validated_impact_count, 3)
        self.assertEqual(after.outcome, "stable-blocked")
        self.assertEqual(after.validated_impact_count, 0)
        self.assertEqual({item.fixture_sha256 for item in baseline}, {item.fixture_sha256 for item in retest})
        self.assertEqual(len(agent.audit_events), 3)
        self.assertNotIn("raw provider response", json.dumps([item.to_dict() for item in baseline + retest]))

    @patch("kimura_assessment.ollama_adapter.urlopen")
    def test_ollama_parses_native_tool_call_without_exposing_arguments(self, opener):
        raw = json.dumps({"message": {"content": "", "tool_calls": [{"function": {"name": "send_email", "arguments": {"body": "secret"}}}]}, "done_reason": "stop"}).encode()
        opener.return_value.__enter__.return_value.read.return_value = raw
        request_types = __import__("kimura_assessment.model_schemas", fromlist=["ModelRequest", "ToolDescription", "ModelSettings"])
        request = request_types.ModelRequest("system", "task", "untrusted", (request_types.ToolDescription("send_email", "synthetic", "schema"),), request_types.ModelSettings("fake-model"), "trial-tool-call")
        result = OllamaProvider().complete(request)
        self.assertEqual(result.proposed_action.action_name, "send_email")
        self.assertEqual(result.proposed_action.argument_keys, ("body",))
        self.assertNotIn("secret", result.__repr__())

    @patch("kimura_assessment.ollama_adapter.urlopen")
    def test_ollama_preflight_confirms_service_and_model(self, opener):
        response = opener.return_value.__enter__.return_value
        response.read.return_value = json.dumps({"models": [{"name": "llama3.2:3b"}]}).encode()
        OllamaProvider(model_id="llama3.2:3b").check_ready()
        self.assertEqual(opener.call_args.args[0].full_url, "http://127.0.0.1:11434/api/tags")

    @patch("kimura_assessment.ollama_adapter.urlopen")
    def test_ollama_preflight_rejects_missing_model_safely(self, opener):
        opener.return_value.__enter__.return_value.read.return_value = json.dumps({"models": []}).encode()
        with self.assertRaisesRegex(OllamaReadinessError, "not installed"):
            OllamaProvider(model_id="missing-model").check_ready()

    def test_ollama_rejects_non_loopback_endpoint(self):
        with self.assertRaises(ValueError):
            OllamaProvider("http://example.test/api/chat")

    @patch("kimura_assessment.ollama_adapter.urlopen")
    def test_ollama_parses_json_proposal_without_exposing_raw_content(self, opener):
        raw = json.dumps({"message": {"content": '{"action":"send_email","arguments":{"body":"secret"}}'}, "done_reason": "stop"}).encode()
        response = opener.return_value.__enter__.return_value
        response.read.return_value = raw
        result = OllamaProvider().complete(__import__("kimura_assessment.model_schemas", fromlist=["ModelRequest"]).ModelRequest("system", "task", "untrusted", (__import__("kimura_assessment.model_schemas", fromlist=["ToolDescription"]).ToolDescription("send_email", "synthetic", "schema"),), __import__("kimura_assessment.model_schemas", fromlist=["ModelSettings"]).ModelSettings("fake-model"), "trial-1"))
        self.assertEqual(result.proposed_action.action_name, "send_email")
        self.assertNotIn("secret", result.__repr__())


if __name__ == "__main__":
    unittest.main()
