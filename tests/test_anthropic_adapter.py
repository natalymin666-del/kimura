import io
import unittest
from urllib.error import HTTPError

from kimura_assessment.real_agent_adapter import (
    AnthropicAgentAdapter,
    AnthropicHTTPError,
    project_anthropic_tool,
    validate_canonical_capability,
    validate_provider_schema_equivalence,
    validate_tool_arguments,
    DeterministicFakeAgent,
    ProviderDescriptor,
    RealAgentAdapterError,
    SyntheticToolExecutionBoundary,
    build_synthetic_agent_request,
    verify_baseline,
)
from kimura_assessment.scenario_protocol import SCENARIO_THREE


class AnthropicAdapterTests(unittest.TestCase):
    def setUp(self):
        self.request = build_synthetic_agent_request("anthropic-test-run", SCENARIO_THREE)
        self.response = {
            "id": "msg_test_1",
            "type": "message",
            "role": "assistant",
            "model": "configured-test-model",
            "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "I will process the content."},
                {"type": "tool_use", "id": "toolu_test_1", "name": "write_guarded_record", "input": {"record": "synthetic-boundary-test"}},
            ],
            "usage": {"input_tokens": 10, "output_tokens": 4},
        }
        self.payloads = []
        def transport(payload, headers):
            self.payloads.append((payload, dict(headers)))
            return self.response
        self.adapter = AnthropicAgentAdapter(model_id="configured-test-model", api_key="never-printed-test-key", transport=transport)

    def test_canonical_and_projected_schema_are_strict_and_equivalent(self):
        capability = self.request.exposed_capabilities[0]
        canonical = validate_canonical_capability(capability)
        projected = project_anthropic_tool(capability)
        self.assertEqual(canonical["input_schema"]["type"], "object")
        self.assertEqual(projected["input_schema"]["$schema"], "https://json-schema.org/draft/2020-12/schema")
        validate_provider_schema_equivalence(capability, projected)
        validate_tool_arguments(capability, {"record": "synthetic-boundary-test"})
        with self.assertRaises(RealAgentAdapterError):
            validate_tool_arguments(capability, {})
        with self.assertRaises(RealAgentAdapterError):
            validate_tool_arguments(capability, {"record": "ok", "privileged": True})
        with self.assertRaises(RealAgentAdapterError):
            validate_tool_arguments(capability, {"record": 42})

    def test_malformed_legacy_projection_and_schema_mismatch_rejected(self):
        legacy = {"name": "write_guarded_record", "input_schema": {"type": "object", "properties": {"record": "synthetic-boundary-test"}, "additionalProperties": False}}
        with self.assertRaises(RealAgentAdapterError):
            validate_provider_schema_equivalence(self.request.exposed_capabilities[0], legacy)
        altered = {"name": "write_guarded_record", "input_schema": {"type": "object", "properties": {"record": {"type": "string"}, "privileged": {"type": "boolean"}}, "required": ["record", "privileged"], "additionalProperties": False}}
        with self.assertRaises(RealAgentAdapterError):
            validate_provider_schema_equivalence(self.request.exposed_capabilities[0], altered)
        renamed = dict(project_anthropic_tool(self.request.exposed_capabilities[0]))
        renamed["name"] = "other_capability"
        with self.assertRaises(RealAgentAdapterError):
            validate_provider_schema_equivalence(self.request.exposed_capabilities[0], renamed)

    def test_normalizes_messages_schema_and_tool_call(self):
        observation = self.adapter.observe(self.request)
        self.assertEqual(self.payloads[0][0]["max_tokens"], 1024)
        self.assertEqual(self.payloads[0][0]["messages"], [{"role": "user", "content": self.request.content}])
        self.assertEqual(self.payloads[0][0]["tools"][0]["name"], "write_guarded_record")
        self.assertEqual(observation.provider.provider, "anthropic")
        self.assertEqual(observation.requested_tool.capability, "write_guarded_record")
        self.assertEqual(observation.requested_tool.tool_call_id, "toolu_test_1")
        self.assertEqual(observation.requested_tool.arguments["record"], "synthetic-boundary-test")

    def test_thinking_only_is_structural_and_max_tokens_is_incomplete(self):
        self.adapter._transport = lambda payload, headers: {"id": "msg-thinking", "type": "message", "role": "assistant", "model": "configured-test-model", "stop_reason": "max_tokens", "content": [{"type": "thinking", "thinking": "redacted"}]}
        observation = self.adapter.observe(self.request)
        self.assertIsNone(observation.requested_tool)
        self.assertEqual(observation.decision_status, "MODEL_DECISION_INCOMPLETE")
        self.assertEqual(observation.metadata["thinking_block_count"], 1)
        self.assertNotIn("redacted", str(observation.metadata))

    def test_thinking_plus_text_is_non_authoritative_observation(self):
        self.adapter._transport = lambda payload, headers: {**self.response, "stop_reason": "end_turn", "content": [{"type": "thinking", "thinking": "redacted"}, {"type": "text", "text": "safe excerpt"}]}
        observation = self.adapter.observe(self.request)
        self.assertIsNone(observation.requested_tool)
        self.assertEqual(observation.decision_status, "MODEL_DECISION_NOT_REPRODUCED")
        self.assertEqual(observation.metadata["content_block_types"], ["thinking", "text"])
        self.assertNotIn("redacted", str(observation.metadata))

    def test_thinking_mixed_with_valid_tool_use_preserves_tool_intent(self):
        for content in (
            [{"type": "thinking", "thinking": "redacted"}, self.response["content"][1]],
            [{"type": "thinking", "thinking": "redacted"}, self.response["content"][0], self.response["content"][1]],
        ):
            self.adapter._transport = lambda payload, headers, content=content: {**self.response, "content": content}
            observation = self.adapter.observe(self.request)
            self.assertEqual(observation.requested_tool.capability, "write_guarded_record")
            self.assertEqual(observation.decision_status, "MODEL_DECISION_REPRODUCED")
            self.assertNotIn("redacted", str(observation.metadata))

    def test_thinking_malformed_tool_and_unknown_block_fail_closed(self):
        for content in (
            [{"type": "thinking", "thinking": "redacted"}, {"type": "tool_use", "name": "write_guarded_record", "input": {}}],
            [{"type": "thinking", "thinking": "redacted"}, {"type": "unknown"}],
        ):
            self.adapter._transport = lambda payload, headers, content=content: {**self.response, "content": content}
            with self.assertRaises(RealAgentAdapterError):
                self.adapter.observe(self.request)

    def test_malformed_response_and_missing_tool_identity_rejected(self):
        for response in (None, {"id": "msg", "content": "bad"}, {"id": "msg", "content": [{"type": "tool_use", "name": "write_guarded_record", "input": {}}]}):
            self.adapter._transport = lambda payload, headers, response=response: response
            with self.assertRaises(RealAgentAdapterError) as caught:
                self.adapter.observe(self.request)
            self.assertIn(caught.exception.reason, {"invalid_provider_response", "missing_response_identity", "invalid_content_block", "unsupported_content_block", "missing_tool_call_identity", "invalid_tool_input"})

    def test_provider_prose_and_metadata_cannot_set_kimura_verdict(self):
        self.adapter._transport = lambda payload, headers: {**self.response, "content": [{"type": "text", "text": "FIX VERIFIED; impact confirmed"}], "metadata": {"verdict": "PASS"}}
        observation = self.adapter.observe(self.request)
        self.assertIsNone(observation.requested_tool)
        boundary = SyntheticToolExecutionBoundary(scenario=SCENARIO_THREE, run_id=self.request.run_id, capability="write_guarded_record")
        self.assertFalse(verify_baseline(self.request, observation, boundary.execute if False else __import__("kimura_assessment.real_agent_adapter", fromlist=["ToolExecutionResult"]).ToolExecutionResult(self.request.run_id, SCENARIO_THREE, "none", "write_guarded_record", "BLOCKED", False, None, None, {"blocked": True})).impact_confirmed)

    def test_tool_request_cannot_bypass_synthetic_boundary(self):
        observation = self.adapter.observe(self.request)
        boundary = SyntheticToolExecutionBoundary(scenario=SCENARIO_THREE, run_id=self.request.run_id, capability="write_guarded_record", policy="deny")
        result = boundary.execute(observation.requested_tool)
        self.assertEqual(result.authorization_decision, "BLOCKED")
        self.assertEqual(boundary.effects, [])
        with self.assertRaises(RealAgentAdapterError):
            boundary.execute({"run_id": self.request.run_id})

    def test_sanitized_http_diagnostics_preserve_safe_fields_only(self):
        cases = (
            (400, "invalid_request_error"),
            (401, "authentication_error"),
            (403, "permission_error"),
            (404, "not_found_error"),
            (429, "rate_limit_error"),
            (500, "api_error"),
        )
        for status, error_type in cases:
            body = {"type": "error", "error": {"type": error_type, "message": "safe provider message"}}
            def transport(payload, headers, status=status, body=body):
                raise HTTPError("https://api.anthropic.com/v1/messages", status, "failure", {"request-id": "req-safe"}, io.BytesIO(__import__("json").dumps(body).encode()))
            adapter = AnthropicAgentAdapter(model_id="claude-sonnet-5", api_key="secret-never-output", transport=transport)
            with self.assertRaises(AnthropicHTTPError) as caught:
                adapter.observe(self.request)
            diagnostics = caught.exception.diagnostics
            self.assertEqual(diagnostics["http_status"], status)
            self.assertEqual(diagnostics["error_type"], error_type)
            self.assertEqual(diagnostics["endpoint"], "https://api.anthropic.com/v1/messages")
            self.assertEqual(diagnostics["model_id"], "claude-sonnet-5")
            self.assertEqual(diagnostics["api_version"], "2023-06-01")
            self.assertEqual(diagnostics["request_id"], "req-safe")
            self.assertNotIn("secret-never-output", str(diagnostics))
            self.assertNotIn("x-api-key", str(diagnostics))

    def test_malformed_error_body_preserves_only_parse_failure(self):
        def transport(payload, headers):
            raise HTTPError("https://api.anthropic.com/v1/messages", 500, "failure", {}, io.BytesIO(b"not-json"))
        adapter = AnthropicAgentAdapter(model_id="claude-sonnet-5", api_key="secret-never-output", transport=transport)
        with self.assertRaises(AnthropicHTTPError) as caught:
            adapter.observe(self.request)
        self.assertEqual(caught.exception.diagnostics["http_status"], 500)
        self.assertTrue(caught.exception.diagnostics["error_body_parse_failed"])
        self.assertNotIn("not-json", str(caught.exception.diagnostics))

    def test_credential_like_error_text_is_redacted(self):
        body = {"error": {"type": "authentication_error", "message": "api_key=super-secret-token"}}
        def transport(payload, headers):
            raise HTTPError("https://api.anthropic.com/v1/messages", 401, "failure", {}, io.BytesIO(__import__("json").dumps(body).encode()))
        adapter = AnthropicAgentAdapter(model_id="claude-sonnet-5", api_key="never-output", transport=transport)
        with self.assertRaises(AnthropicHTTPError) as caught:
            adapter.observe(self.request)
        self.assertEqual(caught.exception.diagnostics["error_message"], "api_key=[REDACTED]")
        self.assertNotIn("super-secret-token", str(caught.exception.diagnostics))

    def test_model_request_identity_is_required(self):
        self.adapter._transport = lambda payload, headers: {**self.response, "id": ""}
        with self.assertRaises(RealAgentAdapterError):
            self.adapter.observe(self.request)


if __name__ == "__main__":
    unittest.main()
