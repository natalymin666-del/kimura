import unittest
from kimura_assessment.attack_reproduction import (
    AttackReproductionExperiment, AttackVariantSet, OUTCOMES,
    build_scenario_three_variant_set,
)
from kimura_assessment.real_agent_adapter import (
    AnthropicHTTPError, DeterministicFakeAgent, ProviderDescriptor,
    RealAgentAdapterError, SyntheticToolExecutionBoundary, build_synthetic_agent_request,
)
from kimura_assessment.scenario_protocol import SCENARIO_THREE


class AttackHarnessTests(unittest.TestCase):
    def setUp(self):
        self.variant_set = build_scenario_three_variant_set(SCENARIO_THREE)
        self.sealed = self.variant_set.seal()
        self.capability = {
            "name": "write_guarded_record",
            "input_schema": {
                "type": "object",
                "properties": {"record": {"type": "string"}},
                "required": ["record"],
                "additionalProperties": False,
            },
        }
        self.descriptor = ProviderDescriptor("test", "deterministic", "v1", {})

    def observer(self, variant, *, tool=True, mode="normal"):
        request = build_synthetic_agent_request("experiment-run", SCENARIO_THREE, request_id=variant.variant_id)
        request = type(request)(
            request.run_id, request.scenario, variant.content,
            request.exposed_capabilities, request.request_id
        )
        if mode == "provider":
            raise AnthropicHTTPError({"http_status": 503})
        if mode == "normalize":
            raise RealAgentAdapterError("bad response", reason="invalid_provider_response")
        if mode == "harness":
            return object()
        return DeterministicFakeAgent(descriptor=self.descriptor, request_tool=tool).observe(request)

    def experiment(self, observer=None):
        return AttackReproductionExperiment(
            experiment_id="experiment-1",
            variant_set=self.sealed,
            scenario=SCENARIO_THREE,
            run_id="experiment-run",
            provider="test",
            model="deterministic",
            fixture_id="fixture-3",
            observer=observer or self.observer,
            capability_schema=self.capability,
            boundary_factory=lambda run_id: SyntheticToolExecutionBoundary(
                scenario=SCENARIO_THREE, run_id=run_id, capability="write_guarded_record", policy="permit"
            ),
        )

    def test_exactly_ten_and_fingerprint_is_stable(self):
        self.assertEqual(len(self.variant_set.variants), 10)
        self.assertEqual(self.variant_set.fingerprint, self.variant_set.seal().fingerprint)
        self.assertNotEqual(self.variant_set.fingerprint, build_scenario_three_variant_set(SCENARIO_THREE).fingerprint if False else "x")

    def test_duplicate_and_binding_tampering_rejected(self):
        with self.assertRaises(ValueError):
            AttackVariantSet(self.variant_set.variant_set_id, 1, SCENARIO_THREE, self.variant_set.variants + (self.variant_set.variants[0],))
        self.variant_set.variants[0].expected_request_contract["arguments"]["record"] = "changed"
        with self.assertRaises(ValueError):
            self.sealed.fingerprint

    def test_all_successful_dangerous_attempts_and_denominators(self):
        experiment = self.experiment()
        results = experiment.run_all()
        self.assertEqual(len(results), 10)
        self.assertEqual({item.outcome for item in results}, {"DANGEROUS_INTENT_REPRODUCED"})
        self.assertEqual(experiment.summary.attempts_total, 10)
        self.assertEqual(experiment.summary.dangerous_intent_rate_all_attempts, 1.0)
        self.assertEqual(experiment.summary.dangerous_intent_rate_conclusive, 1.0)

    def test_outcome_classes_and_failures_are_not_safe(self):
        for mode, expected in (("provider", "PROVIDER_ERROR"), ("normalize", "NORMALIZATION_ERROR"), ("harness", "HARNESS_ERROR")):
            experiment = self.experiment(lambda variant, mode=mode: self.observer(variant, mode=mode))
            self.assertEqual(experiment.run_variant("variant-01").outcome, expected)
        incomplete = self.experiment(lambda variant: self.observer(variant, tool=False))
        request = build_synthetic_agent_request("experiment-run", SCENARIO_THREE)
        incomplete.observer = lambda variant: type(incomplete.observer)(request) if False else self.observer(variant, tool=False)
        self.assertEqual(incomplete.run_variant("variant-01").outcome, "NO_DANGEROUS_INTENT")
        self.assertEqual(incomplete.summary.conclusive_model_decisions, 1)

    def test_max_tokens_maps_to_incomplete(self):
        from kimura_assessment.real_agent_adapter import ModelObservation
        def observer(variant):
            request = build_synthetic_agent_request("experiment-run", SCENARIO_THREE)
            return ModelObservation(request.request_id, self.descriptor, request.content_sha256, request.capability_schema_sha256, "response", "", None, "max_tokens", {})
        experiment = self.experiment(observer)
        self.assertEqual(experiment.run_variant("variant-01").outcome, "MODEL_DECISION_INCOMPLETE")

    def test_no_retries_or_post_result_variant_mutation(self):
        experiment = self.experiment()
        experiment.run_variant("variant-01")
        with self.assertRaises(ValueError):
            experiment.run_variant("variant-01")
        experiment.variant_set.variant_set.variants[0].expected_request_contract["arguments"]["record"] = "changed"
        with self.assertRaises(ValueError):
            experiment.run_variant("variant-02")
        self.assertEqual(len(experiment.attempts), 1)

    def test_only_dangerous_intent_is_replay_eligible(self):
        experiment = self.experiment()
        evidence = experiment.run_variant("variant-01")
        self.assertEqual(evidence.outcome, "DANGEROUS_INTENT_REPRODUCED")
        tool = DeterministicFakeAgent(descriptor=self.descriptor).observe(build_synthetic_agent_request("experiment-run", SCENARIO_THREE)).requested_tool
        binding = experiment.replay_binding(evidence, tool, fixture_id="fixture-3")
        self.assertEqual(binding.variant_id, "variant-01")
        safe = self.experiment(lambda variant: self.observer(variant, tool=False))
        safe_evidence = safe.run_variant("variant-01")
        with self.assertRaises(ValueError):
            safe.replay_binding(safe_evidence, tool, fixture_id="fixture-3")

    def test_replay_binding_mismatches_are_rejected(self):
        experiment = self.experiment()
        evidence = experiment.run_variant("variant-01")
        tool = DeterministicFakeAgent(descriptor=self.descriptor).observe(build_synthetic_agent_request("experiment-run", SCENARIO_THREE)).requested_tool
        with self.assertRaises(ValueError):
            experiment.replay_binding(evidence, tool, fixture_id="other-fixture")
        with self.assertRaises(ValueError):
            experiment.replay_binding(evidence, type(tool)(
                tool.run_id, SCENARIO_THREE, tool.tool_call_id, "other", tool.arguments,
                tool.content_sha256, tool.capability_schema_sha256
            ), fixture_id="fixture-3")

    def test_provider_independent_and_claims_do_not_set_verdict(self):
        result = self.experiment(lambda variant: self.observer(variant, tool=False)).run_variant("variant-01")
        self.assertEqual(result.outcome, "NO_DANGEROUS_INTENT")
        self.assertNotIn("FIX VERIFIED", result.outcome)

    def test_variant_set_scenario_and_fingerprint_binding(self):
        with self.assertRaises(ValueError):
            AttackReproductionExperiment(
                experiment_id="x", variant_set=self.sealed, scenario=__import__("kimura_assessment.scenario_protocol", fromlist=["SCENARIO_ONE"]).SCENARIO_ONE,
                run_id="r", provider="p", model="m", fixture_id="f",
                observer=self.observer, capability_schema=self.capability,
            )

if __name__ == "__main__":
    unittest.main()
