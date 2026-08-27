import tempfile
import unittest
from pathlib import Path

from kimura_assessment.attack_reproduction import (
    AttemptJournal, AttemptJournalEvent, AttackAttemptEvidence,
    AttackReproductionExperiment, DurableAttackExperimentRunner,
    build_scenario_three_variant_set, recover_experiment,
)
from kimura_assessment.real_agent_adapter import AnthropicHTTPError, RealAgentAdapterError
from kimura_assessment.scenario_protocol import SCENARIO_THREE


class RunnerReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.journal = AttemptJournal(Path(self.tmp.name) / "attempts.jsonl")
        self.variant_set = build_scenario_three_variant_set(SCENARIO_THREE).seal()
        self.experiment = AttackReproductionExperiment(
            experiment_id="exp-reliable-1", variant_set=self.variant_set,
            scenario=SCENARIO_THREE, run_id="run-1", provider="test",
            model="deterministic", fixture_id="fixture-1",
            observer=lambda variant: None,
            capability_schema={"name": "write_guarded_record", "input_schema": {
                "type": "object", "properties": {"record": {"type": "string"}},
                "required": ["record"], "additionalProperties": False}},
        )
        self.runner = DurableAttackExperimentRunner(
            experiment=self.experiment, journal=self.journal,
            clock=lambda: "2026-01-01T00:00:00Z",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def evidence(self, variant_id="variant-01", outcome="NO_DANGEROUS_INTENT"):
        return AttackAttemptEvidence(
            "exp-reliable-1", self.variant_set.fingerprint, variant_id,
            self.variant_set.variant_set.resolve(variant_id).content_sha256,
            SCENARIO_THREE.fingerprint, "test", "deterministic", "run-1",
            "response-1", None, None, "NOT_EXECUTED", False, None, outcome,
        )

    def event(self, variant_id, state, ordinal):
        variant = self.variant_set.variant_set.resolve(variant_id)
        return AttemptJournalEvent(
            "exp-reliable-1", self.variant_set.fingerprint, variant_id,
            variant.content_sha256, "run-1", ordinal, "test", "deterministic",
            "2026-01-01T00:00:00Z", state,
        )

    def test_normal_ten_attempt_completion(self):
        results = self.runner.run_all(lambda variant: lambda: self.evidence(variant.variant_id))
        self.assertEqual(len(results), 10)
        recovery = self.runner.recover()
        self.assertFalse(recovery.interrupted)
        self.assertTrue(recovery.metrics_available)
        self.assertEqual(recovery.minimum_proven_api_calls, 10)

    def test_timeout_is_terminal_and_consumes_call(self):
        self.assertIsNone(self.runner.run_variant("variant-01", lambda: (_ for _ in ()).throw(TimeoutError())))
        recovery = self.runner.recover()
        self.assertEqual(recovery.minimum_proven_api_calls, 1)
        self.assertEqual(recovery.maximum_possible_api_calls, 1)
        self.assertEqual(self.journal.read()[-1]["failure_code"], "provider_timeout")

    def test_interruption_before_request_is_ambiguous(self):
        self.journal.append(self.event("variant-01", "ALLOCATED", 1))
        self.journal.append(self.event("variant-01", "REQUEST_STARTING", 2))
        recovery = recover_experiment(self.journal, experiment_id="exp-reliable-1", variant_set=self.variant_set)
        self.assertEqual(recovery.minimum_proven_api_calls, 0)
        self.assertEqual(recovery.maximum_possible_api_calls, 1)
        self.assertIn("variant-01", recovery.ambiguous_variants)

    def test_interruption_after_request_sent_consumes_call(self):
        for ordinal, state in enumerate(("ALLOCATED", "REQUEST_STARTING", "REQUEST_SENT"), 1):
            self.journal.append(self.event("variant-01", state, ordinal))
        recovery = self.runner.recover()
        self.assertEqual(recovery.minimum_proven_api_calls, 1)
        self.assertEqual(recovery.maximum_possible_api_calls, 1)
        self.assertFalse(recovery.metrics_available)

    def test_interruption_after_response_received(self):
        for ordinal, state in enumerate(("ALLOCATED", "REQUEST_STARTING", "REQUEST_SENT", "RESPONSE_RECEIVED"), 1):
            self.journal.append(self.event("variant-01", state, ordinal))
        recovery = self.runner.recover()
        self.assertIn("variant-01", recovery.variants_response_received)
        self.assertNotIn("variant-01", recovery.variants_classified)

    def test_normalization_failure_is_not_safe(self):
        result = self.runner.run_variant("variant-01", lambda: (_ for _ in ()).throw(RealAgentAdapterError("bad", reason="invalid_provider_response")))
        self.assertIsNone(result)
        self.assertEqual(self.journal.read()[-1]["outcome"], "NORMALIZATION_ERROR")

    def test_provider_failure_is_not_safe(self):
        result = self.runner.run_variant("variant-01", lambda: (_ for _ in ()).throw(AnthropicHTTPError({"http_status": 503})))
        self.assertIsNone(result)
        self.assertEqual(self.journal.read()[-1]["outcome"], "PROVIDER_ERROR")

    def test_duplicate_attempt_and_auto_retry_rejected(self):
        self.runner.run_variant("variant-01", lambda: self.evidence())
        with self.assertRaises(ValueError):
            self.runner.run_variant("variant-01", lambda: self.evidence())
        with self.assertRaises(ValueError):
            DurableAttackExperimentRunner(experiment=self.experiment, journal=self.journal, clock=lambda: "now")

    def test_identity_and_sealed_fingerprint_are_preserved(self):
        original = self.variant_set.fingerprint
        self.assertEqual(original, build_scenario_three_variant_set(SCENARIO_THREE).fingerprint)
        self.assertEqual(original, self.experiment.variant_set.fingerprint)
        with self.assertRaises(ValueError):
            self.runner.run_variant("unknown", lambda: self.evidence("unknown"))

    def test_journal_redacts_sensitive_fields(self):
        with self.assertRaises(ValueError):
            self.journal.append(AttemptJournalEvent("e", "f", "v", "h", "r", 1, "p", "m", "t", "CLASSIFIED", failure_code="api_key=secret"))
        self.assertNotIn("thinking", self.journal.path.read_text() if self.journal.path.exists() else "")


if __name__ == "__main__":
    unittest.main()
