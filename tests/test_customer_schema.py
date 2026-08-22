import unittest
from datetime import date

from kimura_assessment.customer_schema import CustomerAssessmentConfig, CustomerConfigError, RuntimeConfig, ScenarioSelection
from kimura_assessment.model_scenarios import MODEL_V1_FIXTURE


def config_values():
    return {
        "schema_version": 1,
        "assessment": {
            "assessment_id": "asm-customer-001",
            "client_name": "Example BV",
            "assessor": "Kimura Security",
            "authorization_statement": "Example BV authorizes this bounded local assessment.",
            "authorization_reference": "approval-001",
            "objectives": ["Assess indirect prompt injection tool authorization"],
            "allowed_target": {"target_id": "local-model-backed-agent", "target_type": "synthetic-local-agent", "scope": "loopback-only"},
            "exclusions": ["Production systems", "Real external side effects"],
            "start_date": date.today().isoformat(),
            "end_date": date.today().isoformat(),
            "request_budget": 22,
        },
        "runtime": {
            "provider": "ollama-local",
            "endpoint": "http://127.0.0.1:11434/api/chat",
            "model_id": "llama3.2:3b",
            "credential_reference": "env://KIMURA_ASSESSMENT_LOCAL_REFERENCE",
        },
        "scenarios": [{"scenario_id": MODEL_V1_FIXTURE.scenario_id, "fixture_id": MODEL_V1_FIXTURE.fixture_id, "trials": 10}],
    }


class CustomerSchemaTests(unittest.TestCase):
    def test_config_builds_existing_contract(self):
        config = CustomerAssessmentConfig.from_dict(config_values())
        self.assertEqual(config.contract.max_requests, 22)
        self.assertEqual(config.contract.credential_references, ("env://KIMURA_ASSESSMENT_LOCAL_REFERENCE",))

    def test_unsupported_target_provider_and_fixture_are_rejected(self):
        for path, value in ((("assessment", "allowed_target", "target_id"), "external-target"), (("runtime", "provider"), "openai"), (("scenarios", 0, "fixture_id"), "wrong")):
            values = config_values()
            current = values
            for part in path[:-1]:
                current = current[part]
            current[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(CustomerConfigError):
                CustomerAssessmentConfig.from_dict(values)

    def test_budget_must_cover_baseline_and_retest(self):
        values = config_values()
        values["assessment"]["request_budget"] = 21
        with self.assertRaises(CustomerConfigError):
            CustomerAssessmentConfig.from_dict(values)

    def test_runtime_must_be_loopback(self):
        with self.assertRaises(CustomerConfigError):
            RuntimeConfig("ollama-local", "http://example.test/api/chat", "model", "env://REF")

    def test_scenario_limits_trials(self):
        with self.assertRaises(CustomerConfigError):
            ScenarioSelection(MODEL_V1_FIXTURE.scenario_id, MODEL_V1_FIXTURE.fixture_id, 101)


if __name__ == "__main__":
    unittest.main()
