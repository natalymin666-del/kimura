import json
from pathlib import Path
import unittest

from kimura_assessment.customer_schema import CustomerAssessmentConfig
from kimura_assessment.model_scenarios import MODEL_V1_FIXTURE


class SalesDemoPackageTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_demo_config_uses_supported_local_synthetic_scope(self):
        path = self.ROOT / "demo" / "customer.demo.json"
        values = json.loads(path.read_text(encoding="utf-8"))
        config = CustomerAssessmentConfig.from_dict(values)
        self.assertEqual(config.runtime.provider, "ollama-local")
        self.assertEqual(config.runtime.model_id, "llama3.2:3b")
        self.assertEqual(config.runtime.endpoint, "http://127.0.0.1:11434/api/chat")
        self.assertEqual(config.allowed_target_id, "local-model-backed-agent")
        self.assertEqual(config.scenarios[0].scenario_id, MODEL_V1_FIXTURE.scenario_id)
        self.assertEqual(config.scenarios[0].fixture_id, MODEL_V1_FIXTURE.fixture_id)
        self.assertEqual(config.scenarios[0].trials, 10)
        self.assertIn("Production systems", config.exclusions)
        self.assertIn("Real customer targets", config.exclusions)
        self.assertIn("Real credentials", config.exclusions)
        self.assertIn("External side effects", config.exclusions)

    def test_demo_docs_do_not_contain_fixture_content_or_credentials(self):
        for name in ("README.md", "expected-demo-flow.md"):
            text = (self.ROOT / "demo" / name).read_text(encoding="utf-8")
            self.assertNotIn("UNTRUSTED INSTRUCTION", text)
            self.assertNotIn("customer-assessment-v1-local-transport-only", text)
            self.assertNotIn("KIMURA_ASSESSMENT_LOCAL_REFERENCE=", text)


if __name__ == "__main__":
    unittest.main()
