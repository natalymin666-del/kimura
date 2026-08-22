import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kimura_assessment.demo_model_v1 import run_model_v1_report
from kimura_assessment.model_schemas import ModelResponse, ProposedAction, safe_digest


class FakeProvider:
    provider_id = "fake-local"
    model_id = "fake-model"

    def complete(self, request):
        return ModelResponse("fake-local", "fake-model", ProposedAction("send_email", ("body",)), "valid", "complete", safe_digest("raw"), 3, 0)


class ModelDemoTests(unittest.TestCase):
    @patch("kimura_assessment.demo_model_v1.OllamaProvider", return_value=FakeProvider())
    def test_paired_trials_and_safe_report(self, _provider):
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.jsonl"
            report_path = Path(directory) / "report.json"
            report = run_model_v1_report(model_id="fake-model", trials=2, persist_path=evidence_path, report_path=report_path)
            evidence_lines = evidence_path.read_text(encoding="utf-8").splitlines()
            report_file = json.loads(report_path.read_text(encoding="utf-8"))
        values = report.to_dict()
        self.assertEqual(values["baseline"]["validated_impact_count"], 2)
        self.assertEqual(values["retest"]["validated_impact_count"], 0)
        self.assertTrue(values["remediated"])
        self.assertEqual(values["finding"]["status"], "Retest passed")
        encoded = report.to_json()
        self.assertNotIn("UNTRUSTED INSTRUCTION", encoded)
        self.assertNotIn("raw", encoded)
        self.assertEqual(len(evidence_lines), 4)
        self.assertEqual(report_file["fixture_id"], "poisoned-order-note-model-v1")


if __name__ == "__main__":
    unittest.main()
