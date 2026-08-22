import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from kimura_assessment.customer_assessment import run_customer_assessment
from kimura_assessment.customer_schema import CustomerAssessmentConfig
from kimura_assessment.html_report import render_customer_report
from kimura_assessment.model_scenarios import MODEL_V1_FIXTURE
from kimura_assessment.model_schemas import ModelResponse, ProposedAction

from tests.test_customer_schema import config_values


class FakeProvider:
    provider_id = "ollama-local"
    model_id = "fake-model"

    def complete(self, request):
        return ModelResponse("ollama-local", self.model_id, ProposedAction("send_email", ()), "valid", "stop", "a" * 64, 12, 1)


class CustomerAssessmentTests(unittest.TestCase):
    def test_full_lifecycle_is_safe_and_retests_exact_fixture(self):
        config = CustomerAssessmentConfig.from_dict(config_values())
        result = run_customer_assessment(config, today=lambda: date(2026, 8, 22), provider_factory=lambda _: FakeProvider(), preflight_writer=lambda _: None)
        report = result.report
        finding = report["findings"][0]
        self.assertEqual(finding["status"], "Retest passed")
        self.assertEqual(finding["proposal_count"], 10)
        self.assertEqual(finding["validated_synthetic_impact"]["count"], 10)
        self.assertEqual(report["retest_results"]["retest"]["validated_impact_count"], 0)
        self.assertEqual(len(result.evidence), 22)
        encoded = result.to_json() + render_customer_report(report)
        for forbidden in (MODEL_V1_FIXTURE.user_task, MODEL_V1_FIXTURE.retrieved_content, "customer-assessment-v1-local-transport-only", "raw_response"):
            self.assertNotIn(forbidden, encoded)

    def test_output_directory_contains_four_deterministic_artifacts(self):
        config = CustomerAssessmentConfig.from_dict(config_values())
        result = run_customer_assessment(config, today=lambda: date(2026, 8, 22), provider_factory=lambda _: FakeProvider(), preflight_writer=lambda _: None)
        with tempfile.TemporaryDirectory() as directory:
            result.write_output(directory, render_customer_report)
            names = sorted(path.name for path in Path(directory).iterdir())
            self.assertEqual(names, ["assessment.json", "evidence.jsonl", "manifest.json", "report.html"])
            manifest = json.loads((Path(directory) / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["finding_count"], 1)
            self.assertEqual(manifest["evidence_count"], 22)
            self.assertEqual(len(manifest["report_hash"]), 64)

    def test_reusing_output_directory_does_not_duplicate_evidence(self):
        config = CustomerAssessmentConfig.from_dict(config_values())
        result = run_customer_assessment(config, today=lambda: date(2026, 8, 22), provider_factory=lambda _: FakeProvider(), preflight_writer=lambda _: None)
        with tempfile.TemporaryDirectory() as directory:
            result.write_output(directory, render_customer_report)
            first = (Path(directory) / "evidence.jsonl").read_text(encoding="utf-8")
            result.write_output(directory, render_customer_report)
            second = (Path(directory) / "evidence.jsonl").read_text(encoding="utf-8")
            self.assertEqual(second, first)

    def test_preflight_happens_before_provider_factory(self):
        config = CustomerAssessmentConfig.from_dict(config_values())
        calls = []
        def provider(_):
            calls.append("provider")
            return FakeProvider()
        lines = []
        run_customer_assessment(config, today=lambda: date(2026, 8, 22), provider_factory=provider, preflight_writer=lines.append)
        self.assertIn("Authorization contract: VALID", lines)
        self.assertEqual(calls, ["provider"])


if __name__ == "__main__":
    unittest.main()
