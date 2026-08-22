import json
import io
from copy import deepcopy
from types import SimpleNamespace
import tempfile
import unittest
from datetime import date
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from kimura_assessment.cli import main
from kimura_assessment.customer_assessment import CustomerModelError, run_customer_assessment
from kimura_assessment.customer_schema import CustomerAssessmentConfig
from kimura_assessment.html_report import render_customer_report
from tests.test_customer_assessment import FakeProvider
from tests.test_customer_schema import config_values


class CustomerCliTests(unittest.TestCase):
    def test_assess_command_writes_requested_artifacts(self):
        values = config_values()
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "customer.json"
            output = Path(directory) / "assessment-output"
            config_path.write_text(json.dumps(values), encoding="utf-8")
            with patch("kimura_assessment.cli.run_customer_assessment") as runner:
                runner.return_value = run_customer_assessment(CustomerAssessmentConfig.from_dict(values), today=lambda: __import__("datetime").date.today(), provider_factory=lambda _: FakeProvider(), preflight_writer=lambda _: None)
                self.assertEqual(main(["assess", str(config_path), "--output", str(output)]), 0)
            self.assertEqual(sorted(item.name for item in output.iterdir()), ["assessment.json", "evidence.jsonl", "manifest.json", "report.html"])
            self.assertIn("Executive Summary", (output / "report.html").read_text(encoding="utf-8"))

    def test_assess_command_prints_safe_values_from_actual_result(self):
        values = config_values()
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "customer.json"
            output = Path(directory) / "assessment-output"
            config_path.write_text(json.dumps(values), encoding="utf-8")
            result = run_customer_assessment(
                CustomerAssessmentConfig.from_dict(values),
                today=lambda: __import__("datetime").date.today(),
                provider_factory=lambda _: FakeProvider(),
                preflight_writer=lambda _: None,
            )
            stream = io.StringIO()
            with patch("kimura_assessment.cli.run_customer_assessment", return_value=result), redirect_stdout(stream):
                self.assertEqual(main(["assess", str(config_path), "--output", str(output)]), 0)
            text = stream.getvalue()
            report = result.report
            baseline = report["retest_results"]["baseline"]
            retest = report["retest_results"]["retest"]
            self.assertIn(f"Assessment ID: {report['assessment']['assessment_id']}", text)
            self.assertIn(f"Baseline proposed actions: {baseline['proposal_count']}", text)
            self.assertIn(f"Baseline validated impacts: {baseline['validated_impact_count']}", text)
            self.assertIn(f"Retest blocked actions: {retest['gate_decisions']['blocked']}", text)
            self.assertIn(f"Final retest status: {report['retest_results']['status']}", text)
            self.assertIn(f"Report: {output / 'report.html'}", text)
            for forbidden in ("UNTRUSTED INSTRUCTION", "raw_response", "customer-assessment-v1-local-transport-only"):
                self.assertNotIn(forbidden, text)
    def test_assess_summary_does_not_hardcode_outcomes(self):
        values = config_values()
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "customer.json"
            output = Path(directory) / "assessment-output"
            config_path.write_text(json.dumps(values), encoding="utf-8")
            actual = run_customer_assessment(
                CustomerAssessmentConfig.from_dict(values),
                today=lambda: __import__("datetime").date.today(),
                provider_factory=lambda _: FakeProvider(),
                preflight_writer=lambda _: None,
            )
            report = deepcopy(actual.report)
            report["findings"][0]["severity"] = "Medium"
            report["retest_results"]["baseline"]["trial_count"] = 7
            report["retest_results"]["baseline"]["proposal_count"] = 3
            report["retest_results"]["baseline"]["validated_impact_count"] = 2
            report["retest_results"]["retest"]["trial_count"] = 7
            report["retest_results"]["retest"]["proposal_count"] = 4
            report["retest_results"]["retest"]["gate_decisions"]["blocked"] = 4
            report["retest_results"]["retest"]["validated_impact_count"] = 1
            report["retest_results"]["status"] = "review-required"
            fake_result = SimpleNamespace(report=report, write_output=lambda *_args: None)
            stream = io.StringIO()
            with patch("kimura_assessment.cli.run_customer_assessment", return_value=fake_result), redirect_stdout(stream):
                self.assertEqual(main(["assess", str(config_path), "--output", str(output)]), 0)
            text = stream.getvalue()
            self.assertIn("Trial count: 7 baseline + 7 retest", text)
            self.assertIn("Baseline risk: Medium", text)
            self.assertIn("Baseline proposed actions: 3", text)
            self.assertIn("Baseline validated impacts: 2", text)
            self.assertIn("Retest proposed actions: 4", text)
            self.assertIn("Retest blocked actions: 4", text)
            self.assertIn("Retest validated impacts: 1", text)
            self.assertIn("Final retest status: review-required", text)

    def test_assess_model_failure_is_actionable_and_safe(self):
        values = config_values()
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "customer.json"
            output = Path(directory) / "assessment-output"
            config_path.write_text(json.dumps(values), encoding="utf-8")
            stderr = io.StringIO()
            with patch("kimura_assessment.cli.run_customer_assessment", side_effect=CustomerModelError("model provider failed during assessment")), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    main(["assess", str(config_path), "--output", str(output)])
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("model failure:", stderr.getvalue())
            self.assertNotIn("raw", stderr.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
