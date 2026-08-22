import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kimura_assessment.cli import main
from kimura_assessment.customer_assessment import run_customer_assessment
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
                runner.return_value = run_customer_assessment(CustomerAssessmentConfig.from_dict(values), today=lambda: __import__("datetime").date(2026, 8, 22), provider_factory=lambda _: FakeProvider(), preflight_writer=lambda _: None)
                self.assertEqual(main(["assess", str(config_path), "--output", str(output)]), 0)
            self.assertEqual(sorted(item.name for item in output.iterdir()), ["assessment.json", "evidence.jsonl", "manifest.json", "report.html"])
            self.assertIn("Executive Summary", (output / "report.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
