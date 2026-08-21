import json
from datetime import date
import os
import tempfile
import unittest
from pathlib import Path

from kimura_assessment.demo import DEMO_ASSESSMENT_ID, DEMO_RESPONSE, run_demo


class ConferenceDemoTests(unittest.TestCase):
    def test_demo_is_deterministic_safe_and_restores_environment(self):
        previous = os.environ.get("KIMURA_CONFERENCE_DEMO_PLACEHOLDER")
        os.environ["KIMURA_CONFERENCE_DEMO_PLACEHOLDER"] = "caller-value"
        try:
            first = run_demo()
            second = run_demo()
        finally:
            self.assertEqual(os.environ.get("KIMURA_CONFERENCE_DEMO_PLACEHOLDER"), "caller-value")
            if previous is None:
                os.environ.pop("KIMURA_CONFERENCE_DEMO_PLACEHOLDER", None)
            else:
                os.environ["KIMURA_CONFERENCE_DEMO_PLACEHOLDER"] = previous

        self.assertEqual(first, second)
        result = json.loads(first)
        self.assertEqual(result["assessment_id"], DEMO_ASSESSMENT_ID)
        self.assertEqual(result["authorization_date"], date.today().isoformat())
        self.assertEqual(result["response_length"], len(DEMO_RESPONSE.encode("utf-8")))
        self.assertNotIn(DEMO_RESPONSE, first)
        self.assertNotIn("placeholder", first.lower())

    def test_demo_reuses_safe_persistence_and_reporting(self):
        with tempfile.TemporaryDirectory() as directory:
            persist = Path(directory) / "demo.jsonl"
            report = Path(directory) / "demo-report.json"
            result = json.loads(run_demo(persist_path=persist, report_path=report))
            persisted = json.loads(persist.read_text(encoding="utf-8"))
            report_values = json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(persisted, result)
        self.assertEqual(report_values["result_count"], 1)
        self.assertEqual(report_values["assessment_ids"], [DEMO_ASSESSMENT_ID])
        self.assertNotIn(DEMO_RESPONSE, json.dumps(report_values))

    def test_report_requires_persistence(self):
        with self.assertRaises(ValueError):
            run_demo(report_path=Path("unused-report.json"))


if __name__ == "__main__":
    unittest.main()
