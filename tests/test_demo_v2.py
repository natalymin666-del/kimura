import json
import os
import tempfile
import unittest
from pathlib import Path

from kimura_assessment.demo_v2 import (
    DEMO_V2_CREDENTIAL_REFERENCE,
    DEMO_V2_ASSESSMENT_ID,
    run_demo_v2,
    run_demo_v2_report,
)
from kimura_assessment.scenarios import DEMO_FIXTURE


class ConferenceDemoV2Tests(unittest.TestCase):
    def test_demo_validates_impact_and_passes_exact_fixture_retest(self):
        previous = os.environ.get("KIMURA_CONFERENCE_DEMO_V2_PLACEHOLDER")
        os.environ["KIMURA_CONFERENCE_DEMO_V2_PLACEHOLDER"] = "caller-value"
        try:
            report = run_demo_v2_report()
        finally:
            self.assertEqual(os.environ.get("KIMURA_CONFERENCE_DEMO_V2_PLACEHOLDER"), "caller-value")
            if previous is None:
                os.environ.pop("KIMURA_CONFERENCE_DEMO_V2_PLACEHOLDER", None)
            else:
                os.environ["KIMURA_CONFERENCE_DEMO_V2_PLACEHOLDER"] = previous

        self.assertEqual(report.finding.status, "Retest passed")
        self.assertEqual(report.finding.severity, "High")
        self.assertEqual(report.finding.confidence, "High")
        self.assertTrue(report.remediated)
        self.assertTrue(report.retest_passed)
        self.assertEqual([item.evidence_id for item in report.evidence], [f"evidence-{n:02d}" for n in range(1, 7)])
        encoded = report.to_json()
        self.assertIn(DEMO_V2_ASSESSMENT_ID, encoded)
        self.assertNotIn(DEMO_FIXTURE.user_task, encoded)
        self.assertNotIn(DEMO_V2_CREDENTIAL_REFERENCE, encoded)
        self.assertIn("send_email", encoded)

    def test_demo_report_and_evidence_are_safe_and_repeatable(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.jsonl"
            report_path = Path(directory) / "report.json"
            first = run_demo_v2(persist_path=evidence_path, report_path=report_path)
            second = run_demo_v2()
            persisted = evidence_path.read_text(encoding="utf-8")
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(first, second)
        self.assertEqual(len(persisted.splitlines()), 6)
        self.assertEqual(report["lifecycle"], ["Candidate", "Validated", "Remediated", "Retest passed"])
        self.assertNotIn(DEMO_FIXTURE.user_task, persisted + json.dumps(report))
        self.assertNotIn("conference-demo-v2-placeholder-only", persisted + json.dumps(report))

    def test_report_requires_evidence_persistence(self):
        with self.assertRaises(ValueError):
            run_demo_v2_report(report_path=Path("unused-demo-v2-report.json"))


if __name__ == "__main__":
    unittest.main()
