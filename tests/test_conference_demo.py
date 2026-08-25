import tempfile
import unittest
from pathlib import Path

from kimura_assessment.conference_demo import FIXTURE, MOBILE_REPORT_FILENAME, run_conference_demo


class ConferenceDemoTests(unittest.TestCase):
    def test_demo_is_offline_deterministic_and_replays_exact_fixture(self):
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first_output, first_report = run_conference_demo(Path(first_dir))
            second_output, second_report = run_conference_demo(Path(second_dir))
            self.assertEqual(first_output.replace(first_dir, "OUTPUT"), second_output.replace(second_dir, "OUTPUT"))
            self.assertEqual(first_report.read_bytes(), second_report.read_bytes())
            self.assertIn("BEFORE FIX\nVULNERABLE", first_output)
            self.assertIn("Unauthorized action: ALLOWED", first_output)
            self.assertIn("EXACT SAME ATTACK REPLAYED\nAFTER FIX\nPROTECTED", first_output)
            self.assertIn("Unauthorized action: BLOCKED", first_output)

    def test_security_semantics_are_preserved(self):
        terminal, _report_path = run_conference_demo()
        self.assertIn("BEFORE FIX\nVULNERABLE", terminal)
        self.assertIn("Impact: VALIDATED (synthetic only)", terminal)
        self.assertIn("AFTER FIX\nPROTECTED", terminal)
        self.assertIn("Unauthorized action: BLOCKED", terminal)

        with tempfile.TemporaryDirectory() as output_dir:
            _terminal, report_path = run_conference_demo(Path(output_dir))
            html = report_path.read_text(encoding="utf-8")
            self.assertIn("baseline-permissive-v1", html)
            self.assertIn("tool-policy-deny-untrusted-external-actions", html)
            self.assertIn("same send_email → BLOCKED", html)
            self.assertIn("no real email was sent", html.lower())
            self.assertIn("synthetic ai agent", html.lower())
            self.assertIn("fully offline and deterministic", html.lower())
            self.assertIn(FIXTURE.fixture_sha256, html)
            self.assertIn(FIXTURE.retrieved_content_sha256, html)

    def test_report_contains_required_story_and_safe_evidence(self):
        with tempfile.TemporaryDirectory() as output_dir:
            _terminal, report_path = run_conference_demo(Path(output_dir))
            html = report_path.read_text(encoding="utf-8")
            evidence = (Path(output_dir) / "conference-demo-evidence.jsonl").read_text(encoding="utf-8")
            for expected in ("Benign task", "Untrusted content", "Injected instruction", "Baseline policy decision", "Validated impact", "Remediation", "Exact retest", "BLOCKED", "synthetic"):
                self.assertIn(expected, html)
            self.assertIn(FIXTURE.fixture_sha256, html)
            self.assertNotIn("recipient", evidence)
            self.assertNotIn(FIXTURE.retrieved_document, evidence)

    def test_report_requires_no_external_runtime(self):
        terminal, report_path = run_conference_demo()
        self.assertIsNone(report_path)
        self.assertIn("RESULT: PASS", terminal)


    def test_mobile_report_uses_the_same_runtime_outcomes(self):
        with tempfile.TemporaryDirectory() as output_dir:
            _terminal, laptop_report = run_conference_demo(Path(output_dir))
            mobile_report = Path(output_dir) / MOBILE_REPORT_FILENAME
            self.assertTrue(laptop_report.exists())
            self.assertTrue(mobile_report.exists())

            laptop_html = laptop_report.read_text(encoding="utf-8")
            mobile_html = mobile_report.read_text(encoding="utf-8")
            mobile_upper = mobile_html.upper()
            self.assertIn("BEFORE FIX", mobile_upper)
            self.assertIn("VULNERABLE", mobile_upper)
            self.assertIn("ALLOWED", mobile_upper)
            self.assertIn("EXACT REPLAY", mobile_upper)
            self.assertIn("PROTECTED", mobile_upper)
            self.assertIn("BLOCKED", mobile_upper)
            self.assertIn("PASS", mobile_upper)
            self.assertIn(FIXTURE.fixture_sha256, laptop_html)
            self.assertIn("Synthetic AI agent", mobile_html)
            self.assertIn("Synthetic tool", mobile_html)
            self.assertIn("No real email was sent", mobile_html)
            self.assertIn("No production agent was compromised", mobile_html)
            self.assertNotIn("https://", mobile_html)
            self.assertNotIn("http://", mobile_html)


if __name__ == "__main__":
    unittest.main()
