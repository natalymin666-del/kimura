import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kimura_assessment.demo_v3 import (
    DEMO_V3_ASSESSMENT_ID, DEMO_V3_CREDENTIAL_REFERENCE, DemoV3Report, V3AgentApp,
    run_demo_v3, run_demo_v3_report,
)
from kimura_assessment.scenarios import DEMO_CONTRACT, DEMO_FIXTURE, EXFIL_CONTRACT, EXFIL_FIXTURE

class DemoV3Tests(unittest.TestCase):
    def test_scenarios_independently_validate_and_retest(self):
        app = V3AgentApp()
        for scenario, fixture in ((DEMO_CONTRACT, DEMO_FIXTURE), (EXFIL_CONTRACT, EXFIL_FIXTURE)):
            attack = app.handle({"operation": "attack", "scenario_id": scenario.scenario_id, "fixture_id": fixture.fixture_id})
            self.assertTrue(attack["executed"])
            impact = app.handle({"operation": "validate", "scenario_id": scenario.scenario_id})
            self.assertTrue(impact["validated"])
            if scenario is DEMO_CONTRACT:
                app.enable_tool_policy()
            else:
                app.enable_data_policy()
            retest = app.handle({"operation": "attack", "scenario_id": scenario.scenario_id, "fixture_id": fixture.fixture_id})
            self.assertFalse(retest["executed"])
            self.assertFalse(app.handle({"operation": "validate", "scenario_id": scenario.scenario_id})["validated"])

    def test_wrong_fixture_does_not_create_a_finding_or_audit_event(self):
        app = V3AgentApp()
        result = app.handle({"operation": "attack", "scenario_id": DEMO_CONTRACT.scenario_id, "fixture_id": "not-the-fixture"})
        self.assertFalse(result["executed"])
        self.assertEqual(app.audit_events, [])

    def test_consolidated_report_is_generated_from_two_validated_findings(self):
        report = run_demo_v3_report()
        values = report.to_dict()
        self.assertIsInstance(report, DemoV3Report)
        self.assertEqual(values["assessment_id"], DEMO_V3_ASSESSMENT_ID)
        self.assertEqual(values["scenario_count"], 2)
        self.assertEqual(values["findings_count"], 2)
        self.assertEqual([f["status"] for f in values["validated_findings"]], ["Retest passed", "Retest passed"])
        self.assertEqual(values["remediations_verified"], 2)
        self.assertEqual(values["failed_retests"], 0)
        self.assertEqual(values["lifecycle"][-1], "final-assessment-completed")
        self.assertEqual([f["severity"] for f in values["validated_findings"]], ["High", "High"])
        self.assertEqual([f["confidence"] for f in values["validated_findings"]], ["High", "High"])

    def test_evidence_is_safe_and_exact_attack_fixtures_are_replayed(self):
        report = run_demo_v3_report()
        encoded = report.to_json()
        forbidden = [DEMO_FIXTURE.user_task, EXFIL_FIXTURE.user_task, "agent-demo-v3-placeholder-only", "raw_request", "raw_response"]
        for value in forbidden:
            self.assertNotIn(value, encoded)
        self.assertIn(EXFIL_FIXTURE.synthetic_marker_digest, encoded)
        evidence = report.evidence
        self.assertEqual(evidence[0].request_sha256, evidence[3].request_sha256)
        self.assertEqual(evidence[5].request_sha256, evidence[8].request_sha256)
        self.assertNotIn("raw-synthetic-secret-value", json.dumps([item.to_dict() for item in evidence]))

    def test_persistence_is_hash_only_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.jsonl"
            report_path = Path(directory) / "report.json"
            first = run_demo_v3(persist_path=evidence_path, report_path=report_path)
            persisted = evidence_path.read_text(encoding="utf-8")
            report = report_path.read_text(encoding="utf-8")
        self.assertIn("KIMURA AGENT SECURITY ASSESSMENT", first)
        self.assertEqual(len(persisted.splitlines()), 10)
        self.assertNotIn("support ticket without disclosing", persisted + report)
        self.assertNotIn("agent-demo-v3-placeholder-only", persisted + report)
        self.assertEqual(json.loads(report)["findings_count"], 2)

    def test_cli_demo_v3_output_is_customer_understandable(self):
        from kimura_assessment.cli import main
        with patch("builtins.print") as printer:
            self.assertEqual(main(["demo-v3"]), 0)
        output = printer.call_args.args[0]
        self.assertIn("KIMURA AGENT SECURITY ASSESSMENT", output)
        self.assertIn("Finding 1:", output)
        self.assertIn("Finding 2:", output)
        self.assertIn("2 validated findings", output)
        self.assertIn("0 failed retests", output)

    def test_report_requires_persistence(self):
        with self.assertRaises(ValueError):
            run_demo_v3_report(report_path=Path("unused-v3-report.json"))

if __name__ == "__main__":
    unittest.main()
