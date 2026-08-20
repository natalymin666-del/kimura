from datetime import date
from dataclasses import replace
import hashlib
import json
from unittest import TestCase
from unittest.mock import patch

from kimura_assessment import AssessmentContract, AssessmentExecutionError, AssessmentResult, AssessmentRunner, HttpTarget


class AssessmentRunnerTests(TestCase):
    def setUp(self):
        self.contract = AssessmentContract(
            assessment_id="asm-runner",
            client_name="Local test",
            assessor_name="Kimura",
            authorized_by="approval-local",
            objectives=("test bounded execution",),
            scope=("https://example.test",),
            start_date=date(2026, 8, 20),
            end_date=date(2026, 8, 22),
            max_requests=2,
        )
        self.target = HttpTarget("https://example.test/chat", "input", "output", "env://TEST")

    @patch("kimura_assessment.runner.JsonPostAdapter")
    def test_authorized_window_and_request_budget(self, adapter_type):
        adapter_type.return_value.post.side_effect = ["one", "two"]
        runner = AssessmentRunner(self.contract, self.target, today=lambda: date(2026, 8, 21))

        self.assertEqual(runner.run("first"), "one")
        self.assertEqual(runner.run("second"), "two")
        with self.assertRaises(AssessmentExecutionError):
            runner.run("third")
        self.assertEqual(adapter_type.return_value.post.call_count, 2)

    @patch("kimura_assessment.runner.JsonPostAdapter")
    def test_failed_attempt_consumes_request_budget(self, adapter_type):
        adapter_type.return_value.post.side_effect = RuntimeError("local failure")
        runner = AssessmentRunner(
            replace(self.contract, max_requests=1),
            self.target,
            today=lambda: date(2026, 8, 20),
        )

        with self.assertRaises(RuntimeError):
            runner.run("attempt")
        with self.assertRaises(AssessmentExecutionError):
            runner.run("again")
        self.assertEqual(adapter_type.return_value.post.call_count, 1)

    @patch("kimura_assessment.runner.JsonPostAdapter")
    def test_date_window_is_enforced_before_dispatch(self, adapter_type):
        runner = AssessmentRunner(self.contract, self.target, today=lambda: date(2026, 8, 23))

        with self.assertRaises(AssessmentExecutionError):
            runner.run("outside")
        adapter_type.return_value.post.assert_not_called()

    @patch("kimura_assessment.runner.JsonPostAdapter")
    def test_start_and_end_dates_are_inclusive(self, adapter_type):
        adapter_type.return_value.post.return_value = "local response"
        for current_date in (date(2026, 8, 20), date(2026, 8, 22)):
            with self.subTest(current_date=current_date):
                runner = AssessmentRunner(self.contract, self.target, today=lambda: current_date)
                self.assertEqual(runner.run("inside"), "local response")

    @patch("kimura_assessment.runner.JsonPostAdapter")
    def test_run_result_captures_only_deterministic_safe_metadata(self, adapter_type):
        adapter_type.return_value.post.return_value = "local response"
        runner = AssessmentRunner(self.contract, self.target, today=lambda: date(2026, 8, 21))

        result = runner.run_result("input that must not be stored", {"secret": "request value"})

        self.assertIsInstance(result, AssessmentResult)
        self.assertEqual(result.to_dict(), {
            "schema_version": 1,
            "assessment_id": "asm-runner",
            "execution_number": 1,
            "authorization_date": "2026-08-21",
            "status": "completed",
            "response_length": len("local response".encode("utf-8")),
            "response_sha256": hashlib.sha256(b"local response").hexdigest(),
        })
        encoded = result.to_json()
        self.assertEqual(encoded, result.to_json())
        self.assertEqual(json.loads(encoded), result.to_dict())
        self.assertNotIn("input that must not be stored", encoded)
        self.assertNotIn("request value", encoded)
        self.assertNotIn("local response", encoded)
        self.assertEqual(adapter_type.return_value.post.call_count, 1)

    @patch("kimura_assessment.runner.JsonPostAdapter")
    def test_run_and_run_result_share_one_execution_path_and_budget(self, adapter_type):
        adapter_type.return_value.post.side_effect = ["one", "two"]
        runner = AssessmentRunner(self.contract, self.target, today=lambda: date(2026, 8, 21))

        self.assertEqual(runner.run("first"), "one")
        result = runner.run_result("second")

        self.assertEqual(result.execution_number, 2)
        with self.assertRaises(AssessmentExecutionError):
            runner.run_result("third")
        self.assertEqual(adapter_type.return_value.post.call_count, 2)
