import json
import os
import tempfile
import threading
import unittest
from datetime import date
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from kimura_assessment import AssessmentTargetError, CredentialResolutionError
from kimura_assessment.cli import AssessmentConfigError, run_config
from kimura_assessment import AssessmentResult


class _Handler(BaseHTTPRequestHandler):
    requests = []

    def do_POST(self):  # noqa: N802 - stdlib handler API
        size = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(size))
        self.__class__.requests.append((self.path, self.headers.get("Authorization"), body))
        response = json.dumps({"output": "private local response"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


class CliWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _Handler.requests = []
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        _Handler.requests = []
        self.reference = "env://KIMURA_CLI_TEST_CREDENTIAL"
        self.previous = os.environ.get("KIMURA_CLI_TEST_CREDENTIAL")
        os.environ["KIMURA_CLI_TEST_CREDENTIAL"] = "runtime-only-credential"
        self.config = {
            "contract": {
                "assessment_id": "asm-cli",
                "client_name": "Local test",
                "assessor_name": "Kimura",
                "authorized_by": "approval-local",
                "objectives": ["test one authorized endpoint"],
                "scope": [f"http://127.0.0.1:{self.server.server_port}"],
                "start_date": "2026-08-20",
                "end_date": "2026-08-20",
                "credential_references": [self.reference],
                "max_requests": 1,
            },
            "target": {
                "endpoint": f"http://127.0.0.1:{self.server.server_port}/chat",
                "input_path": "messages.0.content",
                "response_path": "output",
                "credential_reference": self.reference,
            },
            "input_text": "private input text",
            "request_json": {"messages": [{"role": "user"}]},
        }

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("KIMURA_CLI_TEST_CREDENTIAL", None)
        else:
            os.environ["KIMURA_CLI_TEST_CREDENTIAL"] = self.previous

    def write_config(self, values=None):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as handle:
            json.dump(values or self.config, handle)
            return Path(handle.name)

    def test_successful_local_workflow_returns_safe_result_only(self):
        path = self.write_config()
        try:
            result_json = run_config(path)
        finally:
            path.unlink()

        result = json.loads(result_json)
        self.assertEqual(result["assessment_id"], "asm-cli")
        self.assertEqual(result["status"], "completed")
        self.assertNotIn("private", result_json)
        self.assertNotIn("runtime-only-credential", result_json)
        self.assertEqual(_Handler.requests[0][2]["messages"][0]["content"], "private input text")

    def test_invalid_contract_is_rejected_before_dispatch(self):
        config = json.loads(json.dumps(self.config))
        config["contract"]["objectives"] = []
        path = self.write_config(config)
        try:
            with self.assertRaises(AssessmentConfigError):
                run_config(path)
        finally:
            path.unlink()
        self.assertEqual(_Handler.requests, [])

    def test_out_of_scope_endpoint_is_rejected_before_dispatch(self):
        config = json.loads(json.dumps(self.config))
        config["target"]["endpoint"] = "http://127.0.0.1:1/chat"
        path = self.write_config(config)
        try:
            with self.assertRaises(AssessmentTargetError) as raised:
                run_config(path)
        finally:
            path.unlink()
        self.assertIn("outside the authorized assessment scope", str(raised.exception))
        self.assertEqual(_Handler.requests, [])

    def test_missing_runtime_credential_is_rejected_safely(self):
        os.environ.pop("KIMURA_CLI_TEST_CREDENTIAL", None)
        path = self.write_config()
        try:
            with self.assertRaises(CredentialResolutionError) as raised:
                run_config(path)
        finally:
            path.unlink()
        self.assertIn("environment variable is not set", str(raised.exception))
        self.assertNotIn("runtime-only-credential", str(raised.exception))
        self.assertEqual(_Handler.requests, [])

    def test_existing_contract_runner_and_result_behavior_is_reused(self):
        path = self.write_config()
        try:
            with patch("kimura_assessment.cli.AssessmentRunner") as runner_type:
                runner_type.return_value.run_result.return_value.to_json.return_value = '{"status":"completed"}'
                self.assertEqual(run_config(path), '{"status":"completed"}')
                runner_type.return_value.run_result.assert_called_once()
        finally:
            path.unlink()

    def test_optional_persistence_and_report_do_not_change_result_output(self):
        path = self.write_config()
        persist_path = Path(tempfile.mktemp(suffix=".jsonl"))
        report_path = Path(tempfile.mktemp(suffix=".json"))
        result = AssessmentResult.completed("asm-cli", 1, date(2026, 8, 20), "not stored")
        try:
            with patch("kimura_assessment.cli.AssessmentRunner") as runner_type:
                runner_type.return_value.run_result.return_value = result
                self.assertEqual(
                    run_config(path, persist_path=persist_path, report_path=report_path),
                    result.to_json(),
                )
            persisted = json.loads(persist_path.read_text(encoding="utf-8"))
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted, result.to_dict())
            self.assertEqual(report["result_count"], 1)
            self.assertNotIn("not stored", report_path.read_text(encoding="utf-8"))
        finally:
            path.unlink()
            persist_path.unlink(missing_ok=True)
            report_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
