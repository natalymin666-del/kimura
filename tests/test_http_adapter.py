import json
from datetime import date
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from kimura_assessment import (
    AssessmentContract,
    AssessmentRunner,
    AssessmentTargetError,
    HttpTarget,
    credential_environment_name,
)


class _Handler(BaseHTTPRequestHandler):
    requests = []

    def do_POST(self):  # noqa: N802 - stdlib handler API
        size = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(size))
        self.__class__.requests.append((self.path, self.headers["Authorization"], body))
        response = json.dumps({"choices": [{"message": {"content": "local response"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


class HttpAdapterTests(unittest.TestCase):
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
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}/v1/chat"
        self.reference = "env://KIMURA_TEST_RUNTIME_CREDENTIAL"
        self.contract = AssessmentContract(
            assessment_id="asm-local",
            client_name="Local test",
            assessor_name="Kimura",
            authorized_by="approval-local",
            objectives=("test one authorized endpoint",),
            scope=(f"http://127.0.0.1:{self.server.server_port}",),
            start_date=date(2026, 8, 20),
            end_date=date(2026, 8, 20),
            credential_references=(self.reference,),
        )
        self.previous = os.environ.get("KIMURA_TEST_RUNTIME_CREDENTIAL")
        os.environ["KIMURA_TEST_RUNTIME_CREDENTIAL"] = "runtime-" + str(self.server.server_port)

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("KIMURA_TEST_RUNTIME_CREDENTIAL", None)
        else:
            os.environ["KIMURA_TEST_RUNTIME_CREDENTIAL"] = self.previous

    def test_nested_input_and_response_paths_and_runtime_authentication(self):
        target = HttpTarget(self.endpoint, "messages.0.content", "choices.0.message.content", self.reference)
        result = AssessmentRunner(self.contract, target).run("hello", {"messages": [{"role": "user"}]})

        self.assertEqual(result, "local response")
        self.assertEqual(_Handler.requests[0][0], "/v1/chat")
        self.assertEqual(_Handler.requests[0][1], "Bearer runtime-" + str(self.server.server_port))
        self.assertEqual(_Handler.requests[0][2]["messages"][0]["content"], "hello")

    def test_out_of_scope_target_is_rejected_before_request(self):
        target = HttpTarget(self.endpoint.replace(f":{self.server.server_port}", ":1"), "content", "content", self.reference)
        with self.assertRaises(AssessmentTargetError):
            AssessmentRunner(self.contract, target)
        self.assertEqual(_Handler.requests, [])

    def test_opaque_reference_maps_without_exposing_credential(self):
        self.assertTrue(credential_environment_name("vault://assessment/local").startswith("KIMURA_CREDENTIAL_"))


if __name__ == "__main__":
    unittest.main()
