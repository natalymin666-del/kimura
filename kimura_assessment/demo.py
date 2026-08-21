"""A deterministic, loopback-only Conference Demo v1 workflow."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import date
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading
from typing import Iterator

from .http_adapter import HttpTarget
from .persistence import AssessmentResultStore
from .report import write_report
from .runner import AssessmentRunner
from .schema import AssessmentContract


DEMO_ASSESSMENT_ID = "conference-demo-v1"
DEMO_CREDENTIAL_REFERENCE = "env://KIMURA_CONFERENCE_DEMO_PLACEHOLDER"
DEMO_RESPONSE = "Conference Demo v1 local mock response"
_DEMO_CREDENTIAL = "conference-demo-placeholder-only"


class _DemoHandler(BaseHTTPRequestHandler):
    """Return one fixed response and never contact a remote service."""

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            json.loads(self.rfile.read(content_length))
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return

        body = json.dumps({"output": DEMO_RESPONSE}, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


@contextmanager
def _demo_server() -> Iterator[HTTPServer]:
    server = HTTPServer(("127.0.0.1", 0), _DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@contextmanager
def _demo_credential() -> Iterator[None]:
    previous = os.environ.get("KIMURA_CONFERENCE_DEMO_PLACEHOLDER")
    os.environ["KIMURA_CONFERENCE_DEMO_PLACEHOLDER"] = _DEMO_CREDENTIAL
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("KIMURA_CONFERENCE_DEMO_PLACEHOLDER", None)
        else:
            os.environ["KIMURA_CONFERENCE_DEMO_PLACEHOLDER"] = previous


def run_demo(*, persist_path: Path | None = None, report_path: Path | None = None) -> str:
    """Run the Conference Demo v1 entirely against a local mock server."""

    if report_path is not None and persist_path is None:
        raise ValueError("report_path requires persist_path")

    with _demo_server() as server:
        endpoint = f"http://127.0.0.1:{server.server_port}/conference-demo"
        today = date.today()
        contract = AssessmentContract(
            assessment_id=DEMO_ASSESSMENT_ID,
            client_name="Kimura local conference demo",
            assessor_name="Kimura Security",
            authorized_by="local-demo-approval",
            objectives=("Demonstrate the bounded assessment workflow locally",),
            scope=(f"http://127.0.0.1:{server.server_port}",),
            start_date=today,
            end_date=today,
            credential_references=(DEMO_CREDENTIAL_REFERENCE,),
            max_requests=1,
        )
        target = HttpTarget(
            endpoint=endpoint,
            input_path="messages.0.content",
            response_path="output",
            credential_reference=DEMO_CREDENTIAL_REFERENCE,
        )
        with _demo_credential():
            result = AssessmentRunner(contract, target).run_result(
                "Conference Demo v1 input",
                {"messages": [{"role": "user"}]},
            )

    if persist_path is not None:
        store = AssessmentResultStore(persist_path)
        store.append(result)
        if report_path is not None:
            write_report(store, report_path)
    return result.to_json()
