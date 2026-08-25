"""Minimal local read-only HTTP API over the truthful progress journal."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from threading import Thread
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .progress_journal import ProgressJournal


_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_CACHE_CONTROL = "no-store"


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class _ProgressRequestHandler(BaseHTTPRequestHandler):
    server: "ProgressHTTPServer"

    def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        encoded = _json_bytes(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", _CACHE_CONTROL)
        self.end_headers()
        self.wfile.write(encoded)

    def _error(self, status: HTTPStatus, code: str) -> None:
        self._send_json(status, {"error": code})

    def do_GET(self) -> None:  # noqa: N802 - required HTTP handler name
        parsed = urlsplit(self.path)
        parts = parsed.path.split("/")
        if len(parts) != 5 or parts[1:3] != ["api", "assessments"]:
            self._error(HTTPStatus.NOT_FOUND, "not_found")
            return
        run_id = unquote(parts[3])
        resource = parts[4]
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id")
            return
        snapshot = self.server.journal.get_latest_snapshot(run_id)
        if snapshot is None:
            self._error(HTTPStatus.NOT_FOUND, "unknown_run")
            return
        if resource == "snapshot":
            if parsed.query:
                self._error(HTTPStatus.BAD_REQUEST, "unexpected_query")
                return
            self._send_json(HTTPStatus.OK, snapshot.to_dict())
            return
        if resource != "events":
            self._error(HTTPStatus.NOT_FOUND, "not_found")
            return
        query = parse_qs(parsed.query, keep_blank_values=True)
        values = query.get("after_seq")
        if values is None:
            self._error(HTTPStatus.BAD_REQUEST, "missing_after_seq")
            return
        if len(values) != 1 or not _DECIMAL.fullmatch(values[0]):
            if len(values) == 1 and values[0].startswith("-"):
                self._error(HTTPStatus.BAD_REQUEST, "negative_after_seq")
            else:
                self._error(HTTPStatus.BAD_REQUEST, "invalid_after_seq")
            return
        after_seq = int(values[0])
        events = [event.to_dict() for event in self.server.journal.get_events_after(run_id, after_seq)]
        self._send_json(HTTPStatus.OK, {"after_seq": after_seq, "events": events, "latest_sequence": snapshot.sequence, "run_id": run_id})

    def do_POST(self) -> None:  # noqa: N802
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "read_only")

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST

    def log_message(self, _format: str, *args: Any) -> None:
        return


class ProgressHTTPServer(ThreadingHTTPServer):
    """Explicitly managed local read-only server."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, journal: ProgressJournal, host: str = "127.0.0.1", port: int = 0) -> None:
        if host != "127.0.0.1":
            raise ValueError("progress server must bind to 127.0.0.1")
        self.journal = journal
        super().__init__((host, port), _ProgressRequestHandler)
        self._thread: Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("progress server is already running")
        self._thread = Thread(target=self.serve_forever, name="kimura-progress-http", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is not None:
            self.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self.server_close()
