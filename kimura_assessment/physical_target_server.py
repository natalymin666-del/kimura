"""Standard-library HTTP server for the owned isolated synthetic target node."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from typing import Any

from .physical_target_protocol import response_json
from .physical_target_runtime import PhysicalTargetRuntime


NODE_PATH = "/v1/node"
MAX_BODY_BYTES = 64 * 1024


class PhysicalTargetHTTPServer(ThreadingHTTPServer):
    """HTTP server carrying only the bounded node protocol."""

    daemon_threads = True
    allow_reuse_address = True


def _handler_for(runtime: PhysicalTargetRuntime, *, max_body_bytes: int):
    class Handler(BaseHTTPRequestHandler):
        server_version = "KimuraPhysicalTarget/1"
        sys_version = ""

        def _send(self, status: int, body: dict[str, Any]) -> None:
            encoded = response_json(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)

        def _safe_error(self, status: int, code: str, request_id: str = "request-invalid") -> None:
            self._send(status, {
                "protocol_version": 1,
                "request_id": request_id,
                "status": "error",
                "target_id": runtime.config.target_id,
                "target_kind": "owned-isolated-synthetic-target",
                "node_instance_id": runtime.node_instance_id,
                "error_code": code,
                "outcome": "request-rejected",
            })

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            if self.path != NODE_PATH:
                self._safe_error(404, "unsupported-endpoint")
                return
            if self.headers.get("Content-Type") != "application/json":
                self._safe_error(415, "unsupported-content-type")
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 0:
                self._safe_error(411, "content-length-required")
                return
            if length > max_body_bytes:
                self._safe_error(413, "request-too-large")
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                self._safe_error(400, "malformed-request")
                return
            try:
                message = json.loads(raw.decode("utf-8"))
                if not isinstance(message, dict):
                    raise ValueError
                response = runtime.handle(message)
                self._send(200 if response.get("status") == "ok" else 400, response)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._safe_error(400, "malformed-request")

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            self._safe_error(405, "method-not-allowed")

        def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
            self._safe_error(405, "method-not-allowed")

        def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
            self._safe_error(405, "method-not-allowed")

        def log_message(self, *_args: object) -> None:
            pass

    return Handler


def create_server(runtime: PhysicalTargetRuntime, bind_host: str = "127.0.0.1", port: int = 0, *, max_body_bytes: int = MAX_BODY_BYTES) -> PhysicalTargetHTTPServer:
    """Create a configurable local server; callers own its lifecycle."""

    if not bind_host or not isinstance(bind_host, str):
        raise ValueError("bind_host must be a non-empty string")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    if not isinstance(max_body_bytes, int) or max_body_bytes <= 0 or max_body_bytes > MAX_BODY_BYTES:
        raise ValueError("max_body_bytes is outside the permitted range")
    return PhysicalTargetHTTPServer((bind_host, port), _handler_for(runtime, max_body_bytes=max_body_bytes))


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the owned isolated Kimura synthetic target node")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = create_server(PhysicalTargetRuntime(), args.bind, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
