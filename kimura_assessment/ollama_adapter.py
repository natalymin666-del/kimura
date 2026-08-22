"""Loopback-only Ollama adapter with no raw response persistence."""

from __future__ import annotations

import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from .model_adapter import ModelProviderError
from .model_schemas import ModelRequest, ModelResponse, ProposedAction, safe_digest


def _is_loopback(hostname: str | None) -> bool:
    return hostname in {"127.0.0.1", "localhost", "::1"}


class OllamaProvider:
    provider_id = "ollama-local"

    def __init__(self, endpoint: str = "http://127.0.0.1:11434/api/chat", *, model_id: str | None = None, max_response_bytes: int = 131_072):
        parsed = urlsplit(endpoint)
        if parsed.scheme != "http" or not _is_loopback(parsed.hostname) or parsed.username or parsed.password:
            raise ValueError("Ollama endpoint must be an HTTP loopback URL without credentials")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._endpoint = endpoint
        self._max_response_bytes = max_response_bytes
        self.model_id = model_id

    def check_ready(self) -> None:
        """Verify the loopback service is reachable and the requested model exists."""

        if not self.model_id:
            raise OllamaReadinessError("no Ollama model was configured")
        tags_endpoint = urljoin(self._endpoint, "tags")
        try:
            request = Request(tags_endpoint, method="GET", headers={"Accept": "application/json"})
            with urlopen(request, timeout=5.0) as response:
                raw = response.read(self._max_response_bytes + 1)
        except HTTPError as exc:
            raise OllamaReadinessError(f"Ollama runtime returned HTTP {exc.code}") from None
        except (URLError, TimeoutError, OSError) as exc:
            raise OllamaReadinessError(f"Ollama runtime is unreachable ({type(exc).__name__})") from None
        if len(raw) > self._max_response_bytes:
            raise OllamaReadinessError("Ollama model list exceeded the response size limit")
        try:
            decoded = json.loads(raw.decode("utf-8"))
            models = decoded["models"]
            names = {item["name"] for item in models if isinstance(item, dict) and isinstance(item.get("name"), str)}
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            raise OllamaReadinessError("Ollama returned an invalid model list") from None
        if self.model_id not in names:
            raise OllamaReadinessError(f"configured Ollama model is not installed: {self.model_id}")

    def complete(self, request: ModelRequest) -> ModelResponse:
        settings = request.settings
        tools = [{"type": "function", "function": {"name": tool.name, "description": tool.description, "parameters": {"type": "object", "additionalProperties": True}}} for tool in request.tools]
        body = json.dumps({
            "model": settings.model_id,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": request.system_instruction},
                {"role": "user", "content": request.user_task + "\n\nRetrieved untrusted content:\n" + request.retrieved_content},
            ],
            "tools": tools,
            "options": {key: value for key, value in {"temperature": settings.temperature, "top_p": settings.top_p, "seed": settings.seed, "num_predict": settings.max_output_tokens}.items() if value is not None},
        }, separators=(",", ":")).encode("utf-8")
        started = time.monotonic()
        try:
            request_obj = Request(self._endpoint, data=body, method="POST", headers={"Accept": "application/json", "Content-Type": "application/json"})
            with urlopen(request_obj, timeout=settings.timeout_seconds) as response:
                raw = response.read(self._max_response_bytes + 1)
        except HTTPError as exc:
            raise ModelProviderError(f"ollama_http_{exc.code}") from None
        except (URLError, TimeoutError, OSError) as exc:
            raise ModelProviderError(f"ollama_{type(exc).__name__.lower()}") from None
        if len(raw) > self._max_response_bytes:
            raise ModelProviderError("ollama_response_too_large")
        response_digest = safe_digest(raw.decode("utf-8", errors="replace"))
        try:
            decoded = json.loads(raw.decode("utf-8"))
            message = decoded["message"]
            if not isinstance(message, dict):
                raise ValueError
            proposal = None
            content = message.get("content")
            if isinstance(content, str) and content:
                proposal_doc = json.loads(content)
                action = proposal_doc.get("action") if isinstance(proposal_doc, dict) else None
                arguments = proposal_doc.get("arguments", {}) if isinstance(proposal_doc, dict) else {}
                if isinstance(action, str) and isinstance(arguments, dict):
                    proposal = ProposedAction(action, tuple(sorted(arguments)))
            if proposal is None:
                tool_calls = message.get("tool_calls", [])
                if isinstance(tool_calls, list) and len(tool_calls) == 1:
                    function = tool_calls[0].get("function") if isinstance(tool_calls[0], dict) else None
                    action = function.get("name") if isinstance(function, dict) else None
                    arguments = function.get("arguments", {}) if isinstance(function, dict) else {}
                    if isinstance(action, str) and isinstance(arguments, dict):
                        proposal = ProposedAction(action, tuple(sorted(arguments)))
            status = "valid" if proposal is not None else "invalid_output"
        except (UnicodeDecodeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            proposal = None
            status = "invalid_output"
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=settings.model_id,
            proposed_action=proposal,
            proposal_status=status,
            finish_reason=str(decoded.get("done_reason", "complete")) if isinstance(decoded, dict) else "complete",
            response_sha256=response_digest,
            response_length=len(raw),
            latency_ms=int((time.monotonic() - started) * 1000),
        )


class OllamaReadinessError(RuntimeError):
    """Raised when the local Ollama runtime cannot satisfy preflight."""
