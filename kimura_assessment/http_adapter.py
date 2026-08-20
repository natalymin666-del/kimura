"""One deliberately narrow HTTP target adapter for an assessment."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .schema import AssessmentContract


class AssessmentTargetError(ValueError):
    """Raised when a target, payload, or response is not permitted/valid."""


class CredentialResolutionError(RuntimeError):
    """Raised when the runtime credential cannot be resolved."""


class TargetRequestError(RuntimeError):
    """Raised for safe, non-secret HTTP request failures."""


@dataclass(frozen=True, slots=True)
class HttpTarget:
    """Configuration for exactly one authenticated JSON POST target."""

    endpoint: str
    input_path: str
    response_path: str
    credential_reference: str
    timeout: float = 15.0
    max_response_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        parts = urlsplit(self.endpoint)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username:
            raise AssessmentTargetError("endpoint must be a single HTTP(S) URL without user info")
        if not self.input_path or not self.response_path:
            raise AssessmentTargetError("input_path and response_path are required")
        if self.timeout <= 0 or self.max_response_bytes <= 0:
            raise AssessmentTargetError("timeout and max_response_bytes must be positive")

    @property
    def input_parts(self) -> tuple[str, ...]:
        return _path_parts(self.input_path)

    @property
    def response_parts(self) -> tuple[str, ...]:
        return _path_parts(self.response_path)


def credential_environment_name(reference: str) -> str:
    """Return the environment variable name for an opaque credential reference.

    ``env://NAME`` is a convenient explicit mapping. Other references map to a
    stable, non-reversible name, so the contract never needs to contain a
    secret or a secret-bearing variable value.
    """

    if reference.startswith("env://"):
        name = reference[6:]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise CredentialResolutionError("credential reference has an invalid environment mapping")
        return name
    digest = sha256(reference.encode("utf-8")).hexdigest()[:24].upper()
    return f"KIMURA_CREDENTIAL_{digest}"


def _path_parts(path: str) -> tuple[str, ...]:
    parts = tuple(path.split("."))
    if any(not part for part in parts):
        raise AssessmentTargetError("JSON paths must contain non-empty dot-separated components")
    return parts


def _set_path(document: Any, parts: tuple[str, ...], value: str) -> Any:
    if not isinstance(document, (dict, list)):
        raise AssessmentTargetError("request JSON root must be an object or array")
    current = document
    for position, part in enumerate(parts[:-1]):
        next_is_index = parts[position + 1].isdigit()
        if isinstance(current, dict):
            if part not in current:
                current[part] = [] if next_is_index else {}
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                raise AssessmentTargetError("input JSON path indexes an absent list item")
            current = current[index]
        else:
            raise AssessmentTargetError("input JSON path does not match the request document")
    last = parts[-1]
    if isinstance(current, dict):
        current[last] = value
    elif isinstance(current, list) and last.isdigit() and int(last) < len(current):
        current[int(last)] = value
    else:
        raise AssessmentTargetError("input JSON path does not match the request document")
    return document


def _get_path(document: Any, parts: tuple[str, ...]) -> Any:
    current = document
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise TargetRequestError("response JSON path was not found")
    return current


def _in_scope(endpoint: str, scope: tuple[str, ...]) -> bool:
    target = urlsplit(endpoint)
    normalized_target = (target.scheme.lower(), target.hostname.lower(), target.port or (443 if target.scheme == "https" else 80))
    for entry in scope:
        parsed = urlsplit(entry)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            normalized_entry = (parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80))
            if normalized_entry == normalized_target and (not parsed.path or parsed.path == "/" or target.path == parsed.path or target.path.startswith(parsed.path.rstrip("/") + "/")):
                return True
        elif entry == endpoint:
            return True
    return False


class JsonPostAdapter:
    """Send one authenticated JSON POST after contract scope validation."""

    def __init__(self, contract: AssessmentContract, target: HttpTarget):
        if target.credential_reference not in contract.credential_references:
            raise AssessmentTargetError("target credential reference is not in the assessment contract")
        if not _in_scope(target.endpoint, contract.scope):
            raise AssessmentTargetError("requested endpoint is outside the authorized assessment scope")
        self._target = target
        self._credential_env = credential_environment_name(target.credential_reference)
        # An opener with no redirect handler prevents a response from escaping scope.
        self._opener = build_opener(_NoRedirectHandler)

    def post(self, input_text: str, request_json: Mapping[str, Any] | list[Any] | None = None) -> str:
        if not isinstance(input_text, str):
            raise AssessmentTargetError("input_text must be a string")
        token = os.environ.get(self._credential_env)
        if not token:
            raise CredentialResolutionError("credential environment variable is not set")
        payload = json.loads(json.dumps(request_json if request_json is not None else {}))
        body = json.dumps(_set_path(payload, self._target.input_parts, input_text), separators=(",", ":")).encode("utf-8")
        request = Request(self._target.endpoint, data=body, method="POST", headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        })
        try:
            with self._opener.open(request, timeout=self._target.timeout) as response:
                raw = response.read(self._target.max_response_bytes + 1)
                if len(raw) > self._target.max_response_bytes:
                    raise TargetRequestError("response exceeded configured size limit")
                decoded = json.loads(raw.decode("utf-8"))
        except HTTPError as exc:
            raise TargetRequestError(f"target returned HTTP {exc.code}") from None
        except (URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TargetRequestError(f"target request failed: {type(exc).__name__}") from None
        result = _get_path(decoded, self._target.response_parts)
        if not isinstance(result, str):
            raise TargetRequestError("response JSON path does not contain text")
        return result


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
