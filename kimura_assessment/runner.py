"""Small runner facade for the single HTTP assessment target."""

from __future__ import annotations

from typing import Any, Mapping

from .http_adapter import HttpTarget, JsonPostAdapter
from .schema import AssessmentContract


class AssessmentRunner:
    """Run one configured JSON POST assessment interaction."""

    def __init__(self, contract: AssessmentContract, target: HttpTarget):
        self._adapter = JsonPostAdapter(contract, target)

    def run(self, input_text: str, request_json: Mapping[str, Any] | list[Any] | None = None) -> str:
        return self._adapter.post(input_text, request_json)
