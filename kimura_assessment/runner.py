"""Small runner facade for the single HTTP assessment target."""

from __future__ import annotations

from datetime import date
from typing import Callable
from typing import Any, Mapping

from .http_adapter import HttpTarget, JsonPostAdapter
from .schema import AssessmentContract


class AssessmentExecutionError(RuntimeError):
    """Raised when an assessment cannot be executed under its contract."""


class AssessmentRunner:
    """Run one configured JSON POST assessment interaction."""

    def __init__(
        self,
        contract: AssessmentContract,
        target: HttpTarget,
        *,
        today: Callable[[], date] = date.today,
    ):
        self._adapter = JsonPostAdapter(contract, target)
        self._contract = contract
        self._today = today
        self._request_count = 0

    def run(self, input_text: str, request_json: Mapping[str, Any] | list[Any] | None = None) -> str:
        current_date = self._today()
        if current_date < self._contract.start_date or current_date > self._contract.end_date:
            raise AssessmentExecutionError("assessment is outside its authorized date window")
        if self._request_count >= self._contract.max_requests:
            raise AssessmentExecutionError("assessment request budget is exhausted")
        self._request_count += 1
        return self._adapter.post(input_text, request_json)
