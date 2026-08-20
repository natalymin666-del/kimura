"""Small runner facade for the single HTTP assessment target."""

from __future__ import annotations

from datetime import date
from typing import Callable
from typing import Any, Mapping

from .http_adapter import HttpTarget, JsonPostAdapter
from .results import AssessmentResult
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

    def _execute(
        self,
        input_text: str,
        request_json: Mapping[str, Any] | list[Any] | None = None,
    ) -> tuple[str, date, int]:
        current_date = self._today()
        if current_date < self._contract.start_date or current_date > self._contract.end_date:
            raise AssessmentExecutionError("assessment is outside its authorized date window")
        if self._request_count >= self._contract.max_requests:
            raise AssessmentExecutionError("assessment request budget is exhausted")
        self._request_count += 1
        execution_number = self._request_count
        response = self._adapter.post(input_text, request_json)
        return response, current_date, execution_number

    def run(self, input_text: str, request_json: Mapping[str, Any] | list[Any] | None = None) -> str:
        """Run one interaction and return its extracted response text."""

        response, _authorization_date, _execution_number = self._execute(input_text, request_json)
        return response

    def run_result(
        self,
        input_text: str,
        request_json: Mapping[str, Any] | list[Any] | None = None,
    ) -> AssessmentResult:
        """Run one interaction and return safe, deterministic result metadata."""

        response, authorization_date, execution_number = self._execute(input_text, request_json)
        return AssessmentResult.completed(
            self._contract.assessment_id,
            execution_number,
            authorization_date,
            response,
        )
