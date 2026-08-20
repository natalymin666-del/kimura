"""Deterministic, transport-safe results for authorized assessment executions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date
import hashlib
import json
from typing import Any, Literal


ResultStatus = Literal["completed"]


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    """Safe metadata for one completed authorized assessment execution.

    The result intentionally contains no request or response content and no
    credential-related fields.
    """

    schema_version: int
    assessment_id: str
    execution_number: int
    authorization_date: date
    status: ResultStatus
    response_length: int
    response_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        if not isinstance(self.assessment_id, str) or not self.assessment_id.strip():
            raise ValueError("assessment_id must be a non-empty string")
        if isinstance(self.execution_number, bool) or not isinstance(self.execution_number, int) or self.execution_number <= 0:
            raise ValueError("execution_number must be a positive integer")
        if not isinstance(self.authorization_date, date):
            raise ValueError("authorization_date must be a datetime.date value")
        if self.status != "completed":
            raise ValueError("status must be 'completed'")
        if isinstance(self.response_length, bool) or not isinstance(self.response_length, int) or self.response_length < 0:
            raise ValueError("response_length must be a non-negative integer")
        if not isinstance(self.response_sha256, str) or len(self.response_sha256) != 64:
            raise ValueError("response_sha256 must be a SHA-256 hex digest")
        try:
            int(self.response_sha256, 16)
        except ValueError as exc:
            raise ValueError("response_sha256 must be a SHA-256 hex digest") from exc

    @classmethod
    def completed(
        cls,
        assessment_id: str,
        execution_number: int,
        authorization_date: date,
        response: str,
    ) -> "AssessmentResult":
        """Build safe metadata without retaining the response text."""

        encoded_response = response.encode("utf-8")
        return cls(
            schema_version=1,
            assessment_id=assessment_id,
            execution_number=execution_number,
            authorization_date=authorization_date,
            status="completed",
            response_length=len(encoded_response),
            response_sha256=hashlib.sha256(encoded_response).hexdigest(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation of the result."""

        result = asdict(self)
        result["authorization_date"] = self.authorization_date.isoformat()
        return result

    def to_json(self) -> str:
        """Serialize the result deterministically."""

        return json.dumps(self.to_dict(), sort_keys=True)
