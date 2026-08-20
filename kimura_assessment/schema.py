"""Standard-library assessment contract schema.

This module contains only the data contract for a commercial assessment.  It
intentionally accepts opaque credential *references* but has no field for
credential material, tokens, cookies, or secrets.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date
import json
from typing import Any, Mapping


class ContractValidationError(ValueError):
    """Raised when an assessment contract is incomplete or malformed."""


def _required(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


def _text_tuple(values: tuple[str, ...], field_name: str, *, required: bool) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ContractValidationError(f"{field_name} must be a tuple of strings")
    cleaned = tuple(_required(item, field_name) for item in values)
    if required and not cleaned:
        raise ContractValidationError(f"{field_name} must contain at least one item")
    if len(set(cleaned)) != len(cleaned):
        raise ContractValidationError(f"{field_name} must not contain duplicates")
    return cleaned


@dataclass(frozen=True, slots=True)
class AssessmentContract:
    """The transport-safe contract for one authorized assessment.

    ``credential_references`` are identifiers for credentials held elsewhere
    in an approved secret manager.  They are not the credentials themselves.
    """

    assessment_id: str
    client_name: str
    assessor_name: str
    authorized_by: str
    objectives: tuple[str, ...]
    scope: tuple[str, ...]
    start_date: date
    end_date: date
    exclusions: tuple[str, ...] = ()
    credential_references: tuple[str, ...] = ()
    max_requests: int = 1

    def __post_init__(self) -> None:
        for field_name in ("assessment_id", "client_name", "assessor_name", "authorized_by"):
            _required(getattr(self, field_name), field_name)

        _text_tuple(self.objectives, "objectives", required=True)
        _text_tuple(self.scope, "scope", required=True)
        _text_tuple(self.exclusions, "exclusions", required=False)
        _text_tuple(self.credential_references, "credential_references", required=False)

        if isinstance(self.max_requests, bool) or not isinstance(self.max_requests, int) or self.max_requests <= 0:
            raise ContractValidationError("max_requests must be a positive integer")

        if not isinstance(self.start_date, date) or not isinstance(self.end_date, date):
            raise ContractValidationError("start_date and end_date must be datetime.date values")
        if self.end_date < self.start_date:
            raise ContractValidationError("end_date cannot be before start_date")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation containing no credential material."""

        result = asdict(self)
        result["start_date"] = self.start_date.isoformat()
        result["end_date"] = self.end_date.isoformat()
        return result

    def to_json(self) -> str:
        """Serialize the contract for storage or transport."""

        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, values: Mapping[str, Any]) -> "AssessmentContract":
        """Build a contract from its JSON-safe dictionary representation."""

        if not isinstance(values, Mapping):
            raise ContractValidationError("contract data must be a mapping")
        data = dict(values)
        try:
            data["start_date"] = date.fromisoformat(data["start_date"])
            data["end_date"] = date.fromisoformat(data["end_date"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractValidationError("dates must be ISO-8601 date strings") from exc
        for field_name in ("objectives", "scope", "exclusions", "credential_references"):
            if field_name in data and isinstance(data[field_name], list):
                data[field_name] = tuple(data[field_name])
        try:
            return cls(**data)
        except TypeError as exc:
            raise ContractValidationError("unexpected or missing contract field") from exc
