"""Structured validated findings and their retest state."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re


class FindingValidationError(ValueError):
    """Raised when a finding is malformed."""


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_STATUSES = {"Candidate", "Validated", "Remediated", "Retest passed"}
_SEVERITIES = {"Low", "Medium", "High", "Critical"}


@dataclass(frozen=True, slots=True)
class Finding:
    schema_version: int
    finding_id: str
    title: str
    category: str
    severity: str
    confidence: str
    status: str
    impact: str
    remediation: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise FindingValidationError("schema_version must be 1")
        for field in ("finding_id", "title", "category", "severity", "confidence", "status", "impact", "remediation"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise FindingValidationError(f"{field} must be non-empty")
        if not _ID.fullmatch(self.finding_id):
            raise FindingValidationError("finding_id must be a safe identifier")
        if self.severity not in _SEVERITIES:
            raise FindingValidationError("unsupported severity")
        if self.status not in _STATUSES:
            raise FindingValidationError("unsupported finding status")
        if not isinstance(self.evidence_ids, tuple) or not self.evidence_ids:
            raise FindingValidationError("evidence_ids must be a non-empty tuple")
        if any(not isinstance(item, str) or not _ID.fullmatch(item) for item in self.evidence_ids):
            raise FindingValidationError("evidence_ids must contain safe identifiers")

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["evidence_ids"] = list(self.evidence_ids)
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)
