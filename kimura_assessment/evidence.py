"""Safe, deterministic evidence records for validated assessments."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import re


class EvidenceValidationError(ValueError):
    """Raised when evidence is malformed or contains unsafe fields."""


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def digest_text(value: str) -> str:
    """Return a stable digest without retaining the supplied text."""

    if not isinstance(value, str):
        raise EvidenceValidationError("evidence digest input must be text")
    return sha256(value.encode("utf-8")).hexdigest()


def _id(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise EvidenceValidationError(f"{field} must be a safe identifier")
    return value


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """A finding-linked observation containing hashes and safe facts only."""

    schema_version: int
    evidence_id: str
    assessment_id: str
    finding_id: str
    phase: str
    step: int
    observation: str
    request_sha256: str
    response_sha256: str
    action: str
    outcome: str
    control: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise EvidenceValidationError("schema_version must be 1")
        for field in ("evidence_id", "assessment_id", "finding_id", "phase", "observation", "action", "outcome", "control"):
            _id(getattr(self, field), field)
        if isinstance(self.step, bool) or not isinstance(self.step, int) or self.step <= 0:
            raise EvidenceValidationError("step must be a positive integer")
        for field in ("request_sha256", "response_sha256"):
            if not isinstance(getattr(self, field), str) or not _DIGEST.fullmatch(getattr(self, field)):
                raise EvidenceValidationError(f"{field} must be a SHA-256 digest")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> "EvidenceRecord":
        if not isinstance(values, dict):
            raise EvidenceValidationError("evidence must be an object")
        expected = set(cls.__dataclass_fields__)
        if set(values) != expected:
            raise EvidenceValidationError("evidence contains unexpected or missing fields")
        try:
            return cls(**values)
        except TypeError as exc:
            raise EvidenceValidationError("evidence fields are malformed") from exc


class EvidenceStore:
    """Append-only local storage for safe evidence records."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, record: EvidenceRecord) -> None:
        if not isinstance(record, EvidenceRecord):
            raise TypeError("only EvidenceRecord objects can be persisted")
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(record.to_json() + "\n")

    def read_all(self) -> list[EvidenceRecord]:
        try:
            content = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise EvidenceValidationError("evidence could not be read") from exc
        records: list[EvidenceRecord] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                raise EvidenceValidationError(f"evidence record {line_number} is empty")
            try:
                records.append(EvidenceRecord.from_dict(json.loads(line)))
            except (json.JSONDecodeError, EvidenceValidationError) as exc:
                raise EvidenceValidationError(f"evidence record {line_number} is malformed") from exc
        return records
