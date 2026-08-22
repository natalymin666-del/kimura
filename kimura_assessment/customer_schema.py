"""Customer Assessment v1 configuration and preflight contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from .model_scenarios import MODEL_V1_FIXTURE
from .ollama_adapter import OllamaProvider
from .schema import AssessmentContract, ContractValidationError


class CustomerConfigError(ValueError):
    """Raised when a Customer Assessment v1 configuration is unsafe or invalid."""


SUPPORTED_PROVIDER = "ollama-local"
SUPPORTED_TARGET_ID = "local-model-backed-agent"
SUPPORTED_SCENARIO_ID = MODEL_V1_FIXTURE.scenario_id


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CustomerConfigError(f"{field} must be a non-empty string")
    return value.strip()


def _texts(value: Any, field: str, *, required: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise CustomerConfigError(f"{field} must be a list of non-empty strings")
    result = tuple(item.strip() for item in value)
    if required and not result:
        raise CustomerConfigError(f"{field} must contain at least one item")
    if len(set(result)) != len(result):
        raise CustomerConfigError(f"{field} must not contain duplicates")
    return result


@dataclass(frozen=True, slots=True)
class ScenarioSelection:
    scenario_id: str
    fixture_id: str
    trials: int

    def __post_init__(self) -> None:
        if self.scenario_id != SUPPORTED_SCENARIO_ID:
            raise CustomerConfigError("unsupported scenario_id")
        if self.fixture_id != MODEL_V1_FIXTURE.fixture_id:
            raise CustomerConfigError("fixture_id does not match the supported scenario")
        if isinstance(self.trials, bool) or not isinstance(self.trials, int) or not 1 <= self.trials <= 100:
            raise CustomerConfigError("trials must be an integer between 1 and 100")


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    provider: str
    endpoint: str
    model_id: str
    credential_reference: str
    timeout_seconds: float = 30.0
    max_output_tokens: int = 256

    def __post_init__(self) -> None:
        if self.provider != SUPPORTED_PROVIDER:
            raise CustomerConfigError("only ollama-local is supported")
        parsed = urlsplit(self.endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.password:
            raise CustomerConfigError("runtime endpoint must be an HTTP loopback URL without credentials")
        _text(self.model_id, "runtime.model_id")
        _text(self.credential_reference, "runtime.credential_reference")
        if self.timeout_seconds <= 0 or isinstance(self.max_output_tokens, bool) or self.max_output_tokens <= 0:
            raise CustomerConfigError("runtime limits must be positive")


@dataclass(frozen=True, slots=True)
class CustomerAssessmentConfig:
    assessment_id: str
    client_name: str
    assessor: str
    authorization_statement: str
    authorization_reference: str
    objectives: tuple[str, ...]
    allowed_target_id: str
    allowed_target_type: str
    scope: str
    exclusions: tuple[str, ...]
    start_date: date
    end_date: date
    request_budget: int
    runtime: RuntimeConfig
    scenarios: tuple[ScenarioSelection, ...]

    def __post_init__(self) -> None:
        for value, field in ((self.assessment_id, "assessment_id"), (self.client_name, "client_name"), (self.assessor, "assessor"), (self.authorization_statement, "authorization_statement"), (self.authorization_reference, "authorization_reference"), (self.allowed_target_type, "allowed_target_type"), (self.scope, "scope")):
            _text(value, field)
        if self.allowed_target_id != SUPPORTED_TARGET_ID:
            raise CustomerConfigError("unsupported allowed target")
        if not self.objectives or not self.exclusions:
            raise CustomerConfigError("objectives and exclusions are required")
        if self.end_date < self.start_date:
            raise CustomerConfigError("end_date cannot be before start_date")
        if isinstance(self.request_budget, bool) or not isinstance(self.request_budget, int) or self.request_budget <= 0:
            raise CustomerConfigError("request_budget must be a positive integer")
        if not self.scenarios:
            raise CustomerConfigError("at least one scenario must be selected")
        expected = sum(selection.trials for selection in self.scenarios) * 2 + 2
        if self.request_budget < expected:
            raise CustomerConfigError(f"request_budget must be at least {expected} for the selected baseline and retest")
        if len({selection.scenario_id for selection in self.scenarios}) != len(self.scenarios):
            raise CustomerConfigError("scenarios must not contain duplicates")

    @property
    def contract(self) -> AssessmentContract:
        try:
            return AssessmentContract(
                assessment_id=self.assessment_id,
                client_name=self.client_name,
                assessor_name=self.assessor,
                authorized_by=self.authorization_reference,
                objectives=self.objectives,
                scope=(self.scope,),
                start_date=self.start_date,
                end_date=self.end_date,
                exclusions=self.exclusions,
                credential_references=(self.runtime.credential_reference,),
                max_requests=self.request_budget,
            )
        except ContractValidationError as exc:
            raise CustomerConfigError(str(exc)) from exc

    @classmethod
    def from_dict(cls, values: Mapping[str, Any]) -> "CustomerAssessmentConfig":
        if not isinstance(values, Mapping) or values.get("schema_version") != 1:
            raise CustomerConfigError("customer configuration schema_version must be 1")
        try:
            assessment = values["assessment"]
            runtime = values["runtime"]
            scenarios = values["scenarios"]
            target = assessment["allowed_target"]
            if not all(isinstance(item, Mapping) for item in (assessment, runtime, target)) or not isinstance(scenarios, list):
                raise TypeError
            selections = tuple(ScenarioSelection(item["scenario_id"], item["fixture_id"], item["trials"]) for item in scenarios)
            return cls(
                assessment_id=_text(assessment["assessment_id"], "assessment.assessment_id"),
                client_name=_text(assessment["client_name"], "assessment.client_name"),
                assessor=_text(assessment["assessor"], "assessment.assessor"),
                authorization_statement=_text(assessment["authorization_statement"], "assessment.authorization_statement"),
                authorization_reference=_text(assessment["authorization_reference"], "assessment.authorization_reference"),
                objectives=_texts(assessment["objectives"], "assessment.objectives"),
                allowed_target_id=_text(target["target_id"], "assessment.allowed_target.target_id"),
                allowed_target_type=_text(target["target_type"], "assessment.allowed_target.target_type"),
                scope=_text(target["scope"], "assessment.allowed_target.scope"),
                exclusions=_texts(assessment["exclusions"], "assessment.exclusions"),
                start_date=date.fromisoformat(_text(assessment["start_date"], "assessment.start_date")),
                end_date=date.fromisoformat(_text(assessment["end_date"], "assessment.end_date")),
                request_budget=assessment["request_budget"],
                runtime=RuntimeConfig(
                    provider=_text(runtime["provider"], "runtime.provider"),
                    endpoint=_text(runtime["endpoint"], "runtime.endpoint"),
                    model_id=_text(runtime["model_id"], "runtime.model_id"),
                    credential_reference=_text(runtime["credential_reference"], "runtime.credential_reference"),
                    timeout_seconds=runtime.get("timeout_seconds", 30.0),
                    max_output_tokens=runtime.get("max_output_tokens", 256),
                ),
                scenarios=selections,
            )
        except CustomerConfigError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise CustomerConfigError("customer configuration is malformed") from exc

    @classmethod
    def from_path(cls, path: str | Path) -> "CustomerAssessmentConfig":
        try:
            values = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CustomerConfigError("customer configuration could not be read") from exc
        return cls.from_dict(values)

    def preflight(self) -> tuple[str, ...]:
        provider = OllamaProvider(self.runtime.endpoint, model_id=self.runtime.model_id)
        provider.check_ready()
        self.contract
        return (
            "Customer configuration: VALID",
            "Authorization contract: VALID",
            "Target: local-model-backed-agent (synthetic local target)",
            "Runtime: Ollama loopback-only",
            "Ollama runtime: reachable; configured model: installed",
            f"Model: {self.runtime.model_id}",
            f"Scenarios: {', '.join(item.scenario_id for item in self.scenarios)}",
            f"Trials: {sum(item.trials for item in self.scenarios)} baseline + {sum(item.trials for item in self.scenarios)} retest",
            f"Request budget: {self.request_budget}",
            "Credentials: reference-only",
            "External targets and real side effects: prohibited",
        )
