"""Deterministic, provider-neutral calibration suite for model-backed trials."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Iterable

from .agent_wrapper import AgentPolicy, ModelBackedAgent
from .model_schemas import AgentTrialResult, TrialConfig
from .model_scenarios import CALIBRATION_FIXTURES, CONTROL_FIXTURES, ModelScenarioFixture
from .ollama_adapter import OllamaProvider


@dataclass(frozen=True, slots=True)
class CalibrationFixtureResult:
    fixture_id: str
    fixture_sha256: str
    model: str
    trial_count: int
    proposed_action_count: int
    allowed_action_count: int
    validated_impact_count: int
    success_rate: float
    classification: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _classification(results: tuple[AgentTrialResult, ...]) -> str:
    impact_count = sum(item.validated_impact for item in results)
    if impact_count == 0:
        return "no-impact"
    if impact_count == len(results):
        return "stable"
    return "flaky"


def summarize_fixture(fixture: ModelScenarioFixture, results: tuple[AgentTrialResult, ...], *, model: str) -> CalibrationFixtureResult:
    if not results:
        raise ValueError("at least one trial result is required")
    impact_count = sum(item.validated_impact for item in results)
    return CalibrationFixtureResult(
        fixture.fixture_id, fixture.fixture_sha256, model, len(results),
        sum(item.proposed_action == fixture.expected_tool for item in results),
        sum(item.gate_decision == "allowed" for item in results), impact_count,
        impact_count / len(results), _classification(results),
    )


def run_calibration_suite(provider, *, model_id: str, trials: int = 10, fixtures: Iterable[ModelScenarioFixture] = CALIBRATION_FIXTURES, policy: AgentPolicy = AgentPolicy("baseline-permissive-v1", False)) -> tuple[CalibrationFixtureResult, ...]:
    """Run fixtures through the existing proposal, gate, and synthetic tool path."""
    if trials <= 0 or trials > 100:
        raise ValueError("trials must be between 1 and 100")
    if not isinstance(model_id, str) or not model_id:
        raise ValueError("model_id must be non-empty")
    if hasattr(provider, "model_id"):
        provider.model_id = model_id
    agent = ModelBackedAgent(provider)
    summaries = []
    for fixture in tuple(fixtures):
        configs = tuple(TrialConfig(f"{fixture.fixture_id}-trial-{index + 1:02d}", index) for index in range(trials))
        results, _aggregate = agent.run_trials(fixture, policy, configs)
        summaries.append(summarize_fixture(fixture, results, model=model_id))
    if not summaries:
        raise ValueError("at least one calibration fixture is required")
    return tuple(summaries)


def calibration_json(results: tuple[CalibrationFixtureResult, ...]) -> str:
    """Serialize summaries without fixture text or model responses."""
    return json.dumps([item.to_dict() for item in results], sort_keys=True)


def run_ollama_calibration(*, model_id: str, trials: int = 10) -> str:
    """Run the suite through loopback Ollama and return safe JSON summaries."""
    return calibration_json(run_calibration_suite(OllamaProvider(model_id=model_id), model_id=model_id, trials=trials))


def run_ollama_controls(*, model_id: str, trials: int = 5) -> str:
    """Run only the benign controls through the full proposal/gate path."""
    return calibration_json(run_calibration_suite(OllamaProvider(model_id=model_id), model_id=model_id, trials=trials, fixtures=CONTROL_FIXTURES))
