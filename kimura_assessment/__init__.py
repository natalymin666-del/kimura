"""Minimal, isolated Kimura assessment contract package."""

from .schema import AssessmentContract, ContractValidationError
from .customer_schema import CustomerAssessmentConfig, CustomerConfigError, RuntimeConfig, ScenarioSelection
from .customer_assessment import CustomerAssessmentResult, run_customer_assessment
from .html_report import render_customer_report
from .http_adapter import (
    AssessmentTargetError,
    CredentialResolutionError,
    HttpTarget,
    JsonPostAdapter,
    TargetRequestError,
    credential_environment_name,
)
from .results import AssessmentResult
from .persistence import AssessmentResultStore, PersistenceError
from .report import build_report, report_from_store, report_json_from_store, write_report
from .runner import AssessmentExecutionError, AssessmentRunner
from .evidence import EvidenceRecord, EvidenceStore, EvidenceValidationError, digest_text
from .findings import Finding, FindingValidationError
from .risk import RiskEvaluator
from .scenarios import AgentDemoContract, ScenarioFixture, DEMO_V3_SCENARIOS, EXFIL_CONTRACT, EXFIL_FIXTURE
from .model_schemas import AgentTrialResult, ModelRequest, ModelResponse, ModelSettings, ProposedAction, TrialAggregate, TrialConfig
from .model_scenarios import MODEL_V1_FIXTURE, ModelScenarioFixture
from .calibration import CALIBRATION_FIXTURES, CalibrationFixtureResult, calibration_json, run_calibration_suite, run_ollama_calibration
from .scenario_protocol import SCENARIO_ONE, SCENARIO_TWO, SCENARIO_THREE, SP_V1_REGISTRY, ScenarioDefinition, ScenarioProtocolError, ScenarioRegistry
from .attack_reproduction import AttackAttemptEvidence, AttackReproductionExperiment, AttackVariant, AttackVariantSet, ExperimentSummary, OUTCOMES, ReplayBinding, SCENARIO_THREE_VARIANT_SET_ID, SealedAttackVariantSet, build_scenario_three_variant_set, AttemptJournal, AttemptJournalEvent, DurableAttackExperimentRunner, ExperimentRecovery, JOURNAL_STATES, recover_experiment, ReplayEvidenceCapsule, ReplayEvidenceCapsuleStore
from .real_agent_adapter import AgentRequest, AnthropicAgentAdapter, AnthropicHTTPError, DeterministicFakeAgent, KimuraVerdict, ModelObservation, ProviderDescriptor, RealAgentAdapterError, SyntheticToolExecutionBoundary, ToolExecutionResult, ToolRequest, build_synthetic_agent_request, compare_replay_invariants, validate_canonical_capability, validate_provider_schema_equivalence, validate_tool_arguments, verify_baseline, verify_control_block

__all__ = [
    "AssessmentContract",
    "CustomerAssessmentConfig",
    "CustomerAssessmentResult",
    "CustomerConfigError",
    "RuntimeConfig",
    "ScenarioSelection",
    "run_customer_assessment",
    "render_customer_report",
    "AssessmentExecutionError",
    "AssessmentRunner",
    "AssessmentResult",
    "AssessmentResultStore",
    "AssessmentTargetError",
    "ContractValidationError",
    "CredentialResolutionError",
    "HttpTarget",
    "JsonPostAdapter",
    "TargetRequestError",
    "PersistenceError",
    "build_report",
    "report_from_store",
    "report_json_from_store",
    "write_report",
    "credential_environment_name",
    "AgentDemoContract",
    "ScenarioFixture",
    "DEMO_V3_SCENARIOS",
    "EXFIL_CONTRACT",
    "EXFIL_FIXTURE",
    "EvidenceRecord",
    "EvidenceStore",
    "EvidenceValidationError",
    "Finding",
    "FindingValidationError",
    "RiskEvaluator",
    "digest_text",
    "AgentTrialResult",
    "ModelRequest",
    "ModelResponse",
    "ModelSettings",
    "ProposedAction",
    "TrialAggregate",
    "TrialConfig",
    "MODEL_V1_FIXTURE",
    "ModelScenarioFixture",
    "CALIBRATION_FIXTURES",
    "CalibrationFixtureResult",
    "calibration_json",
    "run_calibration_suite",
    "run_ollama_calibration",
    "ScenarioDefinition",
    "ScenarioProtocolError",
    "ScenarioRegistry",
    "SCENARIO_ONE",
    "SCENARIO_TWO",
    "SCENARIO_THREE",
    "SP_V1_REGISTRY",
    "ReplayEvidenceCapsule",
    "ReplayEvidenceCapsuleStore",
    "AttemptJournal",
    "AttemptJournalEvent",
    "DurableAttackExperimentRunner",
    "ExperimentRecovery",
    "JOURNAL_STATES",
    "recover_experiment",
    "AttackAttemptEvidence",
    "AttackReproductionExperiment",
    "AttackVariant",
    "AttackVariantSet",
    "ExperimentSummary",
    "OUTCOMES",
    "ReplayBinding",
    "SCENARIO_THREE_VARIANT_SET_ID",
    "SealedAttackVariantSet",
    "build_scenario_three_variant_set",
    "AgentRequest",
    "AnthropicAgentAdapter",
    "AnthropicHTTPError",
    "DeterministicFakeAgent",
    "KimuraVerdict",
    "ModelObservation",
    "ProviderDescriptor",
    "RealAgentAdapterError",
    "SyntheticToolExecutionBoundary",
    "ToolExecutionResult",
    "ToolRequest",
    "build_synthetic_agent_request",
    "validate_canonical_capability",
    "validate_provider_schema_equivalence",
    "validate_tool_arguments",
    "compare_replay_invariants",
    "verify_baseline",
    "verify_control_block",
]
