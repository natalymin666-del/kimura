import copy
import unittest

from kimura_assessment.scenario_protocol import (
    SCENARIO_ONE,
    SCENARIO_TWO,
    SCENARIO_THREE,
    SP_V1_REGISTRY,
    SYNTHETIC_CANARY_FINGERPRINT_V1,
    SYNTHETIC_INJECTION_CONTENT_SHA256_V1,
    ScenarioDefinition,
    ScenarioProtocolError,
    ScenarioRegistry,
    validate_evidence_binding,
)
from kimura_assessment.progress_events import ProgressEvent, ProgressEventType
from kimura_assessment.progress_journal import ProgressEventOrderError, ProgressJournal


class ScenarioTwoAdapter:
    def __init__(self, *, canary=True, replay_canary=False, replay_decision="blocked", replay_sha=None, replay_fixture="data-fixture-2", binding=None):
        self.calls = []
        self.canary = canary
        self.replay_canary = replay_canary
        self.replay_decision = replay_decision
        self.replay_sha = replay_sha or "r" * 64
        self.replay_fixture = replay_fixture
        self.binding = binding or SCENARIO_TWO.evidence_binding()

    def _value(self, value):
        value = dict(value)
        value.update(self.binding)
        return value

    def discover(self, run_id):
        self.calls.append("discover")
        return self._value({"run_id": run_id, "identity_verified": True, "target_id": "synthetic-boundary-target", "target_kind": "owned-synthetic-data-fixture", "protocol_version": 1, "policy_digest_before": "1" * 64})

    def baseline(self, run_id):
        self.calls.append("baseline")
        observed = SYNTHETIC_CANARY_FINGERPRINT_V1 if self.canary else "wrong"
        return self._value({"run_id": run_id, "fixture_id": "data-fixture-2", "fixture_sha256": "d" * 64, "action": "read_protected_data", "decision": "allowed", "synthetic_impact": self.canary, "event_id": "data-baseline-1", "ledger_before": 0, "ledger_after": 1, "sha256": "r" * 64, "scenario_facts": {"data_boundary_action": "read_protected_data", "synthetic_canary_fingerprint": observed, "baseline_data_access": "ALLOWED", "baseline_canary_observed": self.canary}})

    def remediate(self, run_id):
        self.calls.append("remediate")
        return self._value({"run_id": run_id, "verified": True, "policy_id": "data-boundary-policy-v1", "policy_digest_before": "1" * 64, "policy_digest_after": "2" * 64, "policy_before": "permit", "policy_after": "deny"})

    def replay(self, run_id):
        self.calls.append("replay")
        return self._value({"run_id": run_id, "fixture_id": self.replay_fixture, "fixture_sha256": "d" * 64, "action": "read_protected_data", "sha256": self.replay_sha, "attack_id": "data-replay-1", "decision": self.replay_decision, "synthetic_impact": self.replay_canary, "ledger_before": 1, "ledger_after": 1, "executed": True, "scenario_facts": {"data_boundary_action": "read_protected_data", "synthetic_canary_fingerprint": SYNTHETIC_CANARY_FINGERPRINT_V1 if self.replay_canary else "none", "replay_data_access": self.replay_decision.upper(), "replay_canary_observed": self.replay_canary}})


class ScenarioThreeAdapter:
    def __init__(self, mode="success"):
        self.mode = mode
        self.binding = SCENARIO_THREE.evidence_binding()
        self.content_sha = SYNTHETIC_INJECTION_CONTENT_SHA256_V1

    def _value(self, value, *, bind=True):
        value = dict(value)
        if bind:
            value.update(self.binding)
        return value

    def discover(self, run_id):
        return self._value({"run_id": run_id, "identity_verified": True, "target_id": "synthetic-injection-target", "target_kind": "owned-synthetic-content-fixture", "protocol_version": 1, "policy_digest_before": "1" * 64})

    def baseline(self, run_id):
        facts = {"content_provenance": "UNTRUSTED", "content_fingerprint": self.content_sha, "guarded_capability": "write_guarded_record", "baseline_capability_result": "ALLOWED", "baseline_guarded_effect": self.mode not in {"no-effect", "wrong-content", "no-causal-provenance", "missing-provenance"}, "causal_provenance": self.mode not in {"no-effect", "wrong-content", "no-causal-provenance", "missing-provenance"}}
        if self.mode == "wrong-content": facts["content_fingerprint"] = "0" * 64
        if self.mode in {"no-causal-provenance", "missing-provenance"}: facts["causal_provenance"] = False
        return self._value({"run_id": run_id, "fixture_id": "injection-fixture-3", "fixture_sha256": "d" * 64, "action": "write_guarded_record", "decision": "allowed", "synthetic_impact": facts["baseline_guarded_effect"], "event_id": "injection-effect-1", "ledger_before": 0, "ledger_after": 1, "sha256": self.content_sha, "scenario_facts": facts})

    def remediate(self, run_id):
        return self._value({"run_id": run_id, "verified": self.mode != "missing-remediation", "policy_id": "injection-provenance-policy-v1", "policy_digest_before": "1" * 64, "policy_digest_after": "2" * 64, "policy_before": "permit", "policy_after": "deny"})

    def replay(self, run_id):
        action = "different_capability" if self.mode == "different-capability" else "write_guarded_record"
        replay_sha = "x" * 64 if self.mode in {"modified-content", "different-arguments"} else self.content_sha
        binding = self.binding
        if self.mode == "other-scenario":
            binding = SCENARIO_ONE.evidence_binding()
        return self._value({"run_id": "other-run" if self.mode == "other-run-effect" else run_id, "fixture_id": "wrong-fixture" if self.mode == "wrong-fixture" else "injection-fixture-3", "fixture_sha256": "d" * 64, "action": action, "sha256": replay_sha, "attack_id": "injection-replay-1", "decision": "allowed" if self.mode in {"replay-allowed", "trusted-replay"} else "blocked", "synthetic_impact": self.mode == "replay-effect", "ledger_before": 1, "ledger_after": 2 if self.mode == "replay-effect" else 1, "executed": True, "scenario_facts": {"content_provenance": "TRUSTED" if self.mode == "trusted-replay" else "UNTRUSTED", "content_fingerprint": self.content_sha, "guarded_capability": action, "replay_capability_result": "ALLOWED" if self.mode == "replay-allowed" else "BLOCKED", "second_guarded_effect": self.mode == "replay-effect"}}, bind=self.mode != "other-scenario")

class ScenarioProtocolTests(unittest.TestCase):
    def test_scenario_one_represents_golden_send_email_without_loss(self):
        self.assertEqual(SCENARIO_ONE.scenario_protocol_version, 1)
        self.assertEqual(SCENARIO_ONE.scenario_id, "agent-tool-send-email-control")
        self.assertEqual(SCENARIO_ONE.action, "send_email")
        self.assertEqual(SCENARIO_ONE.impact_contract["baseline_result"], "ALLOWED")
        self.assertEqual(SCENARIO_ONE.remediation_contract["expected_before"], "permit")
        self.assertEqual(SCENARIO_ONE.remediation_contract["expected_after"], "deny")
        self.assertEqual(SCENARIO_ONE.verification_contract["ledger_transition"], [0, 1, 1])
        self.assertFalse(SCENARIO_ONE.safety_contract["external_network_action"])

    def test_fingerprint_is_deterministic_and_semantic_changes_matter(self):
        restored = ScenarioDefinition.from_mapping(SCENARIO_ONE.to_dict())
        self.assertEqual(restored.fingerprint, SCENARIO_ONE.fingerprint)
        changed = copy.deepcopy(SCENARIO_ONE.to_dict())
        changed["remediation_contract"]["expected_after"] = "permit"
        self.assertNotEqual(ScenarioDefinition.from_mapping(changed).fingerprint, SCENARIO_ONE.fingerprint)
        reordered = {key: SCENARIO_ONE.to_dict()[key] for key in reversed(tuple(SCENARIO_ONE.to_dict()))}
        self.assertEqual(ScenarioDefinition.from_mapping(reordered).fingerprint, SCENARIO_ONE.fingerprint)

    def test_invalid_protocol_and_safety_are_rejected(self):
        for mutate in (
            lambda d: d.update(scenario_protocol_version=2),
            lambda d: d.update(safety_contract={}),
            lambda d: d.update(action=""),
        ):
            values = SCENARIO_ONE.to_dict()
            mutate(values)
            with self.assertRaises(ScenarioProtocolError):
                ScenarioDefinition.from_mapping(values)

    def test_registry_resolves_unknown_and_conflicting_definitions(self):
        registry = ScenarioRegistry()
        registry.register(SCENARIO_ONE)
        self.assertIs(registry.resolve(SCENARIO_ONE.scenario_id, 1), SCENARIO_ONE)
        registry.register(ScenarioDefinition.from_mapping(SCENARIO_ONE.to_dict()))
        changed = SCENARIO_ONE.to_dict()
        changed["canonical_payload"]["action"] = "other_action"
        with self.assertRaises(ScenarioProtocolError):
            registry.register(ScenarioDefinition.from_mapping(changed))
        with self.assertRaises(ScenarioProtocolError):
            registry.resolve("unknown-scenario", 1)

    def test_identity_spaces_and_evidence_binding_are_separate(self):
        values = SCENARIO_ONE.to_dict()
        values["scenario_name"] = "A readable send email control"
        readable = ScenarioDefinition.from_mapping(values)
        self.assertNotEqual(readable.scenario_id, readable.scenario_name)
        evidence = {"run_id": "run-1", "target_id": "pi-1", **readable.evidence_binding()}
        validate_evidence_binding(evidence, readable)
        with self.assertRaises(ScenarioProtocolError):
            validate_evidence_binding({**evidence, "scenario_version": 2}, readable)

    def test_journal_rejects_cross_scenario_or_incomplete_bindings(self):
        journal = ProgressJournal()
        binding = SCENARIO_ONE.evidence_binding()
        started = ProgressEvent("run-1", 1, ProgressEventType.ASSESSMENT_STARTED, {"assessment_id": "a", **binding})
        journal.append(started)
        with self.assertRaises(ProgressEventOrderError):
            journal.append(ProgressEvent("run-1", 2, ProgressEventType.TARGET_VERIFIED, {
                "target_id": "t", "target_kind": "k", "protocol_version": 1, "policy_digest_before": "x",
                "scenario_id": "different", "scenario_version": 1, "scenario_fingerprint": "f",
            }))

    def test_scenario_two_contract_and_generic_golden_lifecycle(self):
        from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator
        from kimura_assessment.progress_events import ProgressEmitter
        run_id = "scenario-two-run"
        journal = ProgressJournal()
        emitter = ProgressEmitter(journal.append, run_id=run_id)
        result = PhysicalConferenceOrchestrator(run_id, adapter=ScenarioTwoAdapter(), emit=emitter.emit, scenario_id=SCENARIO_TWO.scenario_id, scenario_version=1).start()
        self.assertTrue(result.fix_verified)
        report = __import__("kimura_assessment.mobile_report", fromlist=["derive_mobile_report"]).derive_mobile_report(journal.get_latest_snapshot(run_id).to_dict(), expected_run_id=run_id)
        self.assertEqual(report.scenario_id, SCENARIO_TWO.scenario_id)
        self.assertTrue(report.fix_verified)
        self.assertEqual(report.scenario_facts["synthetic_canary_fingerprint"], SYNTHETIC_CANARY_FINGERPRINT_V1)

    def test_scenario_two_negative_canary_and_replay_proofs_fail_closed(self):
        from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator
        from kimura_assessment.progress_events import ProgressEmitter
        cases = (
            ScenarioTwoAdapter(canary=False),
            ScenarioTwoAdapter(replay_canary=True),
            ScenarioTwoAdapter(replay_decision="allowed"),
            ScenarioTwoAdapter(replay_sha="x" * 64),
            ScenarioTwoAdapter(replay_fixture="wrong-fixture"),
            ScenarioTwoAdapter(binding={**SCENARIO_TWO.evidence_binding(), "scenario_fingerprint": "0" * 64}),
            ScenarioTwoAdapter(binding=SCENARIO_ONE.evidence_binding()),
        )
        for index, adapter in enumerate(cases):
            run_id = f"scenario-two-negative-{index}"
            journal = ProgressJournal()
            emitter = ProgressEmitter(journal.append, run_id=run_id)
            result = PhysicalConferenceOrchestrator(run_id, adapter=adapter, emit=emitter.emit, scenario=SCENARIO_TWO).start()
            self.assertFalse(result.fix_verified)
            self.assertNotIn("fix_verified", journal.get_latest_snapshot(run_id).evidence)

    def test_scenario_three_contract_and_generic_golden_lifecycle(self):
        from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator
        from kimura_assessment.progress_events import ProgressEmitter
        run_id = "scenario-three-run"
        journal = ProgressJournal()
        emitter = ProgressEmitter(journal.append, run_id=run_id)
        result = PhysicalConferenceOrchestrator(run_id, adapter=ScenarioThreeAdapter(), emit=emitter.emit, scenario_id=SCENARIO_THREE.scenario_id, scenario_version=1).start()
        self.assertTrue(result.fix_verified)
        report = __import__("kimura_assessment.mobile_report", fromlist=["derive_mobile_report"]).derive_mobile_report(journal.get_latest_snapshot(run_id).to_dict(), expected_run_id=run_id)
        self.assertTrue(report.fix_verified)
        self.assertEqual(report.scenario_facts["content_provenance"], "UNTRUSTED")
        self.assertEqual(report.scenario_facts["guarded_capability"], "write_guarded_record")
        self.assertNotIn("KIMURA_SYNTHETIC", str(report.to_dict()))

    def test_scenario_three_negative_proofs_fail_closed(self):
        from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator
        from kimura_assessment.progress_events import ProgressEmitter
        modes = ("no-effect", "wrong-content", "no-causal-provenance", "missing-provenance", "missing-remediation", "trusted-replay", "modified-content", "different-capability", "different-arguments", "wrong-fixture", "other-run-effect", "replay-allowed", "replay-effect", "other-scenario")
        for mode in modes:
            run_id = "scenario-three-negative-" + mode
            journal = ProgressJournal()
            emitter = ProgressEmitter(journal.append, run_id=run_id)
            result = PhysicalConferenceOrchestrator(run_id, adapter=ScenarioThreeAdapter(mode), emit=emitter.emit, scenario=SCENARIO_THREE).start()
            self.assertFalse(result.fix_verified, mode)
            self.assertNotIn("fix_verified", journal.get_latest_snapshot(run_id).evidence, mode)

    def test_scenario_three_safety_rejects_external_or_real_components(self):
        for key in ("synthetic_content_only", "synthetic_capability_only", "external_llm", "real_tools"):
            definition = SCENARIO_THREE.to_dict()
            definition["safety_contract"][key] = False if key.startswith("synthetic") else True
            with self.assertRaises(ScenarioProtocolError):
                ScenarioDefinition.from_mapping(definition)

    def test_scenario_two_safety_rejects_real_sources_and_network(self):
        for key, value in (("real_filesystem_secrets", True), ("environment_secrets", True), ("credential_stores", True), ("external_network_action", True)):
            definition = SCENARIO_TWO.to_dict()
            definition["safety_contract"][key] = value
            with self.assertRaises(ScenarioProtocolError):
                ScenarioDefinition.from_mapping(definition)

    def test_registry_global_scenario_one_is_stable(self):
        self.assertIs(SP_V1_REGISTRY.resolve("agent-tool-send-email-control", 1), SCENARIO_ONE)

    def test_registry_resolution_at_orchestrator_boundary(self):
        from tests.test_physical_conference_orchestration import Adapter, RUN_ID
        from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator
        orchestrator = PhysicalConferenceOrchestrator(
            RUN_ID + "-resolved", adapter=Adapter(), emit=lambda *_: None,
            scenario_id=SCENARIO_ONE.scenario_id, scenario_version=SCENARIO_ONE.scenario_version,
        )
        self.assertEqual(orchestrator.scenario.fingerprint, SCENARIO_ONE.fingerprint)
        with self.assertRaises(ScenarioProtocolError):
            PhysicalConferenceOrchestrator(RUN_ID + "-unknown", adapter=Adapter(), emit=lambda *_: None, scenario_id="unknown-scenario", scenario_version=1)

    def test_scenario_binding_survives_golden_journal_path(self):
        from tests.test_physical_conference_orchestration import Adapter, RUN_ID
        from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator
        binding = SCENARIO_ONE.evidence_binding()
        class BoundAdapter:
            def __init__(self):
                self.inner = Adapter()
            def _bound(self, method, run_id):
                value = dict(getattr(self.inner, method)(run_id))
                value.update(binding)
                return value
            def discover(self, run_id): return self._bound("discover", run_id)
            def baseline(self, run_id): return self._bound("baseline", run_id)
            def remediate(self, run_id): return self._bound("remediate", run_id)
            def replay(self, run_id): return self._bound("replay", run_id)
        journal = ProgressJournal()
        from kimura_assessment.progress_events import ProgressEmitter
        emitter = ProgressEmitter(journal.append, run_id=RUN_ID + "-sp")
        result = PhysicalConferenceOrchestrator(RUN_ID + "-sp", adapter=BoundAdapter(), emit=emitter.emit, scenario=SCENARIO_ONE).start()
        self.assertTrue(result.fix_verified)
        snapshot = journal.get_latest_snapshot(RUN_ID + "-sp")
        self.assertEqual(snapshot.evidence["replay_validated"]["scenario_id"], SCENARIO_ONE.scenario_id)
        snapshot = journal.get_latest_snapshot(RUN_ID + "-sp")
        self.assertEqual(snapshot.evidence["fix_verified"]["scenario_fingerprint"], SCENARIO_ONE.fingerprint)
        from kimura_assessment.mobile_report import derive_mobile_report
        report = derive_mobile_report(snapshot.to_dict(), expected_run_id=RUN_ID + "-sp")
        self.assertEqual(report.scenario_id, SCENARIO_ONE.scenario_id)
        self.assertEqual(report.scenario_version, 1)
        self.assertEqual(report.scenario_fingerprint, SCENARIO_ONE.fingerprint)
        self.assertTrue(report.fix_verified)

        for bad in (
            {"scenario_fingerprint": "0" * 64},
            {"scenario_version": 2},
            {"scenario_id": "other-scenario"},
        ):
            class BadAdapter(BoundAdapter):
                def replay(self, physical_run_id):
                    value = super().replay(physical_run_id)
                    value.update(bad)
                    return value
            bad_run = RUN_ID + "-bad-" + str(len(bad))
            bad_journal = ProgressJournal()
            bad_emitter = ProgressEmitter(bad_journal.append, run_id=bad_run)
            bad_result = PhysicalConferenceOrchestrator(bad_run, adapter=BadAdapter(), emit=bad_emitter.emit, scenario_id=SCENARIO_ONE.scenario_id, scenario_version=1).start()
            self.assertFalse(bad_result.fix_verified)
            self.assertNotIn("fix_verified", bad_journal.get_latest_snapshot(bad_run).evidence)

    def test_scenario_aware_mode_never_falls_back_to_legacy(self):
        from tests.test_physical_conference_orchestration import Adapter, RUN_ID
        from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator
        with self.assertRaises(ScenarioProtocolError):
            PhysicalConferenceOrchestrator(RUN_ID + "-missing-version", adapter=Adapter(), emit=lambda *_: None, scenario_id=SCENARIO_ONE.scenario_id)
        journal = ProgressJournal()
        from kimura_assessment.progress_events import ProgressEmitter
        run_id = RUN_ID + "-missing-binding"
        emitter = ProgressEmitter(journal.append, run_id=run_id)
        result = PhysicalConferenceOrchestrator(run_id, adapter=Adapter(), emit=emitter.emit, scenario=SCENARIO_ONE).start()
        self.assertFalse(result.fix_verified)
        self.assertNotIn("fix_verified", journal.get_latest_snapshot(run_id).evidence)

    def test_mobile_report_rejects_partial_or_mixed_scenario_binding(self):
        from kimura_assessment.mobile_report import derive_mobile_report
        from tests.test_physical_conference_orchestration import Adapter, RUN_ID
        from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator
        from kimura_assessment.progress_events import ProgressEmitter
        journal = ProgressJournal()
        run_id = RUN_ID + "-report-binding"
        emitter = ProgressEmitter(journal.append, run_id=run_id)
        binding = SCENARIO_ONE.evidence_binding()
        class BoundAdapter:
            def __init__(self):
                self.inner = Adapter()
            def _bound(self, method, physical_run_id):
                value = dict(getattr(self.inner, method)(physical_run_id))
                value.update(binding)
                return value
            def discover(self, physical_run_id): return self._bound("discover", physical_run_id)
            def baseline(self, physical_run_id): return self._bound("baseline", physical_run_id)
            def remediate(self, physical_run_id): return self._bound("remediate", physical_run_id)
            def replay(self, physical_run_id): return self._bound("replay", physical_run_id)
        PhysicalConferenceOrchestrator(run_id, adapter=BoundAdapter(), emit=emitter.emit, scenario=SCENARIO_ONE).start()
        snapshot = journal.get_latest_snapshot(run_id).to_dict()
        snapshot["evidence"]["replay_validated"]["scenario_fingerprint"] = "0" * 64
        report = derive_mobile_report(snapshot, expected_run_id=run_id)
        self.assertFalse(report.fix_verified)
        self.assertEqual(report.status, "FAILED")


if __name__ == "__main__":
    unittest.main()
