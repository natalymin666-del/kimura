import unittest

from kimura_assessment.mobile_report import MobileReportError, derive_mobile_report
from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator, validate_physical_fixture_binding
from kimura_assessment.physical_fixture_isolation import FixtureIsolationError, run_fixture_path, validate_run_fixture_path
from kimura_assessment.progress_events import ProgressEmitter, ProgressEventType
from kimura_assessment.progress_journal import ProgressJournal


RUN_ID = "phase46a-run-12345678"


class Adapter:
    def __init__(self, fail=None, **overrides):
        self.calls = []
        self.fail = fail
        self.overrides = overrides

    def _call(self, name, evidence):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError(name + " failed")
        value = dict(evidence)
        value.update(self.overrides.get(name, {}))
        return value

    def discover(self, run_id):
        return self._call("discover", {"run_id": run_id, "identity_verified": True, "target_id": "pi-5", "target_kind": "raspberry-pi-5-physical-target", "protocol_version": 1, "policy_digest_before": "1" * 64})

    def baseline(self, run_id):
        return self._call("baseline", {"run_id": run_id, "fixture_id": "fixture-1", "fixture_sha256": "b" * 64, "action": "send_email", "decision": "allowed", "synthetic_impact": True, "event_id": "baseline-1", "ledger_before": 0, "ledger_after": 1, "sha256": "c" * 64})

    def remediate(self, run_id):
        return self._call("remediate", {"run_id": run_id, "verified": True, "policy_id": "physical-remediation-policy-v1", "policy_digest_before": "1" * 64, "policy_digest_after": "2" * 64, "policy_before": "permit", "policy_after": "deny"})

    def replay(self, run_id):
        return self._call("replay", {"run_id": run_id, "fixture_id": "fixture-1", "fixture_sha256": "b" * 64, "action": "send_email", "sha256": "c" * 64, "attack_id": "attack-1", "decision": "blocked", "synthetic_impact": False, "ledger_before": 1, "ledger_after": 1, "executed": True})


def run(adapter, run_id=RUN_ID):
    journal = ProgressJournal()
    emitter = ProgressEmitter(journal.append, run_id=run_id)
    result = PhysicalConferenceOrchestrator(run_id, adapter=adapter, emit=emitter.emit).start()
    return result, journal


class PhysicalConferenceOrchestrationTests(unittest.TestCase):
    def test_waiting_constructor_does_not_contact_and_start_is_explicit(self):
        adapter = Adapter()
        journal = ProgressJournal()
        emitter = ProgressEmitter(journal.append, run_id=RUN_ID)
        orchestrator = PhysicalConferenceOrchestrator(RUN_ID, adapter=adapter, emit=emitter.emit)
        self.assertEqual(adapter.calls, [])
        self.assertEqual(orchestrator.started, False)
        orchestrator.start()
        self.assertEqual(adapter.calls, ["discover", "baseline", "remediate", "replay"])

    def test_conference_and_physical_run_ids_are_explicitly_bound(self):
        adapter = Adapter()
        journal = ProgressJournal()
        emitter = ProgressEmitter(journal.append, run_id=RUN_ID)
        orchestrator = PhysicalConferenceOrchestrator(RUN_ID, adapter=adapter, emit=emitter.emit)
        result = orchestrator.start()
        self.assertTrue(result.fix_verified)
        self.assertNotEqual(orchestrator.run_id, orchestrator.physical_run_id)
        self.assertTrue(orchestrator.physical_run_id.startswith("physical-"))
        self.assertEqual(orchestrator.fixture_path, run_fixture_path(orchestrator.physical_run_id))
        with self.assertRaises(FixtureIsolationError):
            validate_run_fixture_path("kimura-physical-fixture")
        with self.assertRaises(FixtureIsolationError):
            validate_physical_fixture_binding(orchestrator.physical_run_id, run_fixture_path(RUN_ID))
        with self.assertRaises(FixtureIsolationError):
            validate_run_fixture_path("kimura-physical-fixture/runs/" + orchestrator.physical_run_id + "/../" + orchestrator.physical_run_id)

    def test_invalid_or_mixed_physical_run_binding_is_rejected(self):
        with self.assertRaises(ValueError):
            PhysicalConferenceOrchestrator(RUN_ID, adapter=Adapter(), emit=lambda *_: None, physical_run_id=RUN_ID)
        with self.assertRaises(ValueError):
            PhysicalConferenceOrchestrator(RUN_ID, adapter=Adapter(), emit=lambda *_: None, physical_run_id="../other-run")
        result, journal = run(Adapter(baseline={"run_id": RUN_ID}), run_id=RUN_ID + "-binding")
        self.assertFalse(result.fix_verified)
        self.assertNotIn(ProgressEventType.FIX_VERIFIED, [event.event_type for event in journal.get_events_after(RUN_ID + "-binding", 0)])

    def test_success_maps_each_proven_checkpoint_and_binds_report(self):
        result, journal = run(Adapter())
        self.assertTrue(result.fix_verified)
        events = journal.get_events_after(RUN_ID, 0)
        self.assertEqual([event.event_type for event in events], [ProgressEventType.ASSESSMENT_STARTED, ProgressEventType.TARGET_VERIFIED, ProgressEventType.BASELINE_VALIDATED, ProgressEventType.REMEDIATION_VERIFIED, ProgressEventType.REPLAY_IDENTITY_VERIFIED, ProgressEventType.REPLAY_VALIDATED, ProgressEventType.CLEANUP_COMPLETED, ProgressEventType.FIX_VERIFIED])
        report = derive_mobile_report(journal.get_latest_snapshot(RUN_ID).to_dict(), expected_run_id=RUN_ID)
        self.assertEqual(report.run_id, RUN_ID)

    def test_failure_evidence_preserves_stage_message_ids_and_redacts_secrets(self):
        class FailingAdapter(Adapter):
            def baseline(self, run_id):
                self.calls.append("baseline")
                raise FixtureIsolationError("fixture path rejected; token=super-secret")
        result, journal = run(FailingAdapter(), run_id=RUN_ID + "-diagnostic")
        self.assertFalse(result.fix_verified)
        snapshot = journal.get_latest_snapshot(RUN_ID + "-diagnostic")
        failure = snapshot.evidence[ProgressEventType.ASSESSMENT_FAILED.value]
        self.assertEqual(failure["failure_stage"], "setup")
        self.assertEqual(failure["exception_class"], "FixtureIsolationError")
        self.assertIn("fixture path rejected", failure["exception_message"])
        self.assertNotIn("super-secret", failure["exception_message"])
        self.assertEqual(failure["conference_run_id"], RUN_ID + "-diagnostic")
        self.assertEqual(failure["physical_run_id"], "physical-" + RUN_ID + "-diagnostic")
        self.assertEqual(failure["last_verified_event"], ProgressEventType.TARGET_VERIFIED.value)
        self.assertEqual(snapshot.state, ProgressEventType.ASSESSMENT_FAILED.value)
        self.assertNotIn(ProgressEventType.BASELINE_VALIDATED.value, snapshot.evidence)
        self.assertNotIn(ProgressEventType.FIX_VERIFIED.value, snapshot.evidence)
        report = derive_mobile_report(snapshot.to_dict(), expected_run_id=RUN_ID + "-diagnostic")
        self.assertEqual(report.status, "FAILED")
        self.assertIn("setup: fixture path rejected", report.failure_reason)
        self.assertNotIn("super-secret", report.failure_reason)

    def test_duplicate_start_rejected(self):
        adapter = Adapter()
        journal = ProgressJournal()
        emitter = ProgressEmitter(journal.append, run_id=RUN_ID)
        orchestrator = PhysicalConferenceOrchestrator(RUN_ID, adapter=adapter, emit=emitter.emit)
        orchestrator.start()
        with self.assertRaises(Exception):
            orchestrator.start()

    def test_failure_at_each_stage_stops_later_success_events(self):
        for failed in ("discover", "baseline", "remediate", "replay"):
            result, journal = run(Adapter(fail=failed), run_id=RUN_ID + failed)
            self.assertFalse(result.fix_verified)
            event_types = [event.event_type for event in journal.get_events_after(RUN_ID + failed, 0)]
            self.assertNotIn(ProgressEventType.FIX_VERIFIED, event_types)
            self.assertEqual(event_types[-1], ProgressEventType.ASSESSMENT_FAILED)

    def test_mixed_run_sha_and_fixture_evidence_rejected(self):
        for overrides in ({"baseline": {"run_id": "other-run-12345678"}}, {"replay": {"sha256": "x" * 64}}, {"replay": {"fixture_id": "other"}}):
            result, journal = run(Adapter(**overrides), run_id=RUN_ID + "-mixed")
            self.assertFalse(result.fix_verified)
            self.assertNotIn(ProgressEventType.FIX_VERIFIED, [event.event_type for event in journal.get_events_after(RUN_ID + "-mixed", 0)])

    def test_mobile_report_cannot_outrun_journal(self):
        journal = ProgressJournal()
        with self.assertRaises(MobileReportError):
            derive_mobile_report({"run_id": RUN_ID, "sequence": 1, "state": "assessment_started", "terminal": False, "evidence": {}}, expected_run_id=RUN_ID)


if __name__ == "__main__":
    unittest.main()
