import unittest

from kimura_assessment.mobile_report import MobileReportError, derive_mobile_report
from kimura_assessment.physical_conference_orchestration import PhysicalConferenceOrchestrator
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

    def test_success_maps_each_proven_checkpoint_and_binds_report(self):
        result, journal = run(Adapter())
        self.assertTrue(result.fix_verified)
        events = journal.get_events_after(RUN_ID, 0)
        self.assertEqual([event.event_type for event in events], [ProgressEventType.ASSESSMENT_STARTED, ProgressEventType.TARGET_VERIFIED, ProgressEventType.BASELINE_VALIDATED, ProgressEventType.REMEDIATION_VERIFIED, ProgressEventType.REPLAY_IDENTITY_VERIFIED, ProgressEventType.REPLAY_VALIDATED, ProgressEventType.CLEANUP_COMPLETED, ProgressEventType.FIX_VERIFIED])
        report = derive_mobile_report(journal.get_latest_snapshot(RUN_ID).to_dict(), expected_run_id=RUN_ID)
        self.assertEqual(report.run_id, RUN_ID)

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
