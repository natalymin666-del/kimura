import unittest

from kimura_assessment.progress_events import ProgressEvent, ProgressEventType
from kimura_assessment.progress_journal import (
    ProgressEventConflictError,
    ProgressEventGapError,
    ProgressEventOrderError,
    ProgressEventStaleError,
    ProgressJournal,
)


RUN = "journal-run"


def event(sequence, event_type, payload):
    return ProgressEvent(RUN, sequence, event_type, payload)


def pass_events(run_id=RUN):
    def e(sequence, event_type, payload):
        return ProgressEvent(run_id, sequence, event_type, payload)
    return [
        e(1, ProgressEventType.ASSESSMENT_STARTED, {"assessment_id": "physical-assessment-v1"}),
        e(2, ProgressEventType.TARGET_VERIFIED, {"target_id": "target-1", "target_kind": "owned-isolated-synthetic-target", "protocol_version": 1, "policy_digest_before": "1" * 64}),
        e(3, ProgressEventType.BASELINE_VALIDATED, {"fixture_id": "fixture-1", "fixture_sha256": "b" * 64, "action": "send_email", "decision": "allowed", "event_id": "event-0001", "ledger_count": 1}),
        e(4, ProgressEventType.REMEDIATION_VERIFIED, {"policy_id": "physical-remediation-policy-v1", "policy_digest_before": "1" * 64, "policy_digest_after": "3" * 64, "denied_actions": ["send_email"]}),
        e(5, ProgressEventType.REPLAY_IDENTITY_VERIFIED, {"attack_id": "attack-1", "fixture_id": "fixture-1", "fixture_sha256": "b" * 64, "action": "send_email"}),
        e(6, ProgressEventType.REPLAY_VALIDATED, {"decision": "blocked", "executed": True, "synthetic_event_id": None, "ledger_count": 1, "baseline_ledger_count": 1}),
        e(7, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}),
        e(8, ProgressEventType.FIX_VERIFIED, {"baseline_ledger_count": 1, "final_ledger_count": 1}),
    ]


class ProgressJournalTests(unittest.TestCase):
    def test_pass_reconstructs_fix_verified(self):
        journal = ProgressJournal()
        for item in pass_events():
            journal.append(item)
        snapshot = journal.get_latest_snapshot(RUN)
        self.assertEqual(snapshot.state, "fix_verified")
        self.assertTrue(snapshot.terminal)
        self.assertEqual(snapshot.sequence, 8)

    def test_partial_and_failed_are_terminal_without_fix(self):
        for terminal_type in (ProgressEventType.ASSESSMENT_PARTIAL, ProgressEventType.ASSESSMENT_FAILED):
            journal = ProgressJournal()
            for item in pass_events()[:2]:
                journal.append(item)
            journal.append(event(3, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}))
            journal.append(event(4, terminal_type, {"failure_code": "assessment_failed", "last_proven_event": "target_verified", "cleanup_completed": True}))
            snapshot = journal.get_latest_snapshot(RUN)
            self.assertEqual(snapshot.state, terminal_type.value)
            self.assertTrue(snapshot.terminal)
            self.assertNotIn("fix_verified", snapshot.evidence)

    def test_exact_duplicate_is_idempotent(self):
        journal = ProgressJournal()
        first = pass_events()[0]
        journal.append(first)
        before = journal.get_latest_snapshot(RUN).to_dict()
        after = journal.append(first).to_dict()
        self.assertEqual(before, after)
        self.assertEqual(len(journal.get_events(RUN)), 1)

    def test_conflicting_duplicate_and_stale_event_are_rejected(self):
        journal = ProgressJournal()
        journal.append(pass_events()[0])
        with self.assertRaises(ProgressEventConflictError):
            journal.append(event(1, ProgressEventType.ASSESSMENT_STARTED, {"assessment_id": "different"}))
        with self.assertRaises(ValueError):
            journal.append(event(0, ProgressEventType.ASSESSMENT_STARTED, {"assessment_id": "physical-assessment-v1"}))

    def test_sequence_gap_is_rejected_without_mutation(self):
        journal = ProgressJournal()
        with self.assertRaises(ProgressEventGapError):
            journal.append(pass_events()[1])
        self.assertEqual(journal.get_events(RUN), ())

    def test_illegal_ordering_and_terminal_overwrite_are_rejected(self):
        journal = ProgressJournal()
        with self.assertRaises(ProgressEventOrderError):
            journal.append(event(1, ProgressEventType.TARGET_VERIFIED, {"target_id": "target", "target_kind": "owned-isolated-synthetic-target", "protocol_version": 1, "policy_digest_before": "1" * 64}))
        for item in pass_events():
            journal.append(item)
        with self.assertRaises(ProgressEventOrderError):
            journal.append(event(9, ProgressEventType.ASSESSMENT_PARTIAL, {"failure_code": "contradiction", "last_proven_event": "fix_verified", "cleanup_completed": True}))

    def test_fix_requires_expected_ledger_and_all_prior_evidence(self):
        journal = ProgressJournal()
        for item in pass_events()[:6]:
            journal.append(item)
        journal.append(event(7, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}))
        with self.assertRaises(ProgressEventOrderError):
            journal.append(event(8, ProgressEventType.FIX_VERIFIED, {"baseline_ledger_count": 2, "final_ledger_count": 2}))
        self.assertEqual(journal.get_latest_snapshot(RUN).state, "cleanup_completed")

    def test_get_events_after_returns_exact_suffix(self):
        journal = ProgressJournal()
        for item in pass_events():
            journal.append(item)
        suffix = journal.get_events_after(RUN, 5)
        self.assertEqual([item.sequence for item in suffix], [6, 7, 8])

    def test_replaying_events_reconstructs_identical_snapshot(self):
        source = ProgressJournal()
        for item in pass_events():
            source.append(item)
        replay = ProgressJournal()
        for item in source.get_events(RUN):
            replay.append(item)
        self.assertEqual(source.get_latest_snapshot(RUN).to_dict(), replay.get_latest_snapshot(RUN).to_dict())

    def test_malformed_unknown_and_unsafe_events_cannot_advance(self):
        journal = ProgressJournal()
        with self.assertRaises(Exception):
            journal.append(object())
        with self.assertRaises(Exception):
            journal.append(event(1, "unknown", {}))
        self.assertEqual(journal.get_events(RUN), ())

    def test_stored_events_and_snapshot_use_only_approved_payload(self):
        journal = ProgressJournal()
        for item in pass_events():
            journal.append(item)
        for item in journal.get_events(RUN):
            self.assertNotIn("request", item.payload)
            self.assertNotIn("response", item.payload)
            self.assertNotIn("credential", item.payload)
        self.assertNotIn("request", str(journal.get_latest_snapshot(RUN).to_dict()))

    def test_run_ids_are_isolated(self):
        journal = ProgressJournal()
        other = pass_events("other-run")[:2]
        for item in pass_events()[:2]:
            journal.append(item)
        for item in other:
            journal.append(item)
        self.assertEqual(journal.get_events_after(RUN, 0)[0].run_id, RUN)
        self.assertEqual(journal.get_latest_snapshot("other-run").run_id, "other-run")
        self.assertNotEqual(journal.get_latest_snapshot(RUN).to_dict(), journal.get_latest_snapshot("other-run").to_dict())


    def test_started_cannot_skip_directly_to_fix(self):
        journal = ProgressJournal()
        journal.append(pass_events()[0])
        with self.assertRaises(ProgressEventOrderError):
            journal.append(event(2, ProgressEventType.FIX_VERIFIED, {"baseline_ledger_count": 1, "final_ledger_count": 1}))
        self.assertEqual(journal.get_latest_snapshot(RUN).state, "assessment_started")

    def test_cleanup_only_does_not_unlock_fix(self):
        journal = ProgressJournal()
        journal.append(pass_events()[0])
        journal.append(event(2, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}))
        with self.assertRaises(ProgressEventOrderError):
            journal.append(event(3, ProgressEventType.FIX_VERIFIED, {"baseline_ledger_count": 1, "final_ledger_count": 1}))
        self.assertEqual(journal.get_latest_snapshot(RUN).state, "cleanup_completed")

    def test_partial_and_failed_reject_all_later_progress(self):
        for terminal_type in (ProgressEventType.ASSESSMENT_PARTIAL, ProgressEventType.ASSESSMENT_FAILED):
            journal = ProgressJournal()
            journal.append(pass_events()[0])
            journal.append(event(2, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}))
            terminal = event(3, terminal_type, {"failure_code": "stop", "last_proven_event": "cleanup_completed", "cleanup_completed": True})
            journal.append(terminal)
            with self.assertRaises(ProgressEventOrderError):
                journal.append(event(4, ProgressEventType.TARGET_VERIFIED, {"target_id": "late", "target_kind": "owned-isolated-synthetic-target", "protocol_version": 1, "policy_digest_before": "1" * 64}))
            with self.assertRaises(ProgressEventOrderError):
                journal.append(event(4, ProgressEventType.FIX_VERIFIED, {"baseline_ledger_count": 1, "final_ledger_count": 1}))

    def test_terminal_duplicate_is_idempotent_and_conflict_is_rejected(self):
        journal = ProgressJournal()
        for item in pass_events()[:2]:
            journal.append(item)
        journal.append(event(3, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}))
        terminal = event(4, ProgressEventType.ASSESSMENT_PARTIAL, {"failure_code": "stop", "last_proven_event": "cleanup_completed", "cleanup_completed": True})
        journal.append(terminal)
        before = journal.get_latest_snapshot(RUN).to_dict()
        self.assertEqual(journal.append(terminal).to_dict(), before)
        with self.assertRaises(ProgressEventConflictError):
            journal.append(event(4, ProgressEventType.ASSESSMENT_FAILED, {"failure_code": "different", "last_proven_event": "cleanup_completed", "cleanup_completed": True}))

    def test_event_suffix_boundaries_are_exact(self):
        journal = ProgressJournal()
        for item in pass_events():
            journal.append(item)
        self.assertEqual([item.sequence for item in journal.get_events_after(RUN, 0)], list(range(1, 9)))
        self.assertEqual([item.sequence for item in journal.get_events_after(RUN, 4)], [5, 6, 7, 8])
        self.assertEqual(journal.get_events_after(RUN, 8), ())

    def test_other_run_events_cannot_complete_or_change_current_run(self):
        journal = ProgressJournal()
        journal.append(pass_events()[0])
        for item in pass_events("other-run"):
            journal.append(item)
        current = journal.get_latest_snapshot(RUN)
        self.assertEqual(current.state, "assessment_started")
        self.assertEqual(current.sequence, 1)
        self.assertEqual(journal.get_latest_snapshot("other-run").state, "fix_verified")

    def test_mutating_input_or_read_objects_cannot_mutate_history(self):
        journal = ProgressJournal()
        for item in pass_events()[:4]:
            journal.append(item)
        original_event = pass_events()[3]
        original_event.payload["denied_actions"].append("mutated-after-append")
        stored = journal.get_events(RUN)
        stored[3].payload["denied_actions"].append("mutated-read-copy")
        snapshot = journal.get_latest_snapshot(RUN)
        snapshot.evidence["remediation_verified"]["denied_actions"].append("mutated-snapshot-copy")
        fresh = journal.get_latest_snapshot(RUN)
        self.assertEqual(fresh.evidence["remediation_verified"]["denied_actions"], ["send_email"])

if __name__ == "__main__":
    unittest.main()
