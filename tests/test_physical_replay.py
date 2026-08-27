import json
import unittest
from datetime import datetime, timezone

from kimura_assessment.conference_renderer import render_conference_html
from kimura_assessment.physical_replay import (
    ACTION,
    POLICY,
    ReplayError,
    action_fingerprint,
    parse_remediation_evidence,
    serialize_remediation_evidence,
    canonical_action_payload,
    run_remediation_and_replay,
)
from kimura_assessment.physical_target_discovery import PhysicalIdentityEvidence


IDENTITY = PhysicalIdentityEvidence("192.168.2.17", "kimura", "kimura", "aarch64", "Raspberry Pi 5 Model B Rev 1.1", True, True, "IDENTITY VERIFIED", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", "REACHABLE")


def baseline_event():
    return {"event_id": "baseline-run-abc1234", "run_id": "run-abc1234", "action": ACTION, "executed": True, "synthetic_local_only": True, "external_destination": None, "external_network_action": False, "execution_timestamp": "2026-01-01T00:00:02Z"}


class ReplayAdapter:
    def __init__(self, *, ledger=None, policy=None, write_error=None, replay_error=None, replay_update=None, deny_write=True):
        self.ledger = "".join(json.dumps(item) + "\n" for item in (ledger if ledger is not None else [baseline_event()]))
        self.policy = policy if policy is not None else json.dumps({"fixture": POLICY["fixture"], "rules": {ACTION: "permit"}}, sort_keys=True, separators=(",", ":"))
        self.write_error, self.replay_error, self.replay_update, self.deny_write = write_error, replay_error, replay_update, deny_write

    def read_ledger(self, *_): return self.ledger
    def read_policy(self, *_): return self.policy
    def write_policy(self, *_):
        if self.write_error: raise ReplayError(self.write_error)
        self.policy = json.dumps(POLICY if self.deny_write else {"fixture": POLICY["fixture"], "rules": {ACTION: "permit"}}, sort_keys=True, separators=(",", ":"))
    def replay(self, _ip, _user, fixture, payload, fingerprint):
        if self.replay_error: raise ReplayError(self.replay_error)
        result = {"result": "BLOCKED", "action": ACTION, "fingerprint": fingerprint, "fixture_path": "~/" + fixture, "synthetic_impact": False, "external_network_action": False}
        if self.replay_update: self.ledger += json.dumps(self.replay_update) + "\n"
        result.update(self.replay_update or {})
        return result


def run(adapter, **kwargs):
    return run_remediation_and_replay("192.168.2.17", "kimura", adapter=adapter, identity=IDENTITY, expected_baseline_run_id="run-abc1234", clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc), **kwargs)


class PhysicalReplayTests(unittest.TestCase):
    def test_successful_exact_replay_block(self):
        result = run(ReplayAdapter())
        self.assertTrue(result.fix_verified)
        self.assertEqual(result.replay_result, "BLOCKED")
        self.assertEqual((result.pre_replay_event_count, result.post_replay_event_count), (1, 1))
        self.assertEqual(result.baseline_sha256, result.replay_sha256)

    def test_remediation_write_failure(self):
        self.assertFalse(run(ReplayAdapter(write_error="remediation write failure")).fix_verified)

    def test_policy_malformed_or_does_not_deny(self):
        self.assertFalse(run(ReplayAdapter(policy="not-json")).fix_verified)
        self.assertFalse(run(ReplayAdapter(deny_write=False)).fix_verified)

    def test_wrong_fixture_or_missing_baseline(self):
        self.assertFalse(run(ReplayAdapter(replay_update={"fixture_path": "~/wrong-fixture"})).fix_verified)
        self.assertFalse(run(ReplayAdapter(ledger=[])).fix_verified)
        self.assertFalse(run(ReplayAdapter(), fixture_path="../wrong").fix_verified)

    def test_invalid_baseline_event_and_count(self):
        for ledger in ([baseline_event(), baseline_event()], [{**baseline_event(), "action": "other"}], [{**baseline_event(), "executed": False}]):
            self.assertFalse(run(ReplayAdapter(ledger=ledger)).fix_verified)

    def test_replay_action_or_fingerprint_differs(self):
        for update in ({"action": "other"}, {"fingerprint": "0" * 64}):
            self.assertFalse(run(ReplayAdapter(replay_update=update)).fix_verified)

    def test_replay_creates_event_or_count_increases(self):
        event = {"event_id": "replay-1", "run_id": "run-abc1234", "action": ACTION}
        self.assertFalse(run(ReplayAdapter(replay_update=event)).fix_verified)

    def test_stale_baseline_and_wrong_run_identity(self):
        stale = {**baseline_event(), "event_id": "baseline-old", "run_id": "old"}
        self.assertFalse(run(ReplayAdapter(ledger=[stale])).fix_verified)

    def test_target_identity_mismatch_and_replay_execution_failure(self):
        mismatch = PhysicalIdentityEvidence("192.168.2.18", "kimura", "kimura", "aarch64", "Raspberry Pi 5 Model B Rev 1.1", True, True, "IDENTITY VERIFIED", "x", "y", "REACHABLE")
        result = run_remediation_and_replay("192.168.2.17", "kimura", adapter=ReplayAdapter(), identity=mismatch, expected_baseline_run_id="run-abc1234")
        self.assertFalse(result.fix_verified)
        self.assertFalse(run(ReplayAdapter(replay_error="replay execution failure")).fix_verified)

    def test_conference_success_contains_final_states_only_when_proven(self):
        html = render_conference_html(run(ReplayAdapter()).to_conference_result())
        self.assertIn("DENY-ONLY VERIFIED", html)
        self.assertIn("BLOCKED", html)
        self.assertIn("SAME FIXTURE · SHA-256 MATCHED", html)
        self.assertIn("FIX VERIFIED", html)
        failed = render_conference_html(run(ReplayAdapter(write_error="failed")).to_conference_result())
        self.assertNotIn("FIX VERIFIED", failed)



class RemediationEvidenceSerializationTests(unittest.TestCase):
    def setUp(self):
        self.evidence = {"run_id": "phase45i-run-12345678", "remediation": "DENY-ONLY VERIFIED", "policy_before": {"send_email": "permit"}, "policy_after": {"send_email": "deny"}}

    def test_canonical_evidence_round_trip(self):
        raw = serialize_remediation_evidence(self.evidence)
        self.assertTrue(raw.endswith("\n"))
        self.assertEqual(parse_remediation_evidence(raw, self.evidence["run_id"]), self.evidence)

    def test_exact_trailing_n_and_other_malformed_forms_rejected(self):
        valid = serialize_remediation_evidence(self.evidence)
        for raw in (valid[:-1] + "n", valid[:-1] + "\\n", valid[:-2] + "\n", valid + "{}\n"):
            with self.assertRaises(ReplayError):
                parse_remediation_evidence(raw, self.evidence["run_id"])

    def test_cross_run_evidence_rejected(self):
        with self.assertRaises(ReplayError):
            parse_remediation_evidence(serialize_remediation_evidence(self.evidence), "phase45i-other-12345678")

if __name__ == "__main__": unittest.main()
