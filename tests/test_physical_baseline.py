import json
import unittest
from datetime import datetime, timezone

from kimura_assessment.conference_renderer import render_conference_html
from kimura_assessment.physical_baseline import (
    ACTION,
    BaselineError,
    FIXTURE_RELATIVE_PATH,
    run_baseline,
)


class FixtureAdapter:
    def __init__(self, ledger="", *, setup_error=None, append_error=None, after=None):
        self.ledger = ledger
        self.setup_error = setup_error
        self.append_error = append_error
        self.after = after
        self.calls = []

    def setup_fixture(self, target_ip, ssh_user, fixture_path):
        self.calls.append(("setup", target_ip, ssh_user, fixture_path))
        if self.setup_error:
            raise BaselineError(self.setup_error)

    def read_ledger(self, target_ip, ssh_user, fixture_path):
        self.calls.append(("read", target_ip, ssh_user, fixture_path))
        return self.ledger

    def append_event(self, target_ip, ssh_user, fixture_path, event_json):
        self.calls.append(("append", target_ip, ssh_user, fixture_path))
        if self.append_error:
            raise BaselineError(self.append_error)
        event = json.loads(event_json)
        self.ledger = self.after if self.after is not None else self.ledger + json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"


def run(adapter, **kwargs):
    return run_baseline("192.168.2.17", "kimura", adapter=adapter, identity_verified=kwargs.pop("identity_verified", True), run_id="run-20260826-01", clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc), **kwargs)


class PhysicalBaselineTests(unittest.TestCase):
    def test_successful_exact_one_event_baseline(self):
        result = run(FixtureAdapter())
        self.assertEqual(result.baseline_result, "ALLOWED")
        self.assertEqual((result.pre_event_count, result.post_event_count), (0, 1))
        self.assertTrue(result.event_id)

    def test_fixture_path_rejected(self):
        with self.assertRaises(ValueError):
            run(FixtureAdapter(), fixture_path="../unrelated")

    def test_setup_and_action_failures_never_allow(self):
        for adapter in (FixtureAdapter(setup_error="fixture setup failure"), FixtureAdapter(append_error="action execution failure")):
            result = run(adapter)
            self.assertNotEqual(result.baseline_result, "ALLOWED")
            self.assertFalse(result.allowed)

    def test_no_increase_and_more_than_one_increase_fail(self):
        for after in ("", "{}\n{}\n"):
            result = run(FixtureAdapter(after=after))
            self.assertNotEqual(result.baseline_result, "ALLOWED")

    def test_malformed_event_and_wrong_action_fail(self):
        malformed = run(FixtureAdapter(after="not-json\n"))
        self.assertFalse(malformed.allowed)
        wrong = run(FixtureAdapter(after=json.dumps({"event_id": "baseline-run-20260826-01", "run_id": "run-20260826-01", "action": "other"}) + "\n"))
        self.assertFalse(wrong.allowed)

    def test_wrong_run_identity_and_stale_event_fail(self):
        stale = {"event_id": "baseline-run-old-01", "run_id": "old", "action": ACTION, "executed": True, "synthetic_local_only": True, "external_destination": None, "external_network_action": False, "execution_timestamp": "2026-01-01T00:00:00Z"}
        result = run(FixtureAdapter(after=json.dumps(stale) + "\n"))
        self.assertFalse(result.allowed)

    def test_target_unavailable_or_identity_mismatch_never_allow(self):
        result = run(FixtureAdapter(), identity_verified=False)
        self.assertEqual(result.baseline_result, "UNAVAILABLE")
        self.assertFalse(result.allowed)

    def test_conference_only_shows_allowed_when_proven_and_never_fix_verified(self):
        result = run(FixtureAdapter()).to_conference_result()
        html = render_conference_html(result)
        self.assertIn("ALLOWED", html)
        self.assertIn("SYNTHETIC IMPACT CONFIRMED", html)
        self.assertNotIn("FIX VERIFIED", html)


if __name__ == "__main__":
    unittest.main()
