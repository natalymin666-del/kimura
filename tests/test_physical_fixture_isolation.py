import unittest
import subprocess

from kimura_assessment.physical_baseline import SshBaselineAdapter
from kimura_assessment.physical_fixture_isolation import (
    FixtureIsolationError,
    LocalFixtureStore,
    run_fixture_path,
    validate_run_fixture_path,
)


class PhysicalFixtureIsolationTests(unittest.TestCase):
    def test_fresh_unique_run_has_empty_permit_state(self):
        store = LocalFixtureStore()
        first = store.create_run("run-20260826-01")
        second = store.create_run("run-20260826-02")
        self.assertEqual(first.ledger, [])
        self.assertEqual(first.policy["rules"]["send_email"], "permit")
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertEqual(run_fixture_path(first.run_id), "kimura-physical-fixture/runs/run-20260826-01")

    def test_baseline_remediation_and_replay_are_same_run_scoped(self):
        store = LocalFixtureStore()
        store.create_run("run-20260826-01")
        store.create_run("run-20260826-02")
        event = {"event_id": "baseline-run-20260826-01", "run_id": "run-20260826-01", "action": "send_email"}
        store.append_baseline("run-20260826-01", event)
        store.deny("run-20260826-01")
        replay = store.replay("run-20260826-01", "send_email")
        self.assertEqual(replay["result"], "BLOCKED")
        self.assertEqual(store.read("run-20260826-01").ledger, [event])
        self.assertEqual(store.read("run-20260826-02").ledger, [])
        self.assertEqual(store.read("run-20260826-02").policy["rules"]["send_email"], "permit")
        self.assertEqual(store.historical_ledger, [{"event_id": "historical-baseline", "run_id": "legacy"}])

    def test_cross_run_stale_unknown_and_traversal_access_rejected(self):
        store = LocalFixtureStore()
        store.create_run("run-20260826-01")
        with self.assertRaises(FixtureIsolationError):
            store.append_baseline("run-20260826-01", {"run_id": "run-20260826-02", "action": "send_email"})
        with self.assertRaises(FixtureIsolationError):
            store.read("run-20260826-02")
        with self.assertRaises(FixtureIsolationError):
            store.read("../run-20260826-01")
        with self.assertRaises(FixtureIsolationError):
            validate_run_fixture_path("kimura-physical-fixture/runs/other/../run-20260826-01")

    def test_same_run_verification_requires_baseline_then_deny_then_replay(self):
        store = LocalFixtureStore()
        store.create_run("run-20260826-01")
        with self.assertRaises(FixtureIsolationError):
            store.replay("run-20260826-01", "send_email")
        event = {"event_id": "baseline-run-20260826-01", "run_id": "run-20260826-01", "action": "send_email"}
        store.append_baseline("run-20260826-01", event)
        with self.assertRaises(FixtureIsolationError):
            store.append_baseline("run-20260826-01", event)
        with self.assertRaises(FixtureIsolationError):
            store.deny("run-20260826-99")


    def test_remote_setup_executes_run_scoped_command(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        run_id = "phase45e-setup-12345678"
        SshBaselineAdapter(runner=runner).setup_fixture("192.168.2.17", "kimura", run_fixture_path(run_id))
        self.assertEqual(len(calls), 1)
        self.assertIn("kimura-physical-fixture/runs/" + run_id, calls[0][-1])
        self.assertEqual(subprocess.run(["bash", "-n", "-c", calls[0][-1]]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
