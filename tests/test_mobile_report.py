import json
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from kimura_assessment.conference_live_server import ProgressHTTPServer
from kimura_assessment.mobile_report import (
    MobileReportError,
    build_mobile_report_url,
    derive_mobile_report,
    render_mobile_report_html,
)
from kimura_assessment.progress_events import ProgressEvent, ProgressEventType
from kimura_assessment.progress_journal import ProgressJournal
from tests.test_progress_journal import pass_events


def terminal_snapshot(run_id="mobile-run", terminal_type=None):
    journal = ProgressJournal()
    events = pass_events(run_id)
    for event in events:
        journal.append(event)
    if terminal_type is None:
        return journal.get_latest_snapshot(run_id).to_dict()
    partial = ProgressJournal()
    partial.append(events[0])
    partial.append(ProgressEvent(run_id, 2, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}))
    partial.append(ProgressEvent(run_id, 3, terminal_type, {"failure_code": "target unavailable <script>", "last_proven_event": "assessment_started", "cleanup_completed": True}))
    return partial.get_latest_snapshot(run_id).to_dict()


class MobileReportTests(unittest.TestCase):
    def test_pass_projection_contains_runtime_evidence(self):
        report = derive_mobile_report(terminal_snapshot())
        self.assertEqual(report.status, "PASS")
        self.assertEqual(report.run_id, "mobile-run")
        self.assertTrue(report.fix_verified)
        self.assertTrue(report.baseline_impact_confirmed)
        self.assertEqual(report.baseline_decision, "allowed")
        self.assertTrue(report.deny_only_verified)
        self.assertTrue(report.replay_identity_verified)
        self.assertFalse(report.replay_synthetic_impact_confirmed)
        self.assertEqual(report.cleanup_status, "COMPLETED")

    def test_partial_and_failed_never_render_pass_or_fix(self):
        for terminal_type, expected in ((ProgressEventType.ASSESSMENT_PARTIAL, "PARTIAL"), (ProgressEventType.ASSESSMENT_FAILED, "FAILED")):
            report = derive_mobile_report(terminal_snapshot("mobile-run", terminal_type))
            html = render_mobile_report_html(report)
            self.assertEqual(report.status, expected)
            self.assertFalse(report.fix_verified)
            self.assertNotIn("FIX VERIFIED", html)
            self.assertNotIn(">PASS<", html)

    def test_identity_binding_and_missing_values_are_truthful(self):
        snapshot = terminal_snapshot()
        with self.assertRaises(MobileReportError):
            derive_mobile_report(snapshot, expected_run_id="different-run")
        report = derive_mobile_report(terminal_snapshot("missing-run", ProgressEventType.ASSESSMENT_FAILED))
        html = render_mobile_report_html(report)
        self.assertIn("UNAVAILABLE", html)
        self.assertIn("target unavailable &lt;script&gt;", html)
        self.assertNotIn("<script>", html)

    def test_pass_invariants_are_required_for_fix_verified(self):
        snapshot = terminal_snapshot()
        snapshot["evidence"]["replay_validated"]["ledger_count"] = 2
        report = derive_mobile_report(snapshot)
        self.assertEqual(report.status, "FAILED")
        self.assertFalse(report.fix_verified)
        self.assertIn("fix_verified invariants not proven", report.failure_reason)

    def test_mobile_url_payload_is_deterministic_and_local(self):
        url = build_mobile_report_url("http://127.0.0.1:8123", "mobile-run")
        self.assertEqual(url, "http://127.0.0.1:8123/report/mobile-run")
        self.assertEqual(build_mobile_report_url("http://127.0.0.1:8123", "mobile-run"), url)
        with self.assertRaises(ValueError):
            build_mobile_report_url("https://example.invalid", "mobile-run")

    def test_mobile_html_is_responsive_and_offline(self):
        html = render_mobile_report_html(derive_mobile_report(terminal_snapshot()))
        self.assertIn('name="viewport"', html)
        self.assertIn("Owned isolated synthetic target", html)
        self.assertIn("no real external action occurred", html)
        self.assertIn("<details>", html)
        self.assertNotIn("<script src=", html)
        self.assertNotIn("<link", html)
        self.assertNotIn("fetch(", html)
        self.assertNotIn("https://", html)

    def test_local_route_is_read_only_same_run_and_unknown_safe(self):
        journal = ProgressJournal()
        for event in pass_events("route-run"):
            journal.append(event)
        server = ProgressHTTPServer(journal)
        server.start()
        try:
            with urlopen(server.base_url + "/report/route-run", timeout=2) as response:
                html = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("route-run", html)
                self.assertIn("FIX VERIFIED", html)
                self.assertIn("text/html", response.headers["Content-Type"])
            with self.assertRaises(HTTPError) as error:
                urlopen(server.base_url + "/report/other-run", timeout=2)
            self.assertEqual(error.exception.code, 404)
            self.assertEqual(json.loads(error.exception.read().decode("utf-8")), {"error": "unknown_run"})
            waiting = ProgressJournal()
            waiting.append(pass_events("waiting-run")[0])
            server.journal = waiting
            with self.assertRaises(HTTPError) as error:
                urlopen(server.base_url + "/report/waiting-run", timeout=2)
            self.assertEqual(error.exception.code, 409)
            self.assertEqual(json.loads(error.exception.read().decode("utf-8")), {"error": "not_terminal"})
            server.journal = journal
            with self.assertRaises(HTTPError) as error:
                urlopen(Request(server.base_url + "/report/route-run", method="POST"), timeout=2)
            self.assertEqual(error.exception.code, 405)
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
