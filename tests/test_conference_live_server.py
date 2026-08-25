import json
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import unittest

from kimura_assessment.conference_live_server import ProgressHTTPServer
from kimura_assessment.progress_events import ProgressEvent, ProgressEventType
from kimura_assessment.progress_journal import ProgressJournal
from tests.test_progress_journal import pass_events


def read_json(url, method="GET"):
    request = Request(url, method=method)
    try:
        with urlopen(request, timeout=2) as response:
            return response.status, dict(response.headers), json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        return error.code, dict(error.headers), json.loads(error.read().decode("utf-8"))


class ConferenceLiveServerTests(unittest.TestCase):
    def setUp(self):
        self.journal = ProgressJournal()
        for item in pass_events():
            self.journal.append(item)
        self.server = ProgressHTTPServer(self.journal)
        self.server.start()

    def tearDown(self):
        if self.server is not None:
            self.server.stop()

    def url(self, path):
        return self.server.base_url + path

    def test_snapshot_returns_reconstructed_pass(self):
        status, headers, body = read_json(self.url("/api/assessments/journal-run/snapshot"))
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "fix_verified")
        self.assertEqual(body["sequence"], 8)
        self.assertTrue(body["terminal"])
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_partial_and_failed_snapshots_remain_truthful(self):
        for run_id, terminal_type in (("partial-run", ProgressEventType.ASSESSMENT_PARTIAL), ("failed-run", ProgressEventType.ASSESSMENT_FAILED)):
            for item in pass_events(run_id)[:1]:
                self.journal.append(item)
            self.journal.append(ProgressEvent(run_id, 2, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}))
            self.journal.append(ProgressEvent(run_id, 3, terminal_type, {"failure_code": "stopped", "last_proven_event": "cleanup_completed", "cleanup_completed": True}))
            status, _headers, body = read_json(self.url(f"/api/assessments/{run_id}/snapshot"))
            self.assertEqual(status, 200)
            self.assertEqual(body["state"], terminal_type.value)
            self.assertNotIn("fix_verified", body["evidence"])

    def test_events_returns_suffix_and_empty_suffix(self):
        status, _headers, body = read_json(self.url("/api/assessments/journal-run/events?after_seq=4"))
        self.assertEqual(status, 200)
        self.assertEqual([item["sequence"] for item in body["events"]], [5, 6, 7, 8])
        status, _headers, body = read_json(self.url("/api/assessments/journal-run/events?after_seq=8"))
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        self.assertEqual(body["latest_sequence"], 8)

    def test_unknown_run_does_not_leak_another_run(self):
        status, _headers, body = read_json(self.url("/api/assessments/unknown-run/snapshot"))
        self.assertEqual((status, body), (404, {"error": "unknown_run"}))
        status, _headers, body = read_json(self.url("/api/assessments/unknown-run/events?after_seq=0"))
        self.assertEqual((status, body), (404, {"error": "unknown_run"}))

    def test_invalid_paths_and_sequences_fail_closed(self):
        cases = [
            ("/api/assessments/../snapshot", "invalid_run_id"),
            ("/api/assessments/bad%2Frun/snapshot", "invalid_run_id"),
            ("/api/assessments/journal-run/events", "missing_after_seq"),
            ("/api/assessments/journal-run/events?after_seq=abc", "invalid_after_seq"),
            ("/api/assessments/journal-run/events?after_seq=-1", "negative_after_seq"),
            ("/api/assessments/journal-run/events?after_seq=1&after_seq=2", "invalid_after_seq"),
        ]
        for path, error in cases:
            status, headers, body = read_json(self.url(path))
            self.assertEqual(status, 400 if error != "not_found" else 404)
            self.assertEqual(body, {"error": error})
            self.assertEqual(headers["Cache-Control"], "no-store")

    def test_equal_and_greater_sequences_are_empty(self):
        for value in ("8", "100"):
            status, _headers, body = read_json(self.url(f"/api/assessments/journal-run/events?after_seq={value}"))
            self.assertEqual(status, 200)
            self.assertEqual(body["events"], [])

    def test_reads_do_not_mutate_journal_and_are_deterministic(self):
        before = self.journal.get_latest_snapshot("journal-run").to_dict()
        first = read_json(self.url("/api/assessments/journal-run/snapshot"))[2]
        second = read_json(self.url("/api/assessments/journal-run/snapshot"))[2]
        self.assertEqual(first, second)
        self.assertEqual(self.journal.get_latest_snapshot("journal-run").to_dict(), before)

    def test_separate_runs_remain_isolated_and_reads_are_concurrent(self):
        other = ProgressJournal()
        for item in pass_events("other-run"):
            other.append(item)
        for item in other.get_events("other-run"):
            self.journal.append(item)
        def fetch():
            return read_json(self.url("/api/assessments/journal-run/events?after_seq=7"))[2]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _item: fetch(), range(8)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual([item["run_id"] for item in results[0]["events"]], ["journal-run"])
        self.assertEqual(self.journal.get_latest_snapshot("journal-run").state, "fix_verified")

    def test_write_methods_are_rejected_without_mutation(self):
        before = self.journal.get_events("journal-run")
        status, _headers, body = read_json(self.url("/api/assessments/journal-run/snapshot"), method="POST")
        self.assertEqual((status, body), (405, {"error": "read_only"}))
        self.assertEqual(self.journal.get_events("journal-run"), before)

    def test_clean_shutdown(self):
        self.server.stop()
        self.server = None


if __name__ == "__main__":
    unittest.main()
