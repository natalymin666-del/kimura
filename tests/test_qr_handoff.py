import base64
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import unittest

from kimura_assessment.conference_live import render_live_page_html
from kimura_assessment.conference_live_server import ProgressHTTPServer
from kimura_assessment.mobile_report import build_mobile_report_url, build_qr_data_uri
from kimura_assessment.progress_events import ProgressEvent, ProgressEventType
from kimura_assessment.progress_journal import ProgressJournal
from tests.test_progress_journal import pass_events


class QRHandoffTests(unittest.TestCase):
    def test_localhost_default_and_explicit_lan_binding_metadata(self):
        journal = ProgressJournal()
        server = ProgressHTTPServer(journal)
        self.assertEqual(server.bind_host, "127.0.0.1")
        self.assertEqual(server.base_url.split("://", 1)[1].split(":", 1)[0], "127.0.0.1")
        server.server_close()
        lan = ProgressHTTPServer(journal, host="127.0.0.1", public_host="192.168.50.10")
        self.assertEqual(lan.public_host, "192.168.50.10")
        self.assertIn("192.168.50.10", lan.base_url)
        lan.server_close()
        for host in ("0.0.0.0", "::"):
            with self.assertRaises(ValueError):
                ProgressHTTPServer(journal, host=host)

    def test_exact_lan_payload_and_loopback_rejection(self):
        url = build_mobile_report_url("http://192.168.50.10:8123", "fresh.run", allow_loopback=False)
        self.assertEqual(url, "http://192.168.50.10:8123/report/fresh.run")
        self.assertNotIn("127.0.0.1", url)
        with self.assertRaises(ValueError):
            build_mobile_report_url("http://127.0.0.1:8123", "fresh.run", allow_loopback=False)
        with self.assertRaises(ValueError):
            build_mobile_report_url("http://0.0.0.0:8123", "fresh.run", allow_loopback=False)

    def test_qr_is_offline_exact_and_not_a_mutation_endpoint(self):
        url = "http://192.168.50.10:8123/report/fresh.run"
        first = build_qr_data_uri(url)
        second = build_qr_data_uri(url)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("data:image/svg+xml;base64,"))
        svg = base64.b64decode(first.split(",", 1)[1]).decode("utf-8")
        self.assertIn("<svg", svg)
        self.assertNotIn("127.0.0.1", svg)
        with self.assertRaises(ValueError):
            build_qr_data_uri("http://127.0.0.1:8123/report/fresh.run")
        with self.assertRaises(ValueError):
            build_qr_data_uri("http://192.168.50.10:8123/api/assessments/fresh.run/snapshot")

    def test_handoff_is_terminal_only_and_exact_run_bound(self):
        url = "http://192.168.50.10:8123/report/journal-run"
        qr = build_qr_data_uri(url)
        started = render_live_page_html("journal-run", mobile_report_url=url, qr_data_uri=qr)
        self.assertIn("MOBILE_REPORT_URL", started)
        self.assertIn("MOBILE_REPORT_QR", started)
        self.assertIn("http://192.168.50.10:8123/report/journal-run", started)
        self.assertNotIn("127.0.0.1", started)
        self.assertIn("isPass || isPartial || isFailed", started)
        self.assertNotIn("report/other-run", started)

    def test_server_unknown_nonterminal_and_write_routes_fail_closed(self):
        journal = ProgressJournal()
        for event in pass_events("qr-run"):
            journal.append(event)
        server = ProgressHTTPServer(journal)
        server.start()
        try:
            with urlopen(server.base_url + "/report/qr-run", timeout=2) as response:
                self.assertEqual(response.status, 200)
            with self.assertRaises(HTTPError) as error:
                urlopen(server.base_url + "/report/stale-run", timeout=2)
            self.assertEqual(error.exception.code, 404)
            waiting = ProgressJournal()
            waiting.append(pass_events("waiting-run")[0])
            server.journal = waiting
            with self.assertRaises(HTTPError) as error:
                urlopen(server.base_url + "/report/waiting-run", timeout=2)
            self.assertEqual(error.exception.code, 409)
            server.journal = journal
            with self.assertRaises(HTTPError) as error:
                urlopen(Request(server.base_url + "/report/qr-run", method="POST"), timeout=2)
            self.assertEqual(error.exception.code, 405)
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
