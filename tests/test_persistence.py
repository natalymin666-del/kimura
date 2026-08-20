import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from kimura_assessment import AssessmentResult, AssessmentResultStore, PersistenceError
from kimura_assessment.report import report_json_from_store


class AssessmentPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "results.jsonl"
        self.first = AssessmentResult.completed("asm-b", 1, date(2026, 8, 20), "response one")
        self.second = AssessmentResult.completed("asm-a", 2, date(2026, 8, 21), "response two")

    def tearDown(self):
        self.directory.cleanup()

    def test_jsonl_persistence_round_trip_is_deterministic(self):
        store = AssessmentResultStore(self.path)
        store.append(self.first)
        store.append(self.second)

        self.assertEqual(store.read_all(), [self.first, self.second])
        expected = self.first.to_json() + "\n" + self.second.to_json() + "\n"
        self.assertEqual(self.path.read_text(encoding="utf-8"), expected)

    def test_unsafe_and_raw_fields_are_rejected_or_excluded(self):
        encoded = self.first.to_json()
        for unsafe in ("request_json", "input_text", "response_text", "Authorization", "credential", "secret"):
            self.assertNotIn(unsafe, encoded)

        values = self.first.to_dict()
        values["raw_response"] = "private response"
        with self.assertRaises(ValueError):
            AssessmentResult.from_dict(values)

    def test_malformed_persistence_data_is_rejected_without_partial_results(self):
        self.path.write_text(self.first.to_json() + "\nnot-json\n", encoding="utf-8")
        with self.assertRaises(PersistenceError):
            AssessmentResultStore(self.path).read_all()

    def test_report_is_generated_from_persisted_safe_results(self):
        store = AssessmentResultStore(self.path)
        store.append(self.first)
        store.append(self.second)

        report = json.loads(report_json_from_store(store))
        self.assertEqual(report["result_count"], 2)
        self.assertEqual(report["completed_count"], 2)
        self.assertEqual(report["assessment_ids"], ["asm-a", "asm-b"])
        self.assertEqual(report["total_response_bytes"], len(b"response one") + len(b"response two"))
        self.assertNotIn("response one", report_json_from_store(store))


if __name__ == "__main__":
    unittest.main()
