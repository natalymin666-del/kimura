import json
import tempfile
import unittest
from pathlib import Path

from kimura_assessment.evidence import EvidenceRecord, EvidenceStore, EvidenceValidationError, digest_text


class EvidenceTests(unittest.TestCase):
    def record(self):
        return EvidenceRecord(
            schema_version=1,
            evidence_id="evidence-01",
            assessment_id="asm-local",
            finding_id="finding-001",
            phase="attack",
            step=1,
            observation="bounded-demo-observation",
            request_sha256=digest_text("request"),
            response_sha256=digest_text("response"),
            action="send_email",
            outcome="executed",
            control="none",
        )

    def test_evidence_round_trip_contains_hashes_only(self):
        record = self.record()
        self.assertEqual(EvidenceRecord.from_dict(json.loads(record.to_json())), record)
        self.assertNotIn('"raw_request"', record.to_json())
        self.assertNotIn('"raw_response"', record.to_json())
        self.assertNotIn("private body", record.to_json())

    def test_unexpected_raw_field_is_rejected(self):
        values = self.record().to_dict()
        values["raw_response"] = "private body"
        with self.assertRaises(EvidenceValidationError):
            EvidenceRecord.from_dict(values)

    def test_store_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            store = EvidenceStore(path)
            store.append(self.record())
            self.assertEqual(store.read_all(), [self.record()])
            self.assertEqual(path.read_text(encoding="utf-8"), self.record().to_json() + "\n")


if __name__ == "__main__":
    unittest.main()
