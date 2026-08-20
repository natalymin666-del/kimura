import json
from datetime import date
import hashlib
from unittest import TestCase

from kimura_assessment import AssessmentResult


class AssessmentResultTests(TestCase):
    def test_completed_result_is_json_safe_and_deterministic(self):
        result = AssessmentResult.completed(
            "asm-result",
            2,
            date(2026, 8, 21),
            "héllo response",
        )

        expected = {
            "schema_version": 1,
            "assessment_id": "asm-result",
            "execution_number": 2,
            "authorization_date": "2026-08-21",
            "status": "completed",
            "response_length": len("héllo response".encode("utf-8")),
            "response_sha256": hashlib.sha256("héllo response".encode("utf-8")).hexdigest(),
        }
        self.assertEqual(result.to_dict(), expected)
        self.assertEqual(json.loads(result.to_json()), expected)
        self.assertEqual(result.to_json(), result.to_json())

    def test_result_does_not_retain_or_serialize_raw_response(self):
        response = "private response text"
        result = AssessmentResult.completed("asm-result", 1, date(2026, 8, 20), response)

        self.assertNotIn(response, result.to_json())
        self.assertEqual(set(result.to_dict()), {
            "schema_version",
            "assessment_id",
            "execution_number",
            "authorization_date",
            "status",
            "response_length",
            "response_sha256",
        })

    def test_invalid_result_metadata_is_rejected(self):
        common = {
            "schema_version": 1,
            "assessment_id": "asm-result",
            "execution_number": 1,
            "authorization_date": date(2026, 8, 20),
            "status": "completed",
            "response_length": 1,
            "response_sha256": "0" * 64,
        }
        for field, value in (
            ("schema_version", 2),
            ("execution_number", 0),
            ("response_length", -1),
            ("response_sha256", "not-a-digest"),
        ):
            with self.subTest(field=field):
                invalid = dict(common)
                invalid[field] = value
                with self.assertRaises(ValueError):
                    AssessmentResult(**invalid)
