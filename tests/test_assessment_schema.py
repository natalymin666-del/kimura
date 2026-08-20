import json
from datetime import date
import unittest

from kimura_assessment.schema import AssessmentContract, ContractValidationError


def valid_contract() -> AssessmentContract:
    return AssessmentContract(
        assessment_id="asm-001",
        client_name="Example BV",
        assessor_name="Kimura Security",
        authorized_by="client-approval-42",
        objectives=("Evaluate prompt-injection resistance",),
        scope=("https://example.test", "model:production"),
        start_date=date(2026, 8, 20),
        end_date=date(2026, 8, 22),
        exclusions=("production data export",),
        credential_references=("vault://assessment/asm-001/browser",),
    )


class AssessmentContractTests(unittest.TestCase):
    def test_contract_is_json_safe_and_round_trips(self):
        contract = valid_contract()

        encoded = contract.to_json()
        restored = AssessmentContract.from_dict(json.loads(encoded))

        self.assertEqual(restored, contract)
        self.assertEqual(json.loads(encoded)["start_date"], "2026-08-20")

    def test_contract_has_only_opaque_credential_references(self):
        contract = valid_contract()

        self.assertIn("credential_references", contract.to_dict())
        self.assertNotIn("password", contract.to_json().lower())
        self.assertNotIn("token", contract.to_json().lower())
        self.assertNotIn("secret", contract.to_json().lower())

    def test_required_scope_and_objectives_are_enforced(self):
        for field_name in ("scope", "objectives"):
            kwargs = {
                "assessment_id": "asm-001",
                "client_name": "Example BV",
                "assessor_name": "Kimura Security",
                "authorized_by": "approval-42",
                "objectives": () if field_name == "objectives" else ("objective",),
                "scope": () if field_name == "scope" else ("target",),
                "start_date": date(2026, 8, 20),
                "end_date": date(2026, 8, 20),
            }
            with self.assertRaises(ContractValidationError):
                AssessmentContract(**kwargs)

    def test_end_date_cannot_precede_start_date(self):
        with self.assertRaises(ContractValidationError):
            AssessmentContract(
                assessment_id="asm-001",
                client_name="Example BV",
                assessor_name="Kimura Security",
                authorized_by="approval-42",
                objectives=("objective",),
                scope=("target",),
                start_date=date(2026, 8, 22),
                end_date=date(2026, 8, 20),
            )

    def test_max_requests_is_json_safe_and_must_be_positive(self):
        contract = AssessmentContract(
            assessment_id="asm-001",
            client_name="Example BV",
            assessor_name="Kimura Security",
            authorized_by="approval-42",
            objectives=("objective",),
            scope=("target",),
            start_date=date(2026, 8, 20),
            end_date=date(2026, 8, 20),
            max_requests=3,
        )

        self.assertEqual(AssessmentContract.from_dict(json.loads(contract.to_json())), contract)
        for invalid in (0, -1, True, "3"):
            with self.subTest(invalid=invalid), self.assertRaises(ContractValidationError):
                AssessmentContract(
                    assessment_id="asm-001",
                    client_name="Example BV",
                    assessor_name="Kimura Security",
                    authorized_by="approval-42",
                    objectives=("objective",),
                    scope=("target",),
                    start_date=date(2026, 8, 20),
                    end_date=date(2026, 8, 20),
                    max_requests=invalid,
                )


if __name__ == "__main__":
    unittest.main()
