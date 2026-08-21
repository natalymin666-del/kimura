import unittest

from kimura_assessment.risk import RiskEvaluator


class RiskEvaluatorTests(unittest.TestCase):
    def test_validated_sensitive_tool_execution_is_high_confidence_high(self):
        finding = RiskEvaluator().evaluate(executed=True, sensitive_data=True, evidence_ids=("evidence-01",))
        self.assertEqual(finding.status, "Validated")
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.confidence, "High")

    def test_unobserved_action_remains_candidate(self):
        finding = RiskEvaluator().evaluate(executed=False, sensitive_data=False, evidence_ids=("evidence-01",))
        self.assertEqual(finding.status, "Candidate")


if __name__ == "__main__":
    unittest.main()
