import unittest
from datetime import date

from kimura_assessment.customer_assessment import run_customer_assessment
from kimura_assessment.customer_schema import CustomerAssessmentConfig
from kimura_assessment.html_report import render_customer_report
from tests.test_customer_assessment import FakeProvider
from tests.test_customer_schema import config_values


class CustomerHtmlReportTests(unittest.TestCase):
    def test_report_has_customer_sections_and_explicit_boundaries(self):
        result = run_customer_assessment(CustomerAssessmentConfig.from_dict(config_values()), today=lambda: __import__("datetime").date.today(), provider_factory=lambda _: FakeProvider(), preflight_writer=lambda _: None)
        html = render_customer_report(result.report, result.evidence)
        for section in (
            "Executive Summary", "Scope", "Authorization", "Methodology", "Environment / Model Under Test",
            "Findings Summary", "Detailed Findings", "Evidence Summary", "Remediation", "Retest Results",
            "Residual Risk", "Limitations", "Assessment Integrity / Safety Controls",
        ):
            self.assertIn(f">{section}<", html)
        self.assertIn("model proposal", html.lower())
        self.assertIn("local simulated tool execution", html.lower())
        self.assertIn("universal model vulnerability", html.lower())


    def test_report_presents_statuses_metadata_and_safe_evidence(self):
        result = run_customer_assessment(CustomerAssessmentConfig.from_dict(config_values()), today=lambda: __import__("datetime").date.today(), provider_factory=lambda _: FakeProvider(), preflight_writer=lambda _: None)
        html = render_customer_report(result.report, result.evidence)
        for text in ("Baseline risk", "HIGH", "Remediation", "APPLIED", "Retest", "PASSED", "Assessment at a Glance", "asm-customer-001", "Example BV", "llama3.2:3b", "Authorized contract validated", "Impact confirmed from the local audit record", "Impact observed in all baseline trials", "Baseline trial", "Retest trial"):
            self.assertIn(text, html)
        self.assertNotIn("stable-vulnerable", html)
        self.assertNotIn("tool-policy-deny-untrusted-external-actions", html)

    def test_report_escapes_customer_text_and_has_no_external_dependencies(self):
        values = config_values()
        values["assessment"]["client_name"] = "Example <BV> & partners"
        result = run_customer_assessment(CustomerAssessmentConfig.from_dict(values), today=lambda: __import__("datetime").date.today(), provider_factory=lambda _: FakeProvider(), preflight_writer=lambda _: None)
        html = render_customer_report(result.report, result.evidence)
        self.assertIn("Example &lt;BV&gt; &amp; partners", html)
        self.assertNotIn("<script", html.lower())
        self.assertNotIn("<link", html.lower())
        self.assertNotIn("<img", html.lower())
        self.assertNotIn("http://", html.lower())
        self.assertNotIn("https://", html.lower())
        for forbidden in ("Order note:", "UNTRUSTED INSTRUCTION", "raw_response", "customer-assessment-v1-local-transport-only"):
            self.assertNotIn(forbidden, html)


if __name__ == "__main__":
    unittest.main()
