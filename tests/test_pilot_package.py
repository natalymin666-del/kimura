import unittest
from pathlib import Path
from dataclasses import replace

from kimura_assessment.pilot_package import (
    CustomerFinding, PilotIntakeManifest, PilotReadinessResult, RulesOfEngagement,
    build_customer_report, demo_pilot_package, validate_pilot_readiness,
)
from kimura_assessment.pilot_readiness import ContainmentLevel


class PilotPackageTests(unittest.TestCase):
    def setUp(self):
        self.manifest = PilotIntakeManifest(
            "customer-demo", "agent-x", "v1", "sandbox-1",
            ContainmentLevel.CUSTOMER_SANDBOX,
            ({"capability": "change_plan"},), ({"name": "change_plan"},),
            ({"role": "operator"},), ({"owner": "self"},),
            ({"id": "test-user"},), ({"subscription": "sub-1"},),
            ({"production": True},), "read-only state API", "reset fixture",
            "auth-ref-1", "security-contact", ("synthetic only",))
        self.rules = RulesOfEngagement(
            "sandbox-1", ("change_plan",), ({"role": "operator"},),
            ({"subscription": "sub-1"},), ("production mutation",), 1,
            {"max_calls": 2}, {"start": "local", "end": "local"},
            ("stop on unexpected effect",), ("retain structural evidence",),
            ("redact customer content",), "security@example.invalid")

    def test_valid_intake_and_failure_reasons(self):
        result = validate_pilot_readiness(self.manifest, self.rules)
        self.assertEqual(result.status, "PILOT_READY")
        bad = replace(self.manifest, manifest_sha256=None, environment="production")
        with self.assertRaises(ValueError):
            RulesOfEngagement("production", ("x",), (), (), (), 1, {}, {}, ("stop",), ("retain",), ("redact",), "contact")
        self.assertEqual(validate_pilot_readiness(None, None).status, "PRECONDITION_FAILED")
        self.assertIn("INTAKE_MISSING", validate_pilot_readiness(None, self.rules).reasons)
        template = __import__("json").loads(Path("pilot/intake-template.json").read_text())
        self.assertIn("REQUIRED_BEFORE_PILOT", template)
        self.assertIn("OPTIONAL", template)
        self.assertIn("DISCOVERABLE_DURING_ONBOARDING", template)
        self.assertNotIn("credentials", str(template["REQUIRED_BEFORE_PILOT"]).lower())
        mismatched = replace(self.manifest, environment="other-sandbox")
        self.assertIn("ENVIRONMENT_MISMATCH", validate_pilot_readiness(mismatched, self.rules).reasons)

    def test_finding_requires_observable_evidence_and_not_prose(self):
        kwargs = dict(finding_id="f-1", boundary="b", expected_policy="deny",
                      allowed_twin={}, forbidden_twin={}, observed_behavior={},
                      confirmed_state_effect={"observable": True}, impact="contained",
                      evidence_confidence="high", proof_capsule_id="cap-1",
                      severity_rationale="bounded impact", remediation_recommendation="fix",
                      retest_status="pending", allowed_function_preservation="unknown",
                      limitations=("sandbox only",))
        CustomerFinding(**kwargs)
        with self.assertRaises(ValueError):
            CustomerFinding(**{**kwargs, "confirmed_state_effect": {"observable": False}})
        with self.assertRaises(ValueError):
            CustomerFinding(**{**kwargs, "observed_behavior": {"model_prose": "safe"}})

    def test_report_demo_claims_and_required_sections(self):
        demo = demo_pilot_package()
        self.assertIn("SYNTHETIC DEMONSTRATION", demo["label"])
        self.assertEqual(demo["final_verdict"], "CONTROL_FIX_VERIFIED")
        self.assertTrue(demo["proof_capsule"]["verified"])
        offer = Path("pilot/design-partner-offer.md").read_text()
        self.assertIn("Why this is different", offer)
        self.assertIn("What Kimura will not do", offer)
        self.assertIn("## Next step", offer)
        html = Path("pilot/demo-pilot-report.html").read_text()
        for heading in ("ALLOWED TWIN", "FORBIDDEN TWIN", "INDEPENDENT KIMURA VERDICT", "OBSERVABLE IMPACT", "PROOF CAPSULE", "EXACT RETEST", "ALLOWED FUNCTION PRESERVATION", "LIMITATIONS"):
            self.assertIn(heading.lower(), html.lower())
        report = build_customer_report(
            scope={"containment": "sandbox"}, agent_environment={"agent": "mock"},
            boundary_coverage=tuple(demo["boundary_discovery"]),
            findings=(CustomerFinding(
                "f-1", "subscription ownership", "owner-only",
                {}, {}, {"action": "cancel"}, {"observable": True, "effect_count": 1},
                "contained", "high", demo["proof_capsule_references"][0], "bounded",
                "scope-sensitive control", "pending", "unknown", ("sandbox only",)),),
            inconclusive=(), retest_results=({"allowed_function_preservation": "preserved"},),
            limitations=("Not customer validation.",), capsule_references=tuple(demo["proof_capsule_references"]))
        self.assertIn("limitations", report)
        with self.assertRaises(ValueError):
            build_customer_report(scope={}, agent_environment={}, boundary_coverage=(),
                                  findings=(), inconclusive=(), retest_results=(),
                                  limitations=(), capsule_references=())
