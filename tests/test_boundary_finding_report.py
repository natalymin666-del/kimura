import unittest
from dataclasses import replace

from kimura_assessment.boundary_finding_report import (
    BoundaryFindingError, build_boundary_finding, build_local_demo_finding, redact,
    render_boundary_finding_html,
)
from kimura_assessment.adaptive_boundary import AttackChain, ChainTransition
from kimura_assessment.boundary_proof import BoundaryVerdict, ContainedImpactEvidence, sha256
from kimura_assessment.privilege_boundary import build_privilege_baseline, build_privilege_proof_capsule


class BoundaryFindingReportTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.pair, _env, self.allowed, self.forbidden = build_privilege_baseline()
        run = "run-10.1"
        self.allowed = replace(self.allowed, tool_execution={**self.allowed.tool_execution, "run_id": run})
        self.forbidden = replace(self.forbidden, tool_execution={**self.forbidden.tool_execution, "run_id": run})
        capsule = build_privilege_proof_capsule(self.contract, self.pair, self.allowed, self.forbidden)
        self.capsule = replace(capsule,
            execution_evidence={"run_id": run},
            causal_provenance={"proven": True},
            verdict_inputs={"observable_only": True})

    def build(self, **kw):
        values = dict(contract=self.contract, pair=self.pair, allowed=self.allowed,
                      forbidden=self.forbidden, capsule=self.capsule, run_id="run-10.1")
        values.update(kw)
        return build_boundary_finding(finding_id="BF-test", **values)

    def test_confirmed_requires_observable_impact_and_provenance(self):
        finding = self.build()
        self.assertEqual(finding.independent_kimura_verdict, BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED.value)
        no_impact = replace(self.forbidden, state_after=self.forbidden.state_before, effect_count=0,
                            tool_execution={"executed": True, "run_id": "run-10.1"})
        self.assertEqual(self.build(forbidden=no_impact).independent_kimura_verdict, BoundaryVerdict.INCONCLUSIVE.value)
        missing = replace(self.capsule, causal_provenance=None)
        self.assertEqual(self.build(capsule=missing).independent_kimura_verdict, BoundaryVerdict.INCONCLUSIVE.value)

    def test_integrity_prose_and_cross_run_fail_closed(self):
        sealed = replace(self.capsule, capsule_sha256=sha256(self.capsule.to_unsigned()))
        with self.assertRaises(ValueError): replace(sealed, effect_fingerprint="changed")
        with self.assertRaises(BoundaryFindingError): self.build(forbidden=replace(self.forbidden, tool_execution={"executed": True, "run_id": "other"}))
        with self.assertRaises(BoundaryFindingError): self.build(capsule=replace(self.capsule, verdict_inputs={"model_prose": "confirmed"}))

    def test_cross_pair_and_chain_gap_fail_closed(self):
        other_pair_observation = replace(self.forbidden, attempted_action={**self.forbidden.attempted_action, "role": "other"})
        with self.assertRaises(BoundaryFindingError): self.build(forbidden=other_pair_observation)
        chain = AttackChain("gap", (
            ChainTransition("step-1", {"state": "start"}, {"action": "one"}, {"state": "middle"}, {"proven": True}),
            ChainTransition("step-3", {"state": "unproven"}, {"action": "three"}, {"state": "end"}, {"proven": True}),
        ))
        finding = self.build(chain=chain)
        self.assertEqual(finding.independent_kimura_verdict, BoundaryVerdict.INCONCLUSIVE.value)
        self.assertEqual(finding.attack_variant_or_chain_lineage["chain_provenance"], "UNVERIFIED")

    def test_held_and_inconclusive_are_not_pass_or_confirmed_vulnerability(self):
        blocked = replace(self.forbidden, authorization_decision="BLOCKED", state_after=self.forbidden.state_before,
                          effect_count=0, effect_identity="", tool_execution={"executed": False, "run_id": "run-10.1"})
        held = self.build(forbidden=blocked)
        self.assertEqual(held.independent_kimura_verdict, BoundaryVerdict.BOUNDARY_HELD.value)
        self.assertNotEqual(held.independent_kimura_verdict, BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED.value)
        self.assertNotIn("PASS", held.to_json())
        self.assertIn("not a pass", render_boundary_finding_html(held))

    def test_remediation_requires_retest_and_preservation_requires_allowed_observation(self):
        applied_only = replace(self.capsule, remediation_evidence={"applied": True}, exact_retest_evidence={"not_run": True})
        self.assertEqual(self.build(capsule=applied_only).remediation_status, "NOT VERIFIED / NOT RUN")
        retested = replace(self.capsule, remediation_evidence={"verified": True}, exact_retest_evidence={"complete": True})
        self.assertEqual(self.build(capsule=retested).remediation_status, "VERIFIED")
        no_allowed_impact = replace(self.allowed, state_after=self.allowed.state_before, effect_count=0,
                                    tool_execution={"executed": True, "run_id": "run-10.1"})
        self.assertEqual(self.build(allowed=no_allowed_impact).allowed_function_preservation_status, "NOT VERIFIED / UNKNOWN")

    def test_secret_evidence_is_redacted_and_not_rendered(self):
        secret = {"api_key": "sk-live-example", "nested": {"password": "secret"}}
        safe = redact(secret)
        self.assertEqual(safe["api_key"], "[REDACTED]")
        self.assertEqual(safe["nested"]["password"], "[REDACTED]")
        self.assertNotIn("sk-live-example", __import__("json").dumps(safe))

    def test_html_is_customer_safe_and_claim_bounded(self):
        html = render_boundary_finding_html(build_local_demo_finding())
        self.assertIn("CONFIRMED", html)
        self.assertIn("Claim boundary", html)
        self.assertIn("does not establish that the entire agent or system is secure", html)
        self.assertNotIn("raw_thinking", html)
        self.assertNotIn("api_key", html.lower())

    def test_allowed_function_preservation_is_separate(self):
        finding = self.build()
        self.assertEqual(finding.allowed_function_preservation_status, "NOT VERIFIED / UNKNOWN")


if __name__ == "__main__":
    unittest.main()
