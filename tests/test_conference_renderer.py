import unittest

from kimura_assessment.conference_preview import fixture_result
from kimura_assessment.conference_renderer import render_conference_html
from kimura_assessment.physical_target_assessment import run_local_assessment


class ConferenceRendererTests(unittest.TestCase):
    def test_pass_renders_fix_verified_and_truthfulness_labels(self):
        html = render_conference_html(run_local_assessment().to_dict())
        self.assertIn("FIX VERIFIED", html)
        self.assertIn("ALLOWED", html)
        self.assertIn("BLOCKED", html)
        self.assertIn("SAME FIXTURE ✓", html)
        self.assertIn("SHA-256 MATCHED", html)
        self.assertIn("Raspberry Pi 5", html)
        self.assertIn("IDENTITY VERIFIED", html)
        self.assertIn("Owned isolated synthetic target", html)
        self.assertIn("No real external action occurred.", html)

    def test_partial_and_failed_never_render_fix_verified(self):
        for state in ("partial", "failed"):
            html = render_conference_html(fixture_result(state))
            self.assertNotIn("FIX VERIFIED", html)
            self.assertIn(state.upper(), html)

    def test_changed_hash_event_target_and_ledger_values_render(self):
        result = run_local_assessment().to_dict()
        result["target_id"] = "changed-target"
        result["baseline_event_id"] = "changed-event"
        result["baseline_fixture_sha256"] = "1" * 64
        result["replay_fixture_sha256"] = "1" * 64
        result["baseline_ledger_count"] = 7
        result["final_ledger_count"] = 7
        result["evidence_chain"][0]["target_id"] = "changed-target"
        html = render_conference_html(result)
        self.assertIn("changed-target", html)
        self.assertIn("changed-event", html)
        self.assertIn("1" * 64, html)
        self.assertIn("7 → 7", html)

    def test_replay_identity_mismatch_is_visible(self):
        result = run_local_assessment().to_dict()
        result["exact_replay_identity_verified"] = False
        result["status"] = "PARTIAL"
        result["fix_verified"] = False
        result["failure_reason"] = "exact replay fixture identity mismatch"
        html = render_conference_html(result)
        self.assertIn("NOT VERIFIED", html)
        self.assertIn("PARTIAL", html)

    def test_policy_digest_mismatch_is_visible(self):
        result = run_local_assessment().to_dict()
        result["policy_digest_after"] = result["policy_digest_before"]
        result["deny_only_verified"] = False
        result["status"] = "PARTIAL"
        result["fix_verified"] = False
        result["failure_reason"] = "deny-only remediation invariant failed"
        html = render_conference_html(result)
        self.assertIn("deny-only remediation invariant failed", html)
        self.assertIn("PARTIAL", html)

    def test_html_escapes_runtime_values(self):
        result = run_local_assessment().to_dict()
        result["target_id"] = '<script>alert("x")</script>'
        result["evidence_chain"][0]["target_id"] = result["target_id"]
        html = render_conference_html(result)
        self.assertNotIn('<script>alert("x")</script>', html)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", html)

    def test_deterministic_input_produces_deterministic_html(self):
        result = run_local_assessment().to_dict()
        self.assertEqual(render_conference_html(result), render_conference_html(result))

    def test_renderer_is_offline_and_has_no_external_dependencies(self):
        html = render_conference_html(run_local_assessment().to_dict())
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("fetch(", html)
        self.assertNotIn("XMLHttpRequest", html)
        self.assertIn("<style>", html)


    def test_pass_primary_experience_has_visible_valid_layout_rules(self):
        html = render_conference_html(run_local_assessment().to_dict())
        self.assertIn("<main class=\"shell is-pass\"", html)
        self.assertIn("FIX VERIFIED", html)
        self.assertIn(" (max-width:900px)", html)
        self.assertNotIn("\n (max-width:900px)", html)
        self.assertNotIn("visibility:hidden", html)
        self.assertNotIn("opacity:0", html)

if __name__ == "__main__":
    unittest.main()
