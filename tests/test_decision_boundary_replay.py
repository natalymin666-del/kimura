import hashlib
import json
import unittest
from dataclasses import replace

from kimura_assessment.attack_reproduction import ReplayEvidenceCapsule, build_scenario_three_variant_set
from kimura_assessment.decision_boundary_replay import replay_capsule_at_decision_boundary
from kimura_assessment.real_agent_adapter import SyntheticToolExecutionBoundary
from kimura_assessment.scenario_protocol import SCENARIO_THREE


class DecisionBoundaryReplayTests(unittest.TestCase):
    def setUp(self):
        self.variant_set=build_scenario_three_variant_set(SCENARIO_THREE).seal()
        self.variant=self.variant_set.variant_set.resolve("variant-06")
        self.capability={"name":"write_guarded_record","input_schema":{"type":"object","properties":{"record":{"type":"string"}},"required":["record"],"additionalProperties":False}}
        args={"record":"synthetic-boundary-test"}
        args_sha=hashlib.sha256(json.dumps(args,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        self.capsule=ReplayEvidenceCapsule(
            experiment_id="exp-boundary",variant_set_id=self.variant_set.variant_set.variant_set_id,variant_set_version=1,
            variant_set_fingerprint=self.variant_set.fingerprint,variant_id="variant-06",variant_content_hash=self.variant.content_sha256,
            scenario_id=SCENARIO_THREE.scenario_id,scenario_version=1,scenario_fingerprint=SCENARIO_THREE.fingerprint,
            provider="Anthropic",model="claude-sonnet-5",run_id="run-boundary",response_id="response-1",tool_call_id="tool-1",
            capability_id="write_guarded_record",capability_schema_fingerprint=hashlib.sha256(json.dumps([self.capability],sort_keys=True,separators=(",",":")).encode()).hexdigest(),
            canonical_arguments=args,canonical_arguments_sha256=args_sha,canonical_request_fingerprint=hashlib.sha256(json.dumps({"capability":"write_guarded_record","arguments":args},sort_keys=True,separators=(",",":")).encode()).hexdigest(),
            fixture_identity="fixture-1",security_context_fingerprint="context-1",authorization_decision="PERMIT",
            authorization_policy_fingerprint="policy-1",tool_execution_result={"executed":True},
            effect_ledger_before=0,effect_ledger_after=1,exact_effect_count=1,effect_fingerprint="effect-1",
            causal_provenance_evidence={"confirmed":True},attempt_journal_terminal_state="CLASSIFIED")
        self.capsule=replace(self.capsule,replay_capsule_sha256=self.capsule.capsule_id)
    
    
    def replay(self, capsule=None, **kwargs):
        return replay_capsule_at_decision_boundary(
            capsule=capsule or self.capsule, variant_set=self.variant_set, scenario=SCENARIO_THREE,
            capability_schema=self.capability, fixture_identity=kwargs.get("fixture","fixture-1"),
            security_context_fingerprint=kwargs.get("context","context-1"),
            boundary=SyntheticToolExecutionBoundary(scenario=SCENARIO_THREE,run_id=(capsule or self.capsule).run_id,capability="write_guarded_record",policy="deny"),
        )

    def test_exact_capsule_request_is_denied_without_model(self):
        result=self.replay()
        self.assertEqual(result.replay_mode,"DECISION_BOUNDARY_REPLAY")
        self.assertTrue(result.request_reconstructed_from_capsule)
        self.assertTrue(result.request_fingerprint_match)
        self.assertEqual(result.authorization,"BLOCKED")
        self.assertFalse(result.tool_executed)
        self.assertEqual((result.effect_ledger_before,result.effect_ledger_after,result.second_effect_count),(1,1,0))
        self.assertFalse(result.live_model_replay_verified)
        self.assertTrue(result.decision_boundary_control_verified)
        self.assertTrue(result.control_fix_verified)

    def test_all_identity_mismatches_fail_closed(self):
        for field,value in (("variant_content_hash","0"*64),("scenario_fingerprint","0"*64),("capability_id","other"),("canonical_request_fingerprint","0"*64),("canonical_arguments",{"record":"altered"})):
            with self.assertRaises(ValueError):
                self.replay(replace(self.capsule,**{field:value}))
        with self.assertRaises(ValueError): self.replay(fixture="other")
        with self.assertRaises(ValueError): self.replay(context="other")

    def test_capsule_mutation_rejected(self):
        with self.assertRaises(ValueError):
            replace(self.capsule,effect_fingerprint="changed").verify()

    def test_non_deny_boundary_rejected(self):
        with self.assertRaises(ValueError):
            replay_capsule_at_decision_boundary(
                capsule=self.capsule,variant_set=self.variant_set,scenario=SCENARIO_THREE,
                capability_schema=self.capability,fixture_identity="fixture-1",security_context_fingerprint="context-1",
                boundary=SyntheticToolExecutionBoundary(scenario=SCENARIO_THREE,run_id="run-boundary",capability="write_guarded_record",policy="permit"))

if __name__=="__main__":
    unittest.main()
