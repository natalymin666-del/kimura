import json
import tempfile
import unittest
from pathlib import Path

from kimura_assessment.attack_reproduction import (
    AttemptJournal, AttackAttemptEvidence, AttackReproductionExperiment,
    DurableAttackExperimentRunner, ReplayEvidenceCapsule, ReplayEvidenceCapsuleStore,
    build_scenario_three_variant_set,
)
from kimura_assessment.real_agent_adapter import AnthropicHTTPError, RealAgentAdapterError
from kimura_assessment.scenario_protocol import SCENARIO_THREE


class CapsuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.variant_set=build_scenario_three_variant_set(SCENARIO_THREE).seal()
        self.variant=self.variant_set.variant_set.resolve("variant-06")
        self.args={"record":"synthetic-boundary-test"}
        self.args_hash=__import__("hashlib").sha256(json.dumps(self.args,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        self.evidence=AttackAttemptEvidence("exp-capsule", self.variant_set.fingerprint, self.variant.variant_id, self.variant.content_sha256, SCENARIO_THREE.fingerprint, "test", "model", "run-capsule", "response-1", "tool-1", "request-fingerprint", "PERMIT", True, "effect-hash", "DANGEROUS_INTENT_REPRODUCED")

    def tearDown(self):
        self.tmp.cleanup()

    def capsule(self, **changes):
        values=dict(
            experiment_id="exp-capsule", variant_set_id=self.variant.variant_set_id,
            variant_set_version=1, variant_set_fingerprint=self.variant_set.fingerprint,
            variant_id=self.variant.variant_id, variant_content_hash=self.variant.content_sha256,
            scenario_id=SCENARIO_THREE.scenario_id, scenario_version=1,
            scenario_fingerprint=SCENARIO_THREE.fingerprint, provider="test", model="model",
            run_id="run-capsule", response_id="response-1", tool_call_id="tool-1",
            capability_id="write_guarded_record", capability_schema_fingerprint="schema-hash",
            canonical_arguments=self.args, canonical_arguments_sha256=self.args_hash,
            canonical_request_fingerprint="request-fingerprint", fixture_identity="fixture-1",
            security_context_fingerprint="context-hash", authorization_decision="PERMIT",
            authorization_policy_fingerprint="policy-hash",
            tool_execution_result={"executed":True,"effect_event_id":"effect-1"},
            effect_ledger_before=0, effect_ledger_after=1, exact_effect_count=1,
            effect_fingerprint="effect-hash", causal_provenance_evidence={"confirmed":True},
            attempt_journal_terminal_state="CLASSIFIED",
        )
        values.update(changes)
        return ReplayEvidenceCapsule(**values)

    def test_complete_capsule_is_deterministic_and_stored(self):
        capsule=self.capsule()
        self.assertEqual(capsule.capsule_id, capsule.capsule_id)
        store=ReplayEvidenceCapsuleStore(Path(self.tmp.name)/"capsules.jsonl")
        store.write(capsule)
        self.assertEqual(store.read_all()[capsule.capsule_id], capsule.to_dict())

    def test_required_evidence_and_identity_fail_closed(self):
        for field, value in (("authorization_decision","DENY"),("effect_fingerprint",""),("canonical_arguments",{}),("causal_provenance_evidence",{"confirmed":False}),("tool_execution_result",{"executed":False})):
            changes={field:value}
            if field=="canonical_arguments": changes["canonical_arguments_sha256"]="0"*64
            with self.assertRaises(ValueError): self.capsule(**changes)

    def test_binding_mismatches_rejected(self):
        from dataclasses import replace
        capsule = self.capsule()
        for field,value in (("scenario_fingerprint","0"*64),("capability_id","other"),("experiment_id","other-exp"),("run_id","other-run")):
            bad = replace(capsule, **{field: value})
            with self.assertRaises(ValueError):
                bad.validate_binding(
                    variant_set=self.variant_set.variant_set, scenario=SCENARIO_THREE,
                    experiment_id="exp-capsule", run_id="run-capsule",
                    fixture_id="fixture-1", capability="write_guarded_record",
                )

    def test_mutation_detected(self):
        store=ReplayEvidenceCapsuleStore(Path(self.tmp.name)/"capsules.jsonl")
        capsule=self.capsule()
        store.write(capsule)
        raw=capsule.to_dict(); raw["effect_fingerprint"]="changed"
        with Path(self.tmp.name, "capsules.jsonl").open("a") as handle: handle.write(json.dumps(raw)+"\n")
        with self.assertRaises(ValueError): store.read_all()

    def test_raw_provider_content_rejected(self):
        with self.assertRaises(ValueError):
            self.capsule(causal_provenance_evidence={"confirmed":True,"raw_prose":"thinking"})
        with self.assertRaises(ValueError):
            self.capsule(canonical_arguments={"record":"api_key=secret"}, canonical_arguments_sha256=__import__("hashlib").sha256(b'{"record":"api_key=secret"}').hexdigest())

    def experiment(self, capsule_store=None, capsule_factory=None):
        return AttackReproductionExperiment(
            experiment_id="exp-capsule", variant_set=self.variant_set, scenario=SCENARIO_THREE,
            run_id="run-capsule", provider="test", model="model", fixture_id="fixture-1",
            observer=lambda variant: None,
            capability_schema={"name":"write_guarded_record","input_schema":{"type":"object","properties":{"record":{"type":"string"}},"required":["record"],"additionalProperties":False}},
            boundary_factory=None,
        )

    def test_dangerous_classification_requires_capsule(self):
        exp=self.experiment()
        journal=AttemptJournal(Path(self.tmp.name)/"journal.jsonl")
        runner=DurableAttackExperimentRunner(experiment=exp,journal=journal,clock=lambda:"t")
        result=runner.run_variant("variant-06",lambda:self.evidence)
        self.assertIsNone(result)
        self.assertEqual(journal.read()[-1]["failure_code"],"missing_replay_capsule")
        self.assertNotEqual(journal.read()[-1].get("outcome"),"DANGEROUS_INTENT_REPRODUCED")

    def test_dangerous_classification_persists_capsule_before_terminal_state(self):
        store=ReplayEvidenceCapsuleStore(Path(self.tmp.name)/"capsules.jsonl")
        exp=self.experiment()
        journal=AttemptJournal(Path(self.tmp.name)/"journal.jsonl")
        runner=DurableAttackExperimentRunner(experiment=exp,journal=journal,clock=lambda:"t",capsule_store=store,capsule_factory=lambda evidence:self.capsule())
        result=runner.run_variant("variant-06",lambda:self.evidence)
        self.assertEqual(result.outcome,"DANGEROUS_INTENT_REPRODUCED")
        self.assertEqual(journal.read()[-1]["state"],"CLASSIFIED")
        self.assertEqual(len(store.read_all()),1)

    def test_capsule_persistence_failure_is_harness_error(self):
        class BrokenStore:
            def write(self, capsule): raise OSError("disk full")
        exp=self.experiment()
        journal=AttemptJournal(Path(self.tmp.name)/"journal.jsonl")
        runner=DurableAttackExperimentRunner(experiment=exp,journal=journal,clock=lambda:"t",capsule_store=BrokenStore(),capsule_factory=lambda evidence:self.capsule())
        result=runner.run_variant("variant-06",lambda:self.evidence)
        self.assertIsNone(result)
        self.assertEqual(journal.read()[-1]["failure_code"],"capsule_persistence_failed")

if __name__=="__main__":
    unittest.main()
