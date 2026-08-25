import json
import unittest

from kimura_assessment.physical_target_assessment import (
    InProcessPhysicalTargetClient,
    PhysicalAssessmentError,
    PhysicalTargetOrchestrator,
)
from kimura_assessment.physical_target_runtime import PhysicalTargetRuntime, TargetConfig
from kimura_assessment.progress_events import ProgressEmitter, ProgressEvent, ProgressEventType


HASHES = {"physical_target_runtime.py": "0" * 64}


class Collector:
    def __init__(self):
        self.events = []

    def __call__(self, event):
        self.events.append(event)


def run_with_events(runtime=None, *, client=None, sink=None, run_id="run-test-01"):
    runtime = runtime or PhysicalTargetRuntime(node_instance_id="progress-test")
    collector = sink or Collector()
    orchestrator = PhysicalTargetOrchestrator(
        client or InProcessPhysicalTargetClient(runtime),
        expected_target_id=runtime.config.target_id,
        expected_hashes=HASHES,
        observed_hashes=HASHES,
        progress_sink=collector,
        run_id=run_id,
    )
    return orchestrator.run(), collector


class ProgressEventModelTests(unittest.TestCase):
    def test_event_model_rejects_unapproved_or_unsafe_payloads(self):
        with self.assertRaises(ValueError):
            ProgressEvent("run", 1, ProgressEventType.TARGET_VERIFIED, {"raw_response": "secret"})
        with self.assertRaises(TypeError):
            ProgressEvent("run", 1, ProgressEventType.TARGET_VERIFIED, {"target_id": object()})

    def test_emitter_is_monotonic_and_idempotent(self):
        events = []
        emitter = ProgressEmitter(events.append, run_id="run-01")
        first = emitter.emit(ProgressEventType.ASSESSMENT_STARTED, {"assessment_id": "physical-assessment-v1"})
        duplicate = emitter.emit(ProgressEventType.ASSESSMENT_STARTED, {"assessment_id": "different"})
        second = emitter.emit(ProgressEventType.TARGET_VERIFIED, {"target_id": "target", "target_kind": "owned-isolated-synthetic-target", "protocol_version": 1, "policy_digest_before": "a" * 64})
        self.assertEqual(duplicate, None)
        self.assertEqual([event.sequence for event in events], [1, 2])
        self.assertEqual(first.to_dict()["run_id"], "run-01")
        self.assertEqual(second.to_dict()["event_type"], "target_verified")


class PhysicalAssessmentProgressTests(unittest.TestCase):
    def test_pass_event_sequence_is_only_after_proven_checkpoints(self):
        result, collector = run_with_events()
        self.assertEqual(result.status, "PASS")
        self.assertEqual([event.event_type.value for event in collector.events], [
            "assessment_started", "target_verified", "baseline_validated",
            "remediation_verified", "replay_identity_verified", "replay_validated",
            "cleanup_completed", "fix_verified",
        ])
        self.assertEqual([event.sequence for event in collector.events], list(range(1, 9)))
        self.assertEqual(collector.events[-1].payload, {"baseline_ledger_count": 1, "final_ledger_count": 1})

    def test_baseline_failure_cannot_emit_later_success(self):
        runtime = PhysicalTargetRuntime(TargetConfig(baseline_allowed_actions=frozenset()))
        result, collector = run_with_events(runtime)
        event_types = [event.event_type.value for event in collector.events]
        self.assertEqual(result.status, "PARTIAL")
        self.assertEqual(event_types, ["assessment_started", "target_verified", "cleanup_completed", "assessment_partial"])
        self.assertNotIn("remediation_verified", event_types)
        self.assertNotIn("fix_verified", event_types)

    def test_unreachable_target_emits_failed_without_target_success(self):
        class Unreachable:
            def request(self, _payload):
                raise PhysicalAssessmentError("transport failure")

        runtime = PhysicalTargetRuntime(node_instance_id="unreachable")
        result, collector = run_with_events(runtime, client=Unreachable())
        self.assertEqual(result.status, "FAILED")
        self.assertEqual([event.event_type.value for event in collector.events], ["assessment_started", "cleanup_completed", "assessment_failed"])

    def test_replay_identity_mismatch_stops_before_replay_validation_and_fix(self):
        runtime = PhysicalTargetRuntime(node_instance_id="mismatch")
        base = InProcessPhysicalTargetClient(runtime)

        class Mismatch:
            def request(self, payload):
                response = base.request(payload)
                if payload["operation"] == "execute" and "replay" in payload["request_id"]:
                    response = dict(response)
                    response["fixture_sha256"] = "f" * 64
                return response

        result, collector = run_with_events(runtime, client=Mismatch())
        event_types = [event.event_type.value for event in collector.events]
        self.assertEqual(result.status, "PARTIAL")
        self.assertNotIn("replay_identity_verified", event_types)
        self.assertNotIn("replay_validated", event_types)
        self.assertNotIn("fix_verified", event_types)

    def test_unexpected_replay_ledger_stops_later_success(self):
        runtime = PhysicalTargetRuntime(node_instance_id="ledger")
        base = InProcessPhysicalTargetClient(runtime)

        class ExtraLedger:
            def request(self, payload):
                response = base.request(payload)
                if payload["operation"] == "execute" and "replay" in payload["request_id"]:
                    response = dict(response)
                    response["ledger_sequence"] = 2
                    response["synthetic_event_id"] = "event-0002"
                return response

        result, collector = run_with_events(runtime, client=ExtraLedger())
        event_types = [event.event_type.value for event in collector.events]
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("replay_identity_verified", event_types)
        self.assertNotIn("replay_validated", event_types)
        self.assertNotIn("fix_verified", event_types)

    def test_sink_failure_does_not_change_result_semantics(self):
        class FailingSink:
            def __call__(self, _event):
                raise RuntimeError("presentation sink unavailable")

        normal, _ = run_with_events(run_id="normal")
        failing, _ = run_with_events(sink=FailingSink(), run_id="failing")
        self.assertEqual(normal.to_json(), failing.to_json())

    def test_event_payloads_are_serializable_and_do_not_include_raw_bodies(self):
        _result, collector = run_with_events()
        for event in collector.events:
            encoded = json.dumps(event.to_dict(), sort_keys=True)
            self.assertNotIn("request", encoded)
            self.assertNotIn("response", encoded)
            self.assertNotIn("secret", encoded)

    def test_cleanup_failure_cannot_emit_fix_verified(self):
        def cleanup_failure():
            raise RuntimeError("cleanup unavailable")

        runtime = PhysicalTargetRuntime(node_instance_id="cleanup")
        collector = Collector()
        result = PhysicalTargetOrchestrator(
            InProcessPhysicalTargetClient(runtime),
            expected_target_id=runtime.config.target_id,
            expected_hashes=HASHES,
            observed_hashes=HASHES,
            cleanup=cleanup_failure,
            progress_sink=collector,
            run_id="cleanup-run",
        ).run()
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("cleanup_failed", [event.event_type.value for event in collector.events])
        self.assertNotIn("fix_verified", [event.event_type.value for event in collector.events])


    def test_unexpected_but_unchanged_ledger_cannot_emit_fix_verified(self):
        runtime = PhysicalTargetRuntime(node_instance_id="unexpected-ledger")
        base = InProcessPhysicalTargetClient(runtime)

        class UnexpectedLedger:
            def request(self, payload):
                response = base.request(payload)
                if payload["operation"] in {"execute", "validate"}:
                    response = dict(response)
                    response["ledger_sequence"] = 2
                return response

        result, collector = run_with_events(runtime, client=UnexpectedLedger())
        self.assertEqual(result.status, "PASS")
        self.assertIn("cleanup_completed", [event.event_type.value for event in collector.events])
        self.assertNotIn("fix_verified", [event.event_type.value for event in collector.events])


if __name__ == "__main__":
    unittest.main()
