#!/usr/bin/env python3
"""Run a local-network-only Phase 4.4b PASS handoff review."""

from __future__ import annotations

import argparse
import time
from uuid import uuid4

from kimura_assessment.conference_live import render_live_page_html
from kimura_assessment.conference_live_server import ProgressHTTPServer
from kimura_assessment.mobile_report import build_mobile_report_url, build_qr_data_uri
from kimura_assessment.progress_events import ProgressEvent, ProgressEventType
from kimura_assessment.progress_journal import ProgressJournal


def pass_events(run_id: str) -> list[ProgressEvent]:
    def event(sequence: int, event_type: ProgressEventType, payload: dict[str, object]) -> ProgressEvent:
        return ProgressEvent(run_id, sequence, event_type, payload)

    return [
        event(1, ProgressEventType.ASSESSMENT_STARTED, {"assessment_id": "physical-assessment-v1"}),
        event(2, ProgressEventType.TARGET_VERIFIED, {"target_id": "target-1", "target_kind": "owned-isolated-synthetic-target", "protocol_version": 1, "policy_digest_before": "a" * 64}),
        event(3, ProgressEventType.BASELINE_VALIDATED, {"fixture_id": "fixture-1", "fixture_sha256": "b" * 64, "action": "send_email", "decision": "allowed", "event_id": "event-0001", "ledger_count": 1}),
        event(4, ProgressEventType.REMEDIATION_VERIFIED, {"policy_id": "policy-1", "policy_digest_before": "a" * 64, "policy_digest_after": "c" * 64, "denied_actions": ["send_email"]}),
        event(5, ProgressEventType.REPLAY_IDENTITY_VERIFIED, {"attack_id": "attack-1", "fixture_id": "fixture-1", "fixture_sha256": "b" * 64, "action": "send_email"}),
        event(6, ProgressEventType.REPLAY_VALIDATED, {"decision": "blocked", "executed": False, "synthetic_event_id": None, "ledger_count": 1, "baseline_ledger_count": 1}),
        event(7, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}),
        event(8, ProgressEventType.FIX_VERIFIED, {"baseline_ledger_count": 1, "final_ledger_count": 1}),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve a same-origin Phase 4.4b PASS review on an explicit LAN host")
    parser.add_argument("--host", required=True, help="explicit laptop LAN address to bind and publish")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    run_id = "phase44b-" + uuid4().hex
    journal = ProgressJournal()
    for event in pass_events(run_id):
        journal.append(event)
    server = ProgressHTTPServer(journal, host=args.host, port=args.port)
    mobile_url = build_mobile_report_url(server.base_url, run_id, allow_loopback=False)
    qr_data_uri = build_qr_data_uri(mobile_url)
    server.page_html = render_live_page_html(run_id, mobile_report_url=mobile_url, qr_data_uri=qr_data_uri)
    server.start()
    print(f"LAPTOP LAN HOST: {args.host}", flush=True)
    print(f"CONFERENCE URL: {server.base_url}{server.page_path}", flush=True)
    print(f"MOBILE REPORT URL: {mobile_url}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0
    finally:
        server.stop()


if __name__ == "__main__":
    raise SystemExit(main())
