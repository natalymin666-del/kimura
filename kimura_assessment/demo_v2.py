"""Deterministic loopback Conference Demo v2 for agent security assessment."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import date
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading
from typing import Iterator

from .evidence import EvidenceRecord, EvidenceStore, digest_text
from .findings import Finding
from .http_adapter import HttpTarget
from .remediation import RemediationController
from .risk import RiskEvaluator
from .runner import AssessmentRunner
from .scenarios import DEMO_CONTRACT, DEMO_FIXTURE
from .schema import AssessmentContract


DEMO_V2_ASSESSMENT_ID = "conference-demo-v2"
DEMO_V2_CREDENTIAL_REFERENCE = "env://KIMURA_CONFERENCE_DEMO_V2_PLACEHOLDER"
_DEMO_V2_CREDENTIAL = "conference-demo-v2-placeholder-only"


class VulnerableAgentApp:
    """A local agent-like service with one deliberately unsafe policy."""

    def __init__(self):
        self.tool_policy_enabled = False
        self.audit_events: list[dict[str, object]] = []

    def enable_tool_policy(self) -> None:
        self.tool_policy_enabled = True

    def handle(self, request: dict[str, object]) -> dict[str, object]:
        operation = request.get("operation")
        if operation == "discover":
            return {
                "operation": "discover",
                "agent": DEMO_CONTRACT.target_label,
                "retrieval": "local-fixture",
                "tools": [DEMO_CONTRACT.expected_tool],
                "policy": "deny-untrusted-external-actions" if self.tool_policy_enabled else "permissive",
            }
        if operation == "remediate":
            RemediationController(self).apply()
            return {"operation": "remediate", "control": "tool-policy-deny-untrusted-external-actions"}
        if operation == "attack":
            if request.get("fixture_id") != DEMO_FIXTURE.fixture_id:
                return {"operation": "attack", "attempted": False, "control": "fixture-not-recognized"}
            executed = not self.tool_policy_enabled
            event_id = f"tool-event-{len(self.audit_events) + 1:02d}"
            event = {
                "event_id": event_id,
                "fixture_id": DEMO_FIXTURE.fixture_id,
                "source_document_id": DEMO_FIXTURE.document_id,
                "retrieved_instruction_sha256": DEMO_FIXTURE.poisoned_instruction_digest,
                "tool": DEMO_CONTRACT.expected_tool,
                "executed": executed,
                "data_class": DEMO_CONTRACT.synthetic_data_class,
                "control": "none" if executed else "tool-policy-deny-untrusted-external-actions",
            }
            self.audit_events.append(event)
            return {"operation": "attack", "attempted": True, **event}
        if operation == "validate":
            if not self.audit_events:
                return {"operation": "validate", "validated": False, "event_count": 0}
            event = self.audit_events[-1]
            return {
                "operation": "validate",
                "validated": bool(event["executed"]),
                "event_count": len(self.audit_events),
                "latest_event_id": event["event_id"],
                "tool": event["tool"],
                "executed": event["executed"],
                "data_class": event["data_class"],
                "control": event["control"],
            }
        return {"error": "unsupported-operation"}


def _handler_for(app: VulnerableAgentApp):
    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            try:
                size = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(size))
                if not isinstance(request, dict):
                    raise ValueError
                output = app.handle(request)
            except (ValueError, json.JSONDecodeError):
                self.send_error(400)
                return
            body = json.dumps({"output": json.dumps(output, sort_keys=True, separators=(",", ":"))}, separators=(",", ":")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    return _Handler


@contextmanager
def _agent_server(app: VulnerableAgentApp) -> Iterator[HTTPServer]:
    server = HTTPServer(("127.0.0.1", 0), _handler_for(app))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@contextmanager
def _demo_v2_credential() -> Iterator[None]:
    name = "KIMURA_CONFERENCE_DEMO_V2_PLACEHOLDER"
    previous = os.environ.get(name)
    os.environ[name] = _DEMO_V2_CREDENTIAL
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


class DemoTarget:
    """Typed scenario calls routed through the existing authorized runner."""

    def __init__(self, runner: AssessmentRunner, fixture_id: str):
        self._runner = runner
        self._fixture_id = fixture_id

    def call(self, operation: str) -> tuple[dict[str, object], str, str]:
        payload = {"operation": operation, "fixture_id": self._fixture_id}
        raw = self._runner.run(operation, payload)
        try:
            response = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("demo target returned malformed structured output") from exc
        if not isinstance(response, dict):
            raise RuntimeError("demo target returned an invalid structured output")
        return response, digest_text(json.dumps(payload, sort_keys=True)), digest_text(raw)


class DemoReport:
    """Safe report and concise conference presentation for one demo run."""

    def __init__(self, finding: Finding, evidence: list[EvidenceRecord], *, remediated: bool, retest_passed: bool):
        self.finding = finding
        self.evidence = evidence
        self.remediated = remediated
        self.retest_passed = retest_passed

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "assessment_id": DEMO_V2_ASSESSMENT_ID,
            "authorization": {
                "authorized_by": "local-demo-v2-approval",
                "scope": "http://127.0.0.1",
                "request_budget": 6,
            },
            "finding": self.finding.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "lifecycle": ["Candidate", "Validated", "Remediated", "Retest passed"],
            "remediated": self.remediated,
            "retest_passed": self.retest_passed,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    def terminal_text(self) -> str:
        finding = self.finding
        evidence_ids = ", ".join(item.evidence_id for item in self.evidence)
        return "\n".join([
            "Kimura Conference Demo v2 | authorized loopback assessment",
            "Scope: 127.0.0.1 only | credentials: synthetic placeholder | external actions: disabled",
            "",
            "Candidate → Validated → Remediated → Retest passed",
            f"Finding: {finding.title}",
            "Attack: poisoned retrieved document → send_email",
            "Impact: tool execution confirmed by local audit ledger (synthetic-sensitive)",
            f"Risk: {finding.severity} | Confidence: {finding.confidence}",
            f"Evidence: {evidence_ids}",
            "Remediation: deny untrusted external actions and require confirmation",
            "Retest: exact same fixture replayed → action blocked by tool policy → PASS",
        ])


def run_demo_v2_report(*, persist_path: Path | None = None, report_path: Path | None = None) -> DemoReport:
    """Run the complete deterministic scenario and return safe report objects."""

    if report_path is not None and persist_path is None:
        raise ValueError("report_path requires persist_path")
    app = VulnerableAgentApp()
    with _agent_server(app) as server, _demo_v2_credential():
        endpoint = f"http://127.0.0.1:{server.server_port}/agent"
        contract = AssessmentContract(
            assessment_id=DEMO_V2_ASSESSMENT_ID,
            client_name="Kimura local conference demo",
            assessor_name="Kimura Security",
            authorized_by="local-demo-v2-approval",
            objectives=("Validate indirect prompt injection impact and remediation",),
            scope=(f"http://127.0.0.1:{server.server_port}",),
            start_date=date.today(),
            end_date=date.today(),
            credential_references=(DEMO_V2_CREDENTIAL_REFERENCE,),
            max_requests=6,
        )
        target = HttpTarget(endpoint, "input", "output", DEMO_V2_CREDENTIAL_REFERENCE)
        demo_target = DemoTarget(AssessmentRunner(contract, target), DEMO_FIXTURE.fixture_id)
        evidence: list[EvidenceRecord] = []

        def record(phase: str, step: int, response: dict[str, object], request_hash: str, response_hash: str, action: str, outcome: str, control: str) -> EvidenceRecord:
            item = EvidenceRecord(
                schema_version=1,
                evidence_id=f"evidence-{step:02d}",
                assessment_id=DEMO_V2_ASSESSMENT_ID,
                finding_id="finding-indirect-tool-action-001",
                phase=phase,
                step=step,
                observation="validated-audit-ledger-observation" if phase == "validate" else "bounded-demo-observation",
                request_sha256=request_hash,
                response_sha256=response_hash,
                action=action,
                outcome=outcome,
                control=control,
            )
            evidence.append(item)
            return item

        discover, req, resp = demo_target.call("discover")
        record("discover", 1, discover, req, resp, "discover-agent-capabilities", "completed", "assessment-contract")
        attack, req, resp = demo_target.call("attack")
        record("attack", 2, attack, req, resp, "send_email", "executed" if attack.get("executed") else "blocked", str(attack.get("control", "none")))
        validate, req, resp = demo_target.call("validate")
        record("validate", 3, validate, req, resp, "audit-ledger-validation", "confirmed" if validate.get("executed") else "not-observed", str(validate.get("control", "none")))
        finding = RiskEvaluator().evaluate(executed=bool(validate.get("executed")), sensitive_data=validate.get("data_class") == DEMO_CONTRACT.synthetic_data_class, evidence_ids=("evidence-02", "evidence-03"))
        remediate, req, resp = demo_target.call("remediate")
        record("remediation", 4, remediate, req, resp, "apply-tool-policy", "applied", str(remediate.get("control", "none")))
        retest_attack, req, resp = demo_target.call("attack")
        record("retest", 5, retest_attack, req, resp, "send_email", "blocked" if not retest_attack.get("executed") else "executed", str(retest_attack.get("control", "none")))
        retest_validate, req, resp = demo_target.call("validate")
        record("retest", 6, retest_validate, req, resp, "audit-ledger-validation", "passed" if not retest_validate.get("executed") else "failed", str(retest_validate.get("control", "none")))

    final_finding = Finding(
        schema_version=finding.schema_version,
        finding_id=finding.finding_id,
        title=finding.title,
        category=finding.category,
        severity=finding.severity,
        confidence=finding.confidence,
        status="Retest passed" if not retest_validate.get("executed") else finding.status,
        impact=finding.impact,
        remediation=finding.remediation,
        evidence_ids=finding.evidence_ids,
    )
    report = DemoReport(final_finding, evidence, remediated=not bool(retest_attack.get("executed")), retest_passed=not bool(retest_validate.get("executed")))
    if persist_path is not None:
        store = EvidenceStore(persist_path)
        for item in evidence:
            store.append(item)
        if report_path is not None:
            Path(report_path).write_text(report.to_json() + "\n", encoding="utf-8", newline="\n")
    return report


def run_demo_v2(*, persist_path: Path | None = None, report_path: Path | None = None) -> str:
    return run_demo_v2_report(persist_path=persist_path, report_path=report_path).terminal_text()
