"""Deterministic multi-scenario local Agent Security Assessment Demo v3."""

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
from .scenarios import DEMO_CONTRACT, DEMO_FIXTURE, EXFIL_CONTRACT, EXFIL_FIXTURE
from .schema import AssessmentContract

DEMO_V3_ASSESSMENT_ID = "commercial-agent-security-demo-v3"
DEMO_V3_CREDENTIAL_REFERENCE = "env://KIMURA_AGENT_DEMO_V3_PLACEHOLDER"
_DEMO_V3_CREDENTIAL = "agent-demo-v3-placeholder-only"

class V3AgentApp:
    """A deliberately vulnerable local agent with auditable synthetic actions."""
    def __init__(self):
        self.tool_policy_enabled = False
        self.data_policy_enabled = False
        self.audit_events: list[dict[str, object]] = []

    def enable_tool_policy(self) -> None:
        self.tool_policy_enabled = True

    def enable_data_policy(self) -> None:
        self.data_policy_enabled = True

    def handle(self, request: dict[str, object]) -> dict[str, object]:
        operation = request.get("operation")
        scenario_id = request.get("scenario_id")
        contract = DEMO_CONTRACT if scenario_id == DEMO_CONTRACT.scenario_id else EXFIL_CONTRACT if scenario_id == EXFIL_CONTRACT.scenario_id else None
        fixture = DEMO_FIXTURE if contract is DEMO_CONTRACT else EXFIL_FIXTURE if contract is EXFIL_CONTRACT else None
        if operation == "discover":
            return {"operation": "discover", "target": "local-authorized-agent", "scenarios": [DEMO_CONTRACT.scenario_id, EXFIL_CONTRACT.scenario_id], "policy": "permissive" if not (self.tool_policy_enabled and self.data_policy_enabled) else "explicit-deny"}
        if operation == "remediate" and contract is not None:
            control = RemediationController(self).apply() if contract is DEMO_CONTRACT else RemediationController(self).apply_data_policy()
            return {"operation": "remediate", "scenario_id": contract.scenario_id, "control": control, "applied": True}
        if operation == "attack":
            if contract is None or request.get("fixture_id") != fixture.fixture_id:
                return {"operation": "attack", "attempted": False, "executed": False, "control": "fixture-not-recognized"}
            blocked = self.tool_policy_enabled if contract is DEMO_CONTRACT else self.data_policy_enabled
            event_id = f"{contract.scenario_id}-event-{len(self.audit_events) + 1:02d}"
            event = {
                "event_id": event_id, "scenario_id": contract.scenario_id, "fixture_id": fixture.fixture_id,
                "source_document_id": fixture.document_id, "retrieved_instruction_sha256": fixture.poisoned_instruction_digest,
                "tool": contract.expected_tool, "executed": not blocked, "data_class": contract.synthetic_data_class,
                "secret_marker_sha256": fixture.synthetic_marker_digest if contract is EXFIL_CONTRACT else None,
                "control": "none" if not blocked else ("tool-policy-deny-untrusted-external-actions" if contract is DEMO_CONTRACT else "data-tool-policy-deny-untrusted-sensitive-data-egress"),
            }
            self.audit_events.append(event)
            return {"operation": "attack", "attempted": True, **event}
        if operation == "validate" and contract is not None:
            events = [event for event in self.audit_events if event["scenario_id"] == contract.scenario_id]
            if not events:
                return {"operation": "validate", "scenario_id": contract.scenario_id, "validated": False, "executed": False, "event_count": 0}
            event = events[-1]
            return {"operation": "validate", "scenario_id": contract.scenario_id, "validated": bool(event["executed"]), "executed": event["executed"], "event_count": len(events), "latest_event_id": event["event_id"], "tool": event["tool"], "data_class": event["data_class"], "secret_marker_sha256": event["secret_marker_sha256"], "control": event["control"]}
        return {"error": "unsupported-operation"}

def _handler_for(app: V3AgentApp):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            try:
                size = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(size))
                if not isinstance(request, dict):
                    raise ValueError
                output = app.handle(request)
            except (ValueError, json.JSONDecodeError):
                self.send_error(400)
                return
            body = json.dumps({"output": json.dumps(output, sort_keys=True, separators=(",", ":"))}, separators=(",", ":")).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *_args: object) -> None:
            pass
    return Handler

@contextmanager
def _agent_server(app: V3AgentApp) -> Iterator[HTTPServer]:
    server = HTTPServer(("127.0.0.1", 0), _handler_for(app))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield server
    finally:
        server.shutdown(); server.server_close(); thread.join()

@contextmanager
def _credential() -> Iterator[None]:
    name = "KIMURA_AGENT_DEMO_V3_PLACEHOLDER"; previous = os.environ.get(name); os.environ[name] = _DEMO_V3_CREDENTIAL
    try:
        yield
    finally:
        if previous is None: os.environ.pop(name, None)
        else: os.environ[name] = previous

class _Target:
    def __init__(self, runner: AssessmentRunner): self.runner = runner
    def call(self, operation: str, scenario_id: str | None = None, fixture_id: str | None = None) -> tuple[dict[str, object], str, str]:
        payload = {"operation": operation}
        if scenario_id is not None: payload["scenario_id"] = scenario_id
        if fixture_id is not None: payload["fixture_id"] = fixture_id
        raw = self.runner.run(operation, payload)
        response = json.loads(raw)
        if not isinstance(response, dict): raise RuntimeError("demo target returned invalid structured output")
        return response, digest_text(json.dumps(payload, sort_keys=True)), digest_text(raw)

class DemoV3Report:
    def __init__(self, findings: list[Finding], evidence: list[EvidenceRecord], *, scope: str, remediations_verified: int, failed_retests: int):
        self.assessment_id = DEMO_V3_ASSESSMENT_ID; self.target_identifier = "local authorized agent"; self.scope = scope
        self.findings = findings; self.evidence = evidence; self.remediations_verified = remediations_verified; self.failed_retests = failed_retests
    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1, "assessment_id": self.assessment_id, "target_identifier": self.target_identifier, "scope": self.scope,
            "scenario_count": 2, "findings_count": len(self.findings), "validated_findings": [finding.to_dict() for finding in self.findings],
            "severity": [finding.severity for finding in self.findings], "confidence": [finding.confidence for finding in self.findings],
            "impact_status": ["VALIDATED" if finding.status in {"Validated", "Retest passed"} else "NOT VALIDATED" for finding in self.findings],
            "evidence_references": {finding.finding_id: list(finding.evidence_ids) for finding in self.findings},
            "remediation_status": ["APPLIED" if self.remediations_verified == 2 else "INCOMPLETE" for _ in self.findings],
            "retest_status": ["PASSED" if finding.status == "Retest passed" else "FAILED" for finding in self.findings],
            "lifecycle": ["assessment-started", "scenarios-discovered/selected", "attacks-executed", "impact-validated", "findings-generated", "remediation-applied", "exact-fixtures-retested", "final-assessment-completed"],
            "remediations_verified": self.remediations_verified, "failed_retests": self.failed_retests,
            "overall_assessment_summary": f"{sum(f.status == 'Retest passed' for f in self.findings)} validated findings; {self.remediations_verified} remediations verified; {self.failed_retests} failed retests",
            "evidence": [item.to_dict() for item in self.evidence],
        }
    def to_json(self) -> str: return json.dumps(self.to_dict(), sort_keys=True)
    def terminal_text(self) -> str:
        lines = ["KIMURA AGENT SECURITY ASSESSMENT", "", f"Target: {self.target_identifier}", "Scenarios tested: 2", ""]
        labels = ["Indirect Prompt Injection → Unauthorized Tool Action", "Sensitive Data Exfiltration via Agent Tool"]
        for index, (label, finding) in enumerate(zip(labels, self.findings), 1):
            lines += [f"Finding {index}:", label, "Impact: VALIDATED" if finding.status == "Retest passed" else "Impact: NOT VALIDATED", f"Risk: {finding.severity}", f"Confidence: {finding.confidence}", "Remediation: APPLIED" if self.remediations_verified == 2 else "Remediation: INCOMPLETE", "Retest: PASSED" if finding.status == "Retest passed" else "Retest: FAILED", ""]
        lines += ["Assessment:", f"{sum(f.status == 'Retest passed' for f in self.findings)} validated findings", f"{self.remediations_verified} remediations verified", f"{self.failed_retests} failed retests"]
        return "\n".join(lines)

def run_demo_v3_report(*, persist_path: Path | None = None, report_path: Path | None = None) -> DemoV3Report:
    if report_path is not None and persist_path is None: raise ValueError("report_path requires persist_path")
    app = V3AgentApp(); evidence: list[EvidenceRecord] = []; findings: list[Finding] = []; step = 0
    scenario_data = [(DEMO_CONTRACT, DEMO_FIXTURE, "finding-indirect-tool-action-001", "Indirect Prompt Injection → Unauthorized Tool Action", "indirect-prompt-injection/excessive-agency", "Treat retrieved content as untrusted and deny unauthorized external tool actions."), (EXFIL_CONTRACT, EXFIL_FIXTURE, "finding-sensitive-data-exfiltration-001", "Sensitive Data Exfiltration via Agent Tool", "sensitive-data-exfiltration/excessive-agency", "Require an explicit data/tool policy before any sensitive-data egress.")]
    with _agent_server(app) as server, _credential():
        endpoint = f"http://127.0.0.1:{server.server_port}/agent"; today = date.today()
        contract = AssessmentContract(assessment_id=DEMO_V3_ASSESSMENT_ID, client_name="Kimura local commercial assessment", assessor_name="Kimura Security", authorized_by="local-demo-v3-approval", objectives=("Assess multiple deterministic agent security scenarios",), scope=(f"http://127.0.0.1:{server.server_port}",), start_date=today, end_date=today, credential_references=(DEMO_V3_CREDENTIAL_REFERENCE,), max_requests=13)
        target = HttpTarget(endpoint, "input", "output", DEMO_V3_CREDENTIAL_REFERENCE); client = _Target(AssessmentRunner(contract, target))
        client.call("discover")
        for scenario, fixture, finding_id, title, category, remediation in scenario_data:
            sid = scenario.scenario_id
            def record(phase: str, action: str, outcome: str, control: str, req: str, resp: str, finding_key: str) -> None:
                nonlocal step
                step += 1; observation = ("synthetic-secret-marker-" + EXFIL_FIXTURE.synthetic_marker_digest) if finding_key == "finding-sensitive-data-exfiltration-001" else ("validated-audit-ledger-observation" if phase in {"validate", "retest"} else "bounded-scenario-observation"); evidence.append(EvidenceRecord(1, f"v3-evidence-{step:02d}", DEMO_V3_ASSESSMENT_ID, finding_key, phase, step, observation, req, resp, action, outcome, control))
            attack, req, resp = client.call("attack", sid, fixture.fixture_id); record("attack", scenario.expected_tool, "executed" if attack.get("executed") else "blocked", str(attack.get("control", "none")), req, resp, finding_id)
            validate, req, resp = client.call("validate", sid); record("validate", "audit-ledger-validation", "confirmed" if validate.get("executed") else "not-observed", str(validate.get("control", "none")), req, resp, finding_id)
            finding = RiskEvaluator().evaluate(executed=bool(validate.get("executed")), sensitive_data=validate.get("data_class") == scenario.synthetic_data_class, evidence_ids=(f"v3-evidence-{step-1:02d}", f"v3-evidence-{step:02d}"), finding_id=finding_id, title=title, category=category, impact=f"Audit metadata confirmed {scenario.expected_tool} execution caused by untrusted retrieved content; raw data was not retained.", remediation=remediation)
            _remediated, req, resp = client.call("remediate", sid)
            record("remediation", "apply-data-tool-policy" if scenario is EXFIL_CONTRACT else "apply-tool-policy", "applied", "explicit-policy", req, resp, finding_id)
            retest, req, resp = client.call("attack", sid, fixture.fixture_id); record("retest", scenario.expected_tool, "blocked" if not retest.get("executed") else "executed", str(retest.get("control", "none")), req, resp, finding_id)
            retest_validate, req, resp = client.call("validate", sid); record("retest", "audit-ledger-validation", "passed" if not retest_validate.get("executed") else "failed", str(retest_validate.get("control", "none")), req, resp, finding_id)
            findings.append(Finding(1, finding.finding_id, finding.title, finding.category, finding.severity, finding.confidence, "Retest passed" if not retest_validate.get("executed") else finding.status, finding.impact, finding.remediation, finding.evidence_ids))
    report = DemoV3Report(findings, evidence, scope="loopback-only: 127.0.0.1", remediations_verified=sum(f.status == "Retest passed" for f in findings), failed_retests=sum(f.status != "Retest passed" for f in findings))
    if persist_path is not None:
        store = EvidenceStore(persist_path)
        for item in evidence: store.append(item)
        if report_path is not None: Path(report_path).write_text(report.to_json() + "\n", encoding="utf-8", newline="\n")
    return report

def run_demo_v3(*, persist_path: Path | None = None, report_path: Path | None = None) -> str:
    return run_demo_v3_report(persist_path=persist_path, report_path=report_path).terminal_text()
