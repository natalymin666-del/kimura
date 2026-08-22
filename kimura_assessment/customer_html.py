"""Customer-facing static HTML presentation for Customer Assessment v1."""

from __future__ import annotations

from html import escape
import json
from typing import Iterable


def _value(value: object) -> str:
    if isinstance(value, (dict, list)):
        return escape(json.dumps(value, sort_keys=True, indent=2))
    return escape(str(value))


def _customer_text(value: object) -> str:
    text = str(value)
    return (text.replace("The model proposal, policy decision, synthetic execution, and validated impact were recorded as separate stages. Impact was validated only from local synthetic audit metadata.", "The model proposal, tool authorization decision, local simulated tool execution, and impact confirmation were recorded as separate stages. Impact was confirmed only from the local audit record.")
                .replace("Explicit action gate", "Explicit tool authorization policy")
                .replace("Action-gate", "Tool authorization")
                .replace("action-gate", "tool authorization policy")
                .replace("Synthetic execution", "Local simulated tool execution")
                .replace("synthetic execution", "local simulated tool execution")
                .replace("validated impact", "impact confirmed from the local audit record")
                .replace("was validated from audit metadata", "was confirmed from the local audit record")
                .replace("local synthetic audit metadata", "local audit record"))


def _list(values: Iterable[object], *, translate: bool = False) -> str:
    return "<ul>" + "".join(f"<li>{_value(_customer_text(value) if translate else value)}</li>" for value in values) + "</ul>"


def _status(label: str, value: str, kind: str) -> str:
    return f'<div class="status-card {kind}"><div class="label">{label}</div><div class="status-value">{_value(value)}</div></div>'


def _phase(value: str) -> str:
    return {"preflight": "Preflight", "baseline": "Baseline trial", "remediation": "Remediation", "retest": "Retest trial"}.get(value, value)


def _action(value: str) -> str:
    return {"send_email": "Synthetic tool proposal", "target-discovery": "Target discovery", "apply-tool-policy": "Tool authorization policy remediation", "audit-ledger-validation": "Local audit record check", "no-action": "No tool proposal"}.get(value, value)


def _outcome(value: str) -> str:
    return {"impact-validated": "Impact confirmed from the local audit record", "impact-not-validated": "Impact not confirmed", "confirmed": "Confirmed", "applied": "Applied", "blocked": "Blocked by the tested policy"}.get(value, value)


def _conclusion(finding: dict[str, object], retest: dict[str, object]) -> str:
    title = str(finding.get("title", "A tested security condition"))
    baseline = int(retest["baseline"].get("validated_impact_count", 0))
    after = int(retest["retest"].get("validated_impact_count", 0))
    if baseline and not after:
        return f"Kimura observed {title.lower()} under the tested baseline configuration; the tested policy remediation prevented validated impact during exact-fixture replay."
    if baseline:
        return f"Kimura observed {title.lower()} under the tested baseline configuration; validated impact remained present during the tested retest."
    return "Kimura did not validate impact under the tested baseline conditions; the result remains limited to the stated model, runtime, fixture, policy, and trial conditions."


def _evidence_rows(evidence: Iterable[object]) -> str:
    rows = []
    for item in evidence:
        request = getattr(item, "request_sha256", "")
        response = getattr(item, "response_sha256", "")
        rows.append(
            "<tr>"
            f"<td>{_value(_phase(getattr(item, 'phase', '')))}</td>"
            f"<td><code>{_value(getattr(item, 'evidence_id', ''))}</code></td>"
            f"<td>{_value(_action(getattr(item, 'action', '')))}</td>"
            f"<td>{_value(_outcome(getattr(item, 'outcome', '')))}</td>"
            f"<td>request {escape(request[:16])}…<br>response {escape(response[:16])}…</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="5">No evidence records available.</td></tr>'


def render_customer_report(report: dict[str, object], evidence: Iterable[object] | None = None) -> str:
    assessment = report["assessment"]
    authorization = report["authorization"]
    scope = report["scope"]
    environment = report["environment"]
    finding = report["findings"][0]
    retest = report["retest_results"]
    baseline_risk = str(finding.get("severity", "Not observed")).upper()
    remediation = "APPLIED" if report["remediation"].get("status") == "applied-and-tested" else "NOT APPLIED"
    retest_status = {"passed": "PASSED", "failed": "FAILED"}.get(str(retest.get("status")), "NOT RUN")
    baseline_outcome = {"stable-vulnerable": "Impact observed in all baseline trials", "stable-blocked": "Impact blocked in all baseline trials", "flaky-model-or-policy": "Mixed baseline result"}.get(retest["baseline"]["outcome"], retest["baseline"]["outcome"])
    retest_outcome = {"stable-vulnerable": "Impact observed in all retest trials", "stable-blocked": "Impact blocked in all retest trials", "flaky-model-or-policy": "Mixed retest result"}.get(retest["retest"]["outcome"], retest["retest"]["outcome"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kimura Customer Assessment - {_value(assessment['assessment_id'])}</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#f4f6f8;color:#1f2933;font:15px/1.55 Arial,sans-serif}}main{{max-width:1120px;margin:auto;padding:36px 24px}}header{{background:#102a43;color:#fff;padding:30px;border-radius:10px;margin-bottom:20px}}h1{{margin:0 0 6px;font-size:30px}}h2{{color:#102a43;border-bottom:1px solid #d9e2ec;padding-bottom:8px;margin:32px 0 12px}}h3{{color:#243b53}}.card{{background:#fff;border:1px solid #d9e2ec;border-radius:8px;padding:18px 20px;margin:12px 0;box-shadow:0 1px 2px #102a4312}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}}.label{{color:#627d98;font-size:11px;text-transform:uppercase;letter-spacing:.07em}}.value{{font-weight:600}}.status-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0}}.status-card{{background:#fff;border-radius:8px;padding:14px 16px;border-left:5px solid #829ab1;box-shadow:0 1px 2px #102a4312}}.status-card.baseline{{border-left-color:#d64545}}.status-card.remediation,.status-card.retest{{border-left-color:#268c63}}.status-value{{font-size:21px;font-weight:700;margin-top:3px;color:#102a43}}.conclusion{{font-size:17px;line-height:1.5;margin:14px 0 0}}.callout{{background:#fff8e6;border:1px solid #f0c36d;border-left:5px solid #d99a16;border-radius:8px;padding:16px 18px}}.severity-high{{color:#a23b1a;font-weight:700}}.status-pill{{display:inline-block;border-radius:14px;padding:4px 11px;font-weight:700;background:#d9f2e6;color:#146b46}}table{{border-collapse:collapse;width:100%;font-size:14px}}td,th{{border-bottom:1px solid #d9e2ec;padding:9px;text-align:left;vertical-align:top}}th{{color:#486581;font-size:11px;text-transform:uppercase;letter-spacing:.04em}}.table-wrap{{overflow-x:auto}}code{{font-family:Consolas,monospace;font-size:12px}}footer{{color:#627d98;font-size:12px;margin-top:34px}}@media print{{body{{background:#fff}}main{{max-width:none;padding:0}}header{{border-radius:0;print-color-adjust:exact}}.card,.status-card{{box-shadow:none}}.card{{break-inside:avoid}}.table-wrap{{overflow:visible}}}}
</style></head><body><main>
<header><div class="label" style="color:#9fb3c8">KIMURA SECURITY</div><h1>Customer Assessment v1</h1><div>{_value(assessment['client_name'])} · {_value(assessment['assessment_id'])}</div><p class="conclusion">{_conclusion(finding, retest)}</p></header>
<div class="status-grid">{_status('Baseline risk', baseline_risk, 'baseline')} {_status('Remediation', remediation, 'remediation')} {_status('Retest', retest_status, 'retest')}</div>
<section><h2>Assessment at a Glance</h2><div class="card"><div class="grid"><div><div class="label">Assessment ID</div><div class="value">{_value(assessment['assessment_id'])}</div></div><div><div class="label">Customer</div><div class="value">{_value(assessment['client_name'])}</div></div><div><div class="label">Assessor</div><div class="value">{_value(assessment['assessor'])}</div></div><div><div class="label">Assessment dates</div><div class="value">{_value(assessment['start_date'])} to {_value(assessment['end_date'])}</div></div><div><div class="label">Model / runtime</div><div class="value">{_value(environment['model_id'])} / Ollama local</div></div><div><div class="label">Scenario</div><div class="value">{_value(report['selected_scenarios'][0])}</div></div><div><div class="label">Trials</div><div class="value">{_value(finding['trial_count'])} baseline + {_value(retest['retest']['trial_count'])} retest</div></div><div><div class="label">Authorization</div><div class="value">Authorized contract validated</div></div><div><div class="label">Scope / allowed target</div><div class="value">{_value(scope['scope'])} / {_value(scope['target_id'])}</div></div></div></div></section>
<section><h2>Executive Summary</h2><div class="card"><p>This bounded assessment tested one explicitly selected indirect prompt-injection scenario against the configured local model runtime. The baseline produced a finding under the tested conditions; an explicit local policy remediation was applied and the identical fixture was retested.</p></div></section>
<section><h2>Interpretation &amp; Limitations</h2><div class="callout"><p>Results apply only to the tested model, runtime, configuration, fixture, policy, and trial conditions. A model proposal is not automatically validated impact. Local simulated tool execution is not production impact. These findings do not establish universal vulnerability across a model family. Remediation results apply only to the tested policy and exact-fixture replay.</p></div></section>
<section><h2>Scope</h2><div class="card"><div class="grid"><div><div class="label">Allowed target</div><div class="value">{_value(scope['target_id'])}</div></div><div><div class="label">Target type</div><div class="value">{_value(scope['target_type'])}</div></div><div><div class="label">Scope</div><div class="value">{_value(scope['scope'])}</div></div><div><div class="label">Dates</div><div class="value">{_value(assessment['start_date'])} to {_value(assessment['end_date'])}</div></div></div></div></section>
<section><h2>Authorization</h2><div class="card"><p>{_value(authorization['statement'])}</p><p><strong>Reference:</strong> {_value(authorization['reference'])}</p><p><strong>Exclusions:</strong></p>{_list(authorization['exclusions'])}</div></section>
<section><h2>Methodology</h2><div class="card"><p>Kimura ran the selected scenario through the existing authorization, scope, date-window, request-budget, and tool authorization policy controls. The model proposal, local simulated tool execution, remediation, and exact-fixture retest were recorded as separate stages. No automatic scenario expansion or hidden retries were used.</p></div></section>
<section><h2>Environment / Model Under Test</h2><div class="card"><table><tr><th>Provider</th><td>Ollama (local)</td></tr><tr><th>Model</th><td>{_value(environment['model_id'])}</td></tr><tr><th>Endpoint class</th><td>Loopback-only</td></tr><tr><th>Tools</th><td>Local simulated tools only</td></tr></table></div></section>
<section><h2>Findings Summary</h2><div class="card"><table><tr><th>ID</th><th>Title</th><th>Baseline risk</th><th>Status</th><th>Retest</th></tr><tr><td><code>{_value(finding['finding_id'])}</code></td><td>{_value(finding['title'])}</td><td class="severity-high">{_value(baseline_risk)}</td><td>{_value(finding['status'])}</td><td><span class="status-pill">{_value(retest_status)}</span></td></tr></table></div></section>
<section><h2>Detailed Findings</h2><div class="card"><h3>{_value(finding['title'])}</h3><p><strong>Category:</strong> {_value(finding['category'])} · <strong>Confidence:</strong> {_value(finding['confidence'])}</p><p>{_value(_customer_text(finding['impact']))}</p><h3>Observed safe facts</h3>{_list(finding['observed_safe_facts'], translate=True)}<h3>Trial results</h3><div class="table-wrap"><table><tr><th>Trials</th><th>Model proposals</th><th>Tool authorization decisions</th><th>Local simulated tool execution</th><th>Impact confirmed from local audit record</th></tr><tr><td>{_value(finding['trial_count'])}</td><td>{_value(finding['proposal_count'])}</td><td>{_value(finding['gate_decisions'])}</td><td>{_value(retest['baseline']['synthetic_execution_count'])}</td><td>{_value(finding['validated_synthetic_impact'])}</td></tr></table></div></div></section>
<section><h2>Evidence Summary</h2><div class="card"><p>Evidence contains safe classifications and digests only. Raw prompts, retrieved documents, provider responses, credentials, secrets, and sensitive tool arguments were not retained.</p><div class="table-wrap"><table><tr><th>Phase</th><th>Evidence ID</th><th>Event type</th><th>Outcome</th><th>Digest reference</th></tr>{_evidence_rows(evidence or ())}</table></div></div></section>
<section><h2>Remediation</h2><div class="card"><p><strong>Recommendation:</strong> {_value(finding['remediation'])}</p><p><strong>Policy tested:</strong> Deny untrusted external actions</p><p><strong>Production system modified:</strong> {_value(report['remediation']['production_system_modified'])}</p></div></section>
<section><h2>Retest Results</h2><div class="card"><p><strong>Status:</strong> {_value(retest_status)}. The exact same fixture and trial seeds were replayed after remediation.</p><div class="table-wrap"><table><tr><th>Stage</th><th>Model proposals</th><th>Local simulated executions</th><th>Impact confirmed from local audit record</th><th>Outcome</th></tr><tr><td>Baseline</td><td>{_value(retest['baseline']['proposal_count'])}</td><td>{_value(retest['baseline']['synthetic_execution_count'])}</td><td>{_value(retest['baseline']['validated_impact_count'])}</td><td>{_value(baseline_outcome)}</td></tr><tr><td>Retest</td><td>{_value(retest['retest']['proposal_count'])}</td><td>{_value(retest['retest']['synthetic_execution_count'])}</td><td>{_value(retest['retest']['validated_impact_count'])}</td><td>{_value(retest_outcome)}</td></tr></table></div></div></section>
<section><h2>Residual Risk</h2><div class="card"><p>{_value(report['residual_risk'])}</p></div></section>
<section><h2>Limitations</h2><div class="card">{_list(report['limitations'])}</div></section>
<section><h2>Assessment Integrity / Safety Controls</h2><div class="card">{_list(report['integrity_and_safety_controls'], translate=True)}</div></section>
<footer>Prepared by {_value(assessment['assessor'])}. Report schema version {_value(report['schema_version'])}. This report is self-contained and intended for offline review.</footer>
</main></body></html>
"""