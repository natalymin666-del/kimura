"""Deterministic, offline mobile handoff derived from terminal journal evidence."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from html import escape
from typing import Any, Mapping
from urllib.parse import quote, urlsplit, urlunsplit

import qrcode
from qrcode.image.svg import SvgPathImage


class MobileReportError(ValueError):
    """Raised when a truthful terminal mobile report cannot be derived."""


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _payload(evidence: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = evidence.get(key)
    return value if isinstance(value, Mapping) else {}


def _pass_invariants(evidence: Mapping[str, Any]) -> bool:
    baseline = _payload(evidence, "baseline_validated")
    remediation = _payload(evidence, "remediation_verified")
    identity = _payload(evidence, "replay_identity_verified")
    replay = _payload(evidence, "replay_validated")
    cleanup = _payload(evidence, "cleanup_completed")
    return (
        baseline.get("decision") == "allowed"
        and baseline.get("ledger_count") == 1
        and bool(_text(baseline.get("event_id")))
        and bool(_text(remediation.get("policy_id")))
        and remediation.get("policy_digest_before") != remediation.get("policy_digest_after")
        and bool(_text(identity.get("fixture_sha256")))
        and bool(_text(identity.get("action")))
        and replay == {"decision": "blocked", "executed": True, "synthetic_event_id": None, "ledger_count": 1, "baseline_ledger_count": 1}
        and cleanup.get("cleanup_attempted") is True
    )


@dataclass(frozen=True, slots=True)
class MobileReport:
    run_id: str
    status: str
    target_id: str | None
    target_kind: str | None
    protocol_version: int | None
    baseline_fixture_id: str | None
    baseline_fixture_sha256: str | None
    baseline_action: str | None
    baseline_decision: str | None
    baseline_impact_confirmed: bool | None
    baseline_event_id: str | None
    baseline_ledger_count: int | None
    remediation_policy_id: str | None
    policy_digest_before: str | None
    policy_digest_after: str | None
    policy_before: str | None
    policy_after: str | None
    deny_only_verified: bool | None
    replay_fixture_id: str | None
    replay_fixture_sha256: str | None
    replay_identity_verified: bool | None
    replay_decision: str | None
    replay_executed: bool | None
    replay_synthetic_impact_confirmed: bool | None
    final_ledger_count: int | None
    cleanup_status: str
    fix_verified: bool
    failure_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def derive_mobile_report(snapshot: Mapping[str, Any], *, expected_run_id: str | None = None) -> MobileReport:
    """Project one terminal snapshot without inventing unavailable evidence."""

    if not isinstance(snapshot, Mapping):
        raise MobileReportError("snapshot must be an object")
    run_id = _text(snapshot.get("run_id"))
    if run_id is None or (expected_run_id is not None and run_id != expected_run_id):
        raise MobileReportError("snapshot run identity mismatch")
    if snapshot.get("terminal") is not True:
        raise MobileReportError("mobile report requires a terminal snapshot")
    state = snapshot.get("state")
    if state not in {"fix_verified", "assessment_partial", "assessment_failed"}:
        raise MobileReportError("unsupported terminal snapshot state")
    evidence = snapshot.get("evidence")
    if not isinstance(evidence, Mapping):
        raise MobileReportError("snapshot evidence must be an object")

    target = _payload(evidence, "target_verified")
    baseline = _payload(evidence, "baseline_validated")
    remediation = _payload(evidence, "remediation_verified")
    identity = _payload(evidence, "replay_identity_verified")
    replay = _payload(evidence, "replay_validated")
    cleanup = _payload(evidence, "cleanup_completed")
    failure_event = _payload(evidence, state)
    fix_verified = state == "fix_verified" and _pass_invariants(evidence)
    status = "PASS" if fix_verified else "PARTIAL" if state == "assessment_partial" else "FAILED"
    baseline_event_id = _text(baseline.get("event_id"))
    baseline_impact = True if baseline_event_id else None
    deny_only = None
    if remediation:
        deny_only = bool(_text(remediation.get("policy_id")) and remediation.get("policy_digest_before") != remediation.get("policy_digest_after"))
    replay_identity = None
    if identity:
        replay_identity = bool(_text(identity.get("fixture_id")) and _text(identity.get("fixture_sha256")) and _text(identity.get("action")))
    replay_impact = None
    if replay:
        replay_impact = False if replay.get("decision") == "blocked" and replay.get("executed") is True and replay.get("synthetic_event_id") is None else True if replay.get("synthetic_event_id") else None
    cleanup_status = "COMPLETED" if cleanup.get("cleanup_attempted") is True else "NOT ESTABLISHED"
    failure_reason = _text(failure_event.get("failure_code")) or ("fix_verified invariants not proven" if state == "fix_verified" and not fix_verified else None)
    protocol = target.get("protocol_version")
    return MobileReport(
        run_id=run_id,
        status=status,
        target_id=_text(target.get("target_id")),
        target_kind=_text(target.get("target_kind")),
        protocol_version=protocol if isinstance(protocol, int) and not isinstance(protocol, bool) else None,
        baseline_fixture_id=_text(baseline.get("fixture_id")),
        baseline_fixture_sha256=_text(baseline.get("fixture_sha256")),
        baseline_action=_text(baseline.get("action")),
        baseline_decision=_text(baseline.get("decision")),
        baseline_impact_confirmed=baseline_impact,
        baseline_event_id=baseline_event_id,
        baseline_ledger_count=_count(baseline.get("ledger_count")),
        remediation_policy_id=_text(remediation.get("policy_id")),
        policy_digest_before=_text(remediation.get("policy_digest_before")) or _text(target.get("policy_digest_before")),
        policy_digest_after=_text(remediation.get("policy_digest_after")),
        policy_before=(f"{_text(baseline.get("action"))}=permit" if _text(baseline.get("action")) else None),
        policy_after=(f"{_text(baseline.get("action"))}=deny" if _text(baseline.get("action")) and _text(remediation.get("policy_digest_after")) else None),
        deny_only_verified=deny_only,
        replay_fixture_id=_text(identity.get("fixture_id")),
        replay_fixture_sha256=_text(identity.get("fixture_sha256")),
        replay_identity_verified=replay_identity,
        replay_decision=_text(replay.get("decision")),
        replay_executed=replay.get("executed") if isinstance(replay.get("executed"), bool) else None,
        replay_synthetic_impact_confirmed=replay_impact,
        final_ledger_count=_count(replay.get("ledger_count")) if replay else None,
        cleanup_status=cleanup_status,
        fix_verified=fix_verified,
        failure_reason=failure_reason,
    )


def build_mobile_report_url(base_url: str, run_id: str, *, allow_loopback: bool = True) -> str:
    """Build the deterministic read-only URL for one exact assessment run."""

    parsed = urlsplit(base_url)
    hostname = parsed.hostname
    if parsed.scheme != "http" or not hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base_url must be a query-free HTTP URL with an explicit host")
    if hostname in {"0.0.0.0", "::", "[::]"}:
        raise ValueError("base_url must not use a wildcard host")
    if not allow_loopback and hostname in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("QR handoff must use an explicit LAN host")
    if not run_id or "/" in run_id:
        raise ValueError("run_id is invalid")
    return urlunsplit((parsed.scheme, parsed.netloc, f"/report/{quote(run_id, safe='')}", "", ""))


def build_qr_data_uri(mobile_report_url: str) -> str:
    """Generate a fully offline SVG QR image for an explicit LAN report URL."""

    parsed = urlsplit(mobile_report_url)
    if parsed.scheme != "http" or parsed.hostname in {None, "127.0.0.1", "localhost", "::1", "0.0.0.0", "::", "[::]"}:
        raise ValueError("QR payload must use an explicit LAN HTTP host")
    if not parsed.path.startswith("/report/") or parsed.query or parsed.fragment:
        raise ValueError("QR payload must point only to the read-only report route")
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=4, image_factory=SvgPathImage)
    qr.add_data(mobile_report_url)
    qr.make(fit=True)
    svg = qr.make_image().to_string()
    return "data:image/svg+xml;base64," + base64.b64encode(svg).decode("ascii")


def _display(value: Any) -> str:
    if value is None or value == "":
        return "UNAVAILABLE"
    return escape(str(value), quote=True)


def render_mobile_report_html(report: MobileReport) -> str:
    """Render a self-contained, mobile-first report with no network assets."""

    status = escape(report.status, quote=True)
    before = _display(report.baseline_decision.upper() if report.baseline_decision else None)
    after = _display(report.replay_decision.upper() if report.replay_decision else None)
    identity = "SAME FIXTURE ✓ · SHA-256 MATCHED" if report.replay_identity_verified else "SAME FIXTURE · NOT VERIFIED"
    replay_impact = "NO SYNTHETIC IMPACT" if report.replay_synthetic_impact_confirmed is False else "IMPACT CONFIRMED" if report.replay_synthetic_impact_confirmed is True else "IMPACT NOT ESTABLISHED"
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#070a0f"><title>Kimura · Mobile Report</title><style>:root{{color-scheme:dark;--ink:#f4f7fb;--muted:#98a4b5;--line:#273241;--surface:#111a25;--cyan:#69d7e8;--green:#73e0a2;--amber:#f2be68;--red:#ff7c86}}*{{box-sizing:border-box}}body{{margin:0;background:#070a0f;color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}main{{width:min(100%,680px);margin:auto;padding:20px;display:grid;gap:18px}}header{{display:flex;justify-content:space-between;gap:12px;align-items:start}}.brand{{font-weight:900;letter-spacing:.18em}}.sub,.label,footer{{color:var(--muted);font-size:11px;letter-spacing:.12em;text-transform:uppercase}}.status{{border:1px solid var(--{('green' if report.status == 'PASS' else 'amber' if report.status == 'PARTIAL' else 'red')});color:var(--{('green' if report.status == 'PASS' else 'amber' if report.status == 'PARTIAL' else 'red')});border-radius:999px;padding:6px 10px;font-weight:800;letter-spacing:.12em}}section,details{{border:1px solid var(--line);border-radius:14px;background:var(--surface);padding:18px}}h1,h2,p{{margin:0}}h1{{overflow-wrap:anywhere}}h1{{font-size:clamp(28px,9vw,50px);line-height:1;letter-spacing:-.06em}}h2{{font-size:16px;letter-spacing:.12em}}.target{{color:var(--cyan);font-weight:800}}.story{{display:grid;grid-template-columns:1fr 28px 1fr;gap:10px;align-items:stretch}}.state{{padding:14px;border:1px solid var(--line);border-radius:10px}}.before{{border-color:#70552d}}.after{{border-color:#2e6d50}}.decision{{font-size:24px;font-weight:900;margin-top:10px}}.before .decision{{color:var(--amber)}}.after .decision{{color:var(--green)}}.arrow{{align-self:center;text-align:center;color:var(--cyan);font-size:24px}}.proof{{grid-column:1/-1;color:var(--cyan);font-weight:800;font-size:12px;letter-spacing:.08em;text-transform:uppercase}}dl{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.4fr);gap:9px 14px;margin:0}}dt{{color:var(--muted);font-size:12px}}dd{{margin:0;overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}}footer{{line-height:1.6;overflow-wrap:anywhere}}@media(max-width:600px){{main{{padding:15px}}.story{{grid-template-columns:1fr}}.arrow{{transform:rotate(90deg)}}dl{{grid-template-columns:1fr}}}}</style></head><body><main data-run-id="{escape(report.run_id, quote=True)}"><header><div><div class="brand">KIMURA</div><div class="sub">Mobile assessment handoff</div></div><div class="status">{status}</div></header><section><div class="label">Exact assessment run</div><h1>{_display(report.run_id)}</h1><p class="target">{_display(report.target_id)} · {_display(report.target_kind)} · protocol {_display(report.protocol_version)}</p></section><section><div class="label">Before → after security story</div><div class="story"><div class="state before"><h2>BEFORE</h2><div class="decision">{before}</div><p>{_display("SYNTHETIC IMPACT CONFIRMED" if report.baseline_impact_confirmed is True else "IMPACT NOT ESTABLISHED")}</p></div><div class="arrow">→</div><div class="state after"><h2>EXACT REPLAY</h2><div class="decision">{after}</div><p>{_display(replay_impact)}</p></div><div class="proof">{_display(identity)}</div></div></section><section><div class="label">Remediation and outcome</div><p>{_display("DENY-ONLY VERIFIED" if report.deny_only_verified is True else "DENY-ONLY NOT ESTABLISHED")}</p><p>{_display("FIX VERIFIED" if report.fix_verified else report.status)}</p></section><details><summary>Evidence · runtime-derived facts</summary><dl><dt>Target ID</dt><dd>{_display(report.target_id)}</dd><dt>Baseline action</dt><dd>{_display(report.baseline_action)}</dd><dt>Baseline event</dt><dd>{_display(report.baseline_event_id)}</dd><dt>Baseline ledger</dt><dd>{_display(report.baseline_ledger_count)}</dd><dt>Policy</dt><dd>{_display(report.policy_after)}</dd><dt>Policy before</dt><dd>{_display(report.policy_before)}</dd><dt>Policy after</dt><dd>{_display(report.policy_after)}</dd><dt>Replay executed</dt><dd>{_display(report.replay_executed)}</dd><dt>Final ledger</dt><dd>{_display(report.final_ledger_count)}</dd><dt>Cleanup</dt><dd>{_display(report.cleanup_status)}</dd><dt>Failure reason</dt><dd>{_display(report.failure_reason)}</dd></dl></details><footer>Owned isolated synthetic target · no real external action occurred · offline report</footer></main></body></html>'''
