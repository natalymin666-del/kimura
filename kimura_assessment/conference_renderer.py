"""Offline deterministic HTML renderer for the Kimura conference shell."""

from __future__ import annotations

from html import escape
from typing import Any, Mapping

from .conference_view_model import ConferenceViewModel, derive_view_model


def _value(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return escape(str(value), quote=True)


def _story(vm: ConferenceViewModel) -> str:
    items = []
    for item in vm.story:
        items.append(
            f'<li class="story-step story-{_value(item["state"])}" data-state="{_value(item["state"])}">'
            f'<span class="story-dot" aria-hidden="true"></span><span>{_value(item["label"])}</span></li>'
        )
    return "".join(items)


def _status_class(vm: ConferenceViewModel) -> str:
    return {"PASS": "is-pass", "PARTIAL": "is-partial", "FAILED": "is-failed"}[vm.display_status]


def render_conference_html(result: Mapping[str, Any]) -> str:
    """Render a complete offline presentation from one serialized result."""

    vm = derive_view_model(result)
    action = _value(vm.action)
    status_label = _value(vm.display_status)
    target_label = "Raspberry Pi 5" if vm.target_kind == "owned-isolated-synthetic-target" else vm.target_kind
    replay_note = "Action blocked, no ledger event created." if vm.replay_impact_label == "NO SYNTHETIC IMPACT" else "Replay impact was not established."
    verified_copy = "Exact replay verified under the deny-only remediation." if vm.fix_verified else (_value(vm.failure_reason) or "Verification incomplete.")
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kimura · Physical Assessment</title>
<style>
:root {{ color-scheme: dark; --ink:#f4f7fb; --muted:#8d99aa; --line:#263140; --surface:#101722; --surface-2:#151f2c; --cyan:#69d7e8; --green:#73e0a2; --amber:#f2be68; --red:#ff7c86; --violet:#a88cf5; }}
* {{ box-sizing:border-box; }}
html,body {{ margin:0; min-height:100%; background:#070a0f; color:var(--ink); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
body {{ min-height:100vh; }}
button {{ font:inherit; }}
.shell {{ min-height:100vh; padding:clamp(22px,4vw,56px); display:grid; grid-template-rows:auto 1fr auto; gap:clamp(24px,4vh,54px); background:radial-gradient(circle at 72% 15%,#122032 0,transparent 35%),#070a0f; }}
.topbar,.footer {{ display:flex; align-items:center; justify-content:space-between; gap:20px; }}
.brand {{ letter-spacing:.22em; font-size:clamp(15px,1.25vw,19px); font-weight:800; }}
.brand span {{ color:var(--cyan); }}
.eyebrow {{ color:var(--muted); font-size:11px; letter-spacing:.17em; text-transform:uppercase; }}
.status-chip {{ border:1px solid var(--line); padding:8px 13px; border-radius:999px; font-size:12px; letter-spacing:.12em; font-weight:800; }}
.is-pass .status-chip {{ color:var(--green); border-color:#2b684b; }} .is-partial .status-chip {{ color:var(--amber); border-color:#765628; }} .is-failed .status-chip {{ color:var(--red); border-color:#77363d; }}
.content {{ width:min(1500px,100%); margin:auto; display:grid; gap:clamp(22px,3vw,42px); align-content:center; }}
.target-row {{ display:grid; grid-template-columns:minmax(280px,.85fr) minmax(0,2fr); gap:clamp(20px,3vw,44px); align-items:stretch; }}
.target-card,.evidence-drawer {{ background:linear-gradient(145deg,rgba(21,31,44,.96),rgba(11,16,24,.96)); border:1px solid var(--line); border-radius:18px; }}
.target-card {{ padding:clamp(22px,2.8vw,42px); position:relative; overflow:hidden; }}
.target-card:before {{ content:""; position:absolute; inset:0 auto 0 0; width:3px; background:var(--cyan); }}
.target-card h1 {{ margin:10px 0 24px; font-size:clamp(28px,3.2vw,54px); line-height:.98; letter-spacing:-.045em; }}
.target-meta {{ display:grid; gap:11px; color:var(--muted); font-size:13px; }}
.target-meta strong {{ color:var(--ink); font-weight:600; display:block; margin-top:3px; overflow-wrap:anywhere; }}
.connected {{ display:inline-flex; align-items:center; gap:8px; color:var(--green); font-size:12px; letter-spacing:.12em; text-transform:uppercase; font-weight:800; }}
.connected:before {{ content:""; width:8px; height:8px; border-radius:50%; background:var(--green); box-shadow:0 0 15px var(--green); }}
.is-failed .connected,.is-partial .connected {{ color:var(--amber); }} .is-failed .connected:before,.is-partial .connected:before {{ background:var(--amber); box-shadow:0 0 15px var(--amber); }}
.story-card {{ display:grid; align-content:center; gap:24px; }}
.story-title {{ margin:0; font-size:clamp(18px,1.8vw,27px); letter-spacing:-.03em; }}
.story-list {{ list-style:none; padding:0; margin:0; display:flex; align-items:center; gap:0; }}
.story-step {{ display:flex; align-items:center; gap:9px; color:var(--muted); font-size:clamp(11px,1vw,14px); white-space:nowrap; }}
.story-step:not(:last-child):after {{ content:""; width:clamp(18px,3vw,62px); height:1px; background:var(--line); margin:0 12px; }}
.story-dot {{ width:10px; height:10px; border:2px solid var(--line); border-radius:50%; flex:none; }}
.story-complete {{ color:var(--ink); }} .story-complete .story-dot {{ border-color:var(--green); background:var(--green); }}
.story-failed {{ color:var(--red); }} .story-failed .story-dot {{ border-color:var(--red); }}
.transformation {{ display:grid; grid-template-columns:1fr 110px 1fr; gap:clamp(12px,2vw,28px); align-items:center; }}
.transform-card {{ min-height:190px; padding:clamp(20px,2.5vw,35px); border-radius:16px; border:1px solid var(--line); background:var(--surface); display:flex; flex-direction:column; justify-content:space-between; }}
.transform-card.before {{ border-color:#70552d; }} .transform-card.after {{ border-color:#2e6d50; }}
.transform-card h2 {{ margin:0; font-size:clamp(14px,1.25vw,18px); letter-spacing:.15em; }}
.action {{ margin:14px 0 0; font-size:clamp(28px,3.1vw,54px); letter-spacing:-.06em; font-weight:750; overflow-wrap:anywhere; }}
.decision {{ margin-top:17px; font-size:clamp(18px,2vw,30px); letter-spacing:.08em; font-weight:850; }}
.before .decision {{ color:var(--amber); }} .after .decision {{ color:var(--green); }}
.impact {{ color:var(--muted); font-size:12px; letter-spacing:.08em; text-transform:uppercase; margin-top:10px; }}
.arrow {{ color:var(--violet); text-align:center; font-size:28px; }} .arrow small {{ display:block; color:var(--muted); font-size:10px; letter-spacing:.13em; text-transform:uppercase; margin-top:8px; }}
.replay-proof {{ grid-column:1 / -1; display:flex; align-items:center; justify-content:center; gap:14px; flex-wrap:wrap; color:var(--muted); font-size:12px; letter-spacing:.1em; text-transform:uppercase; }}
.replay-proof strong {{ color:var(--cyan); }} .hash {{ color:var(--ink); font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:11px; letter-spacing:0; overflow-wrap:anywhere; }}
.evidence-drawer {{ padding:0; overflow:hidden; }}
.evidence-drawer summary {{ cursor:pointer; list-style:none; padding:15px 20px; color:var(--muted); font-size:12px; letter-spacing:.14em; text-transform:uppercase; }}
.evidence-drawer summary::-webkit-details-marker {{ display:none; }} .evidence-drawer summary:after {{ content:"＋"; float:right; color:var(--cyan); }} .evidence-drawer[open] summary:after {{ content:"－"; }}
.evidence-grid {{ border-top:1px solid var(--line); padding:20px; display:grid; grid-template-columns:repeat(4,1fr); gap:18px; }}
.evidence-item {{ min-width:0; }} .evidence-item label {{ color:var(--muted); display:block; font-size:10px; letter-spacing:.13em; text-transform:uppercase; margin-bottom:7px; }} .evidence-item code {{ color:var(--ink); font:11px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; overflow-wrap:anywhere; }}
.final-state {{ display:flex; align-items:center; justify-content:space-between; gap:20px; border-top:1px solid var(--line); padding-top:20px; }}
.final-state h2 {{ margin:0; font-size:clamp(28px,4.5vw,76px); letter-spacing:-.07em; }} .is-pass .final-state h2 {{ color:var(--green); }} .is-partial .final-state h2 {{ color:var(--amber); }} .is-failed .final-state h2 {{ color:var(--red); }}
.final-copy {{ max-width:520px; color:var(--muted); font-size:14px; line-height:1.5; }}
.footer {{ color:var(--muted); font-size:11px; letter-spacing:.08em; text-transform:uppercase; }}
.footer strong {{ color:var(--ink); }}
@media (max-width:900px) {{ .target-row {{ grid-template-columns:1fr; }} .story-list {{ overflow:auto; padding-bottom:7px; }} .transformation {{ grid-template-columns:1fr; }} .arrow {{ transform:rotate(90deg); }} .evidence-grid {{ grid-template-columns:repeat(2,1fr); }} }}
@media (max-width:560px) {{ .shell {{ padding:18px; gap:24px; }} .topbar,.footer,.final-state {{ align-items:flex-start; flex-direction:column; }} .target-card h1 {{ font-size:38px; }} .evidence-grid {{ grid-template-columns:1fr; }} .story-step:not(:last-child):after {{ width:18px; margin:0 7px; }} }}

.shell {{ padding:clamp(18px,2.3vw,36px) clamp(22px,3.2vw,52px); gap:clamp(18px,2.4vh,32px); }}
.brand {{ letter-spacing:.2em; font-size:clamp(22px,2.1vw,34px); line-height:1; font-weight:900; }}
.brand-sub {{ margin-top:8px; color:var(--muted); font-size:clamp(10px,.85vw,13px); letter-spacing:.16em; font-weight:700; }}
.content {{ width:min(1740px,100%); gap:clamp(16px,2vw,30px); align-content:stretch; }}
.target-row {{ grid-template-columns:minmax(300px,.68fr) minmax(0,2.32fr); gap:clamp(18px,2.6vw,42px); }}
.target-card {{ padding:clamp(28px,3.2vw,52px); min-height:clamp(360px,48vh,570px); }}
.target-card h1 {{ margin:14px 0 30px; font-size:clamp(42px,5vw,84px); line-height:.9; letter-spacing:-.065em; }}
.target-label {{ color:var(--cyan); font-size:clamp(16px,1.35vw,22px); line-height:1.2; font-weight:800; letter-spacing:-.02em; }}
.target-owner {{ margin-top:8px; color:var(--muted); font-size:clamp(11px,.95vw,14px); letter-spacing:.08em; text-transform:uppercase; }}
.identity {{ margin-top:13px; color:var(--green); font-size:clamp(12px,1vw,15px); letter-spacing:.12em; font-weight:850; }}
.story-card {{ align-content:stretch; gap:clamp(14px,1.5vw,24px); }}
.story-title {{ font-size:clamp(20px,2.2vw,34px); letter-spacing:-.045em; }}
.story-step {{ font-size:clamp(12px,1.05vw,16px); }}
.transformation {{ grid-template-columns:minmax(0,1fr) clamp(72px,7vw,130px) minmax(0,1fr); gap:clamp(14px,2vw,30px); }}
.transform-card {{ min-height:clamp(260px,32vh,390px); padding:clamp(28px,3.2vw,48px); border-radius:18px; }}
.transform-card h2 {{ font-size:clamp(16px,1.45vw,23px); }}
.action {{ font-size:clamp(38px,5.1vw,86px); letter-spacing:-.075em; font-weight:850; }}
.decision {{ font-size:clamp(28px,3.5vw,62px); letter-spacing:.055em; font-weight:950; }}
.impact {{ font-size:clamp(12px,1vw,16px); }}
.arrow {{ font-size:clamp(38px,5vw,72px); }}
.replay-proof {{ gap:clamp(12px,1.8vw,26px); font-size:clamp(13px,1.1vw,17px); }}
.replay-proof .hash {{ display:none; }}
.final-state {{ padding-top:18px; }}
.final-state h2 {{ font-size:clamp(34px,4.8vw,82px); }}
.final-copy {{ max-width:580px; font-size:clamp(13px,1.1vw,17px); }}
@media (max-width:900px) {{ .target-card {{ min-height:0; }} }}

</style>
</head>
<body>
<main class="shell {_status_class(vm)}" data-assessment-status="{_value(vm.display_status)}">
  <header class="topbar">
    <div><div class="brand">KIMURA</div><div class="brand-sub">AGENTIC SECURITY VALIDATION</div></div>
    <div class="status-chip" data-result-status="{status_label}">{status_label}</div>
  </header>
  <section class="content" aria-label="Kimura physical assessment result">
    <div class="target-row">
      <article class="target-card">
        <div class="connected">{_value("CONNECTED" if vm.physical_target_reached else "NOT VERIFIED")}</div>
        <h1>PHYSICAL<br>TARGET</h1>
        <div class="target-label">{_value(target_label)}</div><div class="target-owner">Owned isolated synthetic target</div><div class="identity">{_value("IDENTITY VERIFIED" if vm.physical_target_reached else "IDENTITY NOT VERIFIED")}</div>
        <div class="target-meta"><div>Runtime target ID<strong>{_value(vm.target_id)}</strong></div><div>Protocol<strong>v{_value(vm.protocol_version)}</strong></div></div>
      </article>
      <article class="story-card">
        <div class="eyebrow">Live assessment story</div><h2 class="story-title">From permitted synthetic action to verified control</h2>
        <ol class="story-list">{_story(vm)}</ol>
        <div class="transformation">
          <section class="transform-card before"><h2>BEFORE</h2><div class="action">{action}</div><div class="decision">{_value(vm.baseline_decision or "NOT ESTABLISHED").upper()}</div><div class="impact">{_value("SYNTHETIC IMPACT CONFIRMED" if vm.baseline_impact_confirmed else "IMPACT NOT CONFIRMED")}</div></section>
          <div class="arrow" aria-hidden="true">↓<small>remediation</small></div>
          <section class="transform-card after"><h2>EXACT REPLAY</h2><div class="action">{action}</div><div class="decision">{_value(vm.replay_decision or "NOT ESTABLISHED").upper()}</div><div class="impact">{_value(vm.replay_impact_label)}</div></section>
          <div class="replay-proof"><strong>{_value("SAME FIXTURE ✓" if vm.exact_replay_identity_verified else "SAME FIXTURE ×")}</strong><span>{_value("SHA-256 MATCHED" if vm.exact_replay_identity_verified else "SHA-256 NOT MATCHED")}</span></div>
        </div>
        <section class="final-state"><div><div class="eyebrow">Assessment outcome</div><h2>{_value("FIX VERIFIED" if vm.fix_verified else vm.display_status)}</h2></div><p class="final-copy">{_value(verified_copy)}<br><br><strong>Owned isolated synthetic target.</strong> No real external action occurred.</p></section>
      </article>
    </div>
    <details class="evidence-drawer"><summary>Evidence drawer · runtime-derived facts</summary><div class="evidence-grid">
      <div class="evidence-item"><label>Target ID</label><code>{_value(vm.target_id)}</code></div><div class="evidence-item"><label>Fixture ID</label><code>{_value(vm.baseline_fixture_id)}</code></div><div class="evidence-item"><label>Fixture SHA-256</label><code>{_value(vm.baseline_fixture_sha256)}</code></div><div class="evidence-item"><label>Baseline event</label><code>{_value(vm.baseline_event_id)}</code></div><div class="evidence-item"><label>Ledger count</label><code>{_value(vm.baseline_ledger_count)} → {_value(vm.final_ledger_count)}</code></div><div class="evidence-item"><label>Policy before</label><code>{_value(vm.policy_digest_before)}</code></div><div class="evidence-item"><label>Policy after</label><code>{_value(vm.policy_digest_after)}</code></div><div class="evidence-item"><label>Replay identity</label><code>{_value("VERIFIED" if vm.exact_replay_identity_verified else "NOT VERIFIED")}</code></div>
    </div></details>
  </section>
  <footer class="footer"><span><strong>synthetic validation only</strong> · no production target · no external action</span><span>{_value(replay_note)}</span></footer>
</main>
</body>
</html>'''
