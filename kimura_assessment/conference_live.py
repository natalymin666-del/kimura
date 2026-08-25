"""Browser-side live state reconstruction page for the Phase 4.2 shell."""

from __future__ import annotations

import json
import re


_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")

_STYLE = r"""
:root{color-scheme:dark;--ink:#f4f7fb;--muted:#8d99aa;--line:#263140;--surface:#101722;--cyan:#69d7e8;--green:#73e0a2;--amber:#f2be68;--red:#ff7c86;--violet:#a88cf5}*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:#070a0f;color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}body{min-height:100vh}.shell{min-height:100vh;padding:clamp(18px,2.3vw,36px) clamp(22px,3.2vw,52px);display:grid;grid-template-rows:auto 1fr auto;gap:clamp(18px,2.4vh,32px);background:radial-gradient(circle at 72% 15%,#122032 0,transparent 35%),#070a0f}.topbar,.footer{display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{letter-spacing:.2em;font-size:clamp(22px,2.1vw,34px);line-height:1;font-weight:900}.brand-sub{margin-top:8px;color:var(--muted);font-size:clamp(10px,.85vw,13px);letter-spacing:.16em;font-weight:700}.eyebrow{color:var(--muted);font-size:11px;letter-spacing:.17em;text-transform:uppercase}.status-chip{border:1px solid var(--line);padding:8px 13px;border-radius:999px;font-size:12px;letter-spacing:.12em;font-weight:800}.is-pass .status-chip{color:var(--green);border-color:#2b684b}.is-partial .status-chip{color:var(--amber);border-color:#765628}.is-failed .status-chip{color:var(--red);border-color:#77363d}.is-waiting .status-chip{color:var(--cyan);border-color:#266878}.content{width:min(1740px,100%);margin:auto;display:grid;gap:clamp(16px,2vw,30px);align-content:stretch}.target-row{display:grid;grid-template-columns:minmax(420px,.9fr) minmax(0,2.1fr);gap:clamp(18px,2.6vw,42px);align-items:stretch}.target-card,.evidence-drawer{background:linear-gradient(145deg,rgba(21,31,44,.96),rgba(11,16,24,.96));border:1px solid var(--line);border-radius:18px}.target-card{padding:clamp(24px,2.6vw,44px);min-height:clamp(360px,48vh,570px);position:relative;overflow:hidden}.target-card:before{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:var(--cyan)}.target-card h1{margin:14px 0 30px;display:inline-block;width:auto;max-width:100%;font-size:clamp(42px,4.2vw,72px);line-height:.9;letter-spacing:-.065em}.target-label{color:var(--cyan);font-size:clamp(16px,1.35vw,22px);line-height:1.2;font-weight:800;letter-spacing:-.02em}.target-owner{margin-top:8px;color:var(--muted);font-size:clamp(11px,.95vw,14px);letter-spacing:.08em;text-transform:uppercase}.identity{margin-top:13px;color:var(--green);font-size:clamp(12px,1vw,15px);letter-spacing:.12em;font-weight:850}.connected{display:inline-flex;align-items:center;gap:8px;color:var(--green);font-size:12px;letter-spacing:.12em;text-transform:uppercase;font-weight:800}.connected:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--green)}.not-connected{color:var(--muted)}.not-connected:before{background:var(--muted)}.target-meta{display:grid;gap:11px;margin-top:24px;color:var(--muted);font-size:13px}.target-meta strong{color:var(--ink);font-weight:600;display:block;margin-top:3px;overflow-wrap:anywhere}.story-card{display:grid;align-content:stretch;gap:clamp(14px,1.5vw,24px)}.story-title{margin:0;font-size:clamp(20px,2.2vw,34px);letter-spacing:-.045em}.story-list{list-style:none;padding:0;margin:0;display:flex;align-items:center;gap:0}.story-step{display:flex;align-items:center;gap:9px;color:var(--muted);font-size:clamp(12px,1.05vw,16px);white-space:nowrap}.story-step:not(:last-child):after{content:"";width:clamp(18px,3vw,62px);height:1px;background:var(--line);margin:0 12px}.story-dot{width:10px;height:10px;border:2px solid var(--line);border-radius:50%;flex:none}.story-complete{color:var(--ink)}.story-complete .story-dot{border-color:var(--green);background:var(--green)}.story-active{color:var(--cyan)}.story-active .story-dot{border-color:var(--cyan)}.story-failed{color:var(--red)}.story-failed .story-dot{border-color:var(--red)}.transformation{display:grid;grid-template-columns:minmax(0,1fr) clamp(72px,7vw,130px) minmax(0,1fr);gap:clamp(14px,2vw,30px);align-items:center}.transform-card{min-height:clamp(260px,32vh,390px);padding:clamp(28px,3.2vw,48px);border-radius:18px;border:1px solid var(--line);background:var(--surface);display:flex;flex-direction:column;justify-content:space-between}.transform-card.before{border-color:#70552d}.transform-card.after{border-color:#2e6d50}.transform-card h2{margin:0;font-size:clamp(16px,1.45vw,23px);letter-spacing:.15em}.action{margin:14px 0 0;font-size:clamp(38px,5.1vw,86px);letter-spacing:-.075em;font-weight:850;overflow-wrap:anywhere}.decision{margin-top:17px;font-size:clamp(28px,3.5vw,62px);letter-spacing:.055em;font-weight:950}.before .decision{color:var(--amber)}.after .decision{color:var(--green)}.impact{color:var(--muted);font-size:clamp(12px,1vw,16px);letter-spacing:.08em;text-transform:uppercase;margin-top:10px}.arrow{color:var(--violet);text-align:center;font-size:clamp(38px,5vw,72px)}.arrow small{display:block;color:var(--muted);font-size:10px;letter-spacing:.13em;text-transform:uppercase;margin-top:8px}.replay-proof{grid-column:1/-1;display:flex;align-items:center;justify-content:center;gap:clamp(12px,1.8vw,26px);flex-wrap:wrap;color:var(--muted);font-size:clamp(13px,1.1vw,17px);letter-spacing:.1em;text-transform:uppercase}.replay-proof strong{color:var(--cyan)}.final-state{display:flex;align-items:center;justify-content:space-between;gap:20px;border-top:1px solid var(--line);padding-top:18px}.final-state h2{margin:0;font-size:clamp(34px,4.8vw,82px);letter-spacing:-.07em}.is-pass .final-state h2{color:var(--green)}.is-partial .final-state h2{color:var(--amber)}.is-failed .final-state h2{color:var(--red)}.final-copy{max-width:580px;color:var(--muted);font-size:clamp(13px,1.1vw,17px);line-height:1.5}.evidence-drawer{padding:0;overflow:hidden}.evidence-drawer summary{padding:15px 20px;color:var(--muted);font-size:12px;letter-spacing:.14em;text-transform:uppercase}.evidence-grid{border-top:1px solid var(--line);padding:20px;display:grid;grid-template-columns:repeat(4,1fr);gap:18px}.evidence-item label{color:var(--muted);display:block;font-size:10px;letter-spacing:.13em;text-transform:uppercase;margin-bottom:7px}.evidence-item code{color:var(--ink);font:11px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.footer{color:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}.footer strong{color:var(--ink)}.connection{color:var(--muted);font-size:11px;letter-spacing:.08em}.connection.reconnecting{color:var(--amber)}.mobile-handoff{display:flex;align-items:center;gap:12px;margin-top:16px;padding:12px 14px;border:1px solid var(--line);border-radius:10px;color:var(--muted);font-size:12px;letter-spacing:.08em;text-transform:uppercase}.mobile-handoff a{color:var(--cyan);overflow-wrap:anywhere;text-transform:none;letter-spacing:0}.mobile-handoff img{width:clamp(96px,9vw,150px);height:clamp(96px,9vw,150px);background:#fff;border-radius:6px;padding:6px;flex:none}
@keyframes proof-arrival{from{opacity:.62;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}.state-reveal .story-active,.state-reveal .proof-arrival{animation:proof-arrival 260ms ease-out both}.state-reveal .transform-card{transition:border-color 220ms ease,box-shadow 220ms ease}.state-reveal .transform-card.after{box-shadow:0 0 0 1px rgba(105,215,232,.2)}.action,.decision{white-space:nowrap;overflow-wrap:normal;word-break:normal}.action{font-size:clamp(24px,3.2vw,56px)}.decision{font-size:clamp(18px,2.2vw,38px)}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}.state-reveal .transform-card{box-shadow:none}}
@media (min-width:1200px){.target-row{grid-template-columns:minmax(580px,1.3fr) minmax(0,1.7fr)}}
@media (max-width:900px){.target-row{grid-template-columns:1fr}.story-list{overflow:auto;padding-bottom:7px}.transformation{grid-template-columns:1fr}.arrow{transform:rotate(90deg)}.evidence-grid{grid-template-columns:repeat(2,1fr)}}@media (max-width:560px){.shell{padding:18px;gap:24px}.topbar,.footer,.final-state{align-items:flex-start;flex-direction:column}.target-card h1{font-size:36px}.evidence-grid{grid-template-columns:1fr}.story-step:not(:last-child):after{width:18px;margin:0 7px}}
"""

_SCRIPT = r"""
(() => {
  const RUN_ID = __RUN_ID__;
  const API_BASE = __API_BASE__;
  const MOBILE_REPORT_URL = __MOBILE_REPORT_URL__;
  const MOBILE_REPORT_QR = __MOBILE_REPORT_QR__;
  const TEST_MODE = Boolean(window.__KIMURA_LIVE_TEST_MODE);
  const SUCCESS_ORDER = ["assessment_started","target_verified","baseline_validated","remediation_verified","replay_identity_verified","replay_validated","cleanup_completed","fix_verified"];
  const EVENT_TYPES = new Set([...SUCCESS_ORDER,"cleanup_failed","assessment_partial","assessment_failed"]);
  const STATE_TYPES = new Set([...SUCCESS_ORDER,"cleanup_failed","assessment_partial","assessment_failed","unknown_run"]);
  let model = {run_id: RUN_ID, sequence: 0, state: "assessment_started", terminal: false, evidence: {}};
  let connection = "connecting";
  let eventsBySequence = new Map();
  let pollTimer = null;
  let presentation = {sequence: 0, state: null};

  function clone(value) { return JSON.parse(JSON.stringify(value)); }
  function validSnapshot(value) {
    if (!value || value.run_id !== RUN_ID || !Number.isInteger(value.sequence) || value.sequence < 1 || typeof value.state !== "string" || !STATE_TYPES.has(value.state) || !value.evidence || typeof value.evidence !== "object") throw new Error("invalid snapshot");
    return {run_id: RUN_ID, sequence: value.sequence, state: value.state, terminal: Boolean(value.terminal), evidence: clone(value.evidence)};
  }
  function validEvent(value) {
    if (!value || value.run_id !== RUN_ID || !Number.isInteger(value.sequence) || value.sequence < 1 || !EVENT_TYPES.has(value.event_type) || !value.payload || typeof value.payload !== "object") throw new Error("invalid event");
    return {run_id: RUN_ID, sequence: value.sequence, event_type: value.event_type, payload: clone(value.payload)};
  }
  function orderedNext(eventType, currentState) {
    if (currentState === "assessment_partial" || currentState === "assessment_failed" || currentState === "fix_verified") throw new Error("terminal state");
    if (eventType === "cleanup_completed") return currentState !== "cleanup_failed";
    if (eventType === "cleanup_failed") return currentState !== "cleanup_completed" && currentState !== "fix_verified";
    if (eventType === "assessment_partial" || eventType === "assessment_failed") return currentState !== "fix_verified";
    const currentIndex = SUCCESS_ORDER.indexOf(currentState);
    const nextIndex = SUCCESS_ORDER.indexOf(eventType);
    if (nextIndex < 0) return false;
    return nextIndex === currentIndex + 1;
  }
  function fixEvidence(evidence) {
    const baseline = evidence.baseline_validated, remediation = evidence.remediation_verified, identity = evidence.replay_identity_verified, replay = evidence.replay_validated, cleanup = evidence.cleanup_completed;
    return Boolean(baseline && baseline.decision === "allowed" && baseline.ledger_count === 1 && baseline.event_id && remediation && remediation.policy_id && remediation.policy_digest_before !== remediation.policy_digest_after && identity && identity.fixture_sha256 && identity.action && replay && replay.decision === "blocked" && replay.executed === false && replay.synthetic_event_id === null && replay.ledger_count === 1 && replay.baseline_ledger_count === 1 && cleanup && cleanup.cleanup_attempted === true);
  }
  function applySnapshot(value) {
    const next = validSnapshot(value);
    if (next.sequence < model.sequence) return false;
    if (next.sequence === model.sequence && model.state !== "assessment_started" && next.state !== model.state) throw new Error("stale snapshot");
    if (next.state === "fix_verified" && (!next.terminal || !fixEvidence(next.evidence))) throw new Error("invalid fix snapshot");
    model = next;
    eventsBySequence = new Map();
    presentation = {sequence: 0, state: null};
    connection = "connected";
    render();
    return true;
  }
  function applyEvent(value) {
    const event = validEvent(value);
    if (event.sequence <= model.sequence) return false;
    if (event.sequence !== model.sequence + 1) throw new Error("event gap");
    if (!orderedNext(event.event_type, model.state)) throw new Error("event order");
    const evidence = clone(model.evidence);
    evidence[event.event_type] = event.payload;
    if (event.event_type === "fix_verified" && !fixEvidence(evidence)) throw new Error("invalid fix evidence");
    model = {run_id: RUN_ID, sequence: event.sequence, state: event.event_type, terminal: ["fix_verified","assessment_partial","assessment_failed"].includes(event.event_type), evidence};
    eventsBySequence.set(event.sequence, event);
    presentation = {sequence: event.sequence, state: event.event_type};
    render();
    return true;
  }
  async function getJson(path) { const response = await fetch(API_BASE + path, {cache: "no-store"}); if (!response.ok) { const error = new Error("HTTP " + response.status); error.status = response.status; throw error; } return response.json(); }
  async function reconcile() { try { applySnapshot(await getJson("/api/assessments/" + encodeURIComponent(RUN_ID) + "/snapshot")); } catch (error) { if (error.status === 404) { model = {run_id: RUN_ID, sequence: 0, state: "unknown_run", terminal: true, evidence: {}}; connection = "unknown"; render(); } else { connection = "reconnecting"; render(); } } }
  async function pollOnce() {
    try {
      const body = await getJson("/api/assessments/" + encodeURIComponent(RUN_ID) + "/events?after_seq=" + model.sequence);
      const events = Array.isArray(body.events) ? body.events : (() => { throw new Error("invalid event response"); })();
      if (Number.isInteger(body.latest_sequence) && body.latest_sequence > model.sequence && events.length === 0) throw new Error("event gap");
      for (const event of events) applyEvent(event);
      connection = "connected";
      render();
    } catch (error) {
      if (error.message === "event gap" || error.message === "event order" || error.message === "invalid event" || error.message === "invalid fix evidence" || error.message === "invalid event response") await reconcile();
      else { connection = "reconnecting"; render(); }
    }
  }
  async function load() { await reconcile(); if (!TEST_MODE) { pollTimer = setInterval(pollOnce, 1000); } }
  function text(parent, tag, value, className) { const element = document.createElement(tag); if (className) element.className = className; element.textContent = value == null || value === "" ? "—" : String(value); parent.appendChild(element); return element; }
  function stage(parent, label, status) { const item = text(parent, "li", label, "story-step story-" + status); text(item, "span", "", "story-dot"); return item; }
  function render() {
    const evidence = model.evidence || {}, target = evidence.target_verified || {}, baseline = evidence.baseline_validated || {}, remediation = evidence.remediation_verified || {}, identity = evidence.replay_identity_verified || {}, replay = evidence.replay_validated || {};
    const isPass = model.state === "fix_verified", isPartial = model.state === "assessment_partial", isFailed = model.state === "assessment_failed", unknown = model.state === "unknown_run";
    const isSuccessChoreography = presentation.sequence === model.sequence && presentation.state === model.state && !isPartial && !isFailed && !unknown; const root = document.createElement("main"); root.className = "shell " + (isPass ? "is-pass" : isPartial ? "is-partial" : isFailed ? "is-failed" : "is-waiting") + (isSuccessChoreography ? " state-reveal" : ""); root.dataset.liveState = model.state; root.dataset.provenSequence = String(model.sequence);
    const top = document.createElement("header"); top.className = "topbar"; const brand = document.createElement("div"); text(brand, "div", "KIMURA", "brand"); text(brand, "div", "AGENTIC SECURITY VALIDATION", "brand-sub"); top.appendChild(brand); text(top, "div", unknown ? "UNAVAILABLE" : isPass ? "PASS" : isPartial ? "PARTIAL" : isFailed ? "FAILED" : "LIVE", "status-chip"); root.appendChild(top);
    const content = document.createElement("section"); content.className = "content"; content.setAttribute("aria-label", "Kimura live physical assessment result"); const row = document.createElement("div"); row.className = "target-row";
    const targetCard = document.createElement("article"); targetCard.className = "target-card"; text(targetCard, "div", target.target_id ? "CONNECTED" : unknown ? "NOT AVAILABLE" : "WAITING", target.target_id ? "connected" : "connected not-connected"); text(targetCard, "h1", "PHYSICAL\nTARGET"); text(targetCard, "div", target.target_id ? "Raspberry Pi 5" : "Awaiting physical target", "target-label"); text(targetCard, "div", "Owned isolated synthetic target", "target-owner"); text(targetCard, "div", target.target_id ? "IDENTITY VERIFIED" : "IDENTITY NOT VERIFIED", "identity"); const meta = document.createElement("div"); meta.className = "target-meta"; const idLine = document.createElement("div"); text(idLine, "span", "Runtime target ID"); text(idLine, "strong", target.target_id || "—"); meta.appendChild(idLine); const protocol = document.createElement("div"); text(protocol, "span", "Protocol"); text(protocol, "strong", target.protocol_version ? "v" + target.protocol_version : "—"); meta.appendChild(protocol); targetCard.appendChild(meta); row.appendChild(targetCard);
    const story = document.createElement("article"); story.className = "story-card"; text(story, "div", "Live assessment story", "eyebrow"); text(story, "h2", unknown ? "Assessment run unavailable" : model.state === "assessment_started" ? "Waiting for physical target assessment" : "From permitted synthetic action to verified control", "story-title"); const list = document.createElement("ol"); list.className = "story-list"; const order = ["target_verified","baseline_validated","remediation_verified","replay_identity_verified","replay_validated","fix_verified"]; const labels = ["Discovery","Baseline attack","Evidence","Remediation","Exact replay","Verification"]; const currentIndex = order.indexOf(model.state); labels.forEach((label, i) => stage(list, label, currentIndex > i || (isPartial && i <= currentIndex) || (isFailed && i <= currentIndex) ? "complete" : currentIndex === i ? "active" : "pending")); story.appendChild(list);
    const transformation = document.createElement("div"); transformation.className = "transformation"; const before = document.createElement("section"); before.className = "transform-card before"; text(before, "h2", "BEFORE"); text(before, "div", baseline.action || "NOT ESTABLISHED", "action"); text(before, "div", baseline.decision ? baseline.decision.toUpperCase() : "NOT ESTABLISHED", "decision"); text(before, "div", baseline.event_id ? "SYNTHETIC IMPACT CONFIRMED" : "IMPACT NOT CONFIRMED", "impact"); transformation.appendChild(before); const arrow = document.createElement("div"); arrow.className = "arrow"; text(arrow, "span", "↓"); text(arrow, "small", "remediation"); transformation.appendChild(arrow); const after = document.createElement("section"); after.className = "transform-card after"; text(after, "h2", "EXACT REPLAY"); text(after, "div", identity.action || baseline.action || "NOT ESTABLISHED", "action"); text(after, "div", replay.decision ? replay.decision.toUpperCase() : "NOT ESTABLISHED", "decision"); text(after, "div", replay.decision === "blocked" ? "NO SYNTHETIC IMPACT" : "NOT ESTABLISHED", "impact"); transformation.appendChild(after); const proof = document.createElement("div"); proof.className = "replay-proof"; text(proof, "strong", identity.fixture_sha256 ? "SAME FIXTURE ✓" : "SAME FIXTURE ×"); text(proof, "span", identity.fixture_sha256 ? "SHA-256 MATCHED" : "SHA-256 NOT MATCHED"); transformation.appendChild(proof); story.appendChild(transformation);
    const final = document.createElement("section"); final.className = "final-state"; const outcome = document.createElement("div"); text(outcome, "div", "Assessment outcome", "eyebrow"); text(outcome, "h2", isPass ? "FIX VERIFIED" : isPartial ? "PARTIAL" : isFailed ? "FAILED" : model.state === "cleanup_completed" ? "CLEANUP COMPLETED" : unknown ? "UNAVAILABLE" : "ASSESSMENT IN PROGRESS"); final.appendChild(outcome); text(final, "p", connection === "reconnecting" ? "Connection interrupted. Preserving the last proven state." : isPass ? "Exact replay verified under the deny-only remediation." : unknown ? "No assessment run is available." : "Only evidence-backed progress is displayed.", "final-copy"); if ((isPass || isPartial || isFailed) && MOBILE_REPORT_URL && MOBILE_REPORT_QR) { const handoff = document.createElement("div"); handoff.className = "mobile-handoff"; const image = document.createElement("img"); image.src = MOBILE_REPORT_QR; image.alt = "QR code for the exact mobile assessment report"; handoff.appendChild(image); const handoffText = document.createElement("div"); text(handoffText, "strong", "MOBILE REPORT"); const link = document.createElement("a"); link.href = MOBILE_REPORT_URL; link.textContent = MOBILE_REPORT_URL; handoffText.appendChild(link); handoff.appendChild(handoffText); story.appendChild(handoff); } story.appendChild(final); row.appendChild(story); content.appendChild(row);
    const drawer = document.createElement("details"); drawer.className = "evidence-drawer"; text(drawer, "summary", "Evidence drawer · runtime-derived facts"); const grid = document.createElement("div"); grid.className = "evidence-grid"; [["Target ID",target.target_id],["Fixture ID",baseline.fixture_id],["Fixture SHA-256",baseline.fixture_sha256],["Baseline event",baseline.event_id],["Ledger count",baseline.ledger_count != null ? baseline.ledger_count + " → " + (replay.ledger_count ?? "—") : "—"],["Policy before",remediation.policy_digest_before || target.policy_digest_before],["Policy after",remediation.policy_digest_after],["Replay identity",identity.fixture_sha256 ? "VERIFIED" : "NOT VERIFIED"]].forEach(([label,value])=>{const item=document.createElement("div");item.className="evidence-item";text(item,"label",label);text(item,"code",value);grid.appendChild(item)});drawer.appendChild(grid); content.appendChild(drawer); root.appendChild(content); const footer=document.createElement("footer");footer.className="footer";text(footer,"span","synthetic validation only · no production target · no external action");text(footer,"span",connection === "reconnecting" ? "RECONNECTING · state preserved" : connection === "unknown" ? "NO ACTIVE RUN" : "LOCAL READ-ONLY PROGRESS");root.appendChild(footer); document.getElementById("app").replaceChildren(root);
  }
  window.KimuraLive = {applyEvent, applySnapshot, getState: () => clone(model), getSequence: () => model.sequence, getPresentation: () => clone(presentation), pollOnce, reconcile};
  render();
  if (!TEST_MODE) load();
})();
"""


def render_live_page_html(run_id: str, *, api_base: str = "", mobile_report_url: str = "", qr_data_uri: str = "") -> str:
    """Return a same-origin-ready live page with no assessment side effects."""

    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError("run_id has invalid syntax")
    script = _SCRIPT.replace("__RUN_ID__", json.dumps(run_id)).replace("__API_BASE__", json.dumps(api_base)).replace("__MOBILE_REPORT_URL__", json.dumps(mobile_report_url)).replace("__MOBILE_REPORT_QR__", json.dumps(qr_data_uri))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Kimura · Live Physical Assessment</title><style>{_STYLE}</style></head><body><div id="app"></div><script>{script}</script></body></html>'''
