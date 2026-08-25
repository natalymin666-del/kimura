import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from kimura_assessment.conference_live import render_live_page_html
from kimura_assessment.progress_events import ProgressEvent, ProgressEventType
from kimura_assessment.progress_journal import ProgressJournal
from tests.test_progress_journal import pass_events


def snapshots():
    result = {}
    events = pass_events()
    for count, name in enumerate(("started", "target", "baseline", "remediation", "identity", "replay", "cleanup", "fix"), 1):
        journal = ProgressJournal()
        for item in events[:count]:
            journal.append(item)
        result[name] = journal.get_latest_snapshot("journal-run").to_dict()
    for run_id, event_type in (("journal-run", ProgressEventType.ASSESSMENT_PARTIAL), ("journal-run", ProgressEventType.ASSESSMENT_FAILED)):
        journal = ProgressJournal()
        journal.append(ProgressEvent(run_id, 1, ProgressEventType.ASSESSMENT_STARTED, {"assessment_id": "physical-assessment-v1"}))
        journal.append(ProgressEvent(run_id, 2, ProgressEventType.CLEANUP_COMPLETED, {"cleanup_attempted": True}))
        journal.append(ProgressEvent(run_id, 3, event_type, {"failure_code": "stopped", "last_proven_event": "cleanup_completed", "cleanup_completed": True}))
        result[event_type.value] = journal.get_latest_snapshot(run_id).to_dict()
    return result


class ConferenceLiveBrowserTests(unittest.TestCase):
    def test_browser_reconstructs_proven_states_and_handles_failures(self):
        node = Path(os.environ.get("KIMURA_NODE", "/home/nataly/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"))
        playwright_root = Path(os.environ.get("KIMURA_PLAYWRIGHT_ROOT", "/home/nataly/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright"))
        chromium = Path(os.environ.get("KIMURA_CHROMIUM", "/opt/BurpSuiteCommunity/burpbrowser/142.0.7444.134/chrome"))
        if not node.exists() or not playwright_root.exists() or not chromium.exists():
            self.skipTest("browser layout dependencies are not installed")
        with tempfile.TemporaryDirectory() as directory:
            html_path = Path(directory) / "live.html"
            html_path.write_text(render_live_page_html("journal-run", api_base="http://api.invalid", mobile_report_url="http://192.168.50.10:8123/report/journal-run", qr_data_uri="data:image/svg+xml;base64,PHN2Zy8+"), encoding="utf-8")
            script = r'''
const { chromium } = require(process.env.KIMURA_PLAYWRIGHT_ROOT);
(async () => {
  const browser = await chromium.launch({headless: true, executablePath: process.env.KIMURA_CHROMIUM, args: ["--no-sandbox"]});
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
  await page.addInitScript(() => { window.__KIMURA_LIVE_TEST_MODE = true; });
  await page.goto("file://" + process.env.KIMURA_HTML_PATH);
  const snapshots = JSON.parse(process.env.KIMURA_SNAPSHOTS);
  const read = () => page.evaluate(() => { const root = document.querySelector(".shell"); const decision = document.querySelector(".before .decision"); const styles = decision ? getComputedStyle(decision) : null; const targetCard = document.querySelector(".target-card"); const targetHeading = document.querySelector(".target-card h1"); const targetStyles = targetCard ? getComputedStyle(targetCard) : null; const targetHeadingRect = targetHeading ? targetHeading.getBoundingClientRect() : null; const targetCardRect = targetCard ? targetCard.getBoundingClientRect() : null; return {state: window.KimuraLive.getState(), text: document.body.innerText, images: document.images.length, targetHeading: targetHeading && targetHeadingRect && targetCardRect && targetStyles ? {text: targetHeading.textContent, clientWidth: targetHeading.clientWidth, scrollWidth: targetHeading.scrollWidth, rightGap: targetCardRect.right - targetHeadingRect.right, paddingRight: parseFloat(targetStyles.paddingRight)} : null, reveal: root.classList.contains("state-reveal"), presentation: window.KimuraLive.getPresentation(), decision: decision ? {whiteSpace: styles.whiteSpace, wordBreak: styles.wordBreak, text: decision.textContent, clientWidth: decision.clientWidth, scrollWidth: decision.scrollWidth} : null, animation: document.querySelector(".story-active") ? getComputedStyle(document.querySelector(".story-active")).animationName : "none", reducedDuration: document.querySelector(".story-active") ? getComputedStyle(document.querySelector(".story-active")).animationDuration : "none", external: document.querySelectorAll("img,script[src],link[rel=stylesheet]").length}; });
  const states = {};
  for (const name of ["started","target","baseline","remediation","identity","replay","cleanup","fix","assessment_partial","assessment_failed"]) {
    await page.reload();
    await page.evaluate(snapshot => window.KimuraLive.applySnapshot(snapshot), snapshots[name]);
    states[name] = await read();
  }
  await page.reload();
  await page.evaluate(snapshot => window.KimuraLive.applySnapshot(snapshot), snapshots.baseline);
  const baselineEvent = snapshots.remediation.evidence.remediation_verified;
  const remediationEvent = {run_id:"journal-run",sequence:4,event_type:"remediation_verified",payload:baselineEvent};
  const firstApply = await page.evaluate(event => window.KimuraLive.applyEvent(event), remediationEvent);
  const presentationAfterFirst = await page.evaluate(() => window.KimuraLive.getPresentation());
  const duplicateApply = await page.evaluate(event => window.KimuraLive.applyEvent(event), remediationEvent);
  const staleApply = await page.evaluate(event => window.KimuraLive.applyEvent({...event, sequence: 1}), remediationEvent);
  const afterDuplicate = await read();
  await page.emulateMedia({reducedMotion: "reduce"});
  await page.reload();
  await page.evaluate(snapshot => window.KimuraLive.applySnapshot(snapshot), snapshots.started);
  const reducedTargetEvent = {run_id:"journal-run",sequence:2,event_type:"target_verified",payload:snapshots.target.evidence.target_verified};
  await page.evaluate(event => window.KimuraLive.applyEvent(event), reducedTargetEvent);
  const reduced = await read();
  await page.reload();
  await page.evaluate(snapshot => window.KimuraLive.applySnapshot(snapshot), snapshots.started);
  await page.evaluate(() => {
    let calls = 0;
    window.fetch = async () => {
      calls += 1;
      if (calls === 1) return {ok:true,json:async()=>({events:[{run_id:"journal-run",sequence:3,event_type:"baseline_validated",payload:{}}]})};
      return {ok:true,json:async()=>window.__RECONCILE_SNAPSHOT};
    };
  });
  await page.evaluate(snapshot => { window.__RECONCILE_SNAPSHOT = snapshot; }, snapshots.target);
  await page.evaluate(() => window.KimuraLive.pollOnce());
  const reconciled = await read();
  await page.evaluate(() => { window.fetch = async () => { throw new Error("offline"); }; });
  await page.evaluate(() => window.KimuraLive.pollOnce());
  const disconnected = await read();
  await page.evaluate(snapshot => window.KimuraLive.applySnapshot(snapshot), snapshots.baseline);
  const malformed = await page.evaluate(() => { const before = window.KimuraLive.getState(); try { window.KimuraLive.applyEvent({bad:true}); } catch (_) {} return {before, after: window.KimuraLive.getState()}; });
  await page.evaluate(() => { window.fetch = async () => { const error = new Error("unknown"); error.status = 404; throw error; }; });
  await page.evaluate(() => window.KimuraLive.reconcile());
  const unknown = await read();
  const escaped = {...snapshots.target, evidence: {...snapshots.target.evidence, target_verified: {...snapshots.target.evidence.target_verified, target_id: "<img src=x onerror=alert(1)>"}}};
  await page.evaluate(snapshot => window.KimuraLive.applySnapshot(snapshot), escaped);
  const escapedView = await read();
  console.log(JSON.stringify({states,firstApply,duplicateApply,staleApply,presentationAfterFirst,afterDuplicate,reduced,reconciled,disconnected,unknown,malformed,escapedView}));
  await browser.close();
})().catch(error => { console.error(error); process.exit(1); });
'''
            environment = {**os.environ, "KIMURA_PLAYWRIGHT_ROOT": str(playwright_root), "KIMURA_CHROMIUM": str(chromium), "KIMURA_HTML_PATH": str(html_path), "KIMURA_SNAPSHOTS": json.dumps(snapshots())}
            completed = subprocess.run([str(node), "-e", script], capture_output=True, text=True, check=False, timeout=45, env=environment)
            if completed.returncode:
                raise AssertionError(completed.stderr)
        output = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(output["states"]["fix"]["state"]["state"], "fix_verified")
        self.assertFalse(output["states"]["started"]["reveal"])
        self.assertFalse(output["states"]["fix"]["reveal"])
        self.assertFalse(output["states"]["assessment_partial"]["reveal"])
        self.assertFalse(output["states"]["assessment_failed"]["reveal"])
        self.assertEqual(output["states"]["started"]["decision"]["text"], "NOT ESTABLISHED")
        self.assertEqual(output["states"]["started"]["decision"]["whiteSpace"], "nowrap")
        self.assertEqual(output["states"]["started"]["decision"]["wordBreak"], "normal")
        self.assertLessEqual(output["states"]["started"]["decision"]["scrollWidth"], output["states"]["started"]["decision"]["clientWidth"])
        for name in ("started", "fix"):
            heading = output["states"][name]["targetHeading"]
            self.assertEqual(heading["text"], "PHYSICAL\nTARGET")
            self.assertLessEqual(heading["scrollWidth"], heading["clientWidth"])
            self.assertGreater(heading["rightGap"], 8)
        self.assertNotIn("MOBILE REPORT", output["states"]["started"]["text"])
        self.assertEqual(output["states"]["started"]["images"], 0)
        self.assertIn("MOBILE REPORT", output["states"]["fix"]["text"])
        self.assertEqual(output["states"]["fix"]["images"], 1)
        self.assertEqual(output["states"]["started"]["external"], 0)
        self.assertTrue(output["reduced"]["reveal"])
        self.assertIn(output["reduced"]["reducedDuration"], ("0.01ms", "1e-05s"))
        self.assertIn("FIX VERIFIED", output["states"]["fix"]["text"])
        for name in ("assessment_partial", "assessment_failed"):
            self.assertNotIn("FIX VERIFIED", output["states"][name]["text"])
        self.assertNotIn("BLOCKED", output["states"]["baseline"]["text"])
        self.assertNotIn("FIX VERIFIED", output["states"]["baseline"]["text"])
        self.assertIn("SAME FIXTURE", output["states"]["identity"]["text"])
        self.assertNotIn("BLOCKED", output["states"]["identity"]["text"])
        self.assertIn("BLOCKED", output["states"]["replay"]["text"])
        self.assertNotIn("FIX VERIFIED", output["states"]["replay"]["text"])
        self.assertEqual(output["afterDuplicate"]["state"]["sequence"], 4)
        self.assertEqual(output["afterDuplicate"]["presentation"], output["presentationAfterFirst"])
        self.assertTrue(output["firstApply"])
        self.assertFalse(output["duplicateApply"])
        self.assertFalse(output["staleApply"])
        self.assertEqual(output["reconciled"]["state"]["state"], "target_verified")
        self.assertEqual(output["reconciled"]["state"]["sequence"], 2)
        self.assertEqual(output["disconnected"]["state"]["state"], "target_verified")
        self.assertIn("RECONNECTING", output["disconnected"]["text"])
        self.assertEqual(output["malformed"]["before"], output["malformed"]["after"])
        self.assertEqual(output["unknown"]["state"]["state"], "unknown_run")
        self.assertIn("UNAVAILABLE", output["unknown"]["text"])
        self.assertEqual(output["escapedView"]["images"], 0)


if __name__ == "__main__":
    unittest.main()
