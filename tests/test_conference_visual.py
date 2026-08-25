import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from kimura_assessment.conference_renderer import render_conference_html
from kimura_assessment.physical_target_assessment import run_local_assessment


class ConferenceVisualLayoutTests(unittest.TestCase):
    def test_pass_core_elements_have_visible_browser_layout(self):
        node = Path(os.environ.get("KIMURA_NODE", "/home/nataly/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"))
        playwright_root = Path(os.environ.get("KIMURA_PLAYWRIGHT_ROOT", "/home/nataly/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright"))
        chromium = Path(os.environ.get("KIMURA_CHROMIUM", "/opt/BurpSuiteCommunity/burpbrowser/142.0.7444.134/chrome"))
        if not node.exists() or not playwright_root.exists() or not chromium.exists():
            self.skipTest("browser layout dependencies are not installed")
        script = r'''
const { chromium } = require(process.env.KIMURA_PLAYWRIGHT_ROOT);
(async () => {
  const browser = await chromium.launch({headless: true, executablePath: process.env.KIMURA_CHROMIUM, args: ["--no-sandbox"]});
  const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
  await page.goto(process.env.KIMURA_LAYOUT_URL, {waitUntil: "domcontentloaded"});
  const selectors = {shell: "main.shell", branding: ".brand", target: ".target-card", before: ".transform-card.before", after: ".transform-card.after", fix: ".final-state"};
  const result = {};
  for (const [name, selector] of Object.entries(selectors)) {
    result[name] = await page.locator(selector).evaluate((element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return {display: style.display, visibility: style.visibility, opacity: style.opacity, width: rect.width, height: rect.height};
    });
  }
  console.log(JSON.stringify(result));
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
'''
        with tempfile.TemporaryDirectory() as directory:
            html_path = Path(directory) / "pass.html"
            html_path.write_text(render_conference_html(run_local_assessment().to_dict()), encoding="utf-8")
            completed = subprocess.run([str(node), "-e", script], capture_output=True, text=True, check=True, timeout=30, env={**os.environ, "KIMURA_PLAYWRIGHT_ROOT": str(playwright_root), "KIMURA_CHROMIUM": str(chromium), "KIMURA_LAYOUT_URL": html_path.as_uri()})
        layout = json.loads(completed.stdout.strip().splitlines()[-1])
        for name, state in layout.items():
            self.assertNotEqual(state["display"], "none", name)
            self.assertEqual(state["visibility"], "visible", name)
            self.assertGreater(float(state["opacity"]), 0, name)
            self.assertGreater(state["width"], 0, name)
            self.assertGreater(state["height"], 0, name)
