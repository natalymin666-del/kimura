import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from kimura_assessment.mobile_report import derive_mobile_report, render_mobile_report_html
from tests.test_mobile_report import terminal_snapshot
from kimura_assessment.progress_events import ProgressEventType


class MobileReportBrowserTests(unittest.TestCase):
    def test_phone_stacks_story_for_all_terminal_statuses(self):
        node = Path(os.environ.get("KIMURA_NODE", "/home/nataly/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"))
        playwright_root = Path(os.environ.get("KIMURA_PLAYWRIGHT_ROOT", "/home/nataly/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright"))
        chromium = Path(os.environ.get("KIMURA_CHROMIUM", "/opt/BurpSuiteCommunity/burpbrowser/142.0.7444.134/chrome"))
        if not node.exists() or not playwright_root.exists() or not chromium.exists():
            self.skipTest("browser layout dependencies are not installed")
        reports = {
            "PASS": derive_mobile_report(terminal_snapshot("pass-mobile-run")),
            "PARTIAL": derive_mobile_report(terminal_snapshot("partial-mobile-run", ProgressEventType.ASSESSMENT_PARTIAL)),
            "FAILED": derive_mobile_report(terminal_snapshot("failed-mobile-run", ProgressEventType.ASSESSMENT_FAILED)),
        }
        script = r'''
const { chromium } = require(process.env.KIMURA_PLAYWRIGHT_ROOT);
(async () => {
  const browser = await chromium.launch({headless: true, executablePath: process.env.KIMURA_CHROMIUM, args: ["--no-sandbox"]});
  const page = await browser.newPage();
  const result = {};
  for (const [status, path] of Object.entries(JSON.parse(process.env.KIMURA_REPORTS))) {
    await page.setViewportSize({width: 390, height: 844});
    await page.goto("file://" + path);
    const phone = await page.evaluate(() => { const story = document.querySelector(".story"); return {status: document.querySelector(".status")?.textContent, columns: getComputedStyle(story).gridTemplateColumns, scrollWidth: document.documentElement.scrollWidth, width: innerWidth, run: document.querySelector("main")?.dataset.runId}; });
    await page.setViewportSize({width: 700, height: 900});
    await page.reload();
    const tablet = await page.evaluate(() => getComputedStyle(document.querySelector(".story")).gridTemplateColumns);
    result[status] = {phone, tablet};
  }
  console.log(JSON.stringify(result));
  await browser.close();
})().catch(error => { console.error(error); process.exit(1); });
'''
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for status, report in reports.items():
                path = Path(directory) / f"{status.lower()}.html"
                path.write_text(render_mobile_report_html(report), encoding="utf-8")
                paths[status] = str(path)
            environment = {**os.environ, "KIMURA_PLAYWRIGHT_ROOT": str(playwright_root), "KIMURA_CHROMIUM": str(chromium), "KIMURA_REPORTS": json.dumps(paths)}
            completed = subprocess.run([str(node), "-e", script], capture_output=True, text=True, check=True, timeout=45, env=environment)
        result = json.loads(completed.stdout.strip().splitlines()[-1])
        for status in ("PASS", "PARTIAL", "FAILED"):
            self.assertEqual(result[status]["phone"]["status"], status)
            self.assertEqual(len(result[status]["phone"]["columns"].split(" ")), 1)
            self.assertLessEqual(result[status]["phone"]["scrollWidth"], result[status]["phone"]["width"])
            self.assertGreaterEqual(len(result[status]["tablet"].split(" ")), 3)


if __name__ == "__main__":
    unittest.main()
