import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "start-flagship-demo.sh"
TARGET_RELATIVE = Path("demo/flagship-refund-boundary-demo.html")


class FlagshipOfflineLauncherTests(unittest.TestCase):
    def run_launcher(self, *, target=True, other_demo=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "demo").mkdir()
            shutil.copy2(LAUNCHER, root / "scripts" / LAUNCHER.name)
            if target:
                (root / TARGET_RELATIVE).write_text("<!doctype html><title>flagship</title>\n", encoding="utf-8")
            if other_demo:
                (root / "demo" / "other-demo.html").write_text("other", encoding="utf-8")
            opener = root / "opener-bin"
            opener.mkdir()
            log = root / "opened.txt"
            (opener / "xdg-open").write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$1\" > \"$OPENED_LOG\"\n", encoding="utf-8")
            (opener / "xdg-open").chmod(0o755)
            env = {**os.environ, "PATH": f"{opener}:{os.environ['PATH']}", "OPENED_LOG": str(log)}
            result = subprocess.run([str(root / "scripts" / LAUNCHER.name)], capture_output=True, text=True, env=env)
            return result, log.read_text().strip() if log.exists() else None

    def test_opens_only_exact_flagship_path(self):
        result, opened = self.run_launcher(other_demo=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(opened, str(Path(tempfile.gettempdir())) if False else opened)
        self.assertTrue(opened.endswith("/demo/flagship-refund-boundary-demo.html"))
        self.assertNotIn("other-demo", opened)

    def test_missing_or_wrong_only_target_fails_clearly(self):
        result, opened = self.run_launcher(target=False, other_demo=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("flagship demo is missing", result.stderr)
        self.assertIsNone(opened)

    def test_launcher_is_static_and_does_not_regenerate(self):
        source = LAUNCHER.read_text(encoding="utf-8")
        for forbidden in ("python", "ollama", "curl", "wget", "pip install", "kimura_assessment", "conference_demo"):
            self.assertNotIn(forbidden, source.lower())
        self.assertEqual(source.count("flagship-refund-boundary-demo.html"), 2)
        self.assertEqual(source.count("exec xdg-open"), 1)
        self.assertEqual(source.count("exec open"), 1)
        self.assertEqual(source.count("exec gio open"), 1)


if __name__ == "__main__":
    unittest.main()
