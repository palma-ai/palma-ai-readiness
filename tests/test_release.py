"""The public download contains a small reproducible source-only skill."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def test_release_is_reproducible_complete_and_excludes_development_files(self):
        with tempfile.TemporaryDirectory() as td:
            a, b = Path(td)/"a.zip", Path(td)/"b.zip"
            for target in (a, b):
                result = subprocess.run([sys.executable, "-I", "-S", str(ROOT/"scripts/build_release.py"),
                                         "--output", str(target)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(Path(str(target)+".sha256").is_file())
            self.assertEqual(a.read_bytes(), b.read_bytes())
            with zipfile.ZipFile(a) as release:
                names = release.namelist()
                for required in ("SKILL.md", "scripts/palma-scan.py", "scripts/palma_scan/collector.py",
                                 "scripts/palma_scan/rules.py", "scripts/palma_scan/report.py",
                                 "scripts/palma_scan/report_theme.py", "scripts/palma_scan/report_font.py",
                                 "scripts/palma_scan/report_regulation.py", "references/eu-ai-regulation.md",
                                 "scripts/palma_scan/governance.py", "scripts/palma_scan/palma_catalog.json",
                                 "scripts/palma_scan/baseline.py", "scripts/palma_scan/machine.py",
                                 "scripts/palma_scan/extra_clients.py", "scripts/palma_scan/brands_extra.py",
                                 "scripts/palma_scan/engine/collection.py",
                                 "scripts/palma_scan/engine/adapters/plugin_components.py",
                                 "scripts/palma_scan/_vendor/json5/lib.py",
                                 "scripts/palma_scan/_vendor/yaml/loader.py",
                                 "scripts/palma_scan/_vendor/NOTICE.md",
                                 "references/report-design.md", "THIRD_PARTY_NOTICES.md"):
                    self.assertIn("palma-ai-readiness/"+required, names)
                self.assertFalse(any(part in name for name in names for part in
                                     ("collector/", "__pycache__", "docs/", "tests/", "examples/", "upload", "enrollment", "build_release")))
                readme = release.read("palma-ai-readiness/README.md").decode("utf-8")
                self.assertNotIn("## Development checks", readme)
                self.assertNotIn("## Publish the skill", readme)
                release.extractall(Path(td)/"extracted")
            entry = Path(td)/"extracted/palma-ai-readiness/scripts/palma-scan.py"
            copied = Path(td)/"copied-home"
            (copied/".opencode").mkdir(parents=True)
            (copied/".continue").mkdir()
            (copied/"opencode.jsonc").write_text("{permission: 'allow', /* JSON5 */}")
            (copied/".continue/config.yaml").write_text("name: Test\nversion: 1.0.0\nschema: v1\nallowAnonymousTelemetry: true\n")
            run = subprocess.run([sys.executable, "-I", "-S", str(entry), "run",
                                  "--copied-home", str(copied), "--output-dir", str(Path(td)/"run"), "--no-open"],
                                 capture_output=True, text=True, cwd=td)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertTrue((Path(td)/"run/report.html").is_file())


if __name__ == "__main__":
    unittest.main()
