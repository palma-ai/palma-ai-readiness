"""Behavioral acceptance checks for the standalone local command surface."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "palma-scan.py"


class CliTests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, "-I", "-S", str(ENTRY), *map(str, args)],
                              capture_output=True, text=True, cwd=ROOT)

    def test_help_exposes_only_local_commands(self):
        result = self.invoke("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("collect", result.stdout)
        self.assertIn("report", result.stdout)
        self.assertNotIn("upload", result.stdout)
        for obsolete in ["upload", "enroll"]:
            self.assertEqual(self.invoke(obsolete).returncode, 2)

    def test_isolated_run_and_deterministic_rebuild(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "synthetic-home"
            home.mkdir()
            output = Path(td) / "run"
            result = self.invoke("run", "--home", home, "--output-dir", output, "--no-open")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({p.name for p in output.iterdir()},
                             {"snapshot.json", "summary.json", "report.html", "share.html"})
            self.assertNotIn(td, (output / "share.html").read_text())
            rebuilt_share = Path(td) / "share-rebuilt.html"
            result = self.invoke("report", "--run-dir", output, "--share", "--output", rebuilt_share)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((output / "share.html").read_bytes(), rebuilt_share.read_bytes())
            snapshot = json.loads((output / "snapshot.json").read_text())
            self.assertEqual(snapshot["scope"]["type"], "copied-home")
            self.assertEqual(snapshot["schemaVersion"], "2.0")
            self.assertNotIn(td, (output / "snapshot.json").read_text())
            first = (output / "report.html").read_bytes()
            rebuilt = Path(td) / "rebuilt.html"
            result = self.invoke("report", "--run-dir", output, "--output", rebuilt)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(first, rebuilt.read_bytes())
            second = self.invoke("run", "--home", home, "--output-dir", output)
            self.assertEqual(second.returncode, 2)
            self.assertEqual(first, (output / "report.html").read_bytes())

    @unittest.skipIf(os.name == "nt", "HOME selects the home folder on POSIX")
    def test_results_go_to_the_home_folder_not_the_working_directory(self):
        with tempfile.TemporaryDirectory() as td:
            home, project = Path(td)/"home", Path(td)/"project"
            home.mkdir()
            project.mkdir()
            copied = Path(td)/"copied-home"
            copied.mkdir()
            result = subprocess.run([sys.executable, "-I", "-S", str(ENTRY), "run", "--copied-home", str(copied), "--no-open"],
                                    capture_output=True, text=True, cwd=project, env={**os.environ, "HOME": str(home)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(project.iterdir()), [])
            runs = [path.name for path in home.iterdir()]
            self.assertEqual(len(runs), 1)
            self.assertTrue(runs[0].startswith("readiness-run-"))

    def test_rejects_unsupported_snapshot_and_unsafe_booking_link(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "input.json"
            source.write_text('{"schemaVersion":"1.0"}')
            result = self.invoke("report", "--report", source, "--output", Path(td)/"out.html")
            self.assertEqual(result.returncode, 2)
            result = self.invoke("run", "--home", td, "--output-dir", Path(td)/"run",
                                 "--booking-url", "javascript:alert(1)")
            self.assertEqual(result.returncode, 2)
            self.assertFalse((Path(td)/"run").exists())

    def test_invalid_home_does_not_create_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td)/"run"
            result = self.invoke("run", "--home", Path(td)/"missing", "--output-dir", output)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
