"""Native cmd.exe checks using a harmless stand-in for the scanner."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.name == "nt", "requires native Windows cmd.exe")
class WindowsLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="palma launcher ")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        shutil.copyfile(Path(__file__).resolve().parents[1] / "scripts/run.cmd", self.folder / "run.cmd")
        (self.folder / "palma-scan.py").write_text(
            "import json, pathlib, sys\n"
            "pathlib.Path(__file__).with_name('result.json').write_text(json.dumps(sys.argv[1:]))\n"
            "raise SystemExit(7 if '--fixture-failure' in sys.argv else 0)\n")
        self.env = {key: value for key, value in os.environ.items() if key.upper() != "PALMA_PYTHON"}
        self.env["PATH"] = str(Path(sys.executable).parent)

    def run_launcher(self, *args):
        return subprocess.run([os.environ["COMSPEC"], "/d", "/c", "run.cmd", *args],
            cwd=self.folder, env=self.env, input="\n", text=True, capture_output=True, timeout=20)

    def test_explicit_python_runs_scanner_and_forwards_arguments(self):
        self.env["PALMA_PYTHON"] = sys.executable
        result = self.run_launcher("--fixture")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads((self.folder / "result.json").read_text()), ["run", "--open", "--fixture"])

    def test_python_on_path_runs_without_an_override(self):
        result = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.folder / "result.json").exists())

    def test_invalid_override_fails_without_falling_back(self):
        self.env["PALMA_PYTHON"] = str(self.folder / "missing.exe")
        result = self.run_launcher()
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.folder / "result.json").exists())

    def test_scanner_failure_exit_code_is_preserved(self):
        self.env["PALMA_PYTHON"] = sys.executable
        self.assertEqual(self.run_launcher("--fixture-failure").returncode, 7)

    def test_missing_python_does_not_run_a_current_directory_impostor(self):
        self.env["PATH"] = str(self.folder / "empty")
        (self.folder / "python.cmd").write_text("@echo compromised>impostor.txt\n@exit /b 0\n")
        (self.folder / "py.cmd").write_text("@echo compromised>impostor.txt\n@exit /b 0\n")
        self.assertEqual(self.run_launcher().returncode, 2)
        self.assertFalse((self.folder / "impostor.txt").exists())
