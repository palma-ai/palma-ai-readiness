"""The public download contains a small reproducible source-only skill."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(target, root=ROOT):
    return subprocess.run([sys.executable, "-I", "-S", str(root / "scripts/build_release.py"), "--output", str(target)],
                          capture_output=True, text=True)


class ReleaseTests(unittest.TestCase):
    def test_release_is_reproducible_complete_and_excludes_development_files(self):
        with tempfile.TemporaryDirectory() as td:
            a, b = Path(td)/"a.zip", Path(td)/"b.zip"
            for target in (a, b):
                result = build(target)
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
                                 "scripts/palma_scan/baseline.py", "scripts/palma_scan/machine.py", "scripts/palma_scan/dedup.py",
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
                manifest = dict(reversed(line.split("  ", 1)) for line in release.read("palma-ai-readiness/MANIFEST.sha256").decode("ascii").splitlines())
                self.assertEqual(set(manifest), {name.removeprefix("palma-ai-readiness/") for name in names} - {"MANIFEST.sha256"})
                for name, digest in manifest.items():
                    self.assertEqual(hashlib.sha256(release.read("palma-ai-readiness/" + name)).hexdigest(), digest, name)
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

            # A copy that differs from its release is refused before any skill code runs.
            version = [sys.executable, "-I", "-S", str(entry), "--version"]
            rules = Path(td)/"extracted/palma-ai-readiness/scripts/palma_scan/rules.py"
            original = rules.read_bytes()
            rules.write_bytes(original + b"\n")
            edited = subprocess.run(version, capture_output=True, text=True, cwd=td)
            self.assertEqual(edited.returncode, 2)
            self.assertIn("scripts/palma_scan/rules.py", edited.stderr)
            rules.write_bytes(original)
            added = Path(td)/"extracted/palma-ai-readiness/scripts/palma_scan/json.py"
            added.write_text("")
            extra = subprocess.run(version, capture_output=True, text=True, cwd=td)
            self.assertEqual(extra.returncode, 2)
            self.assertIn("scripts/palma_scan/json.py", extra.stderr)
            added.unlink()
            release_root = Path(td)/"extracted/palma-ai-readiness"
            bytecode = release_root/"scripts/palma_scan/__pycache__/cli.cpython-314.pyc"
            bytecode.parent.mkdir()
            bytecode.write_bytes(b"planted")
            self.assertEqual(subprocess.run(version, capture_output=True, text=True, cwd=td).returncode, 2, "planted bytecode is refused")
            bytecode.unlink()
            bytecode.parent.rmdir()
            linked = release_root/"scripts/palma_scan/linked"
            linked.symlink_to(Path(td), target_is_directory=True)
            self.assertEqual(subprocess.run(version, capture_output=True, text=True, cwd=td).returncode, 2, "a linked folder is refused")
            linked.unlink()
            self.assertEqual(subprocess.run(version, capture_output=True, text=True, cwd=td).returncode, 0)
            (release_root/"MANIFEST.sha256").unlink()
            missing = subprocess.run(version, capture_output=True, text=True, cwd=td)
            self.assertEqual(missing.returncode, 2, "a release without its manifest is refused")
            self.assertIn("MANIFEST.sha256", missing.stderr)

    def test_release_build_stops_when_a_bundled_parser_differs_from_its_reviewed_hash(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td)/"source"
            for name in ("SKILL.md", "README.md", "THIRD_PARTY_NOTICES.md"):
                (source/name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT/name, source/name)
            for name in ("agents", "references", "scripts"):
                shutil.copytree(ROOT/name, source/name, ignore=shutil.ignore_patterns("__pycache__"))
            self.assertEqual(build(Path(td)/"clean.zip", source).returncode, 0)
            loader = source/"scripts/palma_scan/_vendor/yaml/loader.py"
            loader.write_bytes(loader.read_bytes() + b"\n")
            result = build(Path(td)/"drifted.zip", source)
            self.assertEqual(result.returncode, 2)
            self.assertIn("yaml/loader.py", result.stderr)
            self.assertFalse((Path(td)/"drifted.zip").exists())

    def test_release_stamps_the_entrypoint_and_ships_the_batch_launcher_with_crlf(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td)/"release.zip"
            self.assertEqual(build(archive).returncode, 0)
            with zipfile.ZipFile(archive) as release:
                entry = release.read("palma-ai-readiness/scripts/palma-scan.py")
                launcher = release.read("palma-ai-readiness/scripts/run.cmd")
        self.assertIn(b"\nRELEASE = True\n", entry)
        self.assertNotIn(b"\nRELEASE = False\n", entry)
        self.assertEqual(launcher.count(b"\n"), launcher.count(b"\r\n"))

    def test_windows_launcher_needs_no_powershell_policy_change(self):
        commands = [line for line in (ROOT/"scripts/run.cmd").read_text().splitlines() if not line.startswith("rem ")]
        self.assertIn('set "NoDefaultCurrentDirectoryInExePath=1"', commands, "a py or python in the current folder is never run")
        self.assertFalse([line for line in commands if "powershell" in line.lower() or "executionpolicy" in line.lower()])
        self.assertIn('%palma_exe% -I -S "%~dp0palma-scan.py" run --open %*', commands)
        # cmd variable names ignore case, so the launcher's own variable must not be PALMA_PYTHON.
        self.assertFalse(re.search(r'set "?palma_python=', "\n".join(commands), re.IGNORECASE))


if __name__ == "__main__":
    unittest.main()
