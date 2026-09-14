"""A malformed document or failing adapter ends one source, never the scan."""
from contextlib import ExitStack, redirect_stderr
import io
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan import cli, collector, machine
from palma_scan.collector import collect
from palma_scan.engine.parsing import ParseError, parse_document
from palma_scan.model import validate
from palma_scan.rules import evaluate

# Each input escaped the parser boundary before as something other than ValueError.
CRASH_CLASS = {
    "truncated XML plist (ExpatError)": (b'<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.exa', "plist"),
    "malformed plist date (AttributeError)": (b'<?xml version="1.0"?><plist version="1.0"><dict><key>a</key><date>nope</date></dict></plist>', "plist"),
    "unknown plist encoding (LookupError)": (b'<?xml version="1.0" encoding="U-0xTF-8"?><plist version="1.0"><dict><key>a</key><string>b</string></dict></plist>', "plist"),
    "unbalanced plist structure (IndexError)": (b'<?xml version="1.0"?><plist version="1.0"><key>a</key></plist>', "plist"),
    "invalid YAML timestamp (AttributeError)": (b"name: example\nupdated: !!timestamp 2020-99-99x\n", "yaml"),
    "invalid front matter timestamp (AttributeError)": (b"---\nname: example\nupdated: !!timestamp 2020-99-99x\n---\nbody\n", "markdown"),
}


class ParserBoundaryTests(unittest.TestCase):
    def test_every_decoder_failure_is_a_document_parse_error(self):
        for label, (raw, format_name) in CRASH_CLASS.items():
            with self.subTest(label):
                with self.assertRaises(ParseError):
                    parse_document(raw, format_name)

    def test_machine_metadata_reader_reports_malformed_documents_as_value_errors(self):
        with tempfile.TemporaryDirectory() as td:
            # Resolve macOS's /var alias: a redirected ancestor is rejected before parsing.
            root = Path(td).resolve()
            for name, raw in (("broken.plist", CRASH_CLASS["truncated XML plist (ExpatError)"][0]),
                              ("dated.plist", CRASH_CLASS["malformed plist date (AttributeError)"][0])):
                path = root / name
                path.write_bytes(raw)
                with self.subTest(name), self.assertRaises(ValueError) as caught:
                    machine._regular_metadata(path, "plist")
                self.assertEqual(str(caught.exception), "unsupported metadata document")
            deep = root / "deep.json"
            deep.write_text("[" * 100000 + "]" * 100000)
            with self.assertRaises(ValueError) as caught:
                machine._regular_metadata(deep)
            self.assertEqual(str(caught.exception), "unsupported metadata document")


class CollectionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve() / "home"
        self.home.mkdir()

    def write(self, relative, value):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value if isinstance(value, str) else json.dumps(value))
        return path

    def scan(self):
        snapshot = collect(self.home, scope_type="copied-home")
        snapshot["findings"] = evaluate(snapshot)
        validate(snapshot)
        return snapshot

    @unittest.skipIf(os.name == "nt", "POSIX fixture modes")
    def test_malformed_app_bundle_plist_neither_ends_the_scan_nor_names_the_bundle(self):
        self.write("Applications/PRIVATE_BROKEN.app/Contents/Info.plist", CRASH_CLASS["truncated XML plist (ExpatError)"][0])
        base = self.home / "Applications/Codex.app/Contents"
        self.write("Applications/Codex.app/Contents/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.openai.codex", "CFBundleShortVersionString": "26.901.1", "CFBundleExecutable": "Main"}))
        self.write("Applications/Codex.app/Contents/MacOS/Main", b"binary")
        (base / "MacOS/Main").chmod(0o755)
        self.write(".claude/settings.json", {"sandbox": {"enabled": False}})
        snapshot = self.scan()
        installed = [item for item in snapshot["observations"] if item["kind"] == "client" and item["details"].get("activation") == "installed"]
        self.assertEqual([(item["client"], item["details"].get("version")) for item in installed], [("codex", "26.901.1")])
        self.assertIn("sandbox-disabled", {item["ruleId"] for item in snapshot["findings"]})
        self.assertNotIn("PRIVATE_BROKEN", json.dumps(snapshot))

    def test_failing_adapter_records_a_gap_and_other_sources_are_still_collected(self):
        self.write(".claude/skills/example/SKILL.md", "---\nname: example\n---\nbody\n")
        self.write(".claude/settings.json", {"sandbox": {"enabled": False}})
        with patch("palma_scan.engine.collection.scan_skills", side_effect=RuntimeError("PRIVATE_EXCEPTION_TEXT")):
            snapshot = self.scan()
        failed = [source for source in snapshot["sources"] if source.get("reason") == "adapter_error"]
        self.assertTrue(failed)
        self.assertTrue(all(source["status"] == "error" for source in failed))
        self.assertEqual(snapshot["status"], "partial")
        self.assertIn("sandbox-disabled", {item["ruleId"] for item in snapshot["findings"]})
        self.assertNotIn("PRIVATE_EXCEPTION_TEXT", json.dumps(snapshot))

    def test_failing_translation_rolls_back_only_that_source(self):
        self.write(".gemini/settings.json", {"tools": {"sandbox": False}})
        self.write(".claude/settings.json", {"sandbox": {"enabled": False}})
        original = collector._Collector.extensions

        def extensions(instance, source, data, context="base"):
            if source["client"] == "gemini-cli":
                raise RuntimeError("PRIVATE_EXTRACTOR_TEXT")
            return original(instance, source, data, context)

        with patch.object(collector._Collector, "extensions", extensions):
            snapshot = self.scan()
        gemini = next(source for source in snapshot["sources"] if source["location"] == "~/.gemini/settings.json")
        self.assertEqual(gemini["status"], "error")
        self.assertIn("evidence in this source could not be interpreted safely", gemini.get("reasons", []) + [gemini["reason"]])
        # Settings extracted before the failure are withdrawn, not left half-annotated.
        self.assertFalse([item for item in snapshot["observations"] if item["sourceId"] == gemini["id"] and item["kind"] == "setting"])
        sandbox = [item for item in snapshot["findings"] if item["ruleId"] == "sandbox-disabled"]
        self.assertEqual({evidence["location"] for item in sandbox for evidence in item["evidence"]}, {"~/.claude/settings.json"})
        self.assertNotIn("PRIVATE_EXTRACTOR_TEXT", json.dumps(snapshot))


class MachineStepTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "volume/home/PRIVATE_CURRENT"
        self.home.mkdir(parents=True)
        self.layout = {"os": "linux", "roots": [self.root / "volume"], "blockedMounts": set(), "networkMountCount": 0,
                       "profiles": [self.home], "profileRoots": [self.root / "volume/home"], "currentHome": self.home,
                       "gaps": [], "mountIndexVerified": True}

    def core(self, profiles, **kwargs):
        return {"schemaVersion": "2.0", "collector": {"name": "synthetic", "version": "2.1.0"}, "mode": "endpoint",
                "status": "complete", "scope": {"type": kwargs["scope_type"]}, "sources": [], "observations": [],
                "coverage": {"limitations": kwargs["discovery_gaps"]}, "findings": []}

    def collect_with(self, **replacements):
        with ExitStack() as stack:
            stack.enter_context(patch.object(machine, "_layout", return_value=self.layout))
            stack.enter_context(patch.object(machine, "_system_sources", return_value=[]))
            stack.enter_context(patch.object(machine, "_system_command", return_value=""))
            stack.enter_context(patch.object(machine._Discovery, "services", return_value=None))
            stack.enter_context(patch.object(collector, "collect_scopes", side_effect=self.core, create=True))
            for name, value in replacements.items():
                stack.enter_context(patch.object(machine._Discovery, name, value))
            return machine.collect_machine()

    def test_unexpected_step_failure_is_partial_coverage_not_a_lost_scan(self):
        snapshot = self.collect_with(browser_extensions=lambda *_: (_ for _ in ()).throw(RuntimeError("PRIVATE_STEP_TEXT")))
        step = next(source for source in snapshot["sources"] if source["location"] == "machine:browser-ai-extension-metadata")
        self.assertEqual(step["status"], "error")
        self.assertEqual(snapshot["status"], "partial")
        self.assertEqual(len({source["id"] for source in snapshot["sources"]}), len(snapshot["sources"]))
        self.assertNotIn("PRIVATE_STEP_TEXT", json.dumps(snapshot))

    def test_profile_step_failure_falls_back_to_the_current_account(self):
        received = []

        def core(profiles, **kwargs):
            received.extend(profiles)
            return self.core(profiles, **kwargs)

        with patch.object(machine._Discovery, "profiles", side_effect=RuntimeError("PRIVATE")), \
             patch.object(machine, "_layout", return_value=self.layout), \
             patch.object(machine, "_system_sources", return_value=[]), \
             patch.object(machine, "_system_command", return_value=""), \
             patch.object(machine._Discovery, "services", return_value=None), \
             patch.object(collector, "collect_scopes", side_effect=core, create=True):
            snapshot = machine.collect_machine()
        self.assertEqual(received, [{"root": self.home, "alias": "~"}])
        self.assertEqual(snapshot["status"], "partial")


class CliBoundaryTests(unittest.TestCase):
    def run_cli(self, error):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "snapshot.json"
            stderr = io.StringIO()
            with patch("palma_scan.machine.collect_machine", side_effect=error), redirect_stderr(stderr), \
                 patch("sys.stdout", new_callable=io.StringIO):
                code = cli.main(["collect", "--output", str(target)])
            self.assertFalse(target.exists())
        return code, stderr.getvalue()

    def test_unexpected_internal_error_exits_2_without_traceback_or_contents(self):
        code, stderr = self.run_cli(RuntimeError("PRIVATE_DOCUMENT_TEXT"))
        self.assertEqual(code, 2)
        self.assertIn("unexpected internal error (RuntimeError)", stderr)
        self.assertNotIn("PRIVATE_DOCUMENT_TEXT", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_interrupt_exits_130_without_traceback(self):
        code, stderr = self.run_cli(KeyboardInterrupt())
        self.assertEqual(code, 130)
        self.assertIn("interrupted", stderr)
        self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
