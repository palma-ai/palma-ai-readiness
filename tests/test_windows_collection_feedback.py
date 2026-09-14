"""Windows collection regressions using synthetic data, never a machine scan."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.engine.collection import CollectOptions
from palma_scan.engine.filesystem import Budget, ReadGap, SafeFiles
from palma_scan import machine


class WindowsByteReads(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        self.path = self.home / "fixture.bin"
        self.expected = b"first\r\nsecond\x1alast\r\n"
        self.path.write_bytes(self.expected)

    def read(self):
        options = CollectOptions(home=self.home, os_name="windows")
        files = SafeFiles([self.home], Budget(options, time.monotonic()))
        return files.read(self.path)[0]

    @unittest.skipIf(os.name == "nt", "native CRT exercised by the Windows-only test")
    def test_windows_text_mode_cannot_translate_or_truncate_collected_bytes(self):
        # Removing O_BINARY must reproduce CRT CRLF translation and Ctrl-Z EOF.
        open_file, read_file = os.open, os.read
        binary = 0x8000  # The Windows CRT _O_BINARY flag; stripped before host opens.
        modes = {}

        def open_as_windows(path, flags, *args, **kwargs):
            descriptor = open_file(path, flags & ~binary, *args, **kwargs)
            modes[descriptor] = bool(flags & binary)
            return descriptor

        def read_as_windows(descriptor, size):
            data = read_file(descriptor, size)
            return data if modes[descriptor] else data.split(b"\x1a", 1)[0].replace(b"\r\n", b"\n")

        with patch.object(os, "O_BINARY", binary, create=True), \
                patch.object(os, "open", open_as_windows), patch.object(os, "read", read_as_windows):
            self.assertEqual(self.read(), b"first\r\nsecond\x1alast\r\n")

    @unittest.skipUnless(os.name == "nt", "requires native Windows CRT")
    def test_native_windows_preserves_binary_bytes(self):
        self.assertEqual(self.read(), b"first\r\nsecond\x1alast\r\n")


class WindowsFailureDiagnostics(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve() / "PRIVATE_AREA"
        self.directory.mkdir()
        self.discovery = machine._Discovery({"os": "windows"})

    def test_reparse_boundary_keeps_skipped_evidence_without_listing_the_target(self):
        # A Windows reparse attribute is observed at the filesystem boundary;
        # directory discovery previously swallowed the resulting ReadGap.
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path != self.directory:
                return info
            return types.SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev,
                                         st_ino=info.st_ino, st_uid=info.st_uid,
                                         st_file_attributes=0x400)

        source = self.discovery.source("fixture-discovery")
        with patch.object(Path, "lstat", lstat), \
                patch.object(os, "scandir", side_effect=AssertionError("Do not list a reparse target")):
            self.assertEqual(self.discovery.children(self.directory, source), [])
        areas = [item for item in self.discovery.sources if "/area-" in item["location"]]
        self.assertEqual(len(areas), 1)
        self.assertEqual(areas[0]["status"], "skipped")
        self.assertEqual(areas[0]["metadata"]["errorDiagnostics"],
                         [{"stage": "boundary-check", "kind": "read-gap", "reason": "symlink"}])
        self.assertEqual(self.discovery.counts["symlinksSkipped"], 1)
        self.assertNotIn("PRIVATE", json.dumps(self.discovery.sources))

    def test_profile_with_excluded_ancestor_is_skipped_instead_of_failed(self):
        current = self.directory / "home"
        current.mkdir()
        self.discovery.layout["currentHome"] = current
        # Model a mount exclusion at the account boundary; the real profile
        # reader must classify its fixed policy reason separately from OS I/O.
        with patch.object(machine.AccountBoundary, "check_path", side_effect=ReadGap("outside_scope")), \
                patch.object(os, "scandir", side_effect=AssertionError("Do not open an excluded profile")):
            self.assertEqual(self.discovery.profiles(), [])
        areas = [item for item in self.discovery.sources if "/area-" in item["location"]]
        self.assertEqual(len(areas), 1)
        self.assertEqual(areas[0]["status"], "skipped")
        self.assertEqual(areas[0]["metadata"]["errorDiagnostics"],
                         [{"stage": "profile-access", "kind": "read-gap", "reason": "outside_scope"}])
        self.assertEqual(self.discovery.counts["permissionErrors"], 0)
        self.assertNotIn("PRIVATE", json.dumps(self.discovery.sources))

    def test_only_known_policy_exclusions_are_skips_and_never_downgrade_errors(self):
        for error, status, diagnostic in (
                (ReadGap("symlink"), "skipped", {"kind": "read-gap", "reason": "symlink"}),
                (ReadGap("outside_scope"), "skipped", {"kind": "read-gap", "reason": "outside_scope"}),
                (ReadGap("permission_denied", "unreadable"), "error", {"kind": "read-gap", "reason": "permission_denied"}),
                (ReadGap("io_error", "unreadable"), "error", {"kind": "read-gap", "reason": "io_error"}),
                (ReadGap("PRIVATE_REASON", "skipped"), "error", {"kind": "unsupported-value"}),
                (PermissionError(13, "PRIVATE_EXCEPTION"), "error", {"kind": "permission-denied", "errno": 13})):
            with self.subTest(error=type(error).__name__, expected=status):
                discovery = machine._Discovery({"os": "windows"})
                source = discovery.source("fixture-discovery")
                discovery.error(source, error, self.directory, stage="boundary-check")
                area = next(item for item in discovery.sources if "/area-" in item["location"])
                self.assertEqual(area["status"], status)
                self.assertEqual(area["metadata"]["errorDiagnostics"], [{"stage": "boundary-check", **diagnostic}])
                discovery.error(source, OSError(5, "PRIVATE_EXCEPTION"), self.directory)
                discovery.error(source, ReadGap("outside_scope"), self.directory)
                self.assertEqual(area["status"], "error")
                self.assertNotIn("PRIVATE", json.dumps(discovery.sources))

    def test_directory_failure_keeps_native_code_and_stage_without_exception_text(self):
        # Dropping native codes makes inaccessible placeholders indistinguishable
        # from a scanner defect; propagating exception text discloses private paths.
        error = OSError(22, "PRIVATE_EXCEPTION_TEXT", str(self.directory))
        error.winerror = 1920
        source = self.discovery.source("fixture-discovery")
        with patch.object(os, "scandir", side_effect=error):
            self.assertEqual(self.discovery.children(self.directory, source), [])
        area = next(item for item in self.discovery.sources if "/area-" in item["location"])
        self.assertEqual(area.get("metadata", {}).get("errorDiagnostics"),
                         [{"stage": "directory-listing", "kind": "os-error", "errno": 22, "windowsError": 1920}])
        self.assertEqual(area["status"], "error")
        self.assertNotIn("PRIVATE", json.dumps(self.discovery.sources))

    def test_process_timeout_keeps_its_stage_and_omits_partial_command_output(self):
        error = subprocess.TimeoutExpired(["PRIVATE_COMMAND"], 15, output=b"PRIVATE_PROCESS")
        with patch.object(machine, "_windows_system_directory", return_value=self.directory), \
                patch.dict(os.environ, {"USERNAME": "fixture", "USERDOMAIN": ""}), \
                patch.object(machine, "_system_command", side_effect=error):
            self.discovery.processes()
        source = self.discovery.sources[0]
        self.assertEqual(source.get("metadata", {}).get("errorDiagnostics"),
                         [{"stage": "process-inventory", "kind": "timeout"}])
        self.assertEqual(source["status"], "error")
        self.assertNotIn("PRIVATE", json.dumps(self.discovery.sources))

    def test_command_exit_is_distinct_from_output_limit_without_exporting_output(self):
        # The real runner must preserve a nonzero exit status separately from its
        # output budget. Subprocess is the external boundary; no command is run.
        for result, wanted in (
                (subprocess.CompletedProcess([], 7, b"PRIVATE_STDOUT", b"PRIVATE_STDERR"),
                 {"stage": "process-inventory", "kind": "command-exit", "exitStatus": 7}),
                (subprocess.CompletedProcess([], 0, b"PRIVATE_STDOUT", b"PRIVATE_STDERR"),
                 {"stage": "process-inventory", "kind": "output-limit"})):
            with self.subTest(result=result.returncode):
                discovery = machine._Discovery({"os": "windows"})
                windows_os = types.SimpleNamespace(name="nt", environ={"USERNAME": "fixture", "USERDOMAIN": ""})
                with patch.object(machine, "os", windows_os), \
                        patch.object(machine, "_windows_system_directory", return_value=self.directory), \
                        patch.object(subprocess, "run", return_value=result), \
                        patch.object(machine, "MAX_OS_OUTPUT_BYTES", 1):
                    discovery.processes()
                self.assertEqual(discovery.sources[0].get("metadata", {}).get("errorDiagnostics"), [wanted])
                self.assertNotIn("PRIVATE", json.dumps(discovery.sources))


if __name__ == "__main__":
    unittest.main()
