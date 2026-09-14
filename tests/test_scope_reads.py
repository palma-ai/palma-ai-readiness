"""Account exclusions apply at the read boundary, including direct candidates."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan import baseline, machine
from palma_scan.engine.collection import CollectOptions
from palma_scan.engine.filesystem import Budget, ReadGap, SafeFiles


@unittest.skipUnless(hasattr(os, "getuid"), "POSIX ownership fixtures")
class AccountReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.folder = self.root / "profile" / ".cursor"
        self.folder.mkdir(parents=True)
        self.config = self.folder / "mcp.json"
        self.config.write_text(json.dumps({"mcpServers": {"fixture": {"command": "fixture-server"}}}))

    @contextmanager
    def owner(self, path, uid, *, descriptor_only=False):
        target = path.stat()
        lstat, fstat = Path.lstat, os.fstat
        def changed(info):
            if (info.st_dev, info.st_ino) != (target.st_dev, target.st_ino):
                return info
            fields = list(info)
            fields[4] = uid
            return os.stat_result(fields)
        with patch.object(Path, "lstat", lambda p: lstat(p) if descriptor_only else changed(lstat(p))), \
                patch("os.fstat", lambda fd: changed(fstat(fd))):
            yield

    def files(self, **kwargs):
        return SafeFiles([self.root], Budget(CollectOptions(home=self.root), time.monotonic()), **kwargs)

    def test_single_link_files_and_foreign_ancestors_are_never_read(self):
        for target in (self.config, self.folder):
            with self.subTest(target=target.name), self.owner(target, 20001):
                with self.assertRaises(ReadGap):
                    self.files(account_uid=os.getuid()).read(self.config)
                with self.assertRaises((ValueError, ReadGap)):
                    machine._regular_metadata(self.config)

    def test_foreign_directories_are_never_listed(self):
        discovery = machine._Discovery({"os": "macos"}, directory_limit=100, entry_limit=1000, seconds=10)
        with self.owner(self.folder, 20001):
            with self.assertRaises(ReadGap):
                self.files(account_uid=os.getuid()).children(self.folder)
            self.assertEqual(discovery.children(self.folder, discovery.source("fixture")), [])

    def test_ownership_is_rechecked_on_opened_files_and_ancestors(self):
        for target in (self.config, self.folder):
            with self.subTest(target=target.name), self.owner(target, 20001, descriptor_only=True):
                with self.assertRaises(ReadGap):
                    self.files(account_uid=os.getuid()).read(self.config)
                with self.assertRaises((ValueError, ReadGap)):
                    machine._regular_metadata(self.config)

    def test_copied_homes_and_system_owned_paths_keep_their_evidence(self):
        with self.owner(self.folder, 20001):
            self.assertIn(b"fixture-server", self.files().read(self.config)[0])
        for uid in (0, 1, 65534, os.getuid()):
            with self.subTest(uid=uid), self.owner(self.folder, uid):
                self.assertIn(b"fixture-server", self.files(account_uid=os.getuid()).read(self.config)[0])

    def test_system_owned_hardlinks_remain_readable(self):
        os.link(self.config, self.folder / "hardlink.json")
        for uid in (0, 1, 65534):
            with self.subTest(uid=uid), self.owner(self.config, uid):
                self.assertIn(b"fixture-server", self.files(account_uid=os.getuid()).read(self.config)[0])

    def test_native_direct_configuration_and_managed_policy_enforce_ownership(self):
        with self.owner(self.config, 20001), patch.dict(os.environ, {}, clear=True), \
                patch.object(baseline, "installed_client_candidates", return_value=[]), \
                patch.object(baseline, "installation_candidates", return_value=[]):
            snapshot = baseline.collect_scopes([{"root": self.root / "profile"}],
                system_sources=[{"client": "cursor", "path": self.config, "location": "system:fixture"}],
                include_installations=True)
        self.assertFalse([item for item in snapshot["observations"] if item["kind"] == "mcp"])

    def test_explicit_workspace_cannot_override_account_exclusions(self):
        home = self.root / "own"
        home.mkdir()
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(baseline, "installed_client_candidates", return_value=[]), \
                patch.object(baseline, "installation_candidates", return_value=[]):
            snapshot = baseline.collect_scopes([{"root": home}], workspaces=[self.root / "profile"],
                excluded_roots=[self.root / "profile"], include_installations=True)
        self.assertFalse([item for item in snapshot["observations"] if item["kind"] == "mcp"])

    def test_linked_account_targets_stay_excluded_from_explicit_native_workspaces(self):
        home = self.root / "own"
        home.mkdir()
        alias = self.root / "other-account"
        alias.symlink_to(self.root / "profile", target_is_directory=True)
        layout = {"os": "macos", "roots": [], "profiles": [home, alias], "currentHome": home,
                  "blockedMounts": set(), "gaps": [], "mountIndexVerified": True}
        with patch.object(machine, "_layout", return_value=layout), \
                patch.object(machine._Discovery, "processes"), patch.object(machine._Discovery, "services"), \
                patch.object(machine._Discovery, "browser_extensions"), patch.object(machine, "_system_sources", return_value=[]), \
                patch.dict(os.environ, {}, clear=True), \
                patch.object(baseline, "installed_client_candidates", return_value=[]), \
                patch.object(baseline, "installation_candidates", return_value=[]):
            snapshot = machine.collect_machine([self.root / "profile"])
        self.assertFalse([item for item in snapshot["observations"] if item["kind"] == "mcp"])
