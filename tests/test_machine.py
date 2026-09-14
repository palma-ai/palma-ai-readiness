"""Machine scope fixtures; never inventory the developer's real machine."""
from contextlib import ExitStack, contextmanager
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan import machine, collector


class MachineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.volume = self.root / "volume"
        self.home = self.volume / "home/PRIVATE_CURRENT"
        self.other = self.volume / "home/PRIVATE_OTHER"
        self.home.mkdir(parents=True)
        self.other.mkdir()
        self.layout = {"os": "linux", "roots": [self.volume], "blockedMounts": set(),
                       "networkMountCount": 0, "profiles": [self.home, self.other],
                       "profileRoots": [self.volume / "home"], "currentHome": self.home,
                       "gaps": [], "mountIndexVerified": True}

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path, value=""):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return path

    def stub_core(self, profiles, **kwargs):
        self.received_profiles, self.received = profiles, kwargs
        return {"schemaVersion": "2.0", "collector": {"name": "synthetic", "version": "2.1.0"}, "mode": "endpoint", "status": "complete", "scope": {"type": kwargs["scope_type"]}, "sources": [], "observations": [], "coverage": {"limitations": kwargs["discovery_gaps"]}, "findings": []}

    def scan(self, workspaces=None, **budgets):
        with ExitStack() as stack:
            stack.enter_context(patch.object(machine, "_layout", return_value=self.layout))
            stack.enter_context(patch.object(machine, "_environment", return_value={"visibility": "current-operating-system-context", "runtimeContext": "unknown", "containerIndicators": [], "subsystemIndicators": [], "sandboxIndicators": [], "isolation": "not-established"}))
            stack.enter_context(patch.object(machine, "_system_sources", return_value=[]))
            stack.enter_context(patch.object(machine, "_system_command", return_value=""))
            stack.enter_context(patch.object(machine._Discovery, "services", return_value=None))
            stack.enter_context(patch.object(collector, "collect_scopes", side_effect=self.stub_core, create=True))
            stack.enter_context(patch("socket.create_connection", side_effect=AssertionError("network forbidden")))
            snapshot = machine.collect_machine(workspaces, **budgets)
        serialized = json.dumps(snapshot)
        for private in (str(self.root), "PRIVATE_CURRENT", "PRIVATE_OTHER"):
            self.assertNotIn(private, serialized)
        return snapshot

    @contextmanager
    def opened(self):
        """Every directory opened or listed while the block runs."""
        paths, open_, scandir = [], os.open, os.scandir

        def tracking_open(path, flags, *args, **kwargs):
            if flags & getattr(os, "O_DIRECTORY", 0) and not isinstance(path, int):
                paths.append(Path(path))
            return open_(path, flags, *args, **kwargs)

        def tracking_scandir(path="."):
            if not isinstance(path, int):
                paths.append(Path(path))
            return scandir(path)

        with patch.object(os, "open", tracking_open), patch.object(os, "scandir", tracking_scandir):
            yield paths

    def exported(self, locations, **patches):
        """Scan with collection stubbed to return sources at these physical locations."""
        original = self.stub_core

        def core(profiles, **kwargs):
            snapshot = original(profiles, **kwargs)
            snapshot["sources"] = [{"id": f"src-{index}", "client": "claude-code", "scope": "workspace", "status": "collected",
                                    "location": location} for index, location in enumerate(locations)]
            return snapshot

        self.stub_core = core
        try:
            with patch.object(machine, "_account_names", return_value={"PRIVATE_LOGIN"}):
                snapshot = self.scan()
        finally:
            self.stub_core = original
        self.assertNotIn("PRIVATE_LOGIN", json.dumps(snapshot))
        return [source["location"] for source in snapshot["sources"] if not source["location"].startswith("machine:")]

    def test_scope_is_the_current_account_and_projects_outside_other_homes(self):
        outside = self.volume / "arbitrary/deep/data/project"
        self.put(outside / ".mcp.json", {})
        second = self.other / "work/project"
        self.put(second / ".claude/settings.json", {})
        with patch.dict(os.environ, {"HOME": "/PRIVATE_FAKE_HOME", "CODEX_HOME": "/PRIVATE_FAKE_CODEX"}), self.opened() as opened:
            snapshot = self.scan()
        self.assertEqual(snapshot["scope"]["type"], "machine")
        self.assertEqual(snapshot["scope"]["profileCount"], 1)
        self.assertEqual(self.received_profiles, [{"root": self.home, "alias": "~"}])
        self.assertIn(outside, self.received["workspaces"])
        self.assertNotIn(second, self.received["workspaces"])
        self.assertFalse([path for path in opened if path == self.other or self.other in path.parents],
                         "another account's home must never be opened")
        self.assertEqual(snapshot["scope"]["discovery"]["profilesExcluded"], 1)
        self.assertTrue(self.received["include_installations"])
        self.assertEqual(snapshot["coverage"]["limitations"], [])

    def test_temporary_folders_and_the_scanner_folder_are_not_projects_unless_explicit(self):
        temporary = self.volume / "tmp"
        session = temporary / "agent-session/project"
        self.put(session / ".claude/settings.json", {})
        scanner = self.volume / "tools/palma-ai-readiness"
        self.put(scanner / ".claude/settings.json", {})
        self.put(scanner / ".claude/worktrees/copy/.mcp.json", {})
        explicit = temporary / "requested"
        self.put(explicit / ".mcp.json", {})
        with patch.object(machine, "TEMPORARY_ROOTS", {"linux": (str(temporary),)}), patch.object(machine, "SCANNER_ROOT", scanner):
            snapshot = self.scan([explicit])
        workspaces = self.received["workspaces"]
        self.assertNotIn(session, workspaces)
        self.assertFalse([path for path in workspaces if path == scanner or scanner in path.parents])
        self.assertIn(explicit, workspaces)
        # The temporary folder, the scanner folder and the other account's home.
        self.assertEqual(snapshot["scope"]["discovery"]["excludedDirectories"], 3)

    def test_an_excluded_home_reached_through_another_path_stays_excluded(self):
        # The home itself is outside every volume root, so only its identity can exclude the alias.
        elsewhere = self.root / "elsewhere/PRIVATE_OTHER"
        elsewhere.mkdir(parents=True)
        self.layout["profiles"] = [self.home, elsewhere]
        alias = self.volume / "firmlinked-home"
        self.put(alias / ".mcp.json", {})
        original = Path.lstat

        def lstat(path):
            # The alias reports the excluded home's device and inode, as a firmlink would.
            return original(elsewhere) if path == alias else original(path)

        with patch.object(Path, "lstat", lstat):
            self.scan()
        self.assertNotIn(alias, self.received["workspaces"])

    def test_another_accounts_home_is_not_searched_when_it_is_a_volume_or_holds_one(self):
        self.put(self.other / "work/project/.claude/settings.json", {})
        self.put(self.other / "data/repo/.mcp.json", {})
        # A per-user dataset or encrypted home is its own mount; so is a disk mounted inside it.
        self.layout["roots"] = [self.volume, self.other, self.other / "data"]
        with self.opened() as opened:
            snapshot = self.scan()
        self.assertFalse([path for path in self.received["workspaces"] if self.other in path.parents])
        self.assertFalse([path for path in opened if path == self.other or self.other in path.parents])
        self.assertEqual(snapshot["scope"]["discovery"]["excludedDirectories"], 3)

    def test_another_accounts_linked_home_is_not_searched_where_it_points(self):
        target = self.volume / "data/PRIVATE_OTHER"
        self.put(target / "work/project/.mcp.json", {})
        self.other.rmdir()
        self.other.symlink_to(target, target_is_directory=True)
        # A link that would exclude this account's own home is ignored.
        (self.volume / "home/wide").symlink_to(self.volume, target_is_directory=True)
        self.layout["profiles"].append(self.volume / "home/wide")
        mine = self.volume / "code/app"
        self.put(mine / ".mcp.json", {})
        with self.opened() as opened:
            self.scan()
        self.assertFalse([path for path in self.received["workspaces"] if target in path.parents])
        self.assertFalse([path for path in opened if path == target or target in path.parents])
        self.assertIn(mine, self.received["workspaces"])

    @unittest.skipUnless(hasattr(os, "getuid"), "POSIX ownership")
    def test_folders_owned_by_another_person_are_not_opened_wherever_they_are(self):
        relocated = self.volume / "data/relocated-home"
        self.put(relocated / "code/app/.mcp.json", {})
        system = self.volume / "opt/team-tool"
        self.put(system / ".mcp.json", {})
        exported = self.volume / "srv/export"
        self.put(exported / ".mcp.json", {})
        owners = {relocated: os.getuid() + 5000, system: 0, exported: 65534}
        original = Path.lstat

        def lstat(path):
            info = original(path)
            if path not in owners:
                return info
            values = list(info)
            values[4] = owners[path]  # st_uid
            return os.stat_result(values)

        with patch.object(Path, "lstat", lstat), self.opened() as opened:
            self.scan()
        self.assertFalse([path for path in self.received["workspaces"] if relocated in path.parents])
        self.assertFalse([path for path in opened if path == relocated or relocated in path.parents])
        self.assertIn(system, self.received["workspaces"], "system accounts own shared locations")
        self.assertIn(exported, self.received["workspaces"], "nobody is not a person")

    def test_backup_volumes_are_not_searched(self):
        backup = self.volume / "Volumes/com.apple.TimeMachine.localsnapshots/Backups.backupdb/mac/2026-09-14-101010/Data"
        self.put(backup / "Users/someone/work/.claude/settings.json", {})
        self.layout["roots"] = [self.volume, backup]
        with self.opened() as opened:
            self.scan()
        self.assertFalse([path for path in self.received["workspaces"] if backup in path.parents])
        self.assertFalse([path for path in opened if path == backup or backup in path.parents])

    def test_local_drives_are_not_searched_when_other_accounts_cannot_be_identified(self):
        self.put(self.other / "work/project/.claude/settings.json", {})
        explicit = self.volume / "requested"
        self.put(explicit / ".mcp.json", {})
        with patch.object(machine._Discovery, "profiles", side_effect=RuntimeError("PRIVATE")), self.opened() as opened:
            snapshot = self.scan([explicit])
        self.assertEqual(self.received["workspaces"], [explicit])
        self.assertFalse([path for path in opened if path == self.other or self.other in path.parents])
        self.assertEqual(snapshot["status"], "partial")
        self.assertTrue(any("not searched for projects" in item for item in snapshot["coverage"]["limitations"]))

    def test_another_spelling_of_this_accounts_home_is_not_another_account(self):
        # On a case-insensitive disk the account database can spell the home differently.
        spelled = self.volume / "home/private_current"
        self.layout["currentHome"] = spelled
        original = Path.lstat
        discovery = machine._Discovery(self.layout)
        with patch.object(Path, "lstat", lambda path: original(self.home) if path == spelled else original(path)):
            discovery.profiles()
        self.assertEqual([item["root"] for item in discovery.accounts], [self.other])
        self.assertEqual(discovery.counts["profilesExcluded"], 1)

    def test_exported_text_is_scrubbed_of_account_homes_and_the_account_name(self):
        locations = self.exported(["/cache/-volume-home-PRIVATE_CURRENT-repo/.mcp.json",
                                   "/cache/PRIVATE_LOGIN-session/.mcp.json",
                                   str(self.other) + "/shared-project/.mcp.json",
                                   str(self.home) + "/.claude/settings.json"])
        self.assertIn("~/.claude/settings.json", locations)
        self.assertIn("user-1/shared-project/.mcp.json", locations)
        self.assertIn("/cache/[account]-session/.mcp.json", locations)
        self.assertTrue(any("-volume-home-[account]-repo" in location for location in locations))

    def test_this_accounts_home_and_name_are_scrubbed_even_when_the_home_is_not_opened(self):
        self.layout["blockedMounts"] = {self.home}  # for example a network home directory
        locations = self.exported([str(self.home) + "/code/app/.mcp.json", "/scratch/PRIVATE_LOGIN/proj/.mcp.json"])
        self.assertEqual(self.received_profiles, [])
        self.assertIn("~/code/app/.mcp.json", locations)
        self.assertIn("/scratch/[account]/proj/.mcp.json", locations)

    def test_discovery_is_not_limited_to_original_500_entry_budget(self):
        for index in range(650):
            (self.volume / "data" / f"directory-{index:04d}").mkdir(parents=True)
        target = self.volume / "data/directory-0649"
        self.put(target / "opencode.json", {})
        snapshot = self.scan()
        self.assertGreater(snapshot["scope"]["discovery"]["directoriesVisited"], 650)
        self.assertFalse(snapshot["scope"]["discovery"]["truncated"])
        self.assertIn(target, self.received["workspaces"])

    def test_truncation_is_a_real_gap_with_partial_status(self):
        for index in range(10):
            (self.volume / f"data-{index}").mkdir()
        snapshot = self.scan(directory_limit=2)
        self.assertTrue(snapshot["scope"]["discovery"]["truncated"])
        self.assertEqual(snapshot["status"], "partial")
        self.assertTrue(any("budget" in item for item in snapshot["coverage"]["limitations"]))

    def test_source_preserves_every_failure_and_does_not_downgrade_errors(self):
        discovery = machine._Discovery(self.layout)
        source = discovery.source("fixture-discovery")
        discovery.gap(source, "Permission denied in one discovery area.", "error")
        discovery.gap(source, "Directory budget reached.")
        discovery.gap(source, "Directory budget reached.")
        self.assertEqual(source["status"], "error")
        self.assertEqual(source["reasons"], ["Permission denied in one discovery area.", "Directory budget reached."])
        self.assertEqual(len(discovery.gaps), 2)

    def test_layout_metadata_failures_have_specific_source_evidence(self):
        self.layout["gaps"] = ["Local volume metadata could not be fully read.",
                               "Operating-system user profiles could not be enumerated."]
        discovery = machine._Discovery(self.layout)
        source = next(item for item in discovery.sources if item["location"] == "machine:operating-system-discovery-metadata")
        self.assertEqual(source["reasons"], self.layout["gaps"])
        self.assertEqual(source["status"], "error")
        self.assertEqual(len(discovery.gaps), len(self.layout["gaps"]))

    def test_repeated_discovery_area_failures_update_the_stored_source(self):
        discovery = machine._Discovery(self.layout)
        source = discovery.source("fixture-discovery")
        path = self.volume / "PRIVATE_AREA"
        discovery.error(source, PermissionError(13, "PRIVATE_ERROR"), path)
        discovery.error(source, OSError(5, "PRIVATE_ERROR"), path)
        discovery.error(source, PermissionError(13, "PRIVATE_ERROR"), path)
        areas = [item for item in discovery.sources if "/area-" in item["location"]]
        self.assertEqual(len(areas), 1)
        self.assertEqual(areas[0]["reasons"], ["Permission denied for this discovery area.",
                                               "This discovery area could not be read safely."])
        self.assertEqual(len(discovery.gaps), 2)
        self.assertNotIn("PRIVATE", json.dumps(discovery.sources))

    def test_nonlocal_mounts_are_not_traversed_or_used_as_profiles(self):
        remote = self.volume / "network"
        self.put(remote / "PRIVATE_REMOTE/.mcp.json", {})
        self.layout["blockedMounts"] = {remote}
        self.layout["networkMountCount"] = 1
        self.layout["profiles"].append(remote / "PRIVATE_REMOTE")
        snapshot = self.scan()
        self.assertEqual(snapshot["scope"]["discovery"]["networkMountsSkipped"], 1)
        self.assertNotIn(remote / "PRIVATE_REMOTE", self.received["workspaces"])
        self.assertFalse(any(item["root"] == remote / "PRIVATE_REMOTE" for item in self.received_profiles))

    def test_duplicate_roots_and_links_cannot_repeat_or_escape_discovery(self):
        self.layout["roots"].append(self.volume)
        external = self.root / "PRIVATE_EXTERNAL"
        self.put(external / ".mcp.json", {})
        (self.home / "linked").symlink_to(external, target_is_directory=True)
        snapshot = self.scan()
        self.assertNotIn(external, self.received["workspaces"])
        self.assertGreater(snapshot["scope"]["discovery"]["symlinksSkipped"], 0)
        self.assertEqual(len(self.received["workspaces"]), len(set(self.received["workspaces"])))

    def test_permission_failure_is_counted_without_private_path_or_error_text(self):
        denied = self.volume / "PRIVATE_DENIED"
        denied.mkdir()
        open_, scandir = os.open, os.scandir

        def denied_open(path, flags, *args, **kwargs):
            if not isinstance(path, int) and Path(path) == denied:
                raise PermissionError(13, "PRIVATE_ERROR_CANARY", str(path))
            return open_(path, flags, *args, **kwargs)

        def denied_scandir(path="."):
            if not isinstance(path, int) and Path(path) == denied:
                raise PermissionError(13, "PRIVATE_ERROR_CANARY", str(path))
            return scandir(path)

        with patch.object(os, "open", denied_open), patch.object(os, "scandir", denied_scandir):
            snapshot = self.scan()
        self.assertEqual(snapshot["status"], "partial")
        self.assertGreater(snapshot["scope"]["discovery"]["permissionErrors"], 0)
        self.assertNotIn("PRIVATE_DENIED", json.dumps(snapshot))
        self.assertNotIn("PRIVATE_ERROR_CANARY", json.dumps(snapshot))
        self.assertTrue(any("/area-" in source["location"] and source["status"] == "error" for source in snapshot["sources"]))

    @unittest.skipUnless(hasattr(os, "getuid"), "POSIX process ownership")
    def test_process_inventory_keeps_only_known_names_not_paths_pids_or_arguments(self):
        discovery = machine._Discovery(self.layout)
        with patch.object(machine, "_system_command", return_value="/PRIVATE_ACCOUNT/bin/claude\nollama\nPRIVATE_UNKNOWN_PROCESS\nnode\n") as run:
            discovery.processes()
        self.assertEqual(run.call_args.args[0], ["/bin/ps", "-U", str(os.getuid()), "-o", "comm="], "this account's processes only")
        self.assertEqual({item["client"] for item in discovery.observations}, {"claude-code", "ollama"})
        self.assertTrue(all(item["details"]["activation"] == "running" for item in discovery.observations))
        self.assertNotIn("PRIVATE", json.dumps(discovery.observations))

    def test_windows_process_csv_discards_all_columns_except_known_image_name(self):
        layout = dict(self.layout, os="windows")
        discovery = machine._Discovery(layout)
        output = '"Codex.exe","987654","PRIVATE_SESSION","42","999 K"\n"PRIVATE_UNKNOWN.exe","123","PRIVATE_SESSION","9","12 K"'
        with patch.object(machine, "_windows_system_directory", return_value=Path("C:/Windows/System32")), \
             patch.object(machine, "_system_command", return_value=output) as run, patch.dict(os.environ, {"USERNAME": "me"}):
            discovery.processes()
        self.assertEqual(run.call_args.args[0][-2:], ["/FI", "USERNAME eq me"], "this account's processes only")
        self.assertEqual([item["client"] for item in discovery.observations], ["codex"])
        self.assertNotIn("987654", json.dumps(discovery.observations))
        self.assertNotIn("PRIVATE", json.dumps(discovery.observations))

    @unittest.skipUnless(hasattr(os, "getuid"), "POSIX process ownership")
    def test_os_command_runner_has_fixed_paths_no_shell_and_minimal_environment(self):
        uid = str(os.getuid())
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"codex\n", b"")) as run:
            with patch.dict(os.environ, {"SECRET_TOKEN": "PRIVATE_ENV_CANARY", "LD_PRELOAD": "/PRIVATE_PRELOAD"}):
                machine._system_command(["/bin/ps", "-U", uid, "-o", "comm="])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertNotIn("SECRET_TOKEN", run.call_args.kwargs["env"])
        self.assertNotIn("LD_PRELOAD", run.call_args.kwargs["env"])
        with patch.object(subprocess, "run", side_effect=AssertionError("must not run")):
            # Every account's processes, another account's, or arbitrary programs are refused.
            for command in (["/tmp/DISCOVERED_EXECUTABLE"], ["/sbin/mount", "-a"], ["/bin/ps", "auxew"], ["/bin/ps", "-eo", "comm="],
                            ["/bin/ps", "-axo", "comm="], ["/bin/ps", "-U", str(os.getuid() + 1), "-o", "comm="],
                            ["/usr/bin/dscl", ".", "-delete", "/Users/PRIVATE"], []):
                with self.assertRaises(ValueError):
                    machine._system_command(command)

    def test_browser_manifest_hint_is_structural_and_preserves_uncertainty(self):
        path = self.home / ".config/google-chrome/Default/Extensions/PRIVATE_EXTENSION/1/manifest.json"
        self.put(path, {"name": "ChatGPT PRIVATE_DISPLAY_NAME", "permissions": ["cookies", "scripting", "PRIVATE_PERMISSION"], "host_permissions": ["<all_urls>", "https://PRIVATE_HOST/*"]})
        snapshot = self.scan()
        plugins = [item for item in snapshot["observations"] if item["kind"] == "plugin"]
        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0]["details"]["permissions"], ["cookies", "scripting"])
        self.assertTrue(plugins[0]["details"]["broadHostAccess"])
        self.assertEqual(plugins[0]["details"]["auditStatus"], "not-assessed")
        self.assertNotIn("PRIVATE", json.dumps(plugins))

    def test_metadata_reader_rejects_redirects_duplicate_keys_and_special_files(self):
        target = self.put(self.root / "safe.json", {"name": "safe"})
        alias = self.root / "alias.json"
        alias.symlink_to(target)
        with self.assertRaises(ValueError):
            machine._regular_metadata(alias)
        duplicate = self.put(self.root / "duplicate.json", '{"name":"a","name":"PRIVATE_DUPLICATE"}')
        with self.assertRaises(ValueError) as error:
            machine._regular_metadata(duplicate)
        self.assertNotIn("PRIVATE_DUPLICATE", str(error.exception))
        if hasattr(os, "mkfifo"):
            fifo = self.root / "fifo.json"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                machine._regular_metadata(fifo)

    def test_linux_mount_metadata_distinguishes_local_network_and_virtual_filesystems(self):
        data = b"1 0 8:1 / / rw - ext4 /dev/sda rw\n2 1 0:2 / /proc rw - proc proc rw\n3 1 0:3 / /mnt/team rw - nfs server:/PRIVATE_SHARE rw\n4 1 8:2 / /mnt/data\\040disk rw - xfs /dev/sdb rw\n"
        with patch("builtins.open", return_value=io.BytesIO(data)):
            roots, blocked, network_count = machine._mounts("linux")
        self.assertEqual(roots, [Path("/"), Path("/mnt/data disk")])
        self.assertEqual(blocked, {Path("/proc"), Path("/mnt/team")})
        self.assertEqual(network_count, 1)

    def test_macos_mount_and_process_metadata_are_local_and_fixed(self):
        text = "/dev/disk1s1 on / (apfs, sealed, local, read-only)\n/dev/disk2s1 on /Volumes/Local Disk (apfs, local)\n//PRIVATE_SERVER/share on /Volumes/Remote (smbfs, nodev)\nmap auto_home on /System/Volumes/Data/home (autofs, automounted)\n"
        with patch.object(machine, "_system_command", return_value=text) as run:
            roots, blocked, count = machine._mounts("macos")
        self.assertEqual(run.call_args.args[0], ["/sbin/mount"])
        self.assertEqual(roots, [Path("/"), Path("/Volumes/Local Disk")])
        self.assertIn(Path("/Volumes/Remote"), blocked)
        self.assertEqual(count, 1)
        discovery = machine._Discovery(dict(self.layout, os="macos"))
        with patch.object(machine, "_system_command", return_value="/Applications/Codex.app/Contents/MacOS/Codex\n/PRIVATE/Claude\n") as run:
            discovery.processes()
        # -x includes this account's apps that have no terminal.
        self.assertEqual(run.call_args.args[0], ["/bin/ps", "-x", "-U", str(os.getuid()), "-o", "comm="])
        self.assertEqual({o["client"] for o in discovery.observations}, {"codex", "claude-code"})

    def test_localized_chromium_and_firefox_metadata_discard_private_names(self):
        base = self.home / ".config/google-chrome/Default/Extensions/PRIVATE_EXTENSION/1"
        self.put(base / "manifest.json", {"name": "__MSG_appName__", "default_locale": "en", "permissions": ["debugger"]})
        self.put(base / "_locales/en/messages.json", {"appName": {"message": "Claude PRIVATE_NAME"}})
        self.put(self.home / ".mozilla/firefox/PRIVATE_PROFILE/extensions.json", {"addons": [{"defaultLocale": {"name": "Copilot PRIVATE_NAME"}, "id": "PRIVATE_EMAIL", "active": True, "userPermissions": {"permissions": ["cookies", "PRIVATE_PERMISSION"], "origins": ["<all_urls>", "https://PRIVATE_HOST/*"]}}]})
        snapshot = self.scan()
        plugins = [o for o in snapshot["observations"] if o["kind"] == "plugin"]
        self.assertEqual(len(plugins), 2)
        self.assertEqual({o["details"]["activation"] for o in plugins}, {"present"})
        self.assertTrue(any(o["details"]["broadHostAccess"] for o in plugins))
        self.assertNotIn("PRIVATE", json.dumps(plugins))

    def test_all_platform_managed_candidate_paths_are_fixed_and_typed(self):
        for platform in ("macos", "linux", "windows"):
            with self.subTest(platform=platform), patch.object(machine, "_windows_system_directory", return_value=Path("/WINDOWS/System32")):
                sources = machine._system_sources(platform)
            self.assertTrue(any(s["client"] == "copilot-cli" and s["path"].name == "managed-settings.json" for s in sources))
            self.assertTrue(any(s["client"] == "opencode" and s["path"].name == "opencode.jsonc" for s in sources))
            self.assertTrue(all(s["location"].startswith("system:") for s in sources))

    def test_original_managed_path_parity_and_safe_gemini_overrides(self):
        from palma_scan.engine.paths import managed_candidates
        for platform in ("macos", "linux", "windows"):
            env = {"PROGRAMFILES": r"C:\Program Files", "PROGRAMDATA": r"C:\ProgramData"} if platform == "windows" else {}
            with self.subTest(platform=platform), patch.object(machine, "_windows_system_directory", return_value=Path("/WINDOWS/System32")):
                actual = machine._system_sources(platform, environ=env)
            expected = {(candidate.family, candidate.path) for candidate in managed_candidates(platform, env) if candidate.role != "dropins"}
            self.assertTrue(expected.issubset({(item["client"], item["path"]) for item in actual}))
            self.assertEqual({item["path"].name for item in actual if item["client"] == "codex"}, {"config.toml", "requirements.toml", "managed_config.toml"})
        custom = self.volume / "policy/PRIVATE_GEMINI.json"
        discovery = machine._Discovery(self.layout)
        env = {"GEMINI_CLI_SYSTEM_SETTINGS_PATH": str(custom), "GEMINI_CLI_SYSTEM_DEFAULTS_PATH": "relative/PRIVATE_DEFAULTS.json", "SECRET_TOKEN": "PRIVATE_TOKEN"}
        with patch.object(discovery, "children", return_value=[]):
            sources = machine._system_sources("linux", discovery, environ=env)
        self.assertTrue(any(item["client"] == "gemini-cli" and item["path"] == custom for item in sources))
        self.assertTrue(any("GEMINI_CLI_SYSTEM_DEFAULTS_PATH" in gap for gap in discovery.gaps))
        self.assertNotIn("PRIVATE", json.dumps(discovery.sources))
        self.assertNotIn("PRIVATE", json.dumps([item["location"] for item in sources]))


if __name__ == "__main__":
    unittest.main()
