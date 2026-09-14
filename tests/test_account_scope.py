"""The scan covers one account and never exports account names or home paths."""
import io
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan import machine
from palma_scan.engine.redaction import IdentityScrubber


class IdentityScrubberTests(unittest.TestCase):
    def setUp(self):
        self.scrubber = IdentityScrubber([
            {"root": Path("/Users/jdoe"), "alias": "~", "names": ["jdoe"]},
            {"root": Path("/Users/colleague"), "alias": "user-1", "names": []},
        ])

    def test_home_paths_become_aliases_wherever_they_appear(self):
        text = self.scrubber.text
        self.assertEqual(text("/Users/jdoe/.claude.json"), "~/.claude.json")
        self.assertEqual(text("/System/Volumes/Data/Users/jdoe/code/.mcp.json"), "~/code/.mcp.json")
        self.assertEqual(text("copied from /users/JDOE/notes"), "copied from ~/notes")
        self.assertEqual(text("/Users/colleague/project/.mcp.json"), "user-1/project/.mcp.json")
        self.assertEqual(text("/Users/jdoe2/.claude.json"), "/Users/jdoe2/.claude.json")

    def test_the_account_name_is_replaced_only_as_a_whole_token(self):
        text = self.scrubber.text
        self.assertEqual(text("/private/tmp/claude-501/-Users-jdoe-code-app/.claude/settings.json"),
                         "/private/tmp/claude-501/-Users-[account]-code-app/.claude/settings.json")
        self.assertEqual(text("mono-jdoe-feature/.mcp.json"), "mono-[account]-feature/.mcp.json")
        self.assertEqual(text("JDoe@example.test"), "[account]@example.test")
        self.assertEqual(text("jdoexyz and xjdoe"), "jdoexyz and xjdoe")
        # Only the scanning account's name is rewritten; other people are never opened.
        self.assertEqual(text("colleague-notes"), "colleague-notes")

    def test_generic_or_short_names_are_only_removed_from_home_paths(self):
        generic = IdentityScrubber([{"root": Path("/Users/admin"), "alias": "~", "names": ["admin"]}])
        self.assertEqual(generic.text("/Users/admin/.codex/config.toml"), "~/.codex/config.toml")
        self.assertEqual(generic.text("admin-tools connector"), "admin-tools connector")
        short = IdentityScrubber([{"root": Path("/home/al"), "alias": "~", "names": ["al"]}])
        self.assertEqual(short.text("/home/al/.gemini/settings.json"), "~/.gemini/settings.json")
        self.assertEqual(short.text("al-assistant"), "al-assistant")

    def test_windows_home_forms_are_scrubbed_case_insensitively(self):
        windows = IdentityScrubber([{"root": "C:\\Users\\JDoe", "alias": "~", "names": ["JDoe"]}])
        self.assertEqual(windows.text("c:\\users\\jdoe\\.cursor\\mcp.json"), "~\\.cursor\\mcp.json")
        self.assertEqual(windows.text("C:/Users/JDoe/.cursor/mcp.json"), "~/.cursor/mcp.json")

    def test_snapshot_strings_are_scrubbed_but_identifiers_are_kept(self):
        scrubber = IdentityScrubber([{"root": Path("/Users/deadbeef"), "alias": "~", "names": ["deadbeef"]}])
        snapshot = {"scope": {"label": "unchanged"},
                    "sources": [{"id": "src-deadbeef", "location": "/Users/deadbeef/x.json", "reasons": ["deadbeef copy"]}],
                    "observations": [{"id": "obs-1", "sourceId": "src-deadbeef", "name": "deadbeef",
                                      "details": {"configuredLocations": ["/Users/deadbeef/hooks"], "parentId": "obs-deadbeef"}}],
                    "coverage": {"limitations": ["/Users/deadbeef/.claude.json: parse_error"]}}
        scrubber.scrub_snapshot(snapshot)
        self.assertEqual(snapshot["sources"][0], {"id": "src-deadbeef", "location": "~/x.json", "reasons": ["[account] copy"]})
        observation = snapshot["observations"][0]
        self.assertEqual((observation["sourceId"], observation["name"]), ("src-deadbeef", "[account]"))
        self.assertEqual(observation["details"], {"configuredLocations": ["~/hooks"], "parentId": "obs-deadbeef"})
        self.assertEqual(snapshot["coverage"]["limitations"], ["~/.claude.json: parse_error"])


@unittest.skipIf(os.name == "nt", "POSIX account database fixtures")
class AccountMetadataTests(unittest.TestCase):
    def test_macos_daemon_accounts_and_tool_prefixes_are_not_account_homes(self):
        output = ("_www /Library/WebServer\nroot /var/root\nnobody /var/empty\n_homebrew /opt/homebrew\n"
                  "shared /Users/Shared\nalice /Users/alice\nme /Users/me\n")
        with patch.object(machine, "_system_command", return_value=output), \
             patch("pwd.getpwuid", return_value=types.SimpleNamespace(pw_dir="/Users/me")):
            current, profiles, roots = machine._profile_metadata("macos")
        self.assertEqual(current, Path("/Users/me"))
        self.assertEqual(profiles, [Path("/Users/alice"), Path("/Users/me")])
        self.assertEqual(roots, [Path("/Users")])

    def test_linux_service_accounts_are_not_account_homes(self):
        uid = os.getuid()
        passwd = ("root:x:0:0:root:/root:/bin/bash\n"
                  "ollama:x:998:998::/usr/share/ollama:/usr/sbin/nologin\n"
                  "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                  "svc:x:1002:1002::/srv/svc:/bin/false\n"
                  "alice:x:1001:1001::/home/alice:/bin/bash\n"
                  f"me:x:{uid}:{uid}::/home/me:/bin/zsh\n").encode()
        with patch("builtins.open", return_value=io.BytesIO(passwd)):
            current, profiles, _ = machine._profile_metadata("linux")
        self.assertEqual(current, Path("/home/me"))
        self.assertEqual(set(profiles) - {Path("/root")}, {Path("/home/alice"), Path("/home/me")})
        if uid != 0:
            self.assertNotIn(Path("/root"), profiles)

    def test_windows_system_and_service_profiles_are_not_account_homes(self):
        values = {"S-1-5-18": "%SystemRoot%/system32/config/systemprofile",
                  "S-1-5-19": "C:/Windows/ServiceProfiles/LocalService",
                  "S-1-5-21-1": "C:/Users/alice", "S-1-5-21-2": "C:/Users/me"}

        class Key:
            def __init__(self, name):
                self.name = name

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        registry = types.SimpleNamespace(
            HKEY_LOCAL_MACHINE="HKLM",
            OpenKey=lambda parent, name: Key(name),
            QueryValueEx=lambda key, value: ("C:/Users", 1) if value == "ProfilesDirectory" else (values[key.name], 1),
            QueryInfoKey=lambda key: (len(values), 0, 0),
            EnumKey=lambda key, index: list(values)[index])
        with patch.dict(sys.modules, {"winreg": registry}), patch.dict(os.environ, {"USERPROFILE": "C:/Users/me"}):
            current, profiles, roots = machine._profile_metadata("windows")
        self.assertEqual(current, Path("C:/Users/me"))
        self.assertEqual(profiles, [Path("C:/Users/alice"), Path("C:/Users/me")])
        self.assertEqual(roots, [Path("C:/Users")])


if __name__ == "__main__":
    unittest.main()
