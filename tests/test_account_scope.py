"""The scan covers one account and never exports account names or home paths."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan import machine
from palma_scan.collector import collect
from palma_scan.engine.redaction import MAX_SCRUBBED_LENGTH, IdentityScrubber
from palma_scan.model import validate
from palma_scan.rules import evaluate


class IdentityScrubberTests(unittest.TestCase):
    def setUp(self):
        self.scrubber = IdentityScrubber([
            {"root": "/Users/jdoe", "alias": "~", "names": ["jdoe"]},
            {"root": "/Users/colleague", "alias": "user-1", "names": []},
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
        generic = IdentityScrubber([{"root": "/Users/admin", "alias": "~", "names": ["admin"]}])
        self.assertEqual(generic.text("/Users/admin/.codex/config.toml"), "~/.codex/config.toml")
        self.assertEqual(generic.text("admin-tools connector"), "admin-tools connector")
        short = IdentityScrubber([{"root": "/home/al", "alias": "~", "names": ["al"]}])
        self.assertEqual(short.text("/home/al/.gemini/settings.json"), "~/.gemini/settings.json")
        self.assertEqual(short.text("al-assistant"), "al-assistant")

    def test_folder_names_encoded_with_dashes_are_scrubbed(self):
        scrubber = IdentityScrubber([{"root": "/Users/john.doe", "alias": "~", "names": ["john.doe"]}])
        self.assertEqual(scrubber.text("/private/tmp/claude-501/-Users-john-doe-code-app/.claude/settings.json"),
                         "/private/tmp/claude-501/-Users-[account]-code-app/.claude/settings.json")
        self.assertEqual(scrubber.text("C--Users-john-doe-code-app"), "C--Users-[account]-code-app")

    def test_many_accounts_are_scrubbed_with_one_pattern_per_folder_and_nested_homes_keep_their_alias(self):
        accounts = [{"root": "/home/me", "alias": "~"}, {"root": "/home/me/guest", "alias": "user-1"}]
        accounts += [{"root": f"/home/u{index:04d}", "alias": f"user-{index + 2}"} for index in range(2000)]
        scrubber = IdentityScrubber(accounts)
        self.assertEqual(len(scrubber.paths), 2)
        self.assertEqual(scrubber.text("/home/u1999/.mcp.json"), "user-2001/.mcp.json")
        self.assertEqual(scrubber.text("/home/me/guest/x and /home/me/code"), "user-1/x and ~/code")
        self.assertEqual(scrubber.text("/opt/data/project/.claude/settings.json"), "/opt/data/project/.claude/settings.json")

    def test_scrubbing_never_grows_a_field_past_the_snapshot_limit(self):
        scrubber = IdentityScrubber([{"root": "/home/abc", "alias": "~", "names": ["abc"]}])
        location = "/srv/" + "-".join(["abc"] * 2400)
        self.assertLessEqual(len(location), MAX_SCRUBBED_LENGTH)
        self.assertEqual(len(scrubber.scrub({"location": location})["location"]), MAX_SCRUBBED_LENGTH)

    def test_windows_home_forms_are_scrubbed_case_insensitively(self):
        windows = IdentityScrubber([{"root": "C:\\Users\\JDoe", "alias": "~", "names": ["JDoe"]}])
        self.assertEqual(windows.text("c:\\users\\jdoe\\.cursor\\mcp.json"), "~\\.cursor\\mcp.json")
        self.assertEqual(windows.text("C:/Users/JDoe/.cursor/mcp.json"), "~/.cursor/mcp.json")

    def test_snapshot_locations_and_messages_are_scrubbed_but_identifiers_and_labels_are_kept(self):
        scrubber = IdentityScrubber([{"root": "/Users/deadbeef", "alias": "~", "names": ["deadbeef"]}])
        snapshot = {"scope": {"label": "unchanged"},
                    "sources": [{"id": "src-deadbeef", "location": "/Users/deadbeef/x.json", "reasons": ["deadbeef copy"]}],
                    "observations": [{"id": "obs-1", "kind": "setting", "sourceId": "src-deadbeef", "name": "deadbeef",
                                      "details": {"configuredLocations": ["/cache/deadbeef/hooks"], "parentId": "obs-deadbeef",
                                                  "value": "/srv/deadbeef/tool", "label": "deadbeef"}}],
                    "coverage": {"limitations": ["/Users/deadbeef/.claude.json: parse_error"]}}
        scrubber.scrub_snapshot(snapshot)
        self.assertEqual(snapshot["sources"][0], {"id": "src-deadbeef", "location": "~/x.json", "reasons": ["[account] copy"]})
        observation = snapshot["observations"][0]
        self.assertEqual((observation["sourceId"], observation["name"]), ("src-deadbeef", "deadbeef"))
        self.assertEqual(observation["details"], {"configuredLocations": ["/cache/[account]/hooks"], "parentId": "obs-deadbeef",
                                                  "value": "/srv/[account]/tool", "label": "deadbeef"})
        self.assertEqual(snapshot["coverage"]["limitations"], ["~/.claude.json: parse_error"])

    def test_a_login_name_that_is_also_a_client_or_setting_name_changes_no_finding(self):
        with tempfile.TemporaryDirectory() as td:
            # VS Code dev containers sign in as "vscode"; "sandbox" is a Claude Code setting.
            home = Path(td).resolve() / "vscode"
            for relative, value in ((".config/Code/User/settings.json", {"chat.tools.global.autoApprove": True}),
                                    (".claude/settings.json", {"sandbox": {"enabled": False}})):
                (home / relative).parent.mkdir(parents=True)
                (home / relative).write_text(json.dumps(value))
            snapshot = collect(home, scope_type="machine")
            expected = sorted(item["ruleId"] for item in evaluate(json.loads(json.dumps(snapshot))))
            clients = sorted({item["client"] for item in snapshot["observations"]})
            machine.identity_scrubber(home, (), {"sandbox"}).scrub_snapshot(snapshot)
            snapshot["findings"] = evaluate(snapshot)
            validate(snapshot)
        self.assertIn("sandbox-disabled", expected)
        self.assertEqual(sorted(item["ruleId"] for item in snapshot["findings"]), expected)
        self.assertEqual(sorted({item["client"] for item in snapshot["observations"]}), clients)
        self.assertIn("vscode", clients)


@unittest.skipIf(os.name == "nt", "POSIX account database fixtures")
class AccountMetadataTests(unittest.TestCase):
    def test_the_current_home_comes_from_this_accounts_own_lookup(self):
        # Directory-service (LDAP, Active Directory) accounts are not in /etc/passwd.
        with patch("pwd.getpwuid", return_value=types.SimpleNamespace(pw_dir="/home/jdoe")) as lookup:
            self.assertEqual(machine._current_home("linux"), Path("/home/jdoe"))
        lookup.assert_called_once_with(os.getuid())
        with patch.dict(os.environ, {"USERPROFILE": "C:/Users/jdoe"}):
            self.assertEqual(machine._current_home("windows"), Path("C:/Users/jdoe"))

    def test_macos_daemon_accounts_and_tool_prefixes_are_not_account_homes_but_relocated_homes_are(self):
        output = ("_www /Library/WebServer\nroot /var/root\nnobody /var/empty\n_homebrew /opt/homebrew\n"
                  "shared /Users/Shared\nalice /Users/alice\nbob /Volumes/Data/bob\nme /Users/me\n")
        with patch.object(machine, "_system_command", return_value=output):
            profiles, roots = machine._profile_metadata("macos")
        self.assertEqual(profiles, [Path("/Users/alice"), Path("/Volumes/Data/bob"), Path("/Users/me")])
        self.assertEqual(roots, [Path("/Users")])

    def test_linux_service_accounts_are_not_account_homes(self):
        passwd = ("root:x:0:0:root:/root:/bin/bash\n"
                  "ollama:x:998:998::/usr/share/ollama:/usr/sbin/nologin\n"
                  "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                  "svc:x:1002:1002::/srv/svc:/bin/false\n"
                  "arch:x:1004:1004::/srv/arch:/usr/bin/nologin\n"
                  "alice:x:1001:1001::/home/alice:/bin/bash\n"
                  "dana:x:1003:1003::/data/users/dana:/bin/bash\n").encode()
        with patch("builtins.open", return_value=io.BytesIO(passwd)):
            profiles, roots = machine._profile_metadata("linux")
        self.assertEqual(profiles, [Path("/home/alice"), Path("/data/users/dana")])
        self.assertEqual(roots, [Path("/home")])

    def test_windows_system_and_service_profiles_are_not_account_homes_but_other_drives_are(self):
        values = {"S-1-5-18": "%SystemRoot%/system32/config/systemprofile",
                  "S-1-5-19": "C:/Windows/ServiceProfiles/LocalService",
                  "S-1-5-21-1": "C:/Users/alice", "S-1-5-21-2": "C:/Users/me", "S-1-12-1-3": "D:/Users/bob"}

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
        with patch.dict(sys.modules, {"winreg": registry}):
            profiles, roots = machine._profile_metadata("windows")
        self.assertEqual(profiles, [Path("C:/Users/alice"), Path("C:/Users/me"), Path("D:/Users/bob")])
        self.assertEqual(roots, [Path("C:/Users")])


if __name__ == "__main__":
    unittest.main()
