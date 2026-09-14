"""Policy assertions require the setting's meaning, not a category keyword."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan import governance
from palma_scan.collector import collect
from palma_scan.rules import evaluate


class SettingSemanticsTests(unittest.TestCase):
    def scan(self, files):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            for relative, value in files.items():
                path = home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
            snapshot = collect(home)
            return snapshot, {item["ruleId"]: item for item in evaluate(snapshot)}

    def assert_collected(self, snapshot, keys):
        settings = {item["details"]["key"] for item in snapshot["observations"] if item["kind"] == "setting"}
        self.assertTrue(set(keys) <= settings, set(keys) - settings)

    def test_hook_switches_do_not_declare_handlers(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                snapshot, findings = self.scan({
                    ".claude/settings.json": {"disableAllHooks": enabled},
                    ".copilot/settings.json": {"disableAllHooks": enabled},
                    ".config/Code/User/settings.json": {"chat.useHooks": enabled},
                    ".codex/config.toml": "[features]\nhooks=" + str(enabled).lower() + "\ncodex_hooks=" + str(enabled).lower(),
                })
                self.assert_collected(snapshot, ("disableAllHooks", "chat.useHooks", "features.hooks", "features.codex_hooks"))
                self.assertNotIn("hooks-declared", findings)

    def test_disabled_and_cached_hook_handlers_keep_their_evidence_at_info_priority(self):
        hook = {"PreToolUse": [{"hooks": [{"type": "command", "command": "PRIVATE_HANDLER"}]}]}
        snapshot, findings = self.scan({
            ".claude/settings.json": {"disableAllHooks": True, "hooks": hook},
            ".claude/remote-settings.json": {"disableAllHooks": True, "hooks": hook},
            ".config/Code/User/settings.json": {"chat.useHooks": False, "chat.hookFilesLocations": {"./hooks.json": True}},
        })
        finding = findings["hooks-declared"]
        # No handler applies as written: the declarations stay in evidence, the priority does not.
        self.assertEqual((finding["severity"], finding["baselineSeverity"], finding["applies"]), ("info", "medium", 0))
        self.assertIn("switched off", finding["summary"])
        self.assertIn("in a cached policy copy", finding["summary"])
        self.assertTrue(any(item["value"]["observedState"] == "disabled" for item in finding["evidence"]))
        self.assertTrue(any(item["value"]["context"] == "cached" for item in finding["evidence"]))
        self.assertTrue({"disableAllHooks", "chat.useHooks"}.isdisjoint(item["key"] for item in finding["evidence"]))
        self.assertNotIn("PRIVATE_HANDLER", json.dumps(snapshot))

    def test_empty_hook_containers_do_not_declare_handlers(self):
        snapshot, findings = self.scan({".claude/settings.json": {"hooks": {}},
            ".config/Code/User/settings.json": {"chat.useHooks": True, "chat.hookFilesLocations": {}}})
        self.assert_collected(snapshot, ("hooks", "chat.hookFilesLocations"))
        self.assertNotIn("hooks-declared", findings)

    def test_sandbox_options_do_not_claim_sandbox_disabled(self):
        snapshot, findings = self.scan({
            ".claude/settings.json": {"sandbox": {"enabled": True, "allowUnsandboxedCommands": False,
                "autoAllowBashIfSandboxed": False, "failIfUnavailable": False,
                "network": {"allowLocalBinding": False, "allowAllUnixSockets": False}}},
            ".copilot/settings.json": {"sandbox": {"enabled": True, "allowBypass": False,
                "auth": {"git": False, "gh": False}, "userPolicy": {
                    "network": {"allowLocalNetwork": False}, "seatbelt": {"keychainAccess": False}}}},
            ".config/Code/User/settings.json": {"chat.agent.sandbox.enabled": "on", "chat.agent.sandbox.allowNetwork": False},
            ".codex/config.toml": 'sandbox_mode="workspace-write"\n[sandbox_workspace_write]\nnetwork_access=false',
        })
        self.assert_collected(snapshot, ("sandbox.allowUnsandboxedCommands", "sandbox.autoAllowBashIfSandboxed",
            "sandbox.failIfUnavailable", "sandbox.allowBypass", "sandbox.auth.git", "sandbox.auth.gh",
            "sandbox.userPolicy.seatbelt.keychainAccess", "chat.agent.sandbox.allowNetwork", "sandbox_workspace_write.network_access"))
        self.assertNotIn("sandbox-disabled", findings)

    def test_actual_sandbox_off_only_cites_the_switch(self):
        for path, data, key in (
            (".claude/settings.json", {"sandbox": {"enabled": False, "allowUnsandboxedCommands": False}}, "sandbox.enabled"),
            (".copilot/settings.json", {"sandbox": {"enabled": False, "allowBypass": False}}, "sandbox.enabled"),
            (".gemini/settings.json", {"tools": {"sandbox": False}}, "tools.sandbox"),
            (".config/Code/User/settings.json", {"chat.agent.sandbox.enabled": "off", "chat.agent.sandbox.allowNetwork": False}, "chat.agent.sandbox.enabled"),
            (".openclaw/openclaw.json", {"agents": {"defaults": {"sandbox": {"mode": "off", "ssh": {"strictHostKeyChecking": False}}}}}, "agents.defaults.sandbox.mode"),
        ):
            with self.subTest(path=path):
                _, findings = self.scan({path: data})
                finding = findings["sandbox-disabled"]
                self.assertEqual(finding["severity"], "high")
                self.assertEqual({item["key"] for item in finding["evidence"]}, {key})

    def test_protective_browser_settings_do_not_enable_browser_access(self):
        snapshot, findings = self.scan({
            ".gemini/settings.json": {"agents": {"browser": {"confirmSensitiveActions": True, "blockFileUploads": True}}},
            ".codex/config.toml": "[browser_use]\ndisable_auto_review=true",
            ".openclaw/openclaw.json": {"browser": {"enabled": False, "attachOnly": True, "noSandbox": False}},
        })
        self.assert_collected(snapshot, ("agents.browser.confirmSensitiveActions", "agents.browser.blockFileUploads",
            "browser_use.disable_auto_review", "browser.attachOnly", "browser.noSandbox"))
        self.assertNotIn("browser-use-enabled", findings)
        self.assertNotIn("browser-actions-unconfirmed", findings)

    def test_browser_enablement_and_unconfirmed_actions_keep_distinct_evidence(self):
        _, findings = self.scan({".gemini/settings.json": {"agents": {
            "overrides": {"browser_agent": {"enabled": True}},
            "browser": {"confirmSensitiveActions": False, "blockFileUploads": True}}}})
        enabled, unconfirmed = findings["browser-use-enabled"], findings["browser-actions-unconfirmed"]
        self.assertEqual(enabled["severity"], "critical")
        self.assertEqual(unconfirmed["severity"], "critical")
        self.assertEqual({item["key"] for item in enabled["evidence"]}, {"agents.overrides.browser_agent.enabled"})
        self.assertEqual({item["key"] for item in unconfirmed["evidence"]}, {"agents.browser.confirmSensitiveActions"})

    def test_browser_access_grants_and_inactive_switches_remain_critical(self):
        _, findings = self.scan({".codex/config.toml": '''profile="safe"
[browser_use]
disable_auto_review=true
allow_global_persistent_approval=true
[profiles.safe.features]
browser_use=false
[profiles.alternative.features]
browser_use=true
'''})
        finding = findings["browser-use-enabled"]
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual({item["key"] for item in finding["evidence"]}, {
            "features.browser_use", "browser_use.allow_global_persistent_approval"})
        self.assertTrue(any(item["value"]["observedState"] == "disabled" for item in finding["evidence"]))

    def test_unknown_keyword_settings_stay_in_inventory_without_asserting_access(self):
        snapshot, findings = self.scan({".codex/config.toml": '''[browser]
keepAlive=true
[sandbox]
showStatus=false
'''})
        self.assert_collected(snapshot, ("browser.keepAlive", "sandbox.showStatus"))
        self.assertNotIn("browser-use-enabled", findings)
        self.assertNotIn("sandbox-disabled", findings)

    def test_computer_confirmation_metadata_does_not_enable_computer_use(self):
        snapshot, findings = self.scan({".codex/config.toml": '''[computer_use]
confirm_actions=true
block_file_uploads=true
'''})
        self.assert_collected(snapshot, ("computer_use.confirm_actions", "computer_use.block_file_uploads"))
        self.assertNotIn("computer-use-enabled", findings)
        _, findings = self.scan({".codex/config.toml": '''[features]
computer_use=true
[computer_use]
allow_persistent_approval=true
confirm_actions=true
''', ".claude.json": {"computerUseMcpState": "enabled"}})
        finding = findings["computer-use-enabled"]
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual({item["key"] for item in finding["evidence"]}, {
            "features.computer_use", "computer_use.allow_persistent_approval", "computerUseMcpState"})

    def test_stored_broad_categories_do_not_reintroduce_false_findings(self):
        observations = []
        for index, (key, category, value) in enumerate((
            ("disableAllHooks", "hooks", True),
            ("hooks.enabled", "hooks", False),
            ("hooks.mode", "hooks", "off"),
            ("sandbox.allowUnsandboxedCommands", "sandbox", False),
            ("agents.browser.confirmSensitiveActions", "browser", True),
            ("browser_use.disable_auto_review", "browser", True),
        )):
            observations.append({"id": str(index), "sourceId": "source", "client": "fixture", "name": key,
                "kind": "setting", "location": "~/settings.json", "enabled": "disabled",
                "details": {"key": key, "nativeKey": key, "category": category, "value": value,
                            "valueType": "boolean", "valueCollected": True, "context": "cached"}})
        snapshot = {"sources": [{"id": "source", "client": "fixture", "location": "~/settings.json"}], "observations": observations}
        self.assertEqual(governance.evaluate(snapshot), [])


if __name__ == "__main__":
    unittest.main()
