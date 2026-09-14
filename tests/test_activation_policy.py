"""Findings separate declarations that apply as written from ones that cannot yet act."""
import json
import unittest

from test_hardening import Home
from palma_scan.model import summarize
from palma_scan.report import render_report


class ActivationPolicyTests(Home):
    def finding(self, snapshot, rule):
        return next(item for item in snapshot["findings"] if item["ruleId"] == rule)

    def pack(self, base, servers):
        self.put(base + "/.claude-plugin/plugin.json", {"name": "toolkit", "version": "1.0.0"})
        self.put(base + "/.mcp.json", {"mcpServers": servers})

    def test_mixed_declarations_keep_their_priority_and_state_the_split(self):
        self.put(".cursor/mcp.json", {"mcpServers": {"live": {"url": "https://mcp.example.test/mcp"},
                                                     "parked": {"url": "https://mcp.example.test/mcp", "disabled": True}}})
        snapshot = self.scan()
        remote = self.finding(snapshot, "mcp-network-direct")
        self.assertEqual((remote["severity"], remote["declarations"], remote["applies"]), ("high", 2, 1))
        self.assertIn("1 of 2 applies as written; 1 is switched off.", remote["summary"])
        self.assertNotIn("apply", remote["ratingReason"])
        output = render_report(snapshot, summarize(snapshot))
        self.assertIn("<span>1 applies as written</span>", output)
        self.assertIn("<span>2 declarations</span>", output)

    def test_cached_plugin_pack_connectors_do_not_apply_until_the_pack_is_installed(self):
        base = ".claude/plugins/cache/market/toolkit/1.0.0"
        self.pack(base, {"remote": {"type": "http", "url": "https://mcp.example.test/mcp"}, "desktop": {"command": "computer-use-server"}})
        snapshot = self.scan()
        for rule in ("mcp-network-direct", "mcp-local-unaudited", "mcp-computer-use"):
            finding = self.finding(snapshot, rule)
            self.assertEqual((finding["severity"], finding["applies"]), ("info", 0), rule)
            self.assertIn("in a plugin pack that is cached without an installation record", finding["summary"])
            self.assertIn("cached without an installation record", finding["ratingReason"])
            self.assertTrue(finding["evidence"], "the declarations stay in evidence")
            self.assertIn("cached", json.dumps(finding["evidence"]))
        self.assertIn("Plugin pack cached, no installation record", render_report(snapshot, summarize(snapshot)))
        self.put(".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {
            "toolkit@market": [{"scope": "user", "installPath": str(self.home / base), "version": "1.0.0"}]}})
        snapshot = self.scan()
        for rule, severity in (("mcp-network-direct", "high"), ("mcp-local-unaudited", "high"), ("mcp-computer-use", "critical")):
            finding = self.finding(snapshot, rule)
            self.assertEqual((finding["severity"], finding["applies"]), (severity, 1), rule)
            self.assertNotIn("apply as written", finding["summary"])

    def test_an_installed_pack_switched_off_in_settings_does_not_apply(self):
        base = ".claude/plugins/cache/market/toolkit/1.0.0"
        self.pack(base, {"remote": {"type": "http", "url": "https://mcp.example.test/mcp"}})
        self.put(".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {
            "toolkit@market": [{"scope": "user", "installPath": str(self.home / base), "version": "1.0.0"}]}})
        self.put(".claude/settings.json", {"enabledPlugins": {"toolkit@market": False}})
        snapshot = self.scan()
        remote = self.finding(snapshot, "mcp-network-direct")
        self.assertEqual((remote["severity"], remote["applies"]), ("info", 0))
        self.assertIn("in a plugin pack that is switched off", remote["summary"])
        self.assertIn("Plugin pack switched off", render_report(snapshot, summarize(snapshot)))
        self.put(".claude/settings.json", {"enabledPlugins": {"toolkit@market": True}})
        self.assertEqual(self.finding(self.scan(), "mcp-network-direct")["applies"], 1)

    def test_a_copied_home_matches_installation_records_by_cache_folders(self):
        base = ".claude/plugins/cache/market/toolkit/1.0.0"
        self.pack(base, {"remote": {"type": "http", "url": "https://mcp.example.test/mcp"}})
        self.put(".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {
            "toolkit@market": [{"scope": "user", "installPath": "/Users/original/.claude/plugins/cache/market/toolkit/1.0.0", "version": "1.0.0"}]}})
        snapshot = self.scan()
        self.assertEqual(self.finding(snapshot, "mcp-network-direct")["applies"], 1)
        self.assertNotIn("plugins-cached-only", {item["ruleId"] for item in snapshot["findings"]})
        self.assertNotIn("/Users/original", json.dumps(snapshot))

    def test_codex_packs_are_installed_through_their_configuration_or_remote_record(self):
        base = ".codex/plugins/cache/market/toolkit/1.0.0"
        self.put(base + "/.codex-plugin/plugin.json", {"name": "toolkit", "version": "1.0.0"})
        self.put(base + "/.mcp.json", {"mcpServers": {"remote": {"type": "http", "url": "https://mcp.example.test/mcp"}}})
        self.assertEqual(self.finding(self.scan(), "mcp-network-direct")["applies"], 0, "no record: cached")
        self.put(".codex/config.toml", '[plugins."toolkit@market"]\nenabled = true\n')
        remote = self.finding(self.scan(), "mcp-network-direct")
        self.assertEqual((remote["severity"], remote["applies"]), ("high", 1))
        self.put(".codex/config.toml", '[plugins."toolkit@market"]\nenabled = false\n')
        remote = self.finding(self.scan(), "mcp-network-direct")
        self.assertEqual((remote["severity"], remote["applies"]), ("info", 0))
        self.assertIn("in a plugin pack that is switched off", remote["summary"])
        (self.home / ".codex/config.toml").unlink()
        self.put(".codex/plugins/cache/openai-curated-remote/toolkit/.codex-remote-plugin-install.json", {"schema_version": 1, "remote_plugin_id": "plugin_fixture"})
        remote_base = ".codex/plugins/cache/openai-curated-remote/toolkit/1.0.0"
        self.put(remote_base + "/.codex-plugin/plugin.json", {"name": "toolkit", "version": "1.0.0"})
        self.put(remote_base + "/.mcp.json", {"mcpServers": {"curated": {"type": "http", "url": "https://mcp.example.test/mcp"}}})
        snapshot = self.scan()
        names = {item["id"]: item["name"] for item in snapshot["observations"]}
        remote = self.finding(snapshot, "mcp-network-direct")
        self.assertEqual(remote["applies"], 1)
        self.assertIn("1 of 2 applies as written; 1 is in a plugin pack that is cached without an installation record.", remote["summary"])

    def test_copilot_installed_plugins_folder_counts_as_installed(self):
        base = ".copilot/installed-plugins/toolkit"
        self.put(base + "/.claude-plugin/plugin.json", {"name": "toolkit", "version": "1.0.0"})
        self.put(base + "/.mcp.json", {"mcpServers": {"remote": {"type": "http", "url": "https://mcp.example.test/mcp"}}})
        snapshot = self.scan()
        self.assertEqual(self.finding(snapshot, "mcp-network-direct")["applies"], 1)

    def test_unselected_profile_declarations_do_not_apply(self):
        self.put(".codex/config.toml", 'profile="safe"\n[profiles.safe]\nsandbox_mode="read-only"\n'
                                       '[profiles.risky]\napproval_policy="never"\n'
                                       '[profiles.risky.mcp_servers.remote]\nurl="https://mcp.example.test/mcp"\n')
        snapshot = self.scan()
        for rule in ("mcp-network-direct", "approval-prompts-disabled"):
            finding = self.finding(snapshot, rule)
            self.assertEqual((finding["severity"], finding["applies"]), ("info", 0), rule)
            self.assertIn("This declaration does not apply as written: it is in an unselected profile.", finding["summary"])

    def test_a_secret_in_a_disabled_entry_stays_critical(self):
        self.put(".cursor/mcp.json", {"mcpServers": {"parked": {"url": "https://mcp.example.test/mcp", "disabled": True,
                                                                  "headers": {"Authorization": "Bearer PRIVATE_PARKED_TOKEN_123456"}}}})
        snapshot = self.scan()
        inline = self.finding(snapshot, "mcp-inline-credential")
        self.assertEqual(inline["severity"], "critical")
        self.assertNotIn("applies", inline)
        self.assertNotIn("PRIVATE_PARKED_TOKEN_123456", json.dumps(snapshot))

    def test_a_credential_header_the_auth_detector_recognizes_is_a_stored_credential(self):
        self.put(".cursor/mcp.json", {"mcpServers": {"tracker": {"type": "http", "url": "https://mcp.example.test/mcp",
                                                                  "headers": {"X-Credentials": "PRIVATE_HEADER_VALUE_1234567890"}}}})
        snapshot = self.scan()
        inline = self.finding(snapshot, "mcp-inline-credential")
        self.assertEqual(inline["severity"], "critical")
        self.assertNotIn("mcp-static-secret-auth", {item["ruleId"] for item in snapshot["findings"]})
        self.assertNotIn("PRIVATE_HEADER_VALUE_1234567890", json.dumps(snapshot))

    def test_the_same_hook_in_user_and_project_files_is_one_declaration_to_review(self):
        config = 'notify=["notify-send", "Codex"]\n'
        self.put(".codex/config.toml", config)
        self.put("code/app/.codex/config.toml", config)
        snapshot = self.scan([self.home / "code/app"])
        hooks = [item for item in snapshot["observations"] if item["kind"] == "hook"]
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0]["details"]["locationCount"], 2)
        self.assertEqual(set(hooks[0]["details"]["locations"]), {"~/.codex/config.toml", "~/code/app/.codex/config.toml"})
        self.assertEqual(self.finding(snapshot, "hooks-declared")["declarations"], 1)
        self.put("code/app/.codex/config.toml", 'notify=["other-command"]\n')
        snapshot = self.scan([self.home / "code/app"])
        self.assertEqual(len([item for item in snapshot["observations"] if item["kind"] == "hook"]), 2)
        self.assertNotIn("notify-send", json.dumps(snapshot))

    def test_a_secret_supplied_by_reference_is_described_as_such(self):
        self.put(".cursor/mcp.json", {"mcpServers": {"tracker": {"type": "http", "url": "https://mcp.example.test/mcp",
                                                                  "headers": {"Authorization": "Bearer ${env:TRACKER_TOKEN}"}}}})
        snapshot = self.scan()
        static = self.finding(snapshot, "mcp-static-secret-auth")
        self.assertIn("“tracker” signs in with a fixed secret supplied by reference; the value itself is not stored in the file.", static["summary"])
        self.assertNotIn("mcp-inline-credential", {item["ruleId"] for item in snapshot["findings"]})
        output = render_report(snapshot, summarize(snapshot))
        self.assertIn(">Fixed secret supplied by reference</span>", output)
        self.assertNotIn("Credential stored in the file", output)

    def test_a_placeholder_secret_is_not_described_as_a_reference(self):
        self.put(".cursor/mcp.json", {"mcpServers": {"tracker": {"type": "http", "url": "https://mcp.example.test/mcp",
                                                                  "headers": {"Authorization": "Bearer <token>"}, "env": {"OTHER": "${env:OTHER}"}}}})
        snapshot = self.scan()
        static = self.finding(snapshot, "mcp-static-secret-auth")
        self.assertIn("signs in with a fixed secret rather than a short-lived sign-in.", static["summary"])
        self.assertNotIn("not stored in the file", static["summary"])
        output = render_report(snapshot, summarize(snapshot))
        self.assertIn(">Fixed secret</span>", output)
        self.assertNotIn("supplied by reference", output)

    def test_tool_allowlists_are_visible_beside_computer_use_evidence(self):
        self.put(".codex/config.toml", '[mcp_servers.computer-use]\ncommand="computer-use-server"\nenabled_tools=["screenshot"]\n')
        snapshot = self.scan()
        finding = self.finding(snapshot, "mcp-computer-use")
        self.assertEqual((finding["severity"], finding["applies"]), ("critical", 1))
        output = render_report(snapshot, summarize(snapshot))
        self.assertIn(">Tool allowlist configured</span>", output)
        self.assertNotIn("screenshot", json.dumps(snapshot))


if __name__ == "__main__":
    unittest.main()
