import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.collector import collect
from palma_scan.rules import evaluate


class RuleTests(unittest.TestCase):
    def scan(self, files):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            for relative, contents in files.items():
                path = home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents if isinstance(contents, str) else json.dumps(contents), encoding="utf-8")
            snapshot = collect(home)
            return snapshot, evaluate(snapshot)

    def test_never_approval_is_low_even_with_read_only_sandbox(self):
        _, findings = self.scan({".codex/config.toml": 'approval_policy="never"\nsandbox_mode="read-only"'})
        self.assertFalse(any(finding["severity"] in {"critical", "high"} for finding in findings))

    def test_codex_permission_and_unrestricted_access_are_low_with_separate_evidence(self):
        snapshot, findings = self.scan({".codex/config.toml": 'approval_policy="never"\nsandbox_mode="danger-full-access"'})
        low = {finding["ruleId"]: finding for finding in findings if finding["severity"] == "low"}
        self.assertIn("approval-prompts-disabled", low)
        self.assertIn("sandbox-disabled", low)
        self.assertEqual({entry["key"] for entry in low["approval-prompts-disabled"]["evidence"]}, {"approval_policy"})
        self.assertEqual({entry["key"] for entry in low["sandbox-disabled"]["evidence"]}, {"sandbox_mode"})
        self.assertFalse(any(finding["severity"] == "critical" for finding in findings))
        self.assertEqual(findings, evaluate(snapshot))

    def test_unselected_permission_profiles_keep_low_ratings(self):
        _, findings = self.scan({".codex/config.toml": 'profile="safe"\napproval_policy="never"\nsandbox_mode="danger-full-access"\n[profiles.safe]\nsandbox_mode="read-only"\n[profiles.risky]\napproval_policy="never"\nsandbox_mode="danger-full-access"'})
        self.assertFalse(any(finding["severity"] in {"critical", "high"} for finding in findings))

    def test_claude_permission_bypass_is_low_and_sandbox_off_is_high(self):
        _, missing = self.scan({".claude/settings.json": {"permissions": {"defaultMode": "bypassPermissions"}}})
        _, explicit = self.scan({".claude/settings.json": {"permissions": {"defaultMode": "bypassPermissions"}, "sandbox": {"enabled": False}}})
        self.assertEqual(next(item["severity"] for item in missing if item["ruleId"] == "permissions-bypassed"), "low")
        self.assertFalse(any(item["ruleId"] == "sandbox-disabled" for item in missing))
        self.assertEqual(next(item["severity"] for item in explicit if item["ruleId"] == "sandbox-disabled"), "high")

    def test_static_credential_finding_does_not_claim_a_leak(self):
        _, findings = self.scan({".cursor/mcp.json": {"mcpServers": {"server": {"command": "node", "env": {"API_KEY": "PRIVATE_TOKEN"}, "disabled": True}}}})
        credential = next(finding for finding in findings if finding["category"] == "credentials")
        self.assertEqual(credential["severity"], "critical")
        self.assertNotIn("PRIVATE_TOKEN", json.dumps(findings))
        self.assertIn("potential credential", credential["summary"])
        # The only local connector is switched off: its evidence stays, its access priority does not.
        local = next(finding for finding in findings if finding["ruleId"] == "mcp-local-unaudited")
        self.assertEqual((local["severity"], local["baselineSeverity"], local["applies"]), ("info", "critical", 0))
        self.assertIn("This declaration does not apply as written: it is switched off.", local["summary"])

    def test_remote_mcp_governance_is_high_without_claiming_missing_auth(self):
        _, findings = self.scan({".cursor/mcp.json": {"mcpServers": {"remote": {"url": "https://example.test/mcp"}}}})
        self.assertTrue(any(finding["category"] == "mcp" for finding in findings))
        self.assertTrue(any(finding["ruleId"] == "mcp-network-direct" and finding["severity"] == "high" for finding in findings))
        self.assertFalse(any("unauthenticated" in finding["title"].lower() for finding in findings))

    def test_local_skills_are_grouped_at_high_review_priority(self):
        _, findings = self.scan({".agents/skills/one/SKILL.md": "body", ".agents/skills/two/SKILL.md": "body"})
        inventory = [finding for finding in findings if finding["category"] == "extensions"]
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["severity"], "high")
        self.assertEqual(inventory[0]["evidenceType"], "inventory")
        self.assertEqual(len(inventory[0]["observationIds"]), 2)

    def test_browser_and_computer_capability_policies_are_critical(self):
        _, findings = self.scan({".codex/config.toml": '[browser_use]\ndisable_auto_review=true\nallow_global_persistent_approval=true\n[computer_use]\ndefault_app_access="allow"\n'})
        self.assertTrue(any(finding["severity"] == "critical" for finding in findings))
        self.assertFalse(any("bypass" in finding["title"].lower() for finding in findings))

    def test_vscode_global_approval_low_and_browser_capability_critical(self):
        _, findings = self.scan({".config/Code/User/settings.json": {"chat.tools.global.autoApprove": True, "workbench.browser.enableChatTools": True}})
        self.assertEqual(next(item["severity"] for item in findings if item["ruleId"] == "tools-auto-approved"), "low")
        _, false_positive = self.scan({".config/Code/User/settings.json": {"chat.tools.global.autoApprove": "true"}})
        self.assertFalse(any(finding["severity"] in {"high", "critical"} for finding in false_positive))

    def test_every_finding_links_to_real_evidence_and_official_references(self):
        snapshot, findings = self.scan({".claude/settings.json": {"permissions": {"defaultMode": "bypassPermissions"}, "sandbox": {"enabled": False}, "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "echo private"}]}]}}})
        observation_ids = {item["id"] for item in snapshot["observations"]}
        source_ids = {item["id"] for item in snapshot["sources"]}
        self.assertTrue(findings)
        for finding in findings:
            self.assertTrue(set(finding["observationIds"]) <= observation_ids)
            self.assertTrue(all(item["sourceId"] in source_ids for item in finding["evidence"]))
            self.assertTrue(finding["references"])
            self.assertIn(finding["confidence"], {"high", "medium", "low"})

    def test_potential_credentials_are_critical_for_remote_and_loopback(self):
        for url, expected in [("http://remote.test/mcp", "critical"), ("http://127.0.0.1/mcp", "critical")]:
            with self.subTest(url=url):
                _, findings = self.scan({".cursor/mcp.json": {"mcpServers": {"service": {"url": url, "headers": {"Authorization": "Bearer SECRET_VALUE"}}}}})
                finding = next(item for item in findings if item["category"] == "credentials")
                self.assertEqual(finding["severity"], expected)

    def test_disabled_terminal_autoapproval_suppresses_broad_approval_review(self):
        _, findings = self.scan({".config/Code/User/settings.json": {"chat.tools.terminal.enableAutoApprove": False, "chat.tools.terminal.autoApprove": {"/.*/": True}}})
        self.assertFalse(any(finding["category"] == "execution" for finding in findings))

    def test_proxy_relaxations_require_enabled_proxy_for_medium(self):
        _, inactive = self.scan({".codex/config.toml": '[features.network_proxy]\nenabled=false\ndangerously_allow_non_loopback_proxy=true'})
        _, active = self.scan({".codex/config.toml": '[features.network_proxy]\nenabled=true\ndangerously_allow_non_loopback_proxy=true'})
        self.assertFalse(any(finding["severity"] in {"medium", "high", "critical"} for finding in inactive))
        self.assertTrue(any(finding["category"] == "network" and finding["severity"] == "medium" for finding in active))

    def test_cached_policy_is_evaluated_with_cached_context(self):
        _, findings = self.scan({".claude/remote-settings.json": {"permissions": {"defaultMode": "bypassPermissions"}, "sandbox": {"enabled": False}}})
        bypass = next(item for item in findings if item["ruleId"] == "permissions-bypassed")
        # A cached policy copy is historical evidence: kept, but not an applying declaration.
        self.assertEqual((bypass["severity"], bypass["baselineSeverity"], bypass["applies"]), ("info", "critical", 0))
        self.assertIn("in a cached policy copy", bypass["summary"])
        sandbox = next(item for item in findings if item["ruleId"] == "sandbox-disabled")
        self.assertEqual(sandbox["severity"], "info")
        self.assertIn("cached", json.dumps(sandbox["evidence"]))

    def test_remote_control_is_reviewed_only_in_supported_user_scope(self):
        _, findings = self.scan({".claude/settings.json": {"remoteControlAtStartup": True}})
        self.assertTrue(any(finding["category"] == "capabilities" for finding in findings))
        self.assertTrue(any(finding["ruleId"] == "PALMA-CAPABILITY-003" and finding["severity"] == "high" for finding in findings))

    def test_duplicate_and_conflicting_scopes_get_hygiene_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            workspace = home / "project"
            (home / ".codex").mkdir()
            (workspace / ".codex").mkdir(parents=True)
            (home / ".codex/config.toml").write_text('approval_policy="on-request"\nsandbox_mode="read-only"')
            (workspace / ".codex/config.toml").write_text('approval_policy="on-request"\nsandbox_mode="workspace-write"')
            findings = evaluate(collect(home, [workspace]))
            hygiene = [item for item in findings if item["category"] == "hygiene"]
            self.assertEqual({item["severity"] for item in hygiene}, {"info", "low"})

    def test_missing_project_reference_gets_cleanup_review_without_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            (home / ".claude.json").write_text(json.dumps({"projects": {str(home / "missing"): {}}}))
            findings = evaluate(collect(home))
            self.assertTrue(any(item["category"] == "hygiene" for item in findings))
            self.assertTrue((home / ".claude.json").exists())

    def test_explicit_command_sandbox_off_gets_an_isolation_review(self):
        fixtures = [
            (".claude/settings.json", {"sandbox": {"enabled": False}}),
            (".gemini/settings.json", {"tools": {"sandbox": False}}),
            (".config/Code/User/settings.json", {"chat.agent.sandbox.enabled": "off"}),
        ]
        for relative, data in fixtures:
            with self.subTest(client=relative):
                _, findings = self.scan({relative: data})
                self.assertTrue(any(item["severity"] == "high" and item["ruleId"] == "sandbox-disabled" for item in findings))

    def test_tool_level_gemini_sandbox_prevents_claiming_isolation_is_disabled(self):
        _, findings = self.scan({".gemini/settings.json": {"tools": {"sandbox": False}, "security": {"toolSandboxing": True}}})
        self.assertFalse(any(item["category"] == "isolation" and item["severity"] == "medium" for item in findings))

    def test_unused_workspace_sandbox_options_do_not_raise_active_access_findings(self):
        _, findings = self.scan({".codex/config.toml": 'sandbox_mode="read-only"\n[sandbox_workspace_write]\nnetwork_access=true\nwritable_roots=["/"]'})
        self.assertFalse(any(item["category"] in {"network", "filesystem"} for item in findings))

    def test_gemini_yolo_in_json_is_not_a_supported_mode_or_high_finding(self):
        snapshot, findings = self.scan({".gemini/settings.json": {"general": {"defaultApprovalMode": "yolo"}}})
        self.assertEqual(snapshot["status"], "partial")
        self.assertFalse(any(item["severity"] in {"high", "critical"} for item in findings))

    def test_workspace_trust_off_and_explicit_sandbox_socket_access_have_rules(self):
        _, findings = self.scan({".gemini/settings.json": {"security": {"folderTrust": {"enabled": False}}}, ".claude/settings.json": {"sandbox": {"enabled": True, "network": {"allowAllUnixSockets": True}}}})
        self.assertTrue(any(item["category"] == "governance" and item["severity"] == "medium" for item in findings))
        self.assertTrue(any(item["category"] == "network" and item["severity"] == "medium" for item in findings))


if __name__ == "__main__":
    unittest.main()
