"""Additional clients against synthetic files; no endpoint, browser, or network."""
import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.collector import collect
from palma_scan.extra_clients import EXTRA_RULES, EXTRA_SETTING_TYPES, extra_state_documents, normalize_extra_data
from palma_scan.rules import evaluate


class ExtraClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "fictional-home"
        self.home.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def put(self, relative, content, root=None):
        path = (root or self.home) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")

    def scan(self):
        result = collect(self.home)
        result["findings"] = evaluate(result)
        return result

    def settings(self, result, client=None):
        return [item for item in result["observations"] if item["kind"] == "setting" and (client is None or item["client"] == client)]

    def values(self, result, key):
        return [item["details"]["value"] for item in self.settings(result) if item["details"]["key"] == key]

    def rule_ids(self, result):
        return {item["ruleId"] for item in result["findings"]}

    def test_opencode_v1_mcp_credentials_and_commands_remain_private(self):
        self.put(".config/opencode/opencode.json", {"mcp": {
            "PRIVATE_SERVER_NAME": {"type": "local", "command": ["npx", "PRIVATE_COMMAND", "--api-key=PRIVATE_ARG_SECRET"],
                                    "environment": {"API_KEY": "{env:PRIVATE_ENV_NAME}"}, "enabled": False},
            "PRIVATE_REMOTE_NAME": {"type": "remote", "url": "https://user:PRIVATE_URL_SECRET@private.example/path",
                                    "headers": {"Authorization": "Bearer PRIVATE_HEADER_SECRET"}}
        }, "agent": {"PRIVATE_AGENT_NAME": {"prompt": "PRIVATE_INSTRUCTION_BODY"}}})
        result = self.scan()
        connections = [item for item in result["observations"] if item["kind"] == "mcp"]
        self.assertEqual(len(connections), 2)
        local = next(item for item in connections if item["details"]["execution"] == "local")
        self.assertEqual(local["enabled"], "disabled")
        self.assertEqual(local["details"]["credentialReferenceCount"], 1)
        self.assertEqual({item["name"] for item in connections}, {"PRIVATE_SERVER_NAME", "PRIVATE_REMOTE_NAME"})
        self.assertEqual({item["name"] for item in result["observations"] if item["kind"] == "agent"}, {"PRIVATE_AGENT_NAME"})
        serialized = json.dumps(result)
        for value in ("PRIVATE_COMMAND", "PRIVATE_ARG_SECRET", "PRIVATE_ENV_NAME", "PRIVATE_URL_SECRET", "PRIVATE_HEADER_SECRET", "private.example", "user:PRIVATE", "PRIVATE_INSTRUCTION_BODY"):
            self.assertFalse(value in serialized, "Private source text leaked into evidence")

    def test_opencode_v2_mcp_shape_and_disabled_field(self):
        self.put(".config/opencode/opencode.jsonc", {"mcp": {"servers": {
            "one": {"type": "local", "command": ["node", "private.js"], "disabled": True},
            "two": {"type": "remote", "url": "https://example.invalid", "enabled": False}
        }}})
        result = self.scan()
        connections = [item for item in result["observations"] if item["kind"] == "mcp"]
        self.assertEqual(len(connections), 2)
        self.assertEqual(sum(item["enabled"] == "disabled" for item in connections), 1)
        self.assertEqual({item["details"]["execution"] for item in connections}, {"local", "remote"})

    def test_normalization_is_pure_and_preserves_the_original_document(self):
        original = {"mcp": {"service": {"type": "local", "command": ["node", "server.js"], "environment": {"TOKEN": "{env:TOKEN}"}}}}
        prior = copy.deepcopy(original)
        normalized = normalize_extra_data("opencode", original)
        self.assertEqual(original, prior)
        self.assertEqual(normalized["mcpServers"]["service"]["command"], "node")
        self.assertNotEqual(normalized["mcpServers"]["service"]["env"]["TOKEN"], "{env:TOKEN}")

    def test_opencode_v2_last_broad_rule_and_narrow_allow_are_distinct(self):
        self.put(".config/opencode/opencode.json", {"permissions": [
            {"action": "shell", "resource": "*", "effect": "allow"},
            {"action": "shell", "resource": "*", "effect": "ask"},
            {"action": "shell", "resource": "PRIVATE_COMMAND_PATTERN", "effect": "allow"}
        ]})
        result = self.scan()
        self.assertEqual(self.values(result, "permissionReview.broadShellAllow"), [False])
        self.assertNotIn("PALMA-OPENCODE-002", self.rule_ids(result))
        self.assertNotIn("PRIVATE_COMMAND_PATTERN", json.dumps(result))

    def test_disabled_opencode_agents_keep_permission_findings_with_disabled_evidence(self):
        self.put(".config/opencode/opencode.json", {"agents": {"private": {"disabled": True, "permissions": [
            {"action": "shell", "resource": "*", "effect": "allow"}
        ]}}})
        result = self.scan()
        finding = next(item for item in result["findings"] if item["ruleId"] == "PALMA-OPENCODE-002")
        self.assertEqual(finding["severity"], "low")
        self.assertEqual(finding["evidenceType"], "configuration")
        evidence = finding["evidence"][0]["value"]
        self.assertEqual(evidence["observedState"], "disabled")
        self.assertEqual(evidence["effectiveState"], "unknown")
        self.assertTrue(evidence["context"].startswith("base:v2:agent-"))
        settings = [item for item in self.settings(result) if item["details"]["key"].startswith("permissionReview")]
        self.assertTrue(settings)
        self.assertTrue(all(item["enabled"] == "disabled" for item in settings))

    def test_mixed_opencode_permissions_are_cleanup_evidence_with_unique_ids(self):
        self.put(".config/opencode/opencode.json", {"permission": "allow", "permissions": [{"action": "*", "resource": "*", "effect": "ask"}]})
        result = self.scan()
        ids = [item["id"] for item in result["observations"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("PALMA-OPENCODE-006", self.rule_ids(result))
        finding = next(item for item in result["findings"] if item["ruleId"] == "PALMA-OPENCODE-001")
        self.assertEqual(finding["severity"], "low")
        evidence = finding["evidence"][0]["value"]
        self.assertEqual(evidence["context"], "base:v1-permissions")
        self.assertEqual(evidence["effectiveState"], "unknown")
        self.assertEqual(evidence["applicability"], "mixed V1/V2 permission schema; select the supported client schema")

    def test_copilot_current_settings_are_typed(self):
        self.put(".copilot/settings.json", {"sandbox": {"enabled": False}, "experimental": True, "remote": "on", "autoUpdate": "false", "inventedDanger": True})
        result = self.scan()
        self.assertIn("sandbox-disabled", self.rule_ids(result))
        self.assertIn("PALMA-COPILOT-003", self.rule_ids(result))
        self.assertIn("PALMA-COPILOT-004", self.rule_ids(result))
        self.assertEqual(self.values(result, "autoUpdate"), [])
        unknown = [item for item in self.settings(result) if item["details"]["key"] == "inventedDanger"]
        self.assertTrue(all(item["details"]["interpretation"] == "inventory-only" for item in unknown))
        self.assertFalse(any("inventedDanger" in json.dumps(item) for item in result["findings"]))
        self.assertEqual(result["status"], "partial")

    def test_copilot_internal_state_retains_baseline_findings_with_state_context(self):
        self.put(".copilot/config.json", {"sandbox": {"enabled": False}, "remote": "on", "trustedFolders": ["/PRIVATE_PROJECT"], "account": {"token": "PRIVATE_STATE_TOKEN"}})
        result = self.scan()
        sandbox = next(item for item in result["findings"] if item["ruleId"] == "sandbox-disabled")
        self.assertEqual(sandbox["evidence"][0]["value"]["context"], "state")
        self.assertEqual(sandbox["evidence"][0]["value"]["applicability"], "legacy/internal Copilot state; current settings are stored separately")
        remote = next(item for item in result["findings"] if item["ruleId"] == "PALMA-COPILOT-004")
        self.assertEqual(remote["severity"], "high")
        self.assertEqual(remote["evidenceType"], "configuration")
        evidence = remote["evidence"][0]["value"]
        self.assertEqual(evidence["context"], "state")
        self.assertEqual(evidence["effectiveState"], "unknown")
        self.assertEqual(evidence["applicability"], "legacy/internal Copilot state; current settings are stored separately")
        self.assertIn("no active remote session was observed", remote["summary"])
        self.assertEqual(self.values(result, "trustedFolders"), [{"entryCount": 1, "duplicateEntryCount": 0}])
        self.assertNotIn("PRIVATE_", json.dumps(result))

    def test_copilot_saved_mcp_approval_requires_toolname_null(self):
        self.put(".copilot/permissions-config.json", {"locations": {"/PRIVATE_LOCATION": {"tool_approvals": [
            {"kind": "mcp", "serverName": "PRIVATE_SERVER", "toolName": None},
            {"kind": "commands", "commandIdentifiers": ["PRIVATE_COMMAND"]}, {"kind": "write"}
        ], "allowed_directories": ["/PRIVATE_DIRECTORY"]}}})
        result = self.scan()
        self.assertIn("PALMA-COPILOT-005", self.rule_ids(result))
        self.assertIn("PALMA-COPILOT-006", self.rule_ids(result))
        self.assertEqual(self.values(result, "savedApprovals")[0]["commandApprovalCount"], 1)
        self.assertNotIn("PRIVATE_", json.dumps(result))

    def test_copilot_keychain_rule_requires_enabled_sandbox_same_source(self):
        self.put(".copilot/settings.json", {"sandbox": {"enabled": False, "userPolicy": {"seatbelt": {"keychainAccess": True}}}})
        result = self.scan()
        self.assertNotIn("PALMA-COPILOT-002", self.rule_ids(result))

    def test_continue_yaml_tls_data_and_credentials(self):
        self.put(".continue/config.yaml", """name: PRIVATE_CONFIG_NAME
version: 1.0.0
schema: v1
models:
  - name: PRIVATE_MODEL_NAME
    provider: openai
    apiKey: ${{ secrets.PRIVATE_SECRET_REF }}
    requestOptions:
      verifySsl: false
data:
  - name: PRIVATE_DESTINATION
    destination: https://PRIVATE_HOST.invalid/PRIVATE_PATH
    level: all
    apiKey: PRIVATE_LITERAL_SECRET
mcpServers:
  - name: PRIVATE_CONNECTION
    command: node
    args: [PRIVATE_SCRIPT]
rules:
  - PRIVATE_INSTRUCTION_BODY
""")
        result = self.scan()
        self.assertIn("PALMA-CONTINUE-001", self.rule_ids(result))
        self.assertIn("PALMA-CONTINUE-002", self.rule_ids(result))
        self.assertEqual(len([item for item in result["observations"] if item["kind"] == "mcp"]), 1)
        self.assertEqual(sum(item.get("credentialReferenceCount", 0) for item in self.values(result, "additionalCredentialStorage")), 1)
        self.assertEqual([item["name"] for item in result["observations"] if item["kind"] == "mcp"], ["PRIVATE_CONNECTION"])
        for value in ("PRIVATE_SECRET_REF", "PRIVATE_HOST", "PRIVATE_PATH", "PRIVATE_LITERAL_SECRET", "PRIVATE_SCRIPT", "PRIVATE_INSTRUCTION_BODY"):
            self.assertNotIn(value, json.dumps(result))

    def test_continue_nocode_and_local_destination_do_not_raise_code_export(self):
        self.put(".continue/config.yaml", {"data": [
            {"destination": "https://example.invalid", "level": "noCode"},
            {"destination": "file:///PRIVATE_PATH", "level": "all"}
        ]})
        result = self.scan()
        self.assertNotIn("PALMA-CONTINUE-002", self.rule_ids(result))

    def test_continue_imports_record_an_honest_gap_without_fetching(self):
        self.put(".continue/config.yaml", {"mcpServers": [{"uses": "PRIVATE_REMOTE_BLOCK"}]})
        result = self.scan()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(self.values(result, "mcpServers.importedBlocks"), [{"entryCount": 1, "resolution": "not-fetched"}])
        connections = [item for item in result["observations"] if item["kind"] == "mcp"]
        self.assertEqual([item["name"] for item in connections], ["mcpServers[0]"])
        self.assertEqual(connections[0]["details"]["declaration"], "mcpServers[0]")
        self.assertEqual(connections[0]["details"]["transport"], "unknown")
        self.assertNotIn("PRIVATE_REMOTE_BLOCK", json.dumps(result))

    def test_aider_yaml_confirmation_and_credential_presence(self):
        self.put(".aider.conf.yml", "yes-always: true\nverify-ssl: false\nload: PRIVATE_COMMAND_FILE\nopenai-api-key: PRIVATE_KEY\napi-key:\n  - provider=PRIVATE_SECOND_KEY\n")
        result = self.scan()
        self.assertTrue({"PALMA-AIDER-001", "PALMA-AIDER-002", "PALMA-AIDER-003"} <= self.rule_ids(result))
        self.assertEqual(self.values(result, "additionalCredentialStorage")[0]["literalCredentialCount"], 2)
        self.assertNotIn("PRIVATE_", json.dumps(result))

    def test_antigravity_mcp_alias_and_deny_overrides_wildcard_allow(self):
        self.put(".gemini/config/mcp_config.json", {"mcpServers": {"private": {"serverUrl": "https://PRIVATE_HOST.invalid/PRIVATE_PATH"}}})
        self.put(".gemini/antigravity-cli/settings.json", {"permissions": {"allow": ["execute_url(*)", "unsandboxed(*)"], "deny": ["execute_url(*)"]}})
        result = self.scan()
        self.assertIn("PALMA-ANTIGRAVITY-002", self.rule_ids(result))
        self.assertNotIn("PALMA-ANTIGRAVITY-003", self.rule_ids(result))
        self.assertEqual([item["details"]["execution"] for item in result["observations"] if item["kind"] == "mcp"], ["remote"])
        self.assertNotIn("PRIVATE_", json.dumps(result))

    def test_openclaw_json5_gateway_browser_and_exec(self):
        self.put(".openclaw/openclaw.json", """{
  gateway: { bind: 'lan', auth: { mode: 'none', token: 'PRIVATE_TOKEN' } },
  browser: { enabled: true, noSandbox: true },
  tools: { exec: { mode: 'full' } },
  agents: { defaults: { workspace: '/PRIVATE_WORKSPACE' } },
}""")
        result = self.scan()
        self.assertTrue({"PALMA-OPENCLAW-001", "PALMA-OPENCLAW-002", "PALMA-OPENCLAW-004", "PALMA-OPENCLAW-005"} <= self.rule_ids(result))
        self.assertNotIn("PRIVATE_", json.dumps(result))

    def test_disabled_openclaw_browser_does_not_assert_browser_exposure(self):
        self.put(".openclaw/openclaw.json", {"browser": {"enabled": False, "noSandbox": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}}})
        result = self.scan()
        self.assertNotIn("PALMA-OPENCLAW-005", self.rule_ids(result))
        self.assertNotIn("PALMA-OPENCLAW-006", self.rule_ids(result))

    def test_unknown_types_create_gaps_without_echoing_payloads(self):
        self.put(".continue/config.yaml", {"data": [{"destination": "https://example.invalid", "level": ["PRIVATE_UNSUPPORTED"]}]})
        self.put(".config/opencode/opencode.json", {"permissions": [{"action": "shell", "resource": "*", "effect": {"PRIVATE": "value"}}]})
        result = self.scan()
        self.assertEqual(result["status"], "partial")
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("PALMA-OPENCODE-002", self.rule_ids(result))

    def test_catalog_ids_are_unique_and_rule_inputs_are_exact(self):
        self.assertEqual(len(EXTRA_RULES), len({rule["id"] for rule in EXTRA_RULES}))
        for rule in EXTRA_RULES:
            self.assertIsInstance(rule["key"], str)
            self.assertIn(type(rule["value"]), {bool, str})
            self.assertTrue(all(url.startswith("https://") for url in rule["references"]))
        self.assertNotIn("autoApprovalSettings.enabled", EXTRA_SETTING_TYPES["cline"])

    def state_database(self, entries, relative=".config/Code/User/globalStorage/state.vscdb", *, schema=None):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        try:
            connection.execute(schema or "CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
            for key, value in entries.items():
                connection.execute("INSERT INTO ItemTable (key, value) VALUES (?, ?)",
                                   (key, value if isinstance(value, bytes) else json.dumps(value)))
            connection.commit()
        finally:
            connection.close()
        return path

    def test_editor_state_projects_only_documented_preferences(self):
        path = self.state_database({
            "saoudrizwan.claude-dev": {"autoApprovalSettings": {"actions": {"useBrowser": True, "useMcp": False},
                                       "enabled": True}, "toolAutoApprove": True,
                                      "taskHistory": ["PRIVATE_CLINE_CHAT"], "apiKey": "PRIVATE_CREDENTIAL"},
            "RooVeterinaryInc.roo-cline": {"autoApprovalEnabled": True, "alwaysAllowWrite": True,
                                         "alwaysAllowWriteOutsideWorkspace": True, "customInstructions": "PRIVATE_PROMPT"},
            "private.unrelated-extension": b"UNRELATED_NOT_EVEN_JSON",
        })
        prior_bytes, prior_mtime = path.read_bytes(), path.stat().st_mtime_ns
        documents = extra_state_documents(self.home)
        self.assertEqual({item["client"] for item in documents}, {"cline", "roo-code"})
        self.assertTrue(all(item["status"] == "collected" for item in documents))
        cline = next(item for item in documents if item["client"] == "cline")
        self.assertEqual(cline["data"], {"autoApprovalSettings.actions.useBrowser": True,
                                         "autoApprovalSettings.actions.useMcp": False})
        self.assertFalse("PRIVATE" in json.dumps(documents), "Private editor state leaked from projection")
        self.assertEqual(path.read_bytes(), prior_bytes)
        self.assertEqual(path.stat().st_mtime_ns, prior_mtime)
        self.assertFalse(path.with_name(path.name + "-journal").exists())
        self.assertFalse(path.with_name(path.name + "-wal").exists())

    def test_editor_state_reaches_typed_evaluator_without_private_rows(self):
        self.state_database({"rooveterinaryinc.roo-cline": {"autoApprovalEnabled": True, "alwaysAllowWrite": True,
                                                           "alwaysAllowWriteOutsideWorkspace": True, "history": "PRIVATE_HISTORY"}})
        result = self.scan()
        self.assertIn("PALMA-ROO-001", self.rule_ids(result))
        source = next(item for item in result["sources"] if item["client"] == "roo-code" and "state.vscdb" in item["location"])
        self.assertEqual(source.get("storage"), "editor-state")
        self.assertFalse("PRIVATE_HISTORY" in json.dumps(result))

    def test_editor_named_profile_has_actionable_location_and_unverified_selection(self):
        self.state_database({"rooveterinaryinc.roo-cline": {"autoApprovalEnabled": True, "alwaysAllowWrite": True,
                                                           "alwaysAllowWriteOutsideWorkspace": True}},
                            "Library/Application Support/Code/User/profiles/PRIVATE_PROFILE/globalStorage/state.vscdb")
        documents = extra_state_documents(self.home)
        self.assertEqual(len(documents), 1)
        self.assertEqual(documents[0]["context"], "profile")
        self.assertNotIn("PRIVATE_PROFILE", documents[0]["location"])
        result = self.scan()
        finding = next(item for item in result["findings"] if item["ruleId"] == "PALMA-ROO-001")
        self.assertEqual(finding["severity"], "low")
        self.assertEqual(finding["evidenceType"], "configuration")
        self.assertEqual(len(finding["evidence"]), 3)
        self.assertEqual(len({item["sourceId"] for item in finding["evidence"]}), 1)
        for item in finding["evidence"]:
            evidence = item["value"]
            self.assertEqual(evidence["context"], "profile")
            self.assertEqual(evidence["observedState"], "enabled")
            self.assertIs(evidence["value"], True)
            self.assertEqual(evidence["effectiveState"], "unknown")
            self.assertEqual(evidence["applicability"], "named profile selection not observed")
        source = next(item for item in result["sources"] if item["client"] == "roo-code" and "state.vscdb" in item["location"])
        self.assertEqual(source["location"], "~/Library/Application Support/Code/User/profiles/PRIVATE_PROFILE/globalStorage/state.vscdb#rooveterinaryinc.roo-cline")

    def test_editor_state_unsupported_known_type_does_not_echo_payload(self):
        self.state_database({"saoudrizwan.claude-dev": {"autoApprovalSettings": {"actions": {
            "useBrowser": "PRIVATE_INVALID_TYPE", "useMcp": True}}, "private": "DO_NOT_RETURN"}})
        documents = extra_state_documents(self.home)
        self.assertEqual(documents[0]["status"], "error")
        self.assertEqual(documents[0]["data"], {"autoApprovalSettings.actions.useMcp": True})
        self.assertFalse("PRIVATE" in json.dumps(documents))

    def test_editor_state_skips_uncheckpointed_wal_without_touching_it(self):
        path = self.state_database({"saoudrizwan.claude-dev": {"toolAutoApprove": True}})
        wal = path.with_name(path.name + "-wal")
        wal.write_bytes(b"PRIVATE_WAL_CONTENT")
        documents = extra_state_documents(self.home)
        self.assertEqual(documents[0]["status"], "skipped")
        self.assertEqual(documents[0]["reason"], "editor_state_uncheckpointed_wal")
        self.assertEqual(documents[0]["data"], {})
        self.assertEqual(wal.read_bytes(), b"PRIVATE_WAL_CONTENT")

    def test_editor_state_rejects_symlink_without_reading_target(self):
        target = self.home / "PRIVATE_OUTSIDE.sqlite"
        target.write_bytes(b"PRIVATE_PAYLOAD")
        path = self.home / ".config/Code/User/globalStorage/state.vscdb"
        path.parent.mkdir(parents=True)
        path.symlink_to(target)
        documents = extra_state_documents(self.home)
        self.assertEqual(documents[0]["status"], "skipped")
        self.assertEqual(documents[0]["reason"], "symlink")
        self.assertFalse("PRIVATE" in json.dumps(documents))

    def test_editor_state_rejects_malformed_database_and_json(self):
        self.put(".config/Code/User/globalStorage/state.vscdb", "PRIVATE_NOT_A_DATABASE")
        self.state_database({"rooveterinaryinc.roo-cline": b'{"autoApprovalEnabled":true,"autoApprovalEnabled":false}'},
                            "AppData/Roaming/Cursor/User/globalStorage/state.vscdb")
        documents = extra_state_documents(self.home)
        self.assertEqual(len(documents), 2)
        self.assertTrue(all(item["status"] == "error" for item in documents))
        self.assertTrue(all(item["data"] == {} for item in documents))
        self.assertFalse("PRIVATE" in json.dumps(documents))

    def test_editor_state_view_is_not_executed(self):
        path = self.home / ".config/Code/User/globalStorage/state.vscdb"
        path.parent.mkdir(parents=True)
        connection = sqlite3.connect(path)
        connection.execute("CREATE VIEW ItemTable AS SELECT 'saoudrizwan.claude-dev' AS key, '{} ' AS value")
        connection.close()
        documents = extra_state_documents(self.home)
        self.assertEqual(documents[0]["reason"], "editor_state_unknown_schema")
        self.assertEqual(documents[0]["data"], {})

    def test_editor_state_sqlite_connections_are_memory_only(self):
        self.state_database({"saoudrizwan.claude-dev": {"autoApprovalSettings": {"actions": {"useMcp": True}}}})
        connect = sqlite3.connect
        with patch("sqlite3.connect", wraps=connect) as mocked:
            documents = extra_state_documents(self.home)
        self.assertEqual(len(documents), 1)
        mocked.assert_called_once_with(":memory:")

    def test_editor_state_closed_wal_mode_snapshot_is_read_without_file_changes(self):
        path = self.state_database({"saoudrizwan.claude-dev": {"autoApprovalSettings": {"actions": {"useBrowser": True}}}})
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.close()
        original = path.read_bytes()
        self.assertEqual(original[18:20], b"\x02\x02")
        documents = extra_state_documents(self.home)
        self.assertEqual(documents[0]["status"], "collected")
        self.assertEqual(documents[0]["data"], {"autoApprovalSettings.actions.useBrowser": True})
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(path.with_name(path.name + "-wal").exists())

    def test_editor_state_uses_supplied_byte_budget(self):
        import time
        from palma_scan.engine.collection import CollectOptions
        from palma_scan.engine.filesystem import Budget, SafeFiles
        self.state_database({"saoudrizwan.claude-dev": {"autoApprovalSettings": {"actions": {"useBrowser": True}}}})
        options = CollectOptions(home=self.home, environ={}, max_file_bytes=100)
        files = SafeFiles([self.home], Budget(options, time.monotonic()))
        documents = extra_state_documents(self.home, files=files)
        self.assertEqual(documents[0]["status"], "skipped")
        self.assertEqual(documents[0]["reason"], "size_limit")
        self.assertEqual(documents[0]["data"], {})
        self.assertEqual(files.budget.bytes_read, 0)


if __name__ == "__main__":
    unittest.main()
