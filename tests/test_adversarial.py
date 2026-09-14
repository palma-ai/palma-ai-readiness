"""Independent privacy and evidence-boundary checks using synthetic data only."""

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from palma_scan import cli, model


@contextmanager
def offline_guard():
    """Fail if collection, evaluation, or rendering tries network/process work."""
    targets = (
        "socket.socket", "socket.create_connection", "socket.getaddrinfo",
        "urllib.request.urlopen", "subprocess.run", "subprocess.Popen",
        "subprocess.check_output", "os.system", "webbrowser.open",
    )
    with ExitStack() as stack:
        for target in targets:
            stack.enter_context(patch(target, side_effect=AssertionError("Forbidden runtime action: " + target)))
        yield


def artifact():
    return {
        "schemaVersion": "2.0", "collector": {"name": "synthetic", "version": "2.0.0"},
        "mode": "endpoint", "startedAt": "2026-09-10T00:00:00+00:00",
        "completedAt": "2026-09-10T00:00:01+00:00", "status": "complete",
        "scope": {"type": "copied-home", "workspaceCount": 0},
        "sources": [], "observations": [], "coverage": {"limitations": ["Synthetic fixture only."]},
        "findings": [],
    }


class SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class ArtifactBoundaryTests(unittest.TestCase):
    def test_rejects_duplicate_nonfinite_and_excessively_nested_artifacts_without_echoing_content(self):
        values = [
            '{"schemaVersion":"2.0","schemaVersion":"PRIVATE_PARSE_CANARY"}',
            json.dumps(artifact()).replace('"workspaceCount": 0', '"workspaceCount": NaN'),
            '{"schemaVersion":"2.0","collector":' + '[' * 1100 + '0' + ']' * 1100 + '}',
        ]
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input.json"
            for text in values:
                with self.subTest(text_prefix=text[:40]):
                    source.write_text(text, encoding="utf-8")
                    with offline_guard(), self.assertRaises(ValueError) as error:
                        model.read_snapshot(source)
                    self.assertNotIn("PRIVATE_PARSE_CANARY", str(error.exception))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires a Unix-like platform")
    def test_artifact_fifo_is_rejected_before_blocking_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "snapshot.json"
            os.mkfifo(fifo)
            # Never open a FIFO without a writer, even if the implementation regresses.
            with patch.object(Path, "open", side_effect=AssertionError("Attempted blocking FIFO open")):
                with self.assertRaises((ValueError, OSError)):
                    model.read_snapshot(fifo)

    def test_artifact_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target.json"
            target.write_text(json.dumps(artifact()), encoding="utf-8")
            alias = Path(temporary) / "alias.json"
            alias.symlink_to(target)
            with offline_guard(), self.assertRaises((ValueError, OSError)):
                model.read_snapshot(alias)

    def test_declared_artifact_cannot_claim_complete_endpoint_coverage(self):
        snapshot = artifact()
        snapshot["mode"] = "declared"
        snapshot["scope"]["type"] = "declared"
        with self.assertRaises(ValueError):
            model.validate(snapshot)

    def test_incomplete_setting_snapshot_is_rejected_before_evaluation(self):
        snapshot = artifact()
        snapshot["sources"] = [{"id": "source-1", "client": "codex", "scope": "user", "location": "~/.codex/config.toml", "status": "collected"}]
        snapshot["observations"] = [{"id": "obs-1", "kind": "setting", "client": "codex", "name": "Incomplete setting", "sourceId": "source-1", "location": "~/.codex/config.toml", "enabled": "enabled", "details": {}}]
        with self.assertRaises(ValueError):
            model.validate(snapshot)

    def test_cli_parser_errors_keep_raw_document_values_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input.json"
            output = Path(temporary) / "out.html"
            source.write_text('{"schemaVersion":"2.0","SECRET_CANARY":', encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with offline_guard(), redirect_stdout(out), redirect_stderr(err):
                result = cli.main(["report", "--report", str(source), "--output", str(output)])
            self.assertEqual(result, 2)
            self.assertNotIn("SECRET_CANARY", out.getvalue() + err.getvalue())
            self.assertFalse(output.exists())

    def test_render_escapes_injected_markup_and_never_loads_external_assets(self):
        from palma_scan.report import render_report
        attack = '\"><img src="https://EXFIL_CANARY.invalid/a" onerror="alert(1)"><script>alert("INJECT_CANARY")</script>'
        snapshot = artifact()
        snapshot["sources"] = [{"id": "source-1", "client": attack, "scope": "user", "location": attack, "status": "collected", "reason": attack}]
        snapshot["observations"] = [{"id": "obs-1", "kind": "setting", "client": attack, "name": attack, "sourceId": "source-1", "location": attack, "enabled": "unknown", "details": {"key": attack, "value": attack}}]
        snapshot["findings"] = [{"id": "finding-1", "ruleId": attack, "title": attack, "severity": "medium", "category": attack, "confidence": "high", "evidenceType": "configuration", "summary": attack, "impact": attack, "recommendation": attack, "observationIds": ["obs-1"], "evidence": [{"sourceId": "source-1", "location": attack, "key": attack, "value": attack}], "references": ["javascript:alert(1)", "https://user:PRIVATE_CANARY@example.invalid/"]}]
        model.validate(snapshot)
        with offline_guard():
            rendered = render_report(snapshot, model.summarize(snapshot))
        parser = SurfaceParser()
        parser.feed(rendered)
        for tag, attrs in parser.tags:
            self.assertFalse(any(key.lower().startswith("on") for key in attrs), (tag, attrs))
            for key in ("src", "srcset", "poster"):
                self.assertNotIn("EXFIL_CANARY", attrs.get(key, ""))
            if tag in {"script", "iframe", "link", "object", "embed"}:
                self.assertFalse(attrs.get("src") or attrs.get("data") or attrs.get("href"), (tag, attrs))
        self.assertNotIn('<script>alert("INJECT_CANARY")', rendered)
        self.assertNotIn("javascript:alert(1)", rendered)
        self.assertNotIn("PRIVATE_CANARY", rendered)
        policies = [attrs.get("content", "") for tag, attrs in parser.tags
                    if tag == "meta" and attrs.get("http-equiv", "").lower() == "content-security-policy"]
        self.assertTrue(any("connect-src 'none'" in policy for policy in policies))


class CollectorAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.home = self.base / "copied-home"
        self.home.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def put(self, relative, content, root=None):
        target = (root or self.home) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return target

    def scan(self, workspaces=None, evaluate=False):
        from palma_scan.collector import collect
        with offline_guard():
            snapshot = collect(self.home, workspaces or [], scope_type="copied-home")
            if evaluate:
                from palma_scan.rules import evaluate as run_rules
                snapshot["findings"] = run_rules(snapshot)
            else:
                snapshot["findings"] = []
        model.validate(snapshot)
        if not workspaces:
            self.assertNotIn(str(self.base), json.dumps(snapshot))
        # Explicit external workspace locations remain actionable in local evidence.
        self.assertNotIn(str(self.home), json.dumps(snapshot))
        return snapshot

    def test_inherited_environment_cannot_redirect_an_explicit_copied_home_scan(self):
        outside = self.base / "outside-account"
        self.put("config.toml", 'sandbox_mode="danger-full-access"', outside)
        with patch.dict(os.environ, {"CODEX_HOME": str(outside), "CLAUDE_CONFIG_DIR": str(outside), "APPDATA": str(outside)}):
            snapshot = self.scan()
        self.assertFalse(snapshot["observations"])

    def test_standard_platform_editor_locations_are_read_within_the_copied_home(self):
        # These are path-layout fixtures on the current OS, not native Windows ACL tests.
        roots = ("Library/Application Support", ".config", "AppData/Roaming")
        for base in roots:
            self.put(base + "/Code/User/settings.json", {"chat.tools.global.autoApprove": False})
            self.put(base + "/Code - Insiders/User/mcp.json", {"servers": {"example": {"type": "http", "url": "https://example.invalid/mcp"}}})
        snapshot = self.scan()
        settings = [item for item in snapshot["observations"] if item["kind"] == "setting"]
        mcps = [item for item in snapshot["observations"] if item["kind"] == "mcp"]
        # Identical declarations in each platform layout are one declaration in three places.
        for items, filename in ((settings, "Code/User/settings.json"), (mcps, "Code - Insiders/User/mcp.json")):
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["details"]["locationCount"], len(roots))
            self.assertEqual(set(items[0]["details"]["locations"]), {"~/" + base + "/" + filename for base in roots})

    def test_duplicate_and_malformed_config_sources_do_not_echo_private_values(self):
        self.put(".claude/settings.json", '{"permissions":{"defaultMode":"default","defaultMode":"PRIVATE_DUPLICATE_CANARY"}}')
        self.put(".cursor/mcp.json", '{/* JSONC comment */"mcpServers":{"PRIVATE_SOURCE_CANARY":')
        self.put(".gemini/settings.json", '{"tools":{"sandbox":NaN},"API_KEY":"PRIVATE_KEY_CANARY"}')
        self.put(".codex/config.toml", 'approval_policy = "PRIVATE_TOML_CANARY\n')
        snapshot = self.scan(evaluate=True)
        self.assertEqual(snapshot["status"], "partial")
        self.assertGreaterEqual(sum(item["status"] == "error" for item in snapshot["sources"]), 4)
        for canary in ("PRIVATE_DUPLICATE_CANARY", "PRIVATE_SOURCE_CANARY", "PRIVATE_KEY_CANARY", "PRIVATE_TOML_CANARY"):
            self.assertNotIn(canary, json.dumps(snapshot))

    def test_prior_acceptance_in_state_is_not_current_permission_bypass(self):
        self.put(".claude.json", {"bypassPermissionsModeAccepted": True, "computerUseMcpState": "PRIVATE_STATE_CANARY", "history": ["PRIVATE_HISTORY_CANARY"]})
        snapshot = self.scan(evaluate=True)
        self.assertFalse(any(item["severity"] in {"critical", "high"} for item in snapshot["findings"]))
        self.assertNotIn("PRIVATE_STATE_CANARY", json.dumps(snapshot))
        self.assertNotIn("PRIVATE_HISTORY_CANARY", json.dumps(snapshot))

    def test_cached_policy_retains_storage_review_without_active_capability_claims(self):
        self.put(".claude/remote-settings.json", {
            "permissions": {"defaultMode": "bypassPermissions"}, "sandbox": {"enabled": False},
            "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "PRIVATE_CACHED_COMMAND"}]}]},
            "mcpServers": {"archived": {"url": "https://example.invalid/mcp", "headers": {"Authorization": "PRIVATE_CACHED_TOKEN"}}},
        })
        snapshot = self.scan(evaluate=True)
        declarations = [item for item in snapshot["observations"] if item["kind"] != "client"]
        self.assertTrue(declarations)
        self.assertTrue(all(item["details"].get("context") == "cached" for item in declarations))
        self.assertTrue(any(item["ruleId"] == "hooks-declared" and item["severity"] == "critical" for item in snapshot["findings"]))
        self.assertTrue(any(item["category"] == "credentials" and item["severity"] == "critical" for item in snapshot["findings"]))
        for finding in snapshot["findings"]:
            if finding["ruleId"] in {"hooks-declared", "mcp-network-direct"}:
                self.assertIn("cached", json.dumps(finding["evidence"]))
        for canary in ("PRIVATE_CACHED_COMMAND", "PRIVATE_CACHED_TOKEN"):
            self.assertNotIn(canary, json.dumps(snapshot))

    def test_historical_project_references_only_check_existence_inside_scope(self):
        present = self.home / "present-project"
        present.mkdir()
        missing = self.home / "missing-project"
        outside = self.base / "PRIVATE_OUTSIDE_PROJECT"
        outside.mkdir()
        linked = self.home / "linked-project"
        linked.symlink_to(outside, target_is_directory=True)
        self.put(".claude.json", {"projects": {str(path): {} for path in (present, missing, outside, linked, Path("PRIVATE_RELATIVE_PROJECT"))}})
        original_lstat = Path.lstat

        def bounded_lstat(path, *args, **kwargs):
            if path == outside:
                raise AssertionError("A historical reference escaped the selected account")
            return original_lstat(path, *args, **kwargs)

        with patch.object(Path, "lstat", bounded_lstat):
            snapshot = self.scan(evaluate=True)
        counts = next(item["details"]["value"] for item in snapshot["observations"] if item["details"].get("key") == "projects.referenceInventory")
        self.assertEqual(counts["presentWithinHomeCount"], 1)
        self.assertEqual(counts["missingWithinHomeCount"], 1)
        self.assertEqual(counts["notCheckedCount"], 3)
        self.assertNotIn("PRIVATE_OUTSIDE_PROJECT", json.dumps(snapshot))
        self.assertNotIn("PRIVATE_RELATIVE_PROJECT", json.dumps(snapshot))
        self.assertTrue(present.is_dir())
        self.assertTrue(linked.is_symlink())

    def test_repeated_and_conflicting_safe_settings_remain_scope_review_items(self):
        project = self.base / "project"
        self.put(".codex/config.toml", 'approval_policy="on-request"\nsandbox_mode="read-only"\n')
        self.put(".codex/config.toml", 'approval_policy="on-request"\nsandbox_mode="workspace-write"\n', project)
        snapshot = self.scan([project], evaluate=True)
        hygiene = [item for item in snapshot["findings"] if item["category"] == "hygiene"]
        self.assertTrue(any(item["severity"] == "info" for item in hygiene))
        self.assertTrue(any(item["severity"] == "low" for item in hygiene))
        self.assertFalse(any(item["severity"] in {"medium", "high", "critical"} for item in snapshot["findings"]))

    def test_uninterpretable_mcp_declaration_is_not_described_as_local_execution(self):
        self.put(".cursor/mcp.json", {"mcpServers": {"unknown": {}}})
        snapshot = self.scan(evaluate=True)
        self.assertEqual(snapshot["status"], "partial")
        self.assertFalse(any(item["ruleId"] == "mcp-local-unaudited" for item in snapshot["findings"]))
        self.assertTrue(any(item["ruleId"] in {"mcp-unknown-transport", "mcp-unsupported-shape"} for item in snapshot["findings"]))

    def test_credential_references_are_not_literals_and_are_never_resolved(self):
        references = ["${env:API_KEY}", "${input:API_KEY}", "${file:/PRIVATE_FILE_CANARY}", "$API_KEY", "Bearer ${API_KEY}"]
        self.put(".cursor/mcp.json", {"mcpServers": {str(index): {"url": "https://example.invalid/mcp", "headers": {"Authorization": value}} for index, value in enumerate(references)}})
        snapshot = self.scan()
        entries = [item["details"] for item in snapshot["observations"] if item["kind"] == "mcp"]
        self.assertEqual(sum(item["literalCredentialCount"] for item in entries), 0)
        self.assertEqual(sum(item["credentialReferenceCount"] for item in entries), len(references))
        self.assertNotIn("PRIVATE_FILE_CANARY", json.dumps(snapshot))

    def test_literal_fallback_inside_a_secret_reference_is_counted_without_retaining_it(self):
        self.put(".gemini/settings.json", {"mcpServers": {"helper": {"command": "node", "env": {"API_TOKEN": "${API_TOKEN:-PRIVATE_FALLBACK_CANARY}"}}}})
        snapshot = self.scan()
        details = next(item["details"] for item in snapshot["observations"] if item["kind"] == "mcp")
        self.assertGreaterEqual(details["literalCredentialCount"], 1)
        self.assertNotIn("PRIVATE_FALLBACK_CANARY", json.dumps(snapshot))

    def test_profile_structural_settings_do_not_collide_or_become_active(self):
        self.put(".codex/config.toml", 'profile="safe"\n[profiles.safe]\nsandbox_mode="read-only"\n[profiles.safe.sandbox_workspace_write]\nwritable_roots=["/tmp/safe"]\n[profiles.risky]\nsandbox_mode="danger-full-access"\n[profiles.risky.sandbox_workspace_write]\nwritable_roots=["/"]\n')
        snapshot = self.scan()
        broad = [item for item in snapshot["observations"] if item["kind"] == "setting" and item["details"].get("value") == {"entryCount": 1, "broadFilesystemRoot": True}]
        self.assertEqual(len(broad), 1)
        self.assertEqual(broad[0]["enabled"], "disabled")
        self.assertFalse(broad[0]["details"]["profileSelected"])

    def test_project_profile_selection_is_not_promoted_to_active_codex_settings(self):
        project = self.base / "project"
        self.put(".codex/config.toml", 'profile="risky"\n[profiles.risky]\napproval_policy="never"\nsandbox_mode="danger-full-access"\n', project)
        snapshot = self.scan([project], evaluate=True)
        self.assertFalse(any(finding["severity"] in {"critical", "high"} for finding in snapshot["findings"]))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires a Unix-like platform")
    def test_configuration_fifo_and_external_symlink_are_skipped_without_execution(self):
        directory = self.home / ".claude"
        directory.mkdir()
        os.mkfifo(directory / "settings.json")
        external = self.put("outside.toml", 'sandbox_mode="danger-full-access"', self.base)
        link = self.home / ".codex/config.toml"
        link.parent.mkdir()
        link.symlink_to(external)
        snapshot = self.scan()
        self.assertEqual(snapshot["status"], "partial")
        self.assertFalse([item for item in snapshot["observations"] if item["kind"] == "setting"])

    def test_wrong_typed_risky_values_cannot_become_high_priority_findings(self):
        self.put(".config/Code/User/settings.json", {"chat.tools.global.autoApprove": "true", "github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions": 1, "chat.permissions.default": ["autopilot"]})
        snapshot = self.scan(evaluate=True)
        self.assertEqual(snapshot["status"], "partial")
        self.assertFalse(any(item["severity"] in {"critical", "high"} for item in snapshot["findings"]))

    def test_same_source_permission_block_prevents_bypass_alarm(self):
        self.put(".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions", "disableBypassPermissionsMode": "disable"}})
        snapshot = self.scan(evaluate=True)
        self.assertFalse(any(item["severity"] in {"critical", "high"} for item in snapshot["findings"]))

    def test_catch_all_manual_approval_overrides_catch_all_autoapproval(self):
        self.put(".config/Code/User/settings.json", {"chat.tools.terminal.autoApprove": {"/.*/": True, "/^.*$/": False}})
        snapshot = self.scan(evaluate=True)
        self.assertFalse(any(item["category"] == "execution" and item["severity"] in {"medium", "high", "critical"} for item in snapshot["findings"]))

    def test_disabled_connection_retains_critical_exposure_with_disabled_evidence(self):
        self.put(".cursor/mcp.json", {"mcpServers": {"private": {"command": "npx", "args": ["@playwright/mcp"], "disabled": True, "env": {"API_TOKEN": "PRIVATE_DISABLED_CANARY"}}}})
        snapshot = self.scan(evaluate=True)
        credentials = [item for item in snapshot["findings"] if item["category"] == "credentials"]
        self.assertTrue(credentials)
        self.assertTrue(all(item["severity"] == "critical" for item in credentials))
        local = next(item for item in snapshot["findings"] if item["ruleId"] == "mcp-local-unaudited")
        self.assertEqual(local["severity"], "critical")
        self.assertIn("disabled", json.dumps(local["evidence"]))
        self.assertNotIn("PRIVATE_DISABLED_CANARY", json.dumps(snapshot))

    def test_collected_configuration_does_not_claim_verified_critical_exploitation(self):
        self.put(".codex/config.toml", 'approval_policy="never"\nsandbox_mode="danger-full-access"\n')
        snapshot = self.scan(evaluate=True)
        self.assertTrue(any(item["severity"] == "low" for item in snapshot["findings"]))
        self.assertFalse(any(item["severity"] == "critical" for item in snapshot["findings"]))

    def test_offline_pipeline_never_executes_hooks_mcp_or_browser(self):
        self.put(".claude/settings.json", {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "touch EXECUTION_CANARY"}, {"type": "http", "url": "https://example.invalid/HOOK_CANARY"}]}]}})
        self.put(".cursor/mcp.json", {"mcpServers": {"server": {"command": "curl", "args": ["https://example.invalid/MCP_CANARY"]}}})
        snapshot = self.scan(evaluate=True)
        from palma_scan.report import render_report
        with offline_guard():
            rendered = render_report(snapshot, model.summarize(snapshot))
        for canary in ("EXECUTION_CANARY", "HOOK_CANARY", "MCP_CANARY"):
            self.assertNotIn(canary, json.dumps(snapshot) + rendered)


if __name__ == "__main__":
    unittest.main()
