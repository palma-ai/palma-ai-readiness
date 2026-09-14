"""Each declaration counts once, however many files repeat it."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.collector import collect
from palma_scan.dedup import collapse_declarations, merge_clients
from palma_scan.model import summarize, validate
from palma_scan.rules import evaluate


class CopiesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve() / "home"
        self.home.mkdir()

    def put(self, relative, value):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")

    def project(self, relative, *, skill="Review the diff.", url="https://mcp.example.test/mcp"):
        self.put(relative + "/.claude/skills/review/SKILL.md", "---\nname: review\n---\n" + skill)
        self.put(relative + "/.claude/agents/reviewer.md", "---\nname: reviewer\n---\nCheck tests.")
        self.put(relative + "/.claude/settings.json", {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "./check"}]}]}})
        self.put(relative + "/.mcp.json", {"mcpServers": {"tracker": {"type": "http", "url": url}, "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}})
        return self.home / relative

    def scan(self, workspaces):
        snapshot = collect(self.home, workspaces, scope_type="copied-home")
        snapshot["findings"] = evaluate(snapshot)
        validate(snapshot)
        self.assertNotIn("_content", json.dumps(snapshot))
        return snapshot

    def kind(self, snapshot, kind):
        return [item for item in snapshot["observations"] if item["kind"] == kind]

    def finding(self, snapshot, rule):
        return next(item for item in snapshot["findings"] if item["ruleId"] == rule)

    def test_different_credentials_stay_separate_and_a_copied_credential_names_every_file(self):
        self.put("code/app-one/.claude/settings.json", {"env": {"ANTHROPIC_API_KEY": "sk-ant-PRIVATE-ONE-0000000000000000"}})
        self.put("code/app-two/.claude/settings.json", {"env": {"ANTHROPIC_API_KEY": "sk-ant-PRIVATE-TWO-0000000000000000"}})
        for copy in ("code/mono", "code/mono/.claude/worktrees/copy"):
            self.put(copy + "/.claude/settings.json", {"env": {"ANTHROPIC_API_KEY": "sk-ant-PRIVATE-MONO-000000000000000"}})
        shared = {"mcpServers": {"tracker": {"type": "http", "url": "https://mcp.example.test/mcp", "headers": {"Authorization": "Bearer PRIVATE_SHARED_TOKEN_123456"}}}}
        self.put("code/mono/.mcp.json", shared)
        self.put("code/mono/.claude/worktrees/copy/.mcp.json", shared)
        snapshot = self.scan([self.home / "code/app-one", self.home / "code/app-two", self.home / "code/mono", self.home / "code/mono/.claude/worktrees/copy"])
        stored = self.finding(snapshot, "config-inline-credential")
        self.assertEqual(stored["declarations"], 3, "two different secrets, and one secret copied into a worktree")
        self.assertIn("~/code/mono/.claude/settings.json, ~/code/app-one/.claude/settings.json and 2 other files", stored["summary"])
        inline = self.finding(snapshot, "mcp-inline-credential")
        self.assertEqual(inline["declarations"], 1)
        self.assertIn("~/code/mono/.mcp.json and ~/code/mono/.claude/worktrees/copy/.mcp.json", inline["summary"])

    def test_a_copy_in_a_malformed_file_never_stands_in_for_a_well_formed_copy(self):
        odd = {"type": "carrier-pigeon"}
        self.put("a/.cursor/mcp.json", {"mcpServers": {"broken": "not-an-object", "odd": odd}})
        self.put("code/b/.cursor/mcp.json", {"mcpServers": {"odd": odd}})
        snapshot = self.scan([self.home / "a", self.home / "code/b"])
        self.assertEqual(len([item for item in self.kind(snapshot, "mcp") if item["name"] == "odd"]), 2)
        self.assertIn("mcp-unknown-transport", {item["ruleId"] for item in snapshot["findings"]})

    def test_worktree_copies_are_one_declaration_and_changed_copies_stay_separate(self):
        main = self.project("code/mono")
        copies = [self.project(f"code/mono/.claude/worktrees/copy-{index}") for index in range(3)]
        changed = self.project("code/mono-feature", skill="Review the diff and the migration.", url="https://tracker.example.test/mcp")
        snapshot = self.scan([main, *copies, changed])
        skills = sorted(self.kind(snapshot, "skill"), key=lambda item: item["details"].get("locationCount", 1))
        self.assertEqual(len(skills), 2)
        self.assertEqual((skills[1]["details"]["locationCount"], skills[1]["details"]["copyCount"]), (4, 4))
        self.assertEqual(skills[1]["location"], "~/code/mono/.claude/skills/review/SKILL.md")
        self.assertEqual(len(skills[1]["details"]["locations"]), 4)
        self.assertEqual(skills[0]["location"], "~/code/mono-feature/.claude/skills/review/SKILL.md")
        trackers = [item for item in self.kind(snapshot, "mcp") if item["name"] == "tracker"]
        self.assertEqual(sorted(item["details"].get("locationCount", 1) for item in trackers), [1, 4])
        files = [item for item in self.kind(snapshot, "mcp") if item["name"] == "files"]
        self.assertEqual([item["details"]["locationCount"] for item in files], [5])
        self.assertEqual([item["details"]["locationCount"] for item in self.kind(snapshot, "agent")], [5])
        self.assertEqual([item["details"]["locationCount"] for item in self.kind(snapshot, "hook")], [5])
        self.assertEqual(self.finding(snapshot, "mcp-network-direct")["declarations"], 2)
        self.assertEqual(self.finding(snapshot, "mcp-local-unaudited")["declarations"], 1)
        self.assertEqual(self.finding(snapshot, "hooks-declared")["declarations"], 1)
        self.assertNotIn("skills-duplicate-content", {item["ruleId"] for item in snapshot["findings"]})

    def test_desktop_session_copies_of_one_connector_are_one_declaration(self):
        sessions = []
        for index in range(3):
            relative = f"Library/Application Support/Claude/local-agent-mode-sessions/session-{index}"
            self.put(relative + "/.mcp.json", {"mcpServers": {"computer-use": {"command": "computer-use-server"}}})
            sessions.append(self.home / relative)
        snapshot = self.scan(sessions)
        connectors = self.kind(snapshot, "mcp")
        self.assertEqual(len(connectors), 1)
        self.assertEqual(connectors[0]["details"]["locationCount"], 3)

    def test_identical_skill_in_two_cached_plugin_versions_is_one_skill(self):
        for version in ("0.48.0", "0.49.0"):
            base = ".claude/plugins/cache/market/toolkit/" + version
            self.put(base + "/.claude-plugin/plugin.json", {"name": "toolkit", "version": version})
            self.put(base + "/skills/helper/SKILL.md", "---\nname: helper\n---\nSame body.")
        snapshot = self.scan([])
        self.assertEqual(sorted(item["details"].get("version") for item in self.kind(snapshot, "plugin")), ["0.48.0", "0.49.0"])
        skills = self.kind(snapshot, "skill")
        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0]["details"]["locationCount"], 2)
        identities = {item["id"] for item in snapshot["observations"]}
        self.assertIn(skills[0]["details"]["parentId"], identities)

    def test_a_skill_keeps_its_plugin_when_identical_plugin_copies_merge(self):
        for market in ("alpha", "beta"):
            base = f".claude/plugins/cache/{market}/toolkit/1.0.0"
            self.put(base + "/.claude-plugin/plugin.json", {"name": "toolkit", "version": "1.0.0"})
            self.put(base + "/skills/helper/SKILL.md", "---\nname: helper\n---\nSame body.")
        # The longer path's copy is merged away, so its extra skill must follow the kept plugin.
        self.put(".claude/plugins/cache/alpha/toolkit/1.0.0/skills/extra/SKILL.md", "---\nname: extra\n---\nOnly in one copy.")
        snapshot = self.scan([])
        [plugin] = self.kind(snapshot, "plugin")
        extra = next(item for item in self.kind(snapshot, "skill") if item["name"] == "extra")
        self.assertEqual(extra["details"]["parentId"], plugin["id"])

    def test_copies_that_differ_in_env_headers_args_hook_commands_or_agent_body_stay_separate(self):
        variants = [({"env": {"MODE": "a"}}, "./check", "Check tests."), ({"env": {"MODE": "b"}}, "./check", "Check tests."),
                    ({"headers": {"X-Team": "b"}}, "./check", "Check tests."), ({"args": ["--b"]}, "./check", "Check tests."),
                    ({}, "./other", "Check tests."), ({}, "./check", "Check specs.")]
        roots = []
        for index, (extra, command, body) in enumerate(variants):
            relative = f"code/app-{index}"
            self.put(relative + "/.mcp.json", {"mcpServers": {"local": {"command": "node", **extra}}})
            self.put(relative + "/.claude/settings.json", {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": command}]}]}})
            self.put(relative + "/.claude/agents/reviewer.md", "---\nname: reviewer\n---\n" + body)
            roots.append(self.home / relative)
        snapshot = self.scan(roots)
        self.assertEqual(len(self.kind(snapshot, "mcp")), 5, "the two entries without extra fields are one declaration")
        self.assertEqual(len(self.kind(snapshot, "hook")), 2)
        self.assertEqual(len(self.kind(snapshot, "agent")), 2)

    def test_a_client_used_in_many_projects_is_one_row(self):
        projects = {}
        for index in range(5):
            (self.home / f"work/project-{index}").mkdir(parents=True)
            projects[str(self.home / f"work/project-{index}")] = {"allowedTools": [], "mcpServers": {"notes": {"command": "node"}}}
        self.put(".claude.json", {"projects": projects})
        self.put(".claude/settings.json", {"permissions": {"defaultMode": "default"}})
        snapshot = self.scan([])
        clients = [item for item in self.kind(snapshot, "client") if item["client"] == "claude-code"]
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["details"]["projectCount"], 5)
        self.assertNotIn("projectScoped", clients[0]["details"])
        notes = [item for item in self.kind(snapshot, "mcp") if item["name"] == "notes"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["details"]["copyCount"], 5)
        self.assertEqual(summarize(snapshot)["counts"]["mcp"], len(self.kind(snapshot, "mcp")))

    def test_only_sources_that_back_evidence_or_record_a_problem_are_exported(self):
        self.put(".claude/settings.json", {"permissions": {"defaultMode": "default"}})
        self.put(".gemini/settings.json", {"general": {"vimMode": True}})
        self.put(".cursor/mcp.json", '{"mcpServers": ')
        (self.home / ".claude/agents").mkdir(parents=True)  # Listed, but yields no evidence.
        snapshot = self.scan([])
        statuses = {source["status"] for source in snapshot["sources"]}
        self.assertNotIn("missing", statuses)
        referenced = {item["sourceId"] for item in snapshot["observations"]}
        self.assertFalse([source for source in snapshot["sources"] if source["status"] == "collected" and source["id"] not in referenced])
        self.assertTrue([source for source in snapshot["sources"] if source["location"].startswith("~/.cursor/mcp.json") and source["status"] == "error"])
        self.assertGreater(snapshot["coverage"]["sourcesInspected"], len([s for s in snapshot["sources"] if s["status"] == "collected"]))
        self.assertEqual(summarize(snapshot)["coverage"]["collected"], snapshot["coverage"]["sourcesInspected"])
        self.assertNotIn("missing", summarize(snapshot)["coverage"])


class CollapseRulesTests(unittest.TestCase):
    def observation(self, identity, source, location, **changes):
        item = {"id": identity, "kind": "mcp", "client": "cursor", "name": "tracker", "sourceId": source,
                "location": location, "enabled": "enabled", "_content": "same",
                "details": {"transport": "http", "context": "project", "contextId": "context-" + identity}}
        item.update(changes)
        return item

    def test_differences_in_content_state_or_context_are_never_merged(self):
        base = self.observation("a", "s1", "~/one/.mcp.json")
        variants = [
            self.observation("b", "s2", "~/two/.mcp.json", _content="different"),
            self.observation("c", "s3", "~/three/.mcp.json", enabled="disabled"),
            self.observation("d", "s4", "~/four/.mcp.json", details={"transport": "http", "context": "base"}),
            self.observation("e", "s5", "~/five/.mcp.json", _content=None),
        ]
        for variant in variants:
            with self.subTest(variant["id"]):
                result = collapse_declarations([dict(base, details=dict(base["details"])), variant])
                self.assertEqual(len(result), 2)
                self.assertFalse(any("_content" in item for item in result))

    def test_identical_entries_in_one_file_and_context_stay_distinct(self):
        first = self.observation("a", "s1", "~/one/.mcp.json")
        second = self.observation("b", "s1", "~/one/.mcp.json", details=dict(first["details"]))
        third = self.observation("c", "s2", "~/two/.mcp.json")
        result = collapse_declarations([first, second, third])
        self.assertEqual(len(result), 2)
        self.assertEqual(sorted(item["details"].get("copyCount", 1) for item in result), [1, 2])

    def test_one_file_declaring_the_same_server_for_several_projects_is_one_declaration(self):
        items = [self.observation(name, "state", "~/.claude.json") for name in ("p1", "p2", "p3")]
        result = collapse_declarations(items)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["details"]["copyCount"], 3)
        self.assertNotIn("locations", result[0]["details"])
        items = [self.observation(name, "state", "~/.claude.json") for name in ("p1", "p2")] + [self.observation("w", "s2", "~/code/app/.mcp.json")]
        [merged] = collapse_declarations(items)
        self.assertEqual((merged["details"]["copyCount"], merged["details"]["locationCount"]), (3, 2), "copies count declarations, locations count files")

    def test_skills_without_a_complete_digest_are_never_merged(self):
        skills = [{"id": name, "kind": "skill", "client": "codex", "name": "helper", "sourceId": name, "location": "~/" + name,
                   "enabled": "unknown", "details": {"digest": None}} for name in ("a", "b")]
        self.assertEqual(len(collapse_declarations(skills)), 2)

    def test_credential_records_without_content_identity_are_never_merged(self):
        records = [{"id": name, "kind": "setting", "client": "claude-code", "name": "Configuration credential storage", "sourceId": name,
                    "location": f"~/{name}/.claude/settings.json", "enabled": "enabled",
                    "details": {"key": "credentialStorage", "literalCredentialCount": 1}} for name in ("a", "b")]
        self.assertEqual(len(collapse_declarations(records)), 2)

    def test_client_rows_merge_installation_runtime_versions_and_projects(self):
        rows = [
            {"id": "c1", "kind": "client", "client": "claude-code", "name": "claude-code", "sourceId": "s1", "location": "~/.claude.json",
             "enabled": "unknown", "details": {"installationState": "config_only", "activation": "present", "projectScoped": True, "contextId": "context-p1", "authModes": ["unknown"]}},
            {"id": "c2", "kind": "client", "client": "claude-code", "name": "claude-code", "sourceId": "s1", "location": "~/.claude.json",
             "enabled": "unknown", "details": {"installationState": "config_only", "activation": "present", "projectScoped": True, "contextId": "context-p2", "authModes": ["api_key"]}},
            {"id": "c3", "kind": "client", "client": "claude-code", "name": "claude-code", "sourceId": "s2", "location": "~/.local/share/claude/versions/2.1.9",
             "enabled": "unknown", "details": {"installationState": "installed", "activation": "installed", "version": "2.1.9"}},
            {"id": "c4", "kind": "client", "client": "claude-code", "name": "claude-code", "sourceId": "s3", "location": "~/.local/share/claude/versions/2.1.10",
             "enabled": "unknown", "details": {"installationState": "installed", "activation": "installed", "version": "2.1.10"}},
            {"id": "c5", "kind": "client", "client": "claude-code", "name": "claude-code", "sourceId": "s4", "location": "machine:running-process-names",
             "enabled": "unknown", "details": {"activation": "running"}},
            {"id": "c6", "kind": "client", "client": "cursor", "name": "cursor", "sourceId": "s5", "location": "machine:running-process-names",
             "enabled": "unknown", "details": {"activation": "running"}},
        ]
        result = merge_clients(rows)
        self.assertEqual([item["client"] for item in result], ["claude-code", "cursor"])
        claude = result[0]["details"]
        self.assertEqual((claude["installationState"], claude["activation"], claude["processObserved"]), ("installed", "installed", True))
        self.assertEqual((claude["versions"], claude["version"]), (["2.1.9", "2.1.10"], "2.1.10"))
        self.assertEqual(claude["projectCount"], 2)
        self.assertEqual(claude["authModes"], ["api_key"])
        cursor = result[1]["details"]
        self.assertEqual((cursor["installationState"], cursor.get("processObserved")), ("unknown", True))

    def test_versions_with_mixed_suffixes_sort_without_errors(self):
        rows = [{"id": f"c{index}", "kind": "client", "client": "codex", "name": "codex", "sourceId": f"s{index}",
                 "location": f"~/v{index}", "enabled": "unknown", "details": {"activation": "installed", "version": version}}
                for index, version in enumerate(("1.2.3-rc.1", "1.2.3-1", "1.2.3"))]
        self.assertEqual(merge_clients(rows)[0]["details"]["versions"], ["1.2.3", "1.2.3-1", "1.2.3-rc.1"])


if __name__ == "__main__":
    unittest.main()
