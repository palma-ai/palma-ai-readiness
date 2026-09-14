"""The report shows what matters in each record, and the shareable summary names no folders."""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.report import render_report


class Tags(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def base():
    return {"schemaVersion": "2.0", "collector": {"name": "palma-ai-readiness", "version": "2.2.0", "rulesVersion": "test"},
            "mode": "endpoint", "status": "partial", "startedAt": "2026-09-14T10:00:00Z", "completedAt": "2026-09-14T10:01:00Z",
            "scope": {"type": "machine", "platform": "macos", "workspaceCount": 1}, "sources": [], "observations": [], "findings": [],
            "coverage": {"limitations": [], "sourcesInspected": 42}}


def finding(identity, rule, severity, observation_ids, evidence=None, **fields):
    return {"id": identity, "ruleId": rule, "title": fields.pop("title", rule), "severity": severity, "category": "mcp",
            "confidence": "high", "evidenceType": "configuration", "summary": fields.pop("summary", "Summary."),
            "impact": fields.pop("impact", "Impact sentence."), "recommendation": "Next step.",
            "observationIds": observation_ids, "evidence": evidence or [], "references": [], **fields}


class EvidenceTests(unittest.TestCase):
    def test_evidence_is_typed_facts_capped_at_twenty_with_show_all(self):
        data = base()
        data["sources"] = [{"id": "s1", "client": "cursor", "scope": "user", "location": "~/.cursor/mcp.json", "status": "collected"}]
        data["observations"] = [{"id": f"o{index:02d}", "kind": "mcp", "client": "cursor", "name": f"server-{index:02d}", "sourceId": "s1",
                                 "location": "~/.cursor/mcp.json", "enabled": "enabled",
                                 "details": {"execution": "remote", "transport": "http", "auth": "bearer_header", "literalCredentialCount": 1,
                                             "inlineCredentialPresent": True, "capabilityEvidence": "not-identified", "urlCredentialCount": 0}}
                                for index in range(25)]
        data["findings"] = [finding("f1", "mcp-inline-credential", "critical", [item["id"] for item in data["observations"]],
                                    [{"sourceId": "s1", "location": "~/.cursor/mcp.json", "key": item["name"], "value": {"transport": "http"}} for item in data["observations"]])]
        output = render_report(data, {})
        card = output.split('<article class="finding"', 1)[1].split("</article>", 1)[0]
        self.assertNotIn("<pre", card)
        self.assertNotIn("capabilityEvidence", card)
        self.assertNotIn("urlCredentialCount", card)
        first_list = card.split('<ul class="evidence-list">', 1)[1].split("</ul>", 1)[0]
        self.assertEqual(first_list.count('class="evidence-row"'), 20)
        self.assertIn("Show all 25", card)
        self.assertEqual(card.count('class="evidence-row"'), 25)
        for fact in ("Remote service", "Credential stored in the file", "Fixed secret"):
            self.assertIn(f">{fact}</span>", card)

    def test_evidence_beyond_the_row_limit_is_labelled_honestly_in_both_reports(self):
        data = base()
        data["observations"] = [{"id": f"o{index:03d}", "kind": "mcp", "client": "cursor", "name": f"server-{index}", "sourceId": f"s{index}",
                                 "location": "~/.cursor/mcp.json", "enabled": "enabled", "details": {"execution": "local"}} for index in range(250)]
        data["findings"] = [finding("f1", "mcp-local-unaudited", "critical", [item["id"] for item in data["observations"]])]
        local, shared = render_report(data, {}), render_report(data, {}, share=True)
        for output in (local, shared):
            self.assertIn("Show 200 of 250", output)
            self.assertNotIn("Show all 250", output)
        self.assertIn("50 more are listed in snapshot.json", local)
        self.assertIn("50 more are not shown in this summary", shared)
        self.assertNotIn("snapshot.json", shared.split('<article class="finding"', 1)[1].split("</article>", 1)[0])

    def test_system_policy_computer_use_acts_as_the_signed_in_user(self):
        data = base()
        data["observations"] = [{"id": "o1", "kind": "mcp", "client": "claude-code", "name": "computer-use", "sourceId": "s1",
                                 "location": "system:claude-code/managed-mcp.json", "enabled": "enabled",
                                 "details": {"execution": "local", "capability": "computer", "accountAlias": "system"}}]
        data["findings"] = [finding("f1", "mcp-computer-use", "critical", ["o1"])]
        card = render_report(data, {}).split('<article class="finding"', 1)[1]
        self.assertIn(">Set by system policy</span>", card)
        self.assertIn(">Acts as you</span>", card)
        self.assertNotIn("system-wide", card)

    def test_inventory_search_matches_client_names(self):
        from palma_scan.report import _JS
        self.assertIn("closest('.inventory-group')", _JS)
        self.assertIn(".inventory-kind strong", _JS)

    def test_computer_use_rows_name_the_app_what_it_controls_who_it_acts_as_and_approval(self):
        data = base()
        data["sources"] = [{"id": "s1", "client": "claude-desktop", "scope": "user", "location": "~/Library/Application Support/Claude/claude_desktop_config.json", "status": "collected"}]
        data["observations"] = [{"id": "o1", "kind": "mcp", "client": "claude-desktop", "name": "computer-use", "sourceId": "s1",
                                 "location": data["sources"][0]["location"], "enabled": "enabled",
                                 "details": {"execution": "local", "transport": "stdio", "capability": "computer", "autoApproval": "all", "accountAlias": "~"}}]
        data["findings"] = [finding("f1", "mcp-computer-use", "critical", ["o1"], impact="It can see your screen and use the keyboard and mouse as you.")]
        output = render_report(data, {})
        card = output.split('<article class="finding"', 1)[1].split("</article>", 1)[0]
        body, disclosure = card.split('<details class="finding-evidence">', 1)
        self.assertIn("It can see your screen and use the keyboard and mouse as you.", body, "impact is visible without expanding evidence")
        self.assertIn("Claude Desktop", disclosure)
        for fact in ("Controls screen, keyboard and mouse", "Acts as you", "No approval before tool use"):
            self.assertIn(f">{fact}</span>", disclosure)

    def test_settings_show_their_typed_value_even_from_evidence_lines(self):
        data = base()
        data["sources"] = [{"id": "s1", "client": "codex", "scope": "user", "location": "~/.codex/config.toml", "status": "collected"}]
        data["observations"] = [{"id": "o1", "kind": "setting", "client": "codex", "name": "Sandbox", "sourceId": "s1", "location": "~/.codex/config.toml",
                                 "enabled": "enabled", "details": {"legacyShape": True}}]
        data["findings"] = [finding("f1", "sandbox-disabled", "high", ["o1"], [{"sourceId": "s1", "location": "~/.codex/config.toml", "key": "sandbox_mode", "value": "danger-full-access"}])]
        self.assertIn('<code class="fact fact-setting">sandbox_mode = danger-full-access</code>', render_report(data, {}))

    def test_coverage_says_which_folders_were_not_searched_only_when_some_were_skipped(self):
        data = base()
        data["scope"]["discovery"] = {"localVolumes": 1, "projectsDiscovered": 2, "directoriesVisited": 90, "excludedDirectories": 3}
        coverage = render_report(data, {}).split('id="coverage"', 1)[1]
        self.assertIn("not searched for projects", coverage)
        self.assertIn("<code>--workspace</code>", coverage)
        data["scope"]["discovery"]["excludedDirectories"] = 0
        self.assertNotIn("not searched for projects", render_report(data, {}))

    def test_merged_copies_list_every_declared_location(self):
        data = base()
        data["sources"] = [{"id": "s1", "client": "claude-code", "scope": "workspace", "location": "~/code/mono/.mcp.json", "status": "collected"}]
        locations = ["~/code/mono/.mcp.json", "~/code/mono/.claude/worktrees/feature-a/.mcp.json", "~/code/mono/.claude/worktrees/feature-b/.mcp.json"]
        data["observations"] = [{"id": "o1", "kind": "mcp", "client": "claude-code", "name": "tracker", "sourceId": "s1", "location": locations[0],
                                 "enabled": "enabled", "details": {"execution": "remote", "locations": locations, "locationCount": 3, "copyCount": 3}}]
        output = render_report(data, {})
        inventory = output.split('id="inventory"', 1)[1].split('id="coverage"', 1)[0]
        self.assertIn("Declared in 3 places", inventory)
        for location in locations:
            self.assertIn(location, inventory)


class ShareLocationTests(unittest.TestCase):
    def test_locations_keep_only_the_configuration_folder_and_file_name(self):
        from palma_scan.report import _share_location
        expected = {
            "~/.claude.json": "~/.claude.json",
            "~/.claude/settings.json": "~/.claude/settings.json",
            "~/code/PRIVATE_PROJECT/.mcp.json": "project/.mcp.json",
            "~/Library/CloudStorage/OneDrive-PRIVATE_COMPANY/PRIVATE_CLIENT/.mcp.json": "project/.mcp.json",
            "~/Library/Mobile Documents/com~apple~CloudDocs/PRIVATE_PROJECT/.claude/settings.json": "project/.claude/settings.json",
            "~/.codex/worktrees/1a2b/PRIVATE_REPO/.mcp.json": "project/.mcp.json",
            "~/.claude/skills/PRIVATE_SKILL_FOLDER/nested/SKILL.md": "~/.claude/\u2026/SKILL.md",
            "~/Library/Application Support/Claude/claude_desktop_config.json": "~/Library/\u2026/claude_desktop_config.json",
            "~/AppData/Local/PRIVATE_COMPANY/PRIVATE_PROJECT/.vscode/mcp.json": "project/.vscode/mcp.json",
            "/opt/PRIVATE_COMPANY/PRIVATE_PROJECT/.mcp.json": "project/.mcp.json",
            "/Library/WebServer/Documents/PRIVATE_SITE/notes.json": "/Library/\u2026/notes.json",
            "C:/ProgramData/PRIVATE_COMPANY/PRIVATE_PROJECT/settings.json": "C:/ProgramData/\u2026/settings.json",
            "/srv/PRIVATE_HOST/data.json": "location withheld",
            "system:claude-code/managed-settings.json": "system:claude-code/managed-settings.json",
        }
        for location, shared in expected.items():
            with self.subTest(location):
                self.assertEqual(_share_location(location), shared)
                self.assertEqual(_share_location(shared), shared, "applying it twice changes nothing")

    def test_a_real_scan_shares_no_private_folder_name_anywhere_in_the_file(self):
        from palma_scan.collector import collect
        from palma_scan.model import validate
        from palma_scan.rules import evaluate
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            home = Path(td).resolve() / "home"

            def put(relative, value):
                path = home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))

            alpha, beta, gamma, delta = ("code/PRIVATE_PROJECT_ALPHA", "Library/CloudStorage/OneDrive-PRIVATE_COMPANY/PRIVATE_CLIENT_BETA",
                                         ".codex/worktrees/a1b2/PRIVATE_REPO_GAMMA", "code/PRIVATE_PROJECT_DELTA")
            put(alpha + "/.cursor/mcp.json", {"mcpServers": {
                "tracker": {"type": "http", "url": "https://mcp.example.test/mcp", "headers": {"Authorization": "Bearer PRIVATE_TOKEN_abcdefghijklmnop"}},
                "computer-use": {"command": "computer-use-server"},
                "https://jira.PRIVATE_INTERNAL_HOST.example/mcp": {"type": "http", "url": "https://mcp.example.test/other"}}})
            put(alpha + "/.claude/settings.json", {"env": {"ANTHROPIC_API_KEY": "sk-ant-PRIVATE-000000000000000000"}})
            put(beta + "/.mcp.json", {"mcpServers": {"notes": {"command": "node"}}})
            put(gamma + "/.mcp.json", {"mcpServers": {"docs": {"type": "http", "url": "https://docs.example.test/mcp"}}})
            put(delta + "/.vscode/settings.json", {"chat.hookFilesLocations": {"PRIVATE_HOOKS_EPSILON/hooks": True}})
            snapshot = collect(home, [home / alpha, home / beta, home / gamma, home / delta], scope_type="copied-home")
            snapshot["findings"] = evaluate(snapshot)
            validate(snapshot)
            local, shared = render_report(snapshot, {}), render_report(snapshot, {}, share=True)
        self.assertIn("PRIVATE_PROJECT_ALPHA", local)
        self.assertEqual(re.findall(r"PRIVATE_[A-Z_]+", shared), [])
        self.assertIn("Name withheld", shared)
        self.assertNotIn("finding-" + snapshot["findings"][0]["id"][8:], shared)
        self.assertTrue(re.search(r'id="finding-1"', shared), "anchors are numbered, not derived from paths")

    def test_direction_controls_from_names_are_not_rendered(self):
        data = base()
        data["sources"] = [{"id": "s1", "client": "cursor", "scope": "user", "location": "~/.cursor/mcp.json", "status": "collected"}]
        data["observations"] = [{"id": "o1", "kind": "mcp", "client": "cursor", "name": "safe\u202etxt.exe", "sourceId": "s1",
                                 "location": "~/.cursor/mcp.json", "enabled": "enabled", "details": {"execution": "local"}}]
        self.assertNotIn("\u202e", render_report(data, {}))
        self.assertIn("safetxt.exe", render_report(data, {}))


class ShareTests(unittest.TestCase):
    def snapshot(self):
        data = base()
        data["sources"] = [
            {"id": "s1", "client": "claude-code", "scope": "workspace", "location": "~/code/PRIVATE_PROJECT/.claude/worktrees/PRIVATE_BRANCH/.mcp.json", "status": "collected"},
            {"id": "s2", "client": "claude-code", "scope": "user", "location": "~/.claude.json", "status": "collected"},
            {"id": "s3", "client": "cursor", "scope": "workspace", "location": "/Volumes/PRIVATE_DISK/work/.cursor/mcp.json", "status": "error", "reason": "parse_error"},
            {"id": "s4", "client": "machine", "scope": "machine", "location": "machine:local-volume-project-discovery/area-0123456789", "status": "error", "reason": "Permission denied for this discovery area."},
        ]
        data["observations"] = [
            {"id": "o1", "kind": "mcp", "client": "claude-code", "name": "tracker", "sourceId": "s1", "location": data["sources"][0]["location"], "enabled": "enabled",
             "details": {"execution": "remote", "locationCount": 2, "locations": [data["sources"][0]["location"], "~/code/PRIVATE_OTHER/.mcp.json"]}},
            {"id": "o2", "kind": "mcp", "client": "claude-code", "name": "notes", "sourceId": "s2", "location": "~/.claude.json", "enabled": "enabled", "details": {"execution": "local"}},
            {"id": "o3", "kind": "skill", "client": "shared", "name": "release-notes", "sourceId": "s1", "location": "~/PRIVATE_FOLDER/notes/SKILL.md", "enabled": "unknown", "details": {"origin": "project"}},
            {"id": "o4", "kind": "client", "client": "claude-code", "name": "claude-code", "sourceId": "s2", "location": "~/.claude.json", "enabled": "unknown", "details": {}},
        ]
        data["findings"] = [finding("f1", "mcp-network-direct", "critical", ["o1"], [{"sourceId": "s1", "location": data["sources"][0]["location"], "key": "tracker", "value": {}}])]
        return data

    def test_shareable_summary_keeps_standard_paths_and_names_but_no_folders(self):
        output = render_report(self.snapshot(), {}, share=True)
        self.assertNotIn("PRIVATE_", output)
        self.assertIn("project/.mcp.json", output)
        self.assertIn("~/.claude.json", output)
        self.assertIn("location withheld", output)
        self.assertIn("tracker", output)
        self.assertIn("Declared in 2 places", output)
        self.assertIn("<title>Palma · Shareable AI access summary</title>", output)
        self.assertIn("Shareable summary:", output)
        coverage = output.split('id="coverage"', 1)[1]
        self.assertEqual(sorted(re.findall(r'<summary><strong>(\d+)</strong><span>([^<]+)</span>', coverage)),
                         [("1", "Could not be interpreted"), ("1", "Permission denied")])
        self.assertNotIn("<li>", coverage.split("</section>", 1)[0], "the shareable summary lists no source locations")

    def test_local_report_keeps_full_locations(self):
        output = render_report(self.snapshot(), {})
        self.assertIn("~/code/PRIVATE_PROJECT/.claude/worktrees/PRIVATE_BRANCH/.mcp.json", output)
        self.assertIn("/Volumes/PRIVATE_DISK/work/.cursor/mcp.json", output)

    def test_anchors_resolve_in_both_variants(self):
        for share in (False, True):
            tags = Tags(render_report(self.snapshot(), {}, share=share)).tags
            ids = {attrs["id"] for _, attrs in tags if "id" in attrs}
            for tag, attrs in tags:
                if tag == "a" and attrs.get("href", "").startswith("#"):
                    self.assertIn(attrs["href"][1:], ids)


if __name__ == "__main__":
    unittest.main()
