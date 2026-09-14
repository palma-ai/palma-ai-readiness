"""Findings describe the actual risk once, with governance and provenance taken into account."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.collector import collect
from palma_scan.model import validate
from palma_scan.rules import evaluate


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve() / "home"
        self.home.mkdir()

    def put(self, relative, value):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path

    def repository(self, relative):
        self.put(relative + "/.git/HEAD", "ref: refs/heads/main\n")
        for name in ("objects", "refs"):
            (self.home / relative / ".git" / name).mkdir()

    def scan(self, workspaces=()):
        snapshot = collect(self.home, list(workspaces), scope_type="copied-home")
        snapshot["findings"] = evaluate(snapshot)
        validate(snapshot)
        return snapshot

    def rule(self, snapshot, rule_id):
        return [item for item in snapshot["findings"] if item["ruleId"] == rule_id]

    def names(self, snapshot, finding):
        observations = {item["id"]: item["name"] for item in snapshot["observations"]}
        return {observations[identity] for identity in finding["observationIds"]}

    def test_connectors_through_a_palma_gateway_are_governed_and_lookalikes_are_not(self):
        governed = {"space": "https://gateway.palma.ai/mcp", "regional": "https://gateway.eu1.palma.ai/spaces/team/mcp",
                    "suffixed": "https://gateway-west.palma.ai/mcp", "explicit-port": "https://gateway.palma.ai:443/mcp"}
        lookalikes = {"cleartext": "http://gateway.palma.ai/mcp", "other-port": "https://gateway.palma.ai:8443/mcp",
                      "suffix-domain": "https://gateway.palma.ai.example.test/mcp", "prefixed": "https://evilgateway.palma.ai/mcp",
                      "other-host": "https://example-other.palma.ai/mcp", "similar-domain": "https://gateway.palma-ai.test/mcp",
                      "trailing-dot": "https://gateway.palma.ai./mcp", "userinfo": "https://team:PRIVATE@gateway.palma.ai/mcp",
                      "backslash": "https://gateway.palma.ai\\@collector.example.test/mcp"}
        servers = {name: {"type": "http", "url": url} for name, url in {**governed, **lookalikes}.items()}
        servers["gateway.palma.ai"] = {"command": "node"}  # A name is never evidence of governance.
        self.put(".cursor/mcp.json", {"mcpServers": servers})
        snapshot = self.scan()
        connectors = {item["name"]: item for item in snapshot["observations"] if item["kind"] == "mcp"}
        self.assertEqual({name for name, item in connectors.items() if item["details"].get("governedBy") == "palma-gateway"}, set(governed))
        direct = self.rule(snapshot, "mcp-network-direct")
        self.assertEqual(len(direct), 1)
        self.assertEqual(self.names(snapshot, direct[0]), set(lookalikes))

    def test_a_governed_connector_with_an_inline_secret_still_reports_the_credential(self):
        self.put(".cursor/mcp.json", {"mcpServers": {"space": {"type": "http", "url": "https://gateway.palma.ai/mcp",
                                                                "headers": {"Authorization": "Bearer PRIVATE_EXAMPLE_TOKEN_123456"}}}})
        snapshot = self.scan()
        self.assertFalse(self.rule(snapshot, "mcp-network-direct"))
        self.assertEqual([self.names(snapshot, item) for item in self.rule(snapshot, "mcp-inline-credential")], [{"space"}])
        self.assertNotIn("PRIVATE_EXAMPLE_TOKEN_123456", json.dumps(snapshot))

    def test_a_fixed_secret_is_one_finding_and_the_summary_names_what_to_fix(self):
        self.put(".cursor/mcp.json", {"mcpServers": {
            "context7": {"type": "http", "url": "https://mcp.context7.com/mcp", "headers": {"Authorization": "Bearer PRIVATE_EXAMPLE_TOKEN_123456"}},
            "tracker": {"type": "http", "url": "https://mcp.example.test/mcp", "headers": {"Authorization": "Bearer ${env:TRACKER_TOKEN}"}}}})
        snapshot = self.scan()
        [inline] = self.rule(snapshot, "mcp-inline-credential")
        [static] = self.rule(snapshot, "mcp-static-secret-auth")
        self.assertEqual((inline["severity"], self.names(snapshot, inline)), ("critical", {"context7"}))
        self.assertEqual((static["severity"], self.names(snapshot, static)), ("high", {"tracker"}))
        self.assertIn("\u201ccontext7\u201d keeps a potential credential in plain text in ~/.cursor/mcp.json", inline["summary"])
        self.assertIn("use it as you", inline["impact"])
        self.assertNotIn("Control who can invoke tools", inline["impact"])
        self.assertIn("\u201ctracker\u201d signs in with a fixed secret", static["summary"])
        self.assertNotIn("PRIVATE_EXAMPLE_TOKEN_123456", json.dumps(snapshot))

    def test_a_fixed_secret_by_reference_is_reported_beside_an_unrelated_inline_credential(self):
        self.put(".cursor/mcp.json", {"mcpServers": {"tracker": {"type": "http", "url": "https://mcp.example.test/mcp?api_key=PRIVATE_URL_KEY_123456",
                                                                  "headers": {"Authorization": "Bearer ${env:TRACKER_TOKEN}"}}}})
        snapshot = self.scan()
        self.assertEqual([self.names(snapshot, item) for item in self.rule(snapshot, "mcp-inline-credential")], [{"tracker"}])
        self.assertEqual([self.names(snapshot, item) for item in self.rule(snapshot, "mcp-static-secret-auth")], [{"tracker"}])

    def test_summary_names_cannot_close_their_quotes_reorder_text_or_act_as_templates(self):
        secret = {"type": "http", "url": "https://mcp.example.test/mcp", "headers": {"Authorization": "Bearer PRIVATE_EXAMPLE_TOKEN_123456"}}
        self.put(".cursor/mcp.json", {"mcpServers": {
            "a\u201d is routed through the Palma gateway. \u201cz": secret, "{where} {n} \u202ereversed": secret,
            "https://jira.internal.example/mcp": secret, "x" * 200: secret}})
        [finding] = self.rule(self.scan(), "mcp-inline-credential")
        summary = finding["summary"]
        self.assertEqual(summary.count("\u201c"), 3)
        self.assertEqual(summary.count("\u201d"), 3)
        self.assertIn("{where} {n} reversed", summary)
        self.assertNotIn("\u202e", summary)
        self.assertNotIn("jira.internal.example", summary)
        self.assertIn("x" * 59 + "\u2026", summary)
        self.assertIn("and 1 more", summary)

    def test_summaries_stay_short_whatever_the_names_and_paths(self):
        observations = [{"id": f"obs-{index}", "kind": "mcp", "client": "cursor", "name": "n" * 250 + str(index), "sourceId": "src-1",
                         "location": "/" + "folder/" * 580 + f"{index}/mcp.json", "enabled": "enabled",
                         "details": {"transport": "http", "execution": "remote", "auth": "bearer_header", "authSecretInline": True,
                                     "literalCredentialCount": 1, "inlineCredentialPresent": True, "capability": "computer"}}
                        for index in range(6)]
        findings = evaluate({"observations": observations, "sources": []})
        self.assertTrue(findings)
        for finding in findings:
            self.assertLess(len(finding["summary"]), 1000, finding["ruleId"])

    def test_version_control_needs_a_real_repository_that_does_not_ignore_the_skill(self):
        self.repository("code/kept")
        self.put("code/kept/.gitignore", "# build output\n*.log\n/build\n")
        self.put("code/kept/.claude/skills/kept/SKILL.md", "---\nname: kept\n---\nSteps.")
        self.repository("code/ignored")
        self.put("code/ignored/.gitignore", "node_modules/\n.claude/\n")
        self.put("code/ignored/.claude/skills/ignored/SKILL.md", "---\nname: ignored\n---\nSteps.")
        self.repository("code/reincluded")
        self.put("code/reincluded/.gitignore", ".claude/\n!.claude/skills/reincluded/SKILL.md\n")
        self.put("code/reincluded/.claude/skills/reincluded/SKILL.md", "---\nname: reincluded\n---\nSteps.")
        self.put("code/empty-marker/.git", "")
        self.put("code/empty-marker/.claude/skills/marker/SKILL.md", "---\nname: marker\n---\nSteps.")
        snapshot = self.scan([self.home / "code" / name for name in ("kept", "ignored", "reincluded", "empty-marker")])
        findings = {item["severity"]: item for item in self.rule(snapshot, "skills-local-unreviewed")}
        self.assertEqual(self.names(snapshot, findings["high"]), {"kept"})
        self.assertEqual(self.names(snapshot, findings["critical"]), {"ignored", "reincluded", "marker"})
        self.assertIn("not excluded by its .gitignore", findings["high"]["summary"])

    def test_computer_use_summary_names_the_connector_and_what_it_controls(self):
        self.put("Library/Application Support/Claude/claude_desktop_config.json", {"mcpServers": {"computer-use": {"command": "computer-use-server"}}})
        snapshot = self.scan()
        [finding] = self.rule(snapshot, "mcp-computer-use")
        self.assertIn("\u201ccomputer-use\u201d can control the screen, keyboard and mouse as you", finding["summary"])
        self.assertIn("Library/Application Support/Claude/claude_desktop_config.json", finding["summary"])
        self.assertIn("keyboard and mouse", finding["impact"])

    def test_version_controlled_project_skills_are_high_and_other_local_skills_stay_critical(self):
        self.repository("code/tracked")
        self.put("code/tracked/.claude/skills/release/SKILL.md", "---\nname: release\n---\nSteps.")
        self.put("code/worktree/.git", "gitdir: ../tracked/.git/worktrees/worktree\n")
        self.put("code/tracked/.git/worktrees/worktree/HEAD", "ref: refs/heads/worktree\n")
        self.put("code/tracked/.git/worktrees/worktree/commondir", "../..\n")
        self.put("code/tracked/.git/worktrees/worktree/gitdir", str(self.home / "code/worktree/.git") + "\n")
        self.put("code/worktree/.claude/skills/deploy/SKILL.md", "---\nname: deploy\n---\nSteps.")
        self.put("code/untracked/.claude/skills/scratch/SKILL.md", "---\nname: scratch\n---\nSteps.")
        self.put(".claude/skills/downloaded/SKILL.md", "---\nname: downloaded\n---\nSteps.")
        self.put(".git/HEAD", "ref: refs/heads/main\n")  # A dotfiles repository in the home does not count.
        snapshot = self.scan([self.home / "code/tracked", self.home / "code/worktree", self.home / "code/untracked"])
        findings = {item["severity"]: item for item in self.rule(snapshot, "skills-local-unreviewed")}
        self.assertEqual(set(findings), {"critical", "high"})
        self.assertEqual(self.names(snapshot, findings["high"]), {"release", "deploy"})
        self.assertEqual(self.names(snapshot, findings["critical"]), {"scratch", "downloaded"})
        self.assertEqual(findings["high"]["title"], "Project skills in version control need a review record")
        self.assertIn("reviewed like code", findings["high"]["ratingReason"])


if __name__ == "__main__":
    unittest.main()
