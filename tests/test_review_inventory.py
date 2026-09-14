"""Regressions for complete skill discovery and curated finding references."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.collector import collect
from palma_scan.extra_clients import EXTRA_RULES
from palma_scan.rules import evaluate


class ReviewInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve() / "home"
        self.home.mkdir()

    def write(self, relative, content):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return path

    def skills(self, snapshot):
        return [item for item in snapshot["observations"]
                if item["kind"] == "skill" and item["client"] == "claude-code"]

    def test_resource_named_installed_skills_are_collected_and_evaluated(self):
        for name in ("docs", "assets", "images"):
            self.write(f".claude/skills/{name}/SKILL.md", f"---\nname: {name}\n---\nInstructions")
        snapshot = collect(self.home, scope_type="copied-home")
        skills = self.skills(snapshot)
        self.assertEqual({item["name"] for item in skills}, {"docs", "assets", "images"})
        finding = next(item for item in evaluate(snapshot) if item["ruleId"] == "skills-local-unreviewed")
        self.assertEqual(finding["severity"], "high")
        self.assertTrue({item["id"] for item in skills}.issubset(finding["observationIds"]))

    def test_resource_named_namespaces_and_nested_skills_are_collected(self):
        self.write(".claude/skills/docs/writer/SKILL.md", "---\nname: writer\n---\nInstructions")
        self.write(".claude/skills/team/images/SKILL.md", "---\nname: image-tools\n---\nInstructions")
        snapshot = collect(self.home, scope_type="copied-home")
        self.assertEqual({item["name"] for item in self.skills(snapshot)}, {"writer", "image-tools"})

    def test_known_skill_resources_are_hashed_without_becoming_installed_skills(self):
        self.write(".claude/skills/docs/SKILL.md", "---\nname: docs\n---\nInstructions")
        self.write(".claude/skills/docs/assets/SKILL.md", "---\nname: example-only\n---\nDocumentation example")
        self.write(".claude/skills/docs/images/icon.txt", "Image placeholder")
        snapshot = collect(self.home, scope_type="copied-home")
        skills = self.skills(snapshot)
        self.assertEqual([item["name"] for item in skills], ["docs"])
        self.assertEqual(skills[0]["details"]["filesHashed"], 3)
        self.assertTrue(skills[0]["details"]["digest"])

    def test_plugin_skill_with_resource_name_is_collected_with_parent(self):
        base = ".claude/plugins/cache/vendor/illustration/1.0"
        self.write(base + "/.claude-plugin/plugin.json", {"name": "illustration"})
        self.write(base + "/skills/assets/SKILL.md", "---\nname: asset-generator\n---\nInstructions")
        snapshot = collect(self.home, scope_type="copied-home")
        skills = self.skills(snapshot)
        self.assertEqual([item["name"] for item in skills], ["asset-generator"])
        parent = next(item for item in snapshot["observations"]
                      if item["kind"] == "plugin" and item["client"] == "claude-code")
        self.assertEqual(skills[0]["details"]["parentId"], parent["id"])

    def test_grouped_rules_retain_curated_references_across_sources(self):
        self.write(".aider.conf.yml", "verify-ssl: false\n")
        workspace = self.write("project/.aider.conf.yml", "verify-ssl: false\n").parent
        snapshot = collect(self.home, [workspace], scope_type="copied-home")
        rule = dict(next(item for item in EXTRA_RULES if item["id"] == "PALMA-AIDER-002"))
        # A focused rule can cite a subset of the client's documentation. Grouping
        # multiple declarations must retain that selection, without duplicate links.
        rule["references"] = ["https://aider.chat/docs/config/options.html"] * 2
        with patch("palma_scan.rules.EXTRA_RULES", [rule]):
            findings = evaluate(snapshot)
            reversed_findings = evaluate({**snapshot, "observations": list(reversed(snapshot["observations"]))})
        finding = next(item for item in findings if item["ruleId"] == rule["id"])
        self.assertEqual(finding["declarations"], 2)
        self.assertEqual(len({item["sourceId"] for item in finding["evidence"]}), 2)
        self.assertEqual(finding["references"], ["https://aider.chat/docs/config/options.html"])
        self.assertEqual(finding, next(item for item in reversed_findings if item["ruleId"] == rule["id"]))


if __name__ == "__main__":
    unittest.main()
