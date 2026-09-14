"""Finding summaries separate locations; review tiles distinguish evidence from coverage."""
from html.parser import HTMLParser
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.report import render_report
from palma_scan.report_regulation import render_regulation_section
from palma_scan.rules import evaluate


class Tiles(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.states = {}
        self.counts = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "details" and attrs.get("class") == "regulation-tile":
            self.states[attrs["id"]] = attrs.get("data-review-state")
        if attrs.get("class") == "regulation-count":
            self.counts.append(attrs["data-count"])


class FeedbackCopyTests(unittest.TestCase):
    def test_generated_summaries_keep_paths_in_evidence_for_each_affected_rule(self):
        cases = (
            ("mcp-inline-credential", "mcp", {"transport": "http", "inlineCredentialPresent": True}),
            ("mcp-static-secret-auth", "mcp", {"transport": "http", "auth": "bearer_header"}),
            ("mcp-computer-use", "mcp", {"transport": "stdio", "capability": "computer"}),
            ("mcp-browser-automation", "mcp", {"transport": "stdio", "capability": "browser"}),
            ("config-inline-credential", "setting", {"key": "env", "literalCredentialCount": 1}),
        )
        for rule, kind, details in cases:
            with self.subTest(rule=rule):
                location = "~/code/PRIVATE_PROJECT/.cursor/mcp.json"
                observation = {"id": "o1", "kind": kind, "client": "cursor", "name": "Team tools",
                               "sourceId": "s1", "location": location, "enabled": "enabled", "details": details}
                data = {"schemaVersion": "2.0", "mode": "endpoint", "status": "complete", "scope": {},
                        "sources": [{"id": "s1", "client": "cursor", "scope": "workspace", "location": location, "status": "collected"}],
                        "observations": [observation], "findings": [], "coverage": {}}
                data["findings"] = evaluate(data)
                finding = next(item for item in data["findings"] if item["ruleId"] == rule)
                self.assertNotIn(location, finding["summary"])
                self.assertEqual(finding["evidence"][0]["location"], location)
                if kind == "mcp":
                    self.assertIn("Team tools", finding["summary"])
                data["findings"] = [finding]
                output = render_report(data, {})
                article = output.split('<article class="finding"', 1)[1].split("</article>", 1)[0]
                summary, evidence = article.split('<details class="finding-evidence">', 1)
                self.assertNotIn(location, summary)
                self.assertIn(location, evidence)

    def test_local_inventory_without_a_governance_layer_is_not_covered_and_with_one_needs_owner_evidence(self):
        for governed, state in ((False, "not-covered"), (True, "missing-evidence")):
            with self.subTest(governed=governed):
                observations = [{"id": "o1", "kind": "mcp", "details": {"governedBy": "palma-gateway"} if governed else {}}]
                output = render_regulation_section([], observations, False)
                tiles = Tiles(output)
                self.assertEqual(tiles.states, {slug: state for slug in (
                    "regulation-oversight", "regulation-safeguards", "regulation-transparency", "regulation-classification")})
                self.assertEqual(tiles.counts, [])
                self.assertIn("Compliance not assessed", output)
                self.assertEqual("No governance layer found on this machine" in output, not governed)
                self.assertEqual('data-status="not-covered"' in output, not governed)
                self.assertEqual("Coverage not evidenced" in output, governed)
                self.assertEqual(output.count("Assume "), 0 if governed else 4)

    def test_mapped_findings_require_review_without_turning_unmapped_areas_into_passes(self):
        findings = [("f-approval", {"ruleId": "approval-prompts-disabled", "title": "Approval disabled", "severity": "low"}),
                    ("f-sandbox", {"ruleId": "sandbox-disabled", "title": "Sandbox disabled", "severity": "high"})]
        for governed, state, label in ((False, "not-covered", "Not covered · review required"),
                                       (True, "missing-evidence", ">Review required<")):
            with self.subTest(governed=governed):
                observations = [{"id": "o1", "enabled": "enabled", "details": {"governedBy": "palma-gateway"} if governed else {}}]
                output = render_regulation_section(findings, observations, False)
                tiles = Tiles(output)
                self.assertEqual(tiles.states, {
                    "regulation-oversight": "review-required", "regulation-safeguards": "review-required",
                    "regulation-transparency": state, "regulation-classification": state})
                self.assertEqual(tiles.counts, ["1", "1"])
                self.assertIn(label, output)
                self.assertIn('href="#f-approval"', output)
                self.assertIn('href="#f-sandbox"', output)

    def test_a_gateway_connector_that_cannot_apply_is_not_a_governance_layer(self):
        for details, enabled in (({"governedBy": "palma-gateway"}, "disabled"),
                                 ({"governedBy": "palma-gateway", "profileSelected": False}, "unknown"),
                                 ({"governedBy": "palma-gateway", "packageState": "cached"}, "unknown"),
                                 ({"governedBy": "palma-gateway", "context": "cached"}, "unknown")):
            with self.subTest(details=details, enabled=enabled):
                output = render_regulation_section([], [{"id": "o1", "kind": "mcp", "enabled": enabled, "details": details}], False)
                self.assertIn('data-status="not-covered"', output)
                self.assertEqual(set(Tiles(output).states.values()), {"not-covered"})

    def test_empty_and_declared_tiles_do_not_claim_a_machine_coverage_gap(self):
        for observations, declared in (([], False), ([], True), ([{"id": "o1"}], True)):
            with self.subTest(observations=observations, declared=declared):
                output = render_regulation_section([], observations, declared)
                tiles = Tiles(output)
                self.assertEqual(list(tiles.states.values()), ["not-assessed"] * 4)
                self.assertEqual(tiles.counts, [])
                self.assertNotIn('data-governance="observed"', output, "nothing was observed")
                self.assertIn('data-governance="unknown"', output)


if __name__ == "__main__":
    unittest.main()
