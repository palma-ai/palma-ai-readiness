"""Readable inventory groups must retain distinct configuration evidence."""
import copy
import unittest

from test_report import Document, snapshot
from palma_scan.report import render_report


def observation(identity, kind, name, client="codex", **details):
    return {"id": identity, "kind": kind, "name": name, "client": client,
            "sourceId": "source-" + identity, "location": "~/.codex/" + identity + ".json",
            "enabled": "unknown", "details": details}


def inventory(data, share=False):
    return render_report(data, {}, share=share).split('id="inventory"', 1)[1].split('id="coverage"', 1)[0]


class InventoryGroupsTests(unittest.TestCase):
    def test_same_name_across_clients_has_one_row_and_preserves_variants(self):
        data = snapshot()
        data["findings"] = []
        data["observations"] = [
            observation("one", "mcp", "svelte", auth="environment_reference", copyCount=3),
            observation("two", "mcp", "svelte", "cursor", auth="static_header"),
            observation("three", "skill", "helper", digest="a"),
            observation("four", "skill", "helper", "cursor", digest="b"),
        ]
        original = copy.deepcopy(data)
        output = inventory(data)
        document = Document(output)
        rows = [attrs for tag, attrs in document.tags if tag == "li" and attrs.get("class") == "inventory-row"]
        self.assertEqual(len(rows), 2)
        self.assertIn("4 declarations", output)
        self.assertIn("2 declarations", output)
        self.assertIn("Secret from environment", output)
        self.assertIn("Fixed secret", output)
        self.assertIn('data-brand="codex"', output)
        self.assertIn('data-brand="cursor"', output)
        for item in data["observations"]:
            self.assertIn(item["location"], output)
        self.assertEqual(data, original)

    def test_grouping_does_not_claim_every_variant_is_governed(self):
        data = snapshot()
        data["observations"] = [observation("one", "mcp", "tools", governedBy="palma-gateway"),
                                observation("two", "mcp", "tools", execution="local")]
        output = inventory(data)
        self.assertEqual(output.count('class="inventory-row"'), 1)
        self.assertEqual(output.count("Through Palma gateway"), 1)
        self.assertIn('class="inventory-declarations"', output)
        self.assertIn("Runs locally", output)

    def test_different_providers_keep_their_own_identity_under_a_neutral_header(self):
        data = snapshot()
        data["observations"] = [observation("one", "mcp", "tools", provider="github"),
                                observation("two", "mcp", "tools", "cursor", provider="notion")]
        output = inventory(data)
        self.assertIn("Notion", output)
        self.assertIn("GitHub", output)
        row_header = output.split('class="inventory-item-name"', 1)[1].split('class="inventory-declarations"', 1)[0]
        self.assertNotIn('data-brand="github"', row_header)
        self.assertNotIn('data-brand="notion"', row_header)

    def test_redaction_does_not_merge_unrelated_withheld_names(self):
        data = snapshot()
        data["findings"] = []
        data["observations"] = [observation("a", "mcp", "private-a.example"),
                                observation("b", "mcp", "private-b.example"),
                                observation("c", "mcp", "private-a.example", "cursor")]
        output = inventory(data, share=True)
        self.assertEqual(output.count('class="inventory-row"'), 2)
        self.assertNotIn("private-a", output)
        self.assertNotIn("private-b", output)
        self.assertIn("2 declarations", output)
        self.assertIn("1 declaration", output)

    def test_extensions_collapse_but_permission_sets_stay_visible(self):
        data = snapshot()
        data["observations"] = [observation(str(i), "plugin", "AI-related browser extension", "browser-extensions",
                                             aiRelatedNameHint=True, permissions=permissions)
                                for i, permissions in enumerate((["tabs"], ["storage"], ["tabs"]))]
        output = inventory(data)
        self.assertEqual(output.count('class="inventory-row"'), 1)
        self.assertIn("3 extension records", output)
        self.assertIn("Permission: tabs", output)
        self.assertIn("Permission: storage", output)

    def test_share_drops_arbitrary_filename_hash_suffix(self):
        data = snapshot()
        data["observations"] = [observation("a", "agent", "Reviewer")]
        data["observations"][0]["location"] = "~/.claude/agents/reviewer#private-client.example.md"
        output = render_report(data, {}, share=True)
        self.assertNotIn("private-client.example", output)
        self.assertIn("(name withheld).md", output)


if __name__ == "__main__":
    unittest.main()
