"""Independent conformance for the Palma findings catalog and rating policy."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan import governance, rules

FIXTURES = Path(__file__).parent / "fixtures/policy-baseline"
CATALOG_SHA256 = "5ee97c64b7833de3ae04a68a051592eba7d1415dcc08f0913313e86d4f6063b1"
HIGH_PRIORITY_OVERRIDES = {"mcp-local-unaudited", "mcp-network-direct", "skills-local-unreviewed", "hooks-declared"}
LOW_PERMISSION_OVERRIDES = {"permissions-bypassed", "tools-auto-approved", "approval-prompts-disabled"}


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def fixture_snapshot():
    """Project the unchanged original fixture into the independent local format.

    Public fixture endpoint origins are retained only to test the original pure
    condition parameter. Native collection deliberately withholds raw origins.
    """
    original = load("observations.json")
    family = {item["contextId"]: item["family"] for item in original["observations"] if item["kind"] == "client"}
    sources = [{"id": item["id"], "client": item["family"], "scope": item["scope"],
                "location": item["location"].replace("$HOME", "~"), "status": "collected"}
               for item in original["sources"]]
    locations = {item["id"]: item["location"] for item in sources}
    observations = []
    for item in original["observations"]:
        details = {key: value for key, value in item.items()
                   if key not in {"id", "sourceId", "contextId", "name", "kind", "enabled"}}
        details["context"] = "base"
        if item["kind"] == "setting":
            details["key"] = item["nativeKey"]
        elif item["kind"] == "agent":
            details["toolCount"] = len(details.pop("toolNames", []))
        elif item["kind"] == "mcp":
            capability = {"computer-use": "computer", "playwright": "browser"}.get(item["name"], "other")
            details["toolFamily"] = capability
            details["capability"] = capability if capability != "other" else None
        observations.append({"id": item["id"], "sourceId": item["sourceId"],
                             "client": family.get(item["contextId"], "unknown"),
                             "name": item["name"], "kind": item["kind"],
                             "location": locations[item["sourceId"]],
                             "enabled": item.get("enabled", "unknown"), "details": details})
    return {"schemaVersion": "2.0", "collector": {"name": "fixture", "version": "2.1.0"},
            "mode": "endpoint", "status": "complete", "scope": {"type": "copied-home"},
            "sources": sources, "observations": observations, "coverage": {"limitations": []}, "findings": []}


class PolicyBaselineTests(unittest.TestCase):
    def test_bundled_catalog_is_the_exact_original_29_rule_catalog(self):
        path = Path(governance.__file__).with_name("palma_catalog.json")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), CATALOG_SHA256)
        self.assertEqual(governance.catalog(), load("catalog.json"))
        specs = governance.catalog()["rules"]
        self.assertEqual(len(specs), 29)
        self.assertEqual(len({rule["id"] for rule in specs}), 29)
        self.assertEqual({rule["kind"] for rule in specs}, {"client", "mcp", "skill", "plugin", "agent", "setting"})

    def test_original_parameterized_fixture_matches_every_original_evidence_id(self):
        expected = load("expected.json")
        matches = load("matched-observation-ids.json")
        findings = governance.evaluate(fixture_snapshot(), {"gatewayOrigins": expected["gatewayOrigins"]})
        by_rule = {finding["ruleId"]: finding for finding in findings}
        # Documented divergence: a fixed secret written inline is reported once, under the
        # Critical credential rule, so the fixture's overlapping declaration leaves the
        # static-secret rule with no remaining match.
        reported_under = {"mcp-static-secret-auth": "mcp-inline-credential"}
        for rule_id, primary in reported_under.items():
            self.assertTrue(set(matches[rule_id]) <= set(by_rule[primary]["observationIds"]))
            self.assertNotIn(rule_id, by_rule)
        expected_ids = {item["id"] for item in expected["items"]} - set(reported_under)
        self.assertTrue(expected_ids.issubset(by_rule))
        for item in expected["items"]:
            if item["id"] in reported_under:
                continue
            with self.subTest(rule=item["id"]):
                finding = by_rule[item["id"]]
                self.assertEqual(sorted(finding["observationIds"]), matches[item["id"]])
                self.assertEqual(len(finding["observationIds"]), item["declarations"])
                self.assertEqual(finding["distinct"], item["distinct"])
                expected_severity = "low" if item["id"] in LOW_PERMISSION_OVERRIDES else "high" if item["id"] in HIGH_PRIORITY_OVERRIDES else item["severity"]
                self.assertEqual(finding["severity"], expected_severity)
                self.assertEqual(finding["baselineSeverity"], item["severity"])
                self.assertEqual(finding["priorityPolicyVersion"], "2026-09-14.2")
                self.assertIsInstance(finding["ratingReason"], str)
                self.assertTrue(finding["ratingReason"])

    def test_default_has_no_gateway_exemption_or_external_context_requirement(self):
        findings = {item["ruleId"]: item for item in governance.evaluate(fixture_snapshot())}
        self.assertEqual(len(findings["mcp-network-direct"]["observationIds"]), 2)
        self.assertEqual(findings["mcp-network-direct"]["severity"], "high")

    def test_permission_only_findings_are_low_and_keep_catalog_severity(self):
        findings = {item["ruleId"]: item for item in governance.evaluate(fixture_snapshot())}
        for rule_id in LOW_PERMISSION_OVERRIDES:
            with self.subTest(rule=rule_id):
                self.assertEqual(findings[rule_id]["severity"], "low")
                self.assertEqual(findings[rule_id]["baselineSeverity"], "critical")
                self.assertTrue(findings[rule_id]["observationIds"])

    def test_unrestricted_access_is_low_but_actual_sandbox_off_remains_high(self):
        snapshot = fixture_snapshot()
        source = snapshot["sources"][0]
        for value, priority in (("danger-full-access", "low"), ("off", "high"), (False, "high")):
            with self.subTest(value=value):
                snapshot["observations"] = [{"id": "sandbox", "sourceId": source["id"], "client": "codex",
                    "name": "sandbox_mode", "location": source["location"], "enabled": "unknown", "kind": "setting",
                    "details": {"key": "sandbox_mode", "nativeKey": "sandbox_mode", "category": "sandbox",
                                "value": value, "valueCollected": True, "context": "base"}}]
                findings = {item["ruleId"]: item for item in governance.evaluate(snapshot)}
                self.assertEqual(findings["sandbox-disabled"]["severity"], priority)
                self.assertEqual(findings["sandbox-disabled"]["baselineSeverity"], "high")

    def test_unrestricted_folder_grants_group_across_sources_at_low(self):
        snapshot = fixture_snapshot()
        cases = [("codex", "default_permissions", ":danger-full-access", "unrestricted-folder-access"),
                 ("claude-code", "permissions.additionalDirectories", {"broadFilesystemRoot": True}, "PALMA-FILES-001")]
        for client, key, value, rule_id in cases:
            with self.subTest(rule=rule_id):
                snapshot["sources"], snapshot["observations"] = [], []
                for index in range(2):
                    source = {"id": f"folder-source-{index}", "client": client, "scope": "user",
                              "location": f"~/configuration-{index}.json", "status": "collected"}
                    snapshot["sources"].append(source)
                    snapshot["observations"].append({"id": f"folder-{index}", "sourceId": source["id"],
                        "client": client, "name": key, "location": source["location"], "enabled": "unknown", "kind": "setting",
                        "details": {"key": key, "nativeKey": key, "category": "permissions", "value": value, "context": "base"}})
                findings = [item for item in rules.evaluate(snapshot) if item["ruleId"] == rule_id]
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["severity"], "low")
                self.assertEqual(findings[0]["observationIds"], ["folder-0", "folder-1"])

    def test_experimental_fixture_completes_coverage_of_all_29_original_rules(self):
        snapshot = fixture_snapshot()
        snapshot["observations"].append({"id": "experimental-fixture", "sourceId": snapshot["sources"][0]["id"],
            "client": "claude-code", "kind": "setting", "name": "experimental fixture",
            "location": "~/.claude/settings.json", "enabled": "unknown",
            "details": {"key": "experimental.fixture", "nativeKey": "experimental.fixture", "category": "experimental",
                        "value": True, "valueCollected": True, "effectiveState": "unknown", "context": "base"}})
        findings = {item["ruleId"]: item for item in governance.evaluate(snapshot)}
        # The static-secret rule's only fixture match also stores its secret inline, so it
        # is reported under the Critical credential rule instead of as a second finding.
        self.assertTrue(({item["id"] for item in governance.catalog()["rules"]} - {"mcp-static-secret-auth"}).issubset(findings))
        self.assertNotIn("mcp-static-secret-auth", findings)
        self.assertEqual(findings["experimental-enabled"]["severity"], "info")
        self.assertEqual(findings["experimental-enabled"]["observationIds"], ["experimental-fixture"])

    def test_restored_identity_content_and_agent_rules_have_their_own_evidence(self):
        findings = {item["ruleId"]: item for item in governance.evaluate(fixture_snapshot())}
        for rule_id in ("clients-api-key-auth", "clients-outside-enterprise-identity", "clients-config-only",
                        "plugins-sideloaded", "plugins-unknown-origin", "skills-unverifiable",
                        "skills-managed", "agents-broad-tooling"):
            with self.subTest(rule=rule_id):
                self.assertTrue(findings[rule_id]["observationIds"])
                self.assertTrue(findings[rule_id]["evidence"])

    def test_disabled_cached_and_stale_facts_are_not_silently_removed(self):
        snapshot = fixture_snapshot()
        local = next(item for item in snapshot["observations"] if item["name"] == "filesystem")
        local["enabled"] = "disabled"
        local["details"].update(context="cached", activation="cached", effectiveState="stale")
        findings = {item["ruleId"]: item for item in governance.evaluate(snapshot)}
        self.assertIn(local["id"], findings["mcp-local-unaudited"]["observationIds"])
        self.assertIn(local["id"], findings["mcp-declared-disabled"]["observationIds"])
        self.assertEqual(findings["mcp-local-unaudited"]["severity"], "high")
        evidence = json.dumps(findings["mcp-local-unaudited"]["evidence"])
        self.assertIn("disabled", evidence)
        self.assertIn("cached", evidence)
        self.assertIn("settings-stale", findings)
        self.assertIn("plugins-cached-only", findings)

    def test_threshold_boundaries_and_wrong_types_do_not_become_broad_tool_access(self):
        snapshot = fixture_snapshot()
        source = snapshot["sources"][0]
        for value in (9, 10, True, "10", None):
            with self.subTest(tool_count=value):
                snapshot["observations"] = [{"id": "agent", "sourceId": source["id"], "client": "claude-code",
                    "name": "agent", "location": source["location"], "enabled": "unknown", "kind": "agent",
                    "details": {"toolCount": value, "context": "base"}}]
                matched = any(item["ruleId"] == "agents-broad-tooling" for item in governance.evaluate(snapshot))
                self.assertEqual(matched, type(value) is int and value >= 10)

    def test_malformed_credential_counts_are_not_literal_credential_evidence(self):
        snapshot = fixture_snapshot()
        source = snapshot["sources"][0]
        for kind in ("mcp", "setting"):
            for value in (0, True, False, "1", None, {}, [], 1.0, 1):
                with self.subTest(kind=kind, count=value):
                    snapshot["observations"] = [{"id": "record", "sourceId": source["id"], "client": "claude-code",
                        "name": "record", "location": source["location"], "enabled": "unknown", "kind": kind,
                        "details": {"transport": "stdio", "literalCredentialCount": value, "context": "base",
                                    "key": "credential-count", "nativeKey": "credential-count", "category": "other", "value": None}}]
                    findings = governance.evaluate(snapshot)
                    matched = any(item["ruleId"] in {"mcp-inline-credential", "config-inline-credential"} for item in findings)
                    self.assertEqual(matched, type(value) is int and value > 0)

    def test_policy_evaluation_is_pure_offline_and_never_executes_discovered_data(self):
        snapshot = fixture_snapshot()
        snapshot["observations"][0]["details"]["command"] = "$(touch PRIVATE_EXECUTION_CANARY)"
        before = copy.deepcopy(snapshot)
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")), \
             patch("subprocess.run", side_effect=AssertionError("process forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("process forbidden")), \
             patch("builtins.eval", side_effect=AssertionError("eval forbidden")), \
             patch("builtins.exec", side_effect=AssertionError("exec forbidden")):
            first = governance.evaluate(snapshot)
            second = governance.evaluate(snapshot)
        self.assertEqual(first, second)
        self.assertEqual(snapshot, before)
        self.assertNotIn("PRIVATE_EXECUTION_CANARY", json.dumps(first))

    def test_main_evaluator_retains_the_complete_catalog_results(self):
        snapshot = fixture_snapshot()
        baseline = {finding["ruleId"]: finding for finding in governance.evaluate(snapshot)}
        combined = {finding["ruleId"]: finding for finding in rules.evaluate(snapshot)}
        self.assertTrue(set(baseline).issubset(combined))
        for rule_id in baseline:
            self.assertEqual(combined[rule_id]["severity"], baseline[rule_id]["severity"])
            self.assertEqual(combined[rule_id]["observationIds"], baseline[rule_id]["observationIds"])

    def test_known_oversized_cached_components_are_high_and_keep_measured_size(self):
        snapshot = fixture_snapshot()
        snapshot["observations"] = []
        for kind in ("skill", "plugin", "agent", "hook"):
            with self.subTest(component=kind):
                source = {"id": "large-source", "client": "codex", "scope": "user",
                    "location": "~/.codex/plugins/cache/example/component", "status": "skipped",
                    "reason": "size_limit", "artifactRole": "plugin", "componentKind": kind,
                    "packageState": "cached", "sizeBytes": 4_194_305, "limitBytes": 4_194_304}
                snapshot["sources"] = [source, {**source, "id": "large-source-second-adapter"}]
                matches = [item for item in governance.evaluate(snapshot) if item["ruleId"] == "artifacts-oversized"]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0]["severity"], "high")
                self.assertEqual(matches[0]["declarations"], 1)
                self.assertEqual(len(matches[0]["evidence"]), 1)
                self.assertEqual(matches[0]["evidence"][0]["sourceId"], source["id"])
                evidence = json.dumps(matches[0]["evidence"])
                self.assertIn("4194305", evidence)
                self.assertIn("4194304", evidence)
        for source in snapshot["sources"]:
            source.update(componentKind="configuration", artifactRole="configuration")
        self.assertFalse(any(item["ruleId"] == "artifacts-oversized" for item in governance.evaluate(snapshot)))

    def test_retained_instruction_size_uses_strict_review_threshold_and_actual_bytes(self):
        self.assertEqual(governance.INSTRUCTION_REVIEW_BYTES, 65_536)
        snapshot = fixture_snapshot()
        source = {"id": "instruction-source", "client": "codex", "scope": "user",
                  "location": "~/.codex/skills/example/SKILL.md", "status": "collected"}
        snapshot["sources"] = [source]
        for kind in ("skill", "agent"):
            for size in (65_535, 65_536, 65_537, True, "65537", 65_537.0, None):
                with self.subTest(kind=kind, size=size):
                    snapshot["observations"] = [{"id": "instruction", "sourceId": source["id"],
                        "client": "codex", "kind": kind, "name": "Example instructions",
                        "location": source["location"], "enabled": "unknown",
                        "details": {"manifestSizeBytes": size, "context": "base"}}]
                    matches = [item for item in governance.evaluate(snapshot) if item["ruleId"] == "artifacts-oversized"]
                    should_match = type(size) is int and size > 65_536
                    self.assertEqual(len(matches), int(should_match))
                    if should_match:
                        self.assertEqual(matches[0]["severity"], "high")
                        self.assertEqual(matches[0]["declarations"], 1)
                        facts = matches[0]["evidence"][0]["value"]
                        self.assertEqual(facts["sizeBytes"], size)
                        self.assertEqual(facts["reviewThresholdBytes"], 65_536)
                        self.assertEqual(facts["componentKind"], kind)
                        self.assertNotIn("limitBytes", facts)

    def test_plugin_metadata_and_arbitrary_file_bytes_do_not_imply_instruction_overhead(self):
        snapshot = fixture_snapshot()
        source = {"id": "binary-source", "client": "codex", "scope": "user",
                  "location": "~/.codex/plugins/example/assets/tool.bin", "status": "collected",
                  "componentKind": "plugin", "artifactRole": "plugin", "sizeBytes": 5_000_000}
        snapshot["sources"] = [source]
        for observations in ([], [{"id": "plugin", "sourceId": source["id"], "client": "codex",
                "kind": "plugin", "name": "Example plugin", "location": source["location"],
                "enabled": "unknown", "details": {"manifestSizeBytes": 5_000_000, "context": "base"}}]):
            with self.subTest(has_plugin_metadata=bool(observations)):
                snapshot["observations"] = observations
                self.assertFalse(any(item["ruleId"] == "artifacts-oversized" for item in governance.evaluate(snapshot)))

    def test_duplicate_skill_content_groups_all_matching_observations_at_low(self):
        snapshot = fixture_snapshot()
        snapshot["observations"], snapshot["sources"] = [], []
        for index, location in enumerate(("~/.codex/skills/example/SKILL.md", "~/project/.agents/skills/example/SKILL.md",
                                           "~/project/.agents/skills/example/SKILL.md")):
            source = {"id": f"skill-source-{index}", "client": "codex", "scope": "user",
                      "location": location, "status": "collected"}
            snapshot["sources"].append(source)
            snapshot["observations"].append({"id": f"skill-{index}", "sourceId": source["id"], "client": "codex",
                "kind": "skill", "name": "Example skill", "location": location, "enabled": "unknown",
                "details": {"digest": "fixture-content-digest", "context": "base"}})
        matches = [item for item in governance.evaluate(snapshot) if item["ruleId"] == "skills-duplicate-content"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "low")
        self.assertEqual(matches[0]["observationIds"], ["skill-0", "skill-1", "skill-2"])
        self.assertEqual(matches[0]["declarations"], 3)
        self.assertEqual({item["location"] for item in matches[0]["evidence"]},
                         {item["location"] for item in snapshot["observations"]})

    def test_duplicate_skill_content_requires_digest_client_name_and_distinct_locations(self):
        snapshot = fixture_snapshot()
        source = snapshot["sources"][0]
        first = {"id": "first", "sourceId": source["id"], "client": "codex", "kind": "skill",
                 "name": "Example skill", "location": "~/skills/first/SKILL.md", "enabled": "unknown",
                 "details": {"digest": "fixture-content-digest", "context": "base"}}
        second = {**copy.deepcopy(first), "id": "second", "location": "~/skills/second/SKILL.md"}
        cases = {
            "different client": {"client": "claude-code"},
            "different name": {"name": "Another skill"},
            "different digest": {"details": {"digest": "another-content-digest"}},
            "same location": {"location": first["location"]},
            "missing digest": {"details": {}},
            "empty digest": {"details": {"digest": ""}},
            "invalid digest": {"details": {"digest": True}},
        }
        for label, changes in cases.items():
            with self.subTest(condition=label):
                snapshot["observations"] = [first, {**second, **changes}]
                self.assertFalse(any(item["ruleId"] == "skills-duplicate-content" for item in governance.evaluate(snapshot)))

    def test_specific_unsupported_mcp_shape_is_low_but_general_unknown_transport_is_medium(self):
        snapshot = fixture_snapshot()
        observation = next(item for item in snapshot["observations"] if item["name"] == "mystery")
        snapshot["observations"] = [observation]
        source = next(item for item in snapshot["sources"] if item["id"] == observation["sourceId"])
        snapshot["sources"] = [source]
        source.update(status="skipped", reason="unsupported_shape", componentKind="mcp",
                      artifactRole="configuration", classification="mcp-configuration", issueKind="unsupported-mcp-shape")
        findings = {item["ruleId"]: item for item in governance.evaluate(snapshot)}
        self.assertEqual(findings["mcp-unsupported-shape"]["severity"], "low")
        if "mcp-unknown-transport" in findings:
            self.assertEqual(findings["mcp-unknown-transport"]["severity"], "low")
        source.update(issueKind="uninterpreted-mcp-transport", reason="unsupported_transport")
        findings = {item["ruleId"]: item for item in governance.evaluate(snapshot)}
        self.assertNotIn("mcp-unsupported-shape", findings)
        self.assertEqual(findings["mcp-unknown-transport"]["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
