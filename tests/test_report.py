"""Security and truthfulness invariants for the standalone local report."""

import base64
import copy
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from palma_scan.report import render_report


class Document(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.text = []
        self.scripts = []
        self.styles = []
        self.current = None
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag in ("script", "style"):
            self.current = tag

    def handle_endtag(self, tag):
        if tag == self.current:
            self.current = None

    def handle_data(self, data):
        if self.current == "script":
            self.scripts.append(data)
        elif self.current == "style":
            self.styles.append(data)
        else:
            self.text.append(data)


def snapshot():
    return {
        "schemaVersion": "2.0",
        "collector": {"name": "palma-ai-scan", "version": "2.0.0", "rulesVersion": "2026-09-10"},
        "mode": "endpoint", "status": "partial",
        "startedAt": "2026-09-10T10:00:00Z", "completedAt": "2026-09-10T10:00:02Z",
        "scope": {"type": "current-user", "workspaceCount": 1},
        "sources": [
            {"id": "s-collected", "client": "Codex", "scope": "user", "location": "~/.codex/config.toml", "status": "collected"},
            {"id": "s-missing", "client": "Claude Code", "scope": "user", "location": "~/.claude/settings.json", "status": "missing", "reason": "Path not present"},
            {"id": "s-error", "client": "Cursor", "scope": "user", "location": "~/.cursor/mcp.json", "status": "error", "reason": "Permission denied"},
            {"id": "s-skipped", "client": "VS Code", "scope": "workspace", "location": "project/.vscode/mcp.json", "status": "skipped", "reason": "Not in selected scope"},
        ],
        "observations": [
            {"id": "o-client", "kind": "client", "client": "Codex", "name": "Codex", "location": "~/.codex", "sourceId": "s-collected", "enabled": "unknown", "details": {}},
            {"id": "o-setting", "kind": "setting", "client": "Codex", "name": "Sandbox", "location": "~/.codex/config.toml", "sourceId": "s-collected", "enabled": "enabled", "details": {"sandboxMode": "danger-full-access"}},
            {"id": "o-disabled", "kind": "mcp", "client": "Codex", "name": "Disabled connector", "location": "~/.codex/config.toml", "sourceId": "s-collected", "enabled": "disabled", "details": {"transport": "stdio"}},
            {"id": "o-skill", "kind": "skill", "client": "Codex", "name": "Example local skill", "location": "~/.agents/skills/example/SKILL.md", "sourceId": "s-collected", "enabled": "unknown", "details": {"auditState": "unknown"}},
        ],
        "findings": [
            {"id": "f-info", "ruleId": "SKILL-001", "title": "Confirm the trust boundary of local skills", "severity": "info", "category": "content-trust", "confidence": "high", "evidenceType": "inventory", "summary": "A local skill was observed; its audit state is unknown.", "impact": "This inventory does not establish that the skill is unsafe.", "recommendation": "Review the skill before giving it access to sensitive data.", "observationIds": ["o-skill"], "evidence": [{"sourceId": "s-collected", "location": "~/.agents/skills/example/SKILL.md", "key": "auditState", "value": "unknown"}], "references": []},
            {"id": "f-high", "ruleId": "PERM-001", "title": "Filesystem sandbox is disabled", "severity": "high", "category": "agent-permissions", "confidence": "high", "evidenceType": "configuration", "summary": "The configuration permits broad filesystem access.", "impact": "Untrusted instructions may affect files beyond the intended workspace.", "recommendation": "Use a bounded workspace sandbox and review escalation prompts.", "observationIds": ["o-setting"], "evidence": [{"sourceId": "s-collected", "location": "~/.codex/config.toml", "key": "sandbox_mode", "value": "danger-full-access"}], "references": ["https://developers.openai.com/codex/security/"]},
        ],
        "coverage": {"limitations": ["Runtime activity was not observed.", "Only the selected user and workspace paths were considered."]},
    }


class ReportTests(unittest.TestCase):
    def test_regulation_is_collapsed_after_inventory_with_four_native_review_tiles(self):
        output = render_report(snapshot(), {})
        self.assertLess(output.index('id="overview"'), output.index('id="eu-ai-regulation"'))
        self.assertLess(output.index('id="inventory-content"'), output.index('id="eu-ai-regulation"'))
        self.assertLess(output.index('id="eu-ai-regulation"'), output.index('id="coverage"'))
        document = Document(output)
        wrapper = next(attrs for tag, attrs in document.tags if tag == "details" and attrs.get("id") == "eu-ai-regulation")
        self.assertNotIn("open", wrapper)
        tiles = [attrs for tag, attrs in document.tags if tag == "details" and attrs.get("class") == "regulation-tile"]
        self.assertEqual([item["id"] for item in tiles], ["regulation-oversight", "regulation-safeguards", "regulation-transparency", "regulation-classification"])
        self.assertTrue(all("open" not in item for item in tiles), "Details must not crowd the opening summary")

    def test_regulation_tiles_count_review_inputs_without_scoring_unknowns(self):
        data = snapshot()
        data["findings"][0]["ruleId"] = "approval-prompts-disabled"
        data["findings"][1]["ruleId"] = "sandbox-disabled"
        document = Document(render_report(data, {"compliance": 100, "findings": 999}))
        counts = [attrs.get("data-count") for _, attrs in document.tags if attrs.get("class") == "regulation-count"]
        self.assertEqual(counts, ["1", "1"])
        self.assertNotIn("999", " ".join(document.text))
        data["findings"] = []
        document = Document(render_report(data, {}))
        self.assertFalse(any(attrs.get("class") == "regulation-count" for _, attrs in document.tags), "No findings must not look like a passed legal control")

    def test_regulation_indicator_cannot_infer_legal_status_from_priorities(self):
        for severity in ("critical", "high", "low", "info"):
            data = snapshot()
            data["findings"][1]["severity"] = severity
            output = render_report(data, {})
            document = Document(output)
            indicator = next((attrs for _, attrs in document.tags if attrs.get("id") == "regulation-indicator"), {})
            self.assertEqual(indicator.get("data-status"), "review-needed")
            self.assertIn("Compliance not assessed", " ".join(document.text))
        data["findings"] = []
        self.assertIn('data-status="review-needed"', render_report(data, {}))

    def test_empty_and_declared_regulation_status_remains_unassessed(self):
        for mode, observations, expected in (
            ("endpoint", [], "not-assessed"),
            ("declared", snapshot()["observations"], "declared-only"),
            ("declared", [], "declared-only"),
        ):
            data = snapshot()
            data.update(mode=mode, observations=observations, findings=[])
            output = render_report(data, {})
            document = Document(output)
            indicator = next((attrs for _, attrs in document.tags if attrs.get("id") == "regulation-indicator"), {})
            self.assertEqual(indicator.get("data-status"), expected)
            self.assertIn("Compliance not assessed", " ".join(document.text))

    def test_regulation_links_only_existing_allowlisted_findings(self):
        data = snapshot()
        data["findings"][1]["ruleId"] = "sandbox-disabled"
        # A title or category must never turn an unrelated finding into a legal mapping.
        data["findings"][0].update(title="EU AI Act human oversight", category="security")
        document = Document(render_report(data, {}))
        links = [attrs for tag, attrs in document.tags if tag == "a" and attrs.get("class") == "regulation-finding-link"]
        self.assertEqual(len(links), 1)
        finding = next(attrs for tag, attrs in document.tags if tag == "article" and attrs.get("data-severity") == "high")
        self.assertEqual(links[0]["href"], "#" + finding["id"])
        self.assertIn("1 existing finding", " ".join(document.text))

    def test_regulation_keeps_inactive_evidence_and_low_priority_oversight(self):
        data = snapshot()
        data["observations"] = [data["observations"][2]]
        data["findings"] = [data["findings"][1]]
        data["findings"][0].update(ruleId="approval-prompts-disabled", severity="low", observationIds=["o-disabled"])
        output = render_report(data, {})
        self.assertIn('data-status="review-needed"', output)
        document = Document(output)
        self.assertEqual(sum(attrs.get("class") == "regulation-finding-link" for _, attrs in document.tags), 1)
        self.assertIn("Disabled in configuration", " ".join(document.text))

    def test_regulation_article_links_open_exactly_the_articles_they_name(self):
        output = render_report(snapshot(), {})
        links = re.findall(r'<a class="regulation-source" href="([^"]+)"[^>]*>([^<]+)<', output)
        expected = {"Read Article 14": "article-14", "Read Article 26": "article-26", "Read Article 15": "article-15",
                    "Read Article 50": "article-50", "Prohibited practices": "article-5", "High-risk criteria": "article-6"}
        for label, slug in expected.items():
            with self.subTest(label):
                self.assertIn((f"https://ai-act-service-desk.ec.europa.eu/en/ai-act/{slug}", label), links)
        for href, label in links:
            number = re.fullmatch(r"Read Article (\d+)", label)
            if number:
                self.assertTrue(href.endswith("/article-" + number.group(1)), (label, href))
        oversight = output.split('id="regulation-oversight"', 1)[1].split("</details>", 1)[0]
        self.assertIn("ai-act/article-14", oversight)
        self.assertIn("ai-act/article-26", oversight)

    def test_regulation_link_escapes_untrusted_finding_title(self):
        data = snapshot()
        data["findings"][1].update(ruleId="sandbox-disabled", title='<img src="https://invalid.test" onerror="alert(1)">')
        document = Document(render_report(data, {}))
        self.assertEqual(sum(attrs.get("class") == "regulation-finding-link" for _, attrs in document.tags), 1)
        self.assertEqual(sum(tag == "img" for tag, _ in document.tags), 2)
        self.assertFalse(any(key.startswith("on") for _, attrs in document.tags for key in attrs))

    def test_deterministic_and_does_not_mutate_inputs(self):
        data = snapshot()
        before = copy.deepcopy(data)
        summary = {"arbitrary": [1, 2, 3]}
        self.assertEqual(render_report(data, summary), render_report(data, summary))
        self.assertEqual(data, before)
        self.assertEqual(summary, {"arbitrary": [1, 2, 3]})

    def test_visual_counts_come_from_snapshot_not_untrusted_summary(self):
        output = render_report(snapshot(), {"findings": 9000, "critical": 9000})
        self.assertIn("1 item to review first.", output)
        self.assertIn('Showing 2 of 2 findings', output)
        self.assertNotIn("9000", output)
        self.assertIn('<strong>1</strong><p>sources inspected', output)
        self.assertIn("2 sources could not be fully read", output)

    def test_findings_sorted_by_priority_and_internal_anchors_resolve(self):
        document = Document(render_report(snapshot(), {}))
        findings = [attrs for tag, attrs in document.tags if tag == "article"]
        self.assertEqual([item["data-severity"] for item in findings], ["high", "info"])
        ids = [attrs["id"] for _, attrs in document.tags if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for tag, attrs in document.tags:
            if tag == "a" and attrs.get("href", "").startswith("#"):
                self.assertIn(attrs["href"][1:], ids)

    def test_all_untrusted_content_is_escaped_and_never_becomes_executable_markup(self):
        payload = '</script><img src="https://attacker.invalid/collect" onerror="alert(1)"><iframe srcdoc="bad">'
        data = snapshot()
        data["collector"]["version"] = payload
        data["scope"]["type"] = payload
        data["sources"][0].update(client=payload, location=payload, reason=payload)
        data["observations"][1].update(name=payload, client=payload, location=payload, details={payload: payload})
        data["findings"][1].update(title=payload, summary=payload, impact=payload, recommendation=payload, category=payload, ruleId=payload)
        data["findings"][1]["evidence"][0].update(location=payload, key=payload, value={"nested": payload})
        data["coverage"]["limitations"] = [payload]
        output = render_report(data, {})
        document = Document(output)
        self.assertIn('&lt;/script&gt;&lt;img', output)
        self.assertEqual(sum(tag == "script" for tag, _ in document.tags), 1)
        self.assertEqual(sum(tag == "img" for tag, _ in document.tags), 2)
        self.assertFalse(any(tag in ("iframe", "object", "embed", "form") for tag, _ in document.tags))
        self.assertFalse(any(key.startswith("on") for _, attrs in document.tags for key in attrs))

    def test_csp_hashes_match_only_inline_code_and_styles(self):
        document = Document(render_report(snapshot(), {}))
        policy = next(attrs["content"] for tag, attrs in document.tags if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy")
        for code in document.scripts + document.styles:
            digest = base64.b64encode(hashlib.sha256(code.encode()).digest()).decode()
            self.assertIn("'sha256-" + digest + "'", policy)
        self.assertIn("connect-src 'none'", policy)
        self.assertIn("form-action 'none'", policy)
        self.assertIn("default-src 'none'", policy)
        self.assertNotIn("unsafe-inline", policy)
        self.assertNotIn("unsafe-eval", policy)

    def test_no_external_loading_dependencies_or_dynamic_network_apis(self):
        document = Document(render_report(snapshot(), {}))
        for tag, attrs in document.tags:
            if "src" in attrs:
                self.assertTrue(tag == "img" and attrs["src"].startswith("data:image/svg+xml;base64,"))
                self.assertEqual(attrs.get("alt"), "Palma AI")
                logo = base64.b64decode(attrs["src"].split(",", 1)[1], validate=True)
                self.assertEqual(hashlib.sha256(logo).hexdigest(),
                                 "5663024457f028a6ef479de62e5a2a192154f7d30c43a95f9866d8a0c059ab61")
            self.assertNotIn("style", attrs)
            if tag == "link":
                self.fail("Report must not load link resources")
        javascript = "".join(document.scripts)
        for api in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "innerHTML", "document.write", "eval("):
            self.assertNotIn(api, javascript)
        self.assertNotIn("@import", "".join(document.styles))
        # The only CSS resource is the fixed, embedded Onest font. No URL from
        # a snapshot, external stylesheet, local path, or network is permitted.
        css = "".join(document.styles)
        urls = re.findall(r"url\(([^)]+)\)", css)
        self.assertEqual(len(urls), 1)
        self.assertTrue(urls[0].startswith("data:font/ttf;base64,"))
        font = base64.b64decode(urls[0].split(",", 1)[1], validate=True)
        self.assertEqual(hashlib.sha256(font).hexdigest(),
                         "966c5c29b4755da84b6854d5c21dd4eaa2420225d0e9874de602de176d4a9f31")
        policy = next(attrs["content"] for tag, attrs in document.tags
                      if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy")
        self.assertIn("font-src data:", policy)
        self.assertIn("connect-src 'none'", policy)

    def test_priority_bars_match_finding_counts_and_handle_empty_evidence(self):
        data = snapshot()
        severities = ("critical", "high", "medium", "low", "info")
        for counts, widths in (({}, (0, 0, 0, 0, 0)),
                               ({"critical": 3, "high": 2, "medium": 1, "low": 4, "info": 1}, (180, 120, 60, 240, 60)),
                               ({"info": 1}, (0, 0, 0, 0, 240))):
            with self.subTest(counts=counts):
                data["findings"] = [dict(snapshot()["findings"][0], id=f"{severity}-{i}", severity=severity)
                                    for severity, count in counts.items() for i in range(count)]
                output = render_report(data, {"findings": 9000})
                chart = output.split('<aside class="priority-chart"', 1)[1].split('</aside>', 1)[0]
                document = Document(chart)
                bars = [attrs for tag, attrs in document.tags if tag == "rect" and attrs.get("class") in {f"bar-{severity}" for severity in severities}]
                self.assertEqual([bar["class"] for bar in bars], [f"bar-{severity}" for severity in severities])
                self.assertEqual([float(bar["width"]) for bar in bars], list(widths))
                labels = re.findall(r'<span class="chart-number">(\d+)</span>', chart)
                self.assertEqual(list(map(int, labels)), [counts.get(severity, 0) for severity in severities])
                links = [attrs for tag, attrs in document.tags if tag == "a" and attrs.get("class") == "chart-row"]
                self.assertEqual([link["data-priority"] for link in links], list(severities))
                for link, severity in zip(links, severities):
                    self.assertEqual(link["href"], "#findings")
                    self.assertEqual(link["aria-label"], f"Show {counts.get(severity, 0)} {severity.title()} findings")
                self.assertIn(f'{sum(counts.values())} findings', " ".join(document.text))
                self.assertNotIn("9000", " ".join(document.text))

    def test_priority_preview_escapes_titles_and_keeps_recommendations_in_finding_details(self):
        data = snapshot()
        data["findings"][1]["title"] = 'Review <script>untrusted</script> & confirm access.'
        data["findings"][1]["recommendation"] = 'Narrow <script>untrusted</script> & confirm access.'
        output = render_report(data, {})
        overview = output.split('id="overview"', 1)[1].split('id="client-map"', 1)[0]
        self.assertIn('<strong>Review &lt;script&gt;untrusted&lt;/script&gt; &amp; confirm access.</strong>', overview)
        self.assertNotIn('<script>untrusted</script>', overview)
        self.assertNotIn('Narrow', overview)
        finding = output.split('<article class="finding"', 1)[1].split('</article>', 1)[0]
        self.assertIn('<h4>Next step</h4><p>Narrow &lt;script&gt;untrusted&lt;/script&gt; &amp; confirm access.', finding)
        details = next(attrs for tag, attrs in Document(finding).tags if tag == "details" and attrs.get("class") == "finding-details")
        self.assertNotIn("open", details)

    def test_booking_link_default_and_only_supported_https(self):
        baseline = render_report(snapshot(), {})
        self.assertIn('class="booking-link" href="https://calendar.app.google/qVE3L8fGgmQWv3Hx7"', baseline)
        for unsafe in ("javascript:alert(1)", "data:text/html,bad", "http://palma.ai", "//palma.ai", "https://user:secret@palma.ai", "https://palma.ai\n/path", "https://palma.ai\\@evil.invalid", "https://palma.ai:99999", "https://palma.ai:bad", "https://calendar.example.com/palma"):
            with self.subTest(url=unsafe):
                self.assertNotIn('class="booking-link"', render_report(snapshot(), {}, booking_url=unsafe))
        safe = render_report(snapshot(), {}, booking_url="https://palma.ai/team?view=team&source=report")
        self.assertIn('href="https://palma.ai/team?view=team&amp;source=report"', safe)
        self.assertIn('rel="noreferrer noopener" target="_blank">Talk to Palma', safe)

    def test_unsafe_reference_links_are_not_rendered(self):
        data = snapshot()
        data["findings"][1]["references"] = ["javascript:alert(1)", "https://user:secret@example.com", "https://example.com/docs?a=1&b=2",
                                             "https://modelcontextprotocol.io/specification/latest/basic/security_best_practices"]
        document = Document(render_report(data, {}))
        external = [attrs["href"] for tag, attrs in document.tags if tag == "a" and attrs.get("class") not in {"artwork-reference", "regulation-source", "booking-link"} and not attrs["href"].startswith("#")]
        # Only documentation the bundled rules cite is linked.
        self.assertEqual(external, ["https://modelcontextprotocol.io/specification/latest/basic/security_best_practices"])
        for tag, attrs in document.tags:
            if tag == "a" and attrs.get("class") == "regulation-source":
                self.assertTrue(attrs["href"].startswith(("https://ai-act-service-desk.ec.europa.eu/en/", "https://digital-strategy.ec.europa.eu/en/")))
                self.assertNotIn("?", attrs["href"])
                self.assertEqual(attrs["rel"], "noreferrer noopener")

    def test_disabled_inventory_is_kept_without_claiming_execution(self):
        output = render_report(snapshot(), {})
        self.assertIn("Disabled connector", output)
        self.assertIn("Disabled in configuration", output)
        self.assertIn("Enabled in configuration", output)
        inventory = output.split('id="inventory-content"', 1)[1].split('id="eu-ai-regulation"', 1)[0]
        self.assertNotIn("State unknown", output)
        self.assertNotIn("0 enabled", inventory)
        self.assertNotIn("0 disabled", inventory)
        self.assertNotIn("unknown", inventory)
        self.assertNotIn("Observed state", inventory)
        self.assertNotIn("Disabled connector</h3>", output)

    def test_named_inventory_and_client_details_are_collapsed_and_keep_locations(self):
        data = snapshot()
        data["observations"] = [
            {"id": "skill-1", "kind": "skill", "client": "codex", "name": "skill-creator", "enabled": "unknown", "location": "~/.codex/skills/skill-creator/SKILL.md", "details": {"origin": "user", "activation": "present", "auditState": "unknown"}},
            {"id": "skill-2", "kind": "skill", "client": "claude-code", "name": "imagegen", "enabled": "unknown", "location": "~/projects/demo/.claude/skills/imagegen/SKILL.md", "details": {"origin": "project", "activation": "present"}},
            {"id": "skill-3", "kind": "skill", "client": "claude-code", "name": "helper", "enabled": "unknown", "location": "~/projects/demo/.claude/skills/helper/SKILL.md", "details": {"origin": "project"}},
        ]
        data["findings"][0]["observationIds"] = ["skill-2"]
        output = render_report(data, {})
        inventory = output.split('id="inventory-content"', 1)[1].split('id="eu-ai-regulation"', 1)[0]
        document = Document(output)
        groups = [attrs for tag, attrs in document.tags if tag == "details" and attrs.get("class") == "inventory-group"]
        self.assertEqual(len(groups), 3)  # Distinct skills, then two client details groups.
        self.assertTrue(all("open" not in group for group in groups), "inventory groups start collapsed")
        self.assertLess(inventory.index("<strong>Claude Code</strong>"), inventory.index("<strong>Codex</strong>"))
        self.assertIn('<span>2 skills</span>', inventory)
        self.assertIn('data-total="3">3</span>', inventory)
        self.assertLess(inventory.index('<strong>helper</strong>'), inventory.index('<strong>imagegen</strong>'))
        self.assertIn('id="inventory-search" type="search"', inventory)
        self.assertIn('Search inventory by name, client, or location', inventory)
        self.assertIn('~/projects/demo/.claude/skills/imagegen/SKILL.md', inventory)
        finding = next(attrs["id"] for tag, attrs in document.tags if tag == "article" and attrs.get("data-severity") == "info")
        self.assertIn(f'href="#{finding}">1 finding</a>', inventory)
        self.assertNotIn('unknown', inventory)
        self.assertNotIn('>Present<', inventory)
        self.assertNotIn('<pre', inventory)
        self.assertEqual(inventory.count('class="inventory-row"'), 3)

    def test_disabled_status_is_preserved_even_for_installed_artifacts(self):
        data = snapshot()
        data["observations"][2]["details"]["activation"] = "installed"
        inventory = render_report(data, {}).split('id="inventory-content"', 1)[1].split('id="eu-ai-regulation"', 1)[0]
        self.assertIn('class="state state-disabled">Disabled in configuration', inventory)

    def test_finding_policy_context_and_counts_are_optional_and_escaped(self):
        data = snapshot()
        data["findings"][1].update(declarations=12, distinct=5, ratingReason='Potential impact <script>bad()</script>')
        output = render_report(data, {})
        self.assertIn('<span>12 declarations</span><span>5 distinct</span>', output)
        self.assertIn('<h4>Priority rationale</h4><p>Potential impact &lt;script&gt;bad()&lt;/script&gt;', output)

    def test_read_problems_are_grouped_by_cause_and_absent_paths_are_not_listed(self):
        output = render_report(snapshot(), {})
        coverage = output.split('id="coverage"', 1)[1]
        causes = re.findall(r'<details class="coverage-cause"><summary><strong>(\d+)</strong><span>([^<]+)</span>', coverage)
        self.assertEqual(sorted(causes), [("1", "Outside the scan scope"), ("1", "Permission denied")])
        self.assertIn("~/.cursor/mcp.json", coverage)
        self.assertIn("project/.vscode/mcp.json", coverage)
        self.assertNotIn("~/.claude/settings.json", coverage, "an absent candidate path is not a coverage problem")
        self.assertNotIn("This scan has collection gaps", output)
        self.assertNotIn("Some sources could not be assessed", output)
        self.assertNotIn("Keep this in perspective", output)
        self.assertIn("Permission denied", output)

    def test_coverage_shows_each_source_failure_once_without_legacy_checklist(self):
        data = snapshot()
        data["sources"][2].update(reasons=["Permission denied", "Directory budget reached", "Permission denied", "<script>bad()</script>"], reason="Directory budget reached")
        output = render_report(data, {})
        coverage = output.split('id="coverage"', 1)[1]
        self.assertEqual(coverage.count('<span class="source-reason">Permission denied</span>'), 1)
        self.assertEqual(coverage.count('<span class="source-reason">Directory budget reached</span>'), 1)
        self.assertIn('&lt;script&gt;bad()&lt;/script&gt;', coverage)
        self.assertNotIn('<script>bad()</script>', output)
        for statement in data["coverage"]["limitations"]:
            self.assertNotIn(statement, output)

    def test_declared_mode_is_prominent_and_not_claimed_as_an_endpoint_scan(self):
        data = snapshot()
        data["mode"] = "declared"
        output = render_report(data, {})
        self.assertIn("Declared inventory — endpoint not scanned", output)
        self.assertIn("Configuration and local files have not been independently verified", output)
        self.assertNotIn(">Collection complete<", output)

    def test_synthetic_scope_label_is_prominent_and_escaped(self):
        data = snapshot()
        data["scope"]["label"] = "Synthetic example — fictional configuration, not a device scan <script>bad</script>"
        output = render_report(data, {})
        self.assertIn('class="scope-banner" role="note"', output)
        self.assertIn("Synthetic example — fictional configuration, not a device scan &lt;script&gt;bad&lt;/script&gt;", output)
        self.assertLess(output.index('class="scope-banner"'), output.index('id="overview"'))

    def test_profile_and_cached_state_context_is_visible_without_metadata_expansion(self):
        data = snapshot()
        data["observations"][1]["details"].update(context="cached-state", profileSelected=False, shadowedBySelectedProfile=True, effectiveConfiguration=False)
        output = render_report(data, {})
        self.assertIn('class="inventory-context">Context: Cached state · Unselected profile · Overridden by selected profile · Not effective configuration', output)

    def test_mcp_access_overview_separates_reach_and_excludes_disabled_entries(self):
        data = snapshot()
        cases = [
            ("enabled", {"execution": "local"}),
            ("enabled", {"transport": "stdio"}),
            ("enabled", {"execution": "remote", "endpointScope": "loopback", "transport": "http"}),
            ("enabled", {"execution": "remote", "endpointScope": "remote"}),
            ("unknown", {"transport": "unknown"}),
            ("disabled", {"execution": "remote", "endpointScope": "remote"}),
            ("disabled", {"execution": "local"}),
        ]
        data["observations"] = [{"id": f"mcp-{index}", "name": f"MCP {index}", "kind": "mcp", "enabled": state, "details": details} for index, (state, details) in enumerate(cases)]
        output = render_report(data, {})
        counts = dict(re.findall(r'<div class="access-chart-row" data-reach="([^"]+)">.*?<strong>(\d+)</strong></div>', output))
        self.assertEqual(counts, {"local": "2", "loopback": "1", "gateway": "0", "remote": "1", "unknown": "1"})
        self.assertIn("2 disabled entries are excluded from these bars", output)
        self.assertNotIn("whose enabled state is unknown", output)
        self.assertIn("These counts describe configuration, not running processes or live connections", output)
        self.assertIn('href="#inventory">Inspect configurations', output)
        data["observations"].append({"id": "mcp-gateway", "name": "Space", "kind": "mcp", "enabled": "enabled", "details": {"execution": "remote", "endpointScope": "remote", "governedBy": "palma-gateway"}})
        counts = dict(re.findall(r'<div class="access-chart-row" data-reach="([^"]+)">.*?<strong>(\d+)</strong></div>', render_report(data, {})))
        self.assertEqual((counts["gateway"], counts["remote"]), ("1", "1"))
        self.assertLess(output.index('id="client-map"'), output.index('class="access-overview"'))
        self.assertLess(output.index('class="access-overview"'), output.index('id="findings"'))

    def test_mcp_access_overview_keeps_unknown_reach_unknown(self):
        data = snapshot()
        data["observations"] = [{"id": "unknown-mcp", "kind": "mcp", "enabled": "enabled", "details": {"endpointScope": "remote", "transport": "unknown"}}]
        output = render_report(data, {})
        counts = dict(re.findall(r'<div class="access-chart-row" data-reach="([^"]+)">.*?<strong>(\d+)</strong></div>', output))
        self.assertEqual(counts["unknown"], "1")
        self.assertEqual(counts["remote"], "0")

    def test_mcp_access_overview_all_disabled_has_no_inferred_access(self):
        output = render_report(snapshot(), {})
        counts = dict(re.findall(r'<div class="access-chart-row" data-reach="([^"]+)">.*?<strong>(\d+)</strong></div>', output))
        self.assertEqual(set(counts.values()), {"0"})
        self.assertIn("1 disabled entry is excluded from these bars", output)

    def test_no_mcp_inventory_omits_access_overview(self):
        data = snapshot()
        data["observations"] = [item for item in data["observations"] if item["kind"] != "mcp"]
        output = render_report(data, {})
        self.assertNotIn('class="access-overview"', output)
        self.assertNotIn('href="#inventory-mcp"', output)

    def test_privacy_notice_is_at_the_end_not_in_title_area(self):
        output = render_report(snapshot(), {})
        title_area = output.split('class="report-title"', 1)[1].split('id="overview"', 1)[0]
        self.assertNotIn("Local by design", title_area)
        self.assertNotIn("This report makes no network requests", title_area)
        self.assertGreater(output.index('class="local-note local-note-end"'), output.index('</footer>'))
        self.assertEqual(output.count("This report makes no network requests. You control any sharing."), 1)
        visible_text = " ".join("".join(Document(output).text).split())
        self.assertTrue(visible_text.endswith("Local by design. This report makes no network requests. You control any sharing."))

    def test_explicit_booking_replaces_the_team_panels_default_destination(self):
        output = render_report(snapshot(), {}, booking_url="https://palma.ai/team")
        panel = output.split('<aside class="team-teaser"', 1)[1].split('</aside>', 1)[0]
        links = [attrs for tag, attrs in Document(panel).tags if tag == "a"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["href"], "https://palma.ai/team")
        self.assertEqual(links[0]["rel"], "noreferrer noopener")
        self.assertEqual(links[0]["target"], "_blank")
        footer = output.split('<footer class="report-footer"', 1)[1].split('</footer>', 1)[0]
        self.assertFalse(any(tag == "a" for tag, _ in Document(footer).tags), "one booking button in the team panel")
        self.assertLess(output.index('id="coverage"'), output.index('<aside class="team-teaser"'))
        self.assertLess(output.index('</footer>'), output.index('class="local-note local-note-end"'))

    def test_supported_client_icons_have_text_and_only_observed_clients_are_listed(self):
        data = snapshot()
        clients = [("codex", "Codex"), ("claude-code", "Claude Code"), ("claude-desktop", "Claude Desktop"), ("cursor", "Cursor"), ("gemini-cli", "Gemini CLI"), ("vscode", "VS Code"), ("windsurf", "Windsurf"), ("shared", "Shared skills")]
        data["observations"] = [{"id": f"client-{key}", "kind": "client", "client": key, "name": key, "enabled": "unknown"} for key, _ in clients]
        output = render_report(data, {})
        document = Document(output)
        symbols = {attrs["id"] for tag, attrs in document.tags if tag == "symbol"}
        self.assertEqual(symbols, {"brand-codex", "brand-claude", "brand-cursor", "brand-gemini", "brand-vscode", "brand-windsurf"})
        for _, label in clients:
            self.assertIn(label, " ".join(document.text))
        self.assertIn('data-generic="shared"', output)
        client_map = output.split('id="client-map"', 1)[1].split('id="findings"', 1)[0]
        mapped = [attrs for tag, attrs in Document(client_map).tags if tag == "a" and attrs.get("class") == "client-map-identity"]
        self.assertEqual(len(mapped), len(clients))
        self.assertEqual(len({item["href"] for item in mapped}), len(clients))
        for _, label in clients:
            self.assertIn(label, " ".join(Document(client_map).text))
        data["observations"] = []
        empty = render_report(data, {})
        self.assertNotIn('class="client-map-identity"', empty)
        self.assertNotIn('class="brand-sprite"', empty)

    def test_provider_catalog_includes_authentic_and_truthful_generic_icons(self):
        data = snapshot()
        providers = ["github", "slack", "notion", "linear", "atlassian", "figma", "google-drive", "playwright", "chrome", "context7", "browserbase", "filesystem"]
        data["observations"] = [{"id": f"mcp-{provider}", "kind": "mcp", "client": "codex", "name": f"Connection {index}", "enabled": "unknown", "details": {"provider": provider, "providerName": "Untrusted alternative label"}} for index, provider in enumerate(providers)]
        output = render_report(data, {})
        document = Document(output)
        brands = {attrs["data-brand"] for _, attrs in document.tags if "data-brand" in attrs}
        self.assertEqual(brands, {"codex", "github", "slack", "notion", "linear", "atlassian", "figma", "google-drive", "playwright", "chrome"})
        for label in ("GitHub", "Google Drive", "Chrome DevTools", "Context7", "Browserbase", "Filesystem"):
            self.assertIn(f'<span class="observation-instance">{label}</span>', output)
        self.assertIn('<strong>Connection 0</strong>', output)
        self.assertNotIn('<strong>Untrusted alternative label</strong>', output)
        for generic in ("book", "browser", "folder"):
            self.assertIn(f'data-generic="{generic}"', output)

    def test_unknown_provider_never_infers_a_brand_from_name_or_asset_url(self):
        data = snapshot()
        data["observations"] = [{"id": "unknown-provider", "kind": "mcp", "client": "unrecognized-client", "name": "GitHub", "enabled": "unknown", "details": {"provider": "not-a-catalog-value", "providerName": "GitHub", "iconUrl": 'https://attacker.invalid/logo.svg\" onload=\"alert(1)'}}]
        output = render_report(data, {})
        self.assertNotIn('data-brand="github"', output)
        self.assertNotIn('class="brand-sprite"', output)
        self.assertIn('data-generic="connector"', output)
        self.assertIn('data-generic="app"', output)
        # Arbitrary detail fields are never rendered, escaped or otherwise.
        self.assertNotIn("attacker.invalid", output)
        document = Document(output)
        self.assertFalse(any(key.startswith("on") for _, attrs in document.tags for key in attrs))
        self.assertFalse(any(attrs.get("src", "").startswith("https:") for _, attrs in document.tags))

    def test_brand_symbols_and_internal_references_are_safe_and_resolve(self):
        from palma_scan.report import _BRAND_ASSETS
        data = snapshot()
        data["observations"] = [{"id": f"provider-{provider}", "kind": "mcp", "client": "codex", "name": "Example", "details": {"provider": provider}} for provider in ("github", "slack", "notion", "linear", "atlassian", "figma", "google-drive", "playwright", "chrome")]
        document = Document(render_report(data, {}))
        ids = [attrs["id"] for _, attrs in document.tags if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for tag, attrs in document.tags:
            if tag == "use":
                self.assertTrue(attrs["href"].startswith("#brand-"))
                self.assertIn(attrs["href"][1:], ids)
            for value in attrs.values():
                if value and value.startswith("url("):
                    self.assertRegex(value, r'^url\(#[A-Za-z0-9_-]+\)$')
                    self.assertIn(value[5:-1], ids)
        allowed = {"symbol", "path", "g", "defs", "lineargradient", "radialgradient", "stop", "circle", "ellipse", "rect", "polygon", "polyline", "line", "clippath"}
        for _, symbol in _BRAND_ASSETS.values():
            for tag, attrs in Document(symbol).tags:
                self.assertIn(tag, allowed)
                self.assertNotIn("style", attrs)
                self.assertNotIn("href", attrs)
                self.assertNotIn("src", attrs)
                self.assertFalse(any(key.startswith("on") for key in attrs))

    def test_artwork_credits_remain_in_standalone_html_without_file_reads(self):
        with patch("builtins.open", side_effect=AssertionError("Report generation must not read a notice file")):
            output = render_report(snapshot(), {})
        self.assertIn('class="artwork-credits"', output)
        self.assertIn('Copyright (c) 2024 Bjorn Lammers, Meier Lukas, Thomas Camlong and Homarr Labs', output)
        self.assertIn('Creative Commons Attribution 4.0 International Public License', output)
        self.assertIn('Copyright 2021 The Onest Project Authors', output)
        self.assertIn('SIL OPEN FONT LICENSE Version 1.1', output)
        self.assertLess(output.index('class="artwork-credits"'), output.index('class="local-note local-note-end"'))
        credits = [attrs for tag, attrs in Document(output).tags if tag == "a" and attrs.get("class") == "artwork-reference"]
        self.assertEqual([item["href"] for item in credits], [
            "https://github.com/homarr-labs/dashboard-icons/tree/03e8f8e22da16ccddf5e14afa90711391357231e",
            "https://github.com/microsoft/playwright.dev/blob/main/LICENSE",
        ])
        for item in credits:
            self.assertEqual(item["rel"], "noreferrer noopener")
            self.assertEqual(item["target"], "_blank")

    def test_additional_client_icons_and_labels_are_offline_and_identifiable(self):
        data = snapshot()
        clients = ["cline", "roo-code", "continue", "lm-studio", "ollama", "opencode", "copilot-cli"]
        template = data["observations"][0]
        data["observations"] = [dict(copy.deepcopy(template), id=f"client-{i}", client=name, name=name)
                                for i, name in enumerate(clients)]
        output = render_report(data, {})
        for mark in clients[:5]:
            self.assertIn(f'id="brand-{mark}"', output)
            self.assertIn(f'data-brand="{mark}"', output)
        self.assertIn("GitHub Copilot CLI", output)
        self.assertIn("OpenCode", output)
        self.assertIn("Additional client artwork", output)
        self.assertNotIn('src="https://', output)

    def test_priority_preview_does_not_repeat_the_same_condition_across_sources(self):
        data = snapshot()
        high = data["findings"][1]
        data["findings"].extend([dict(copy.deepcopy(high), id=f"repeat-{i}") for i in range(4)])
        output = render_report(data, {})
        overview = output.split('id="overview"', 1)[1].split('id="client-map"', 1)[0]
        self.assertEqual(overview.count("Filesystem sandbox is disabled"), 1)
        self.assertNotIn("Confirm the trust boundary of local skills", overview)
        self.assertIn('data-priority="info" class="overview-info">1 informational', overview)
        self.assertEqual(len([1 for tag, attrs in Document(output).tags if tag == "article"]), 6)

    def test_empty_snapshot_is_useful_without_a_fabricated_score(self):
        output = render_report({}, {})
        self.assertIn("No priority review items.", output)
        self.assertIn("No inventory observations were recorded", output)
        self.assertIn("No source records were included", output)
        self.assertIn('class="booking-link"', output)
        visible_text = " ".join(Document(output).text)
        self.assertNotIn("100%", visible_text)
        self.assertNotIn("security score", visible_text.lower())

    def test_static_report_exposes_findings_and_native_disclosures(self):
        document = Document(render_report(snapshot(), {}))
        self.assertTrue(any(tag == "details" and attrs.get("class") == "finding-evidence" for tag, attrs in document.tags))
        self.assertFalse(any("hidden" in attrs for tag, attrs in document.tags if tag == "article"))
        visible_text = " ".join(document.text)
        self.assertIn("Use a bounded workspace sandbox", visible_text)
        self.assertIn("Untrusted instructions may affect files", visible_text)
        self.assertIn("danger-full-access", visible_text)


if __name__ == "__main__":
    unittest.main()
