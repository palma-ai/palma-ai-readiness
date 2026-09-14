"""Machine-default routing and truthful summaries without inspecting a real endpoint."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan import cli
from palma_scan.model import summarize, validate
from palma_scan.report import render_report


def fixture():
    return {
        "schemaVersion": "2.0", "collector": {"name": "synthetic", "version": "2.1.0"},
        "mode": "endpoint", "status": "partial",
        "startedAt": "2026-09-10T10:00:00Z", "completedAt": "2026-09-10T10:01:00Z",
        "scope": {"type": "machine", "platform": "macos", "profileCount": 2,
                  "workspaceCount": 19, "discovery": {"localVolumes": 2,
                  "profilesAccessible": 2, "projectsDiscovered": 19, "directoriesVisited": 12500}},
        "sources": [{"id": "s1", "client": "codex", "scope": "user", "location": "~/.codex/config.toml", "status": "collected"},
                    {"id": "s2", "client": "machine", "scope": "machine", "location": "machine:local-user-profiles", "status": "error", "reason": "A profile could not be read."}],
        "observations": [{"id": "o1", "kind": "client", "client": "codex", "name": "Codex", "sourceId": "s1",
                          "location": "~/.codex/config.toml", "enabled": "unknown", "details": {"activation": "installed", "version": "1.2.3"}},
                         {"id": "o2", "kind": "client", "client": "codex", "name": "Codex", "sourceId": "s1",
                          "location": "machine:running-process-names", "enabled": "unknown", "details": {"activation": "running"}}],
        "coverage": {"limitations": ["Legacy generic prose should not become a report banner."]}, "findings": [],
    }


class MachineIntegrationTests(unittest.TestCase):
    def test_default_cli_runs_machine_discovery_and_explicit_projects_supplement_it(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)/"project"
            project.mkdir()
            target = Path(td)/"snapshot.json"
            with patch("palma_scan.machine.collect_machine", return_value=fixture()) as machine, \
                 patch("palma_scan.collector.collect", side_effect=AssertionError("Do not narrow default scope")), \
                 patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(cli.main(["collect", "--workspace", str(project), "--output", str(target)]), 0)
            machine.assert_called_once_with([project])
            self.assertEqual(json.loads(target.read_text())["scope"]["type"], "machine")

    def test_copied_home_requires_explicit_option_and_never_scans_host(self):
        with tempfile.TemporaryDirectory() as td:
            data = fixture()
            data["scope"] = {"type": "copied-home", "workspaceCount": 0}
            with patch("palma_scan.collector.collect", return_value=data) as copied, \
                 patch("palma_scan.machine.collect_machine", side_effect=AssertionError("Copied evidence cannot scan host")), \
                 patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(cli.main(["collect", "--copied-home", td, "--output", str(Path(td)/"snapshot.json")]), 0)
            copied.assert_called_once_with(Path(td), [], scope_type="copied-home")

    def test_machine_report_counts_client_families_and_shows_real_discovery_and_state(self):
        data = validate(fixture())
        summary = summarize(data)
        self.assertEqual(summary["counts"]["client"], 1)
        self.assertEqual(summary["scope"], "machine")
        report = render_report(data, summary)
        self.assertIn("Your account on this computer · macOS · 19 projects", report)
        self.assertIn("12,500", report)
        self.assertIn("Installed</span>", report)
        self.assertIn("Process observed</span>", report)
        self.assertIn("Version 1.2.3", report)
        self.assertIn("A profile could not be read.", report)
        self.assertNotIn("This scan has collection gaps", report)
        self.assertNotIn("Keep this in perspective", report)
        self.assertNotIn("Legacy generic prose", report)
        self.assertIn('metric-number">1</span><span class="metric-label">AI clients observed', report)

    def test_large_inventory_is_not_rejected_by_previous_record_count_cap(self):
        data = fixture()
        template = data["observations"][0]
        data["observations"] = [dict(copy.deepcopy(template), id=f"observation-{i}") for i in range(10001)]
        self.assertIs(validate(data), data)
        self.assertEqual(summarize(data)["counts"]["client"], 1)

    def test_detected_isolation_is_not_labeled_as_physical_host(self):
        data = fixture()
        data["scope"]["environment"] = {"containerIndicators": ["docker"], "subsystemIndicators": ["wsl"], "sandboxIndicators": []}
        report = render_report(data, {})
        self.assertIn("Container context", report)
        self.assertIn("Subsystem context", report)


if __name__ == "__main__":
    unittest.main()
