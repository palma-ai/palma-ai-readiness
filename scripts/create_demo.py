#!/usr/bin/env python3
"""Create a clearly synthetic report by exercising the real scanner and rules."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required.")
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from palma_scan.collector import collect
from palma_scan.rules import evaluate
from palma_scan.model import json_text, summarize, validate
from palma_scan.report import render_report
from palma_scan.cli import write_new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("Choose a new demo directory.")
    with tempfile.TemporaryDirectory(prefix="palma-synthetic-") as temporary:
        home = Path(temporary)
        fixtures = {
            ".codex/config.toml": 'approval_policy="never"\nsandbox_mode="danger-full-access"\n[features]\ncomputer_use=true\n[mcp_servers.browser]\ncommand="npx"\nargs=["@playwright/mcp@latest"]\n',
            ".claude/settings.json": {"permissions": {"defaultMode": "default"}, "sandbox": {"enabled": True},
                                      "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "echo synthetic-only"}]}]},
                                      "enabledPlugins": {"sample-plugin@demo": True, "retired-plugin@demo": False}},
            ".claude/remote-settings.json": {"permissions": {"defaultMode": "bypassPermissions"}},
            ".claude.json": {"projects": {str(home / "retired-project"): {}, str(home / "project"): {}}},
            "project/.claude/settings.json": {"permissions": {"defaultMode": "default"}, "sandbox": {"enabled": False}},
            ".cursor/mcp.json": {"mcpServers": {"documentation": {"url": "https://mcp.notion.com/mcp"},
                                               "source-control": {"url": "https://api.githubcopilot.com/mcp/"},
                                               "test-service": {"url": "http://demo.example.test/mcp", "headers": {"Authorization": "Bearer fictional-example-value"}},
                                               "disabled": {"command": "node", "disabled": True}}},
            ".gemini/settings.json": {"agents": {"overrides": {"browser_agent": {"enabled": True}}, "browser": {"sessionMode": "existing", "confirmSensitiveActions": False}}},
            "Library/Application Support/Claude/claude_desktop_config.json": {
                "mcpServers": {"documentation": {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]}}},
            ".config/Code/User/settings.json": {"chat.tools.global.autoApprove": True, "workbench.browser.enableChatTools": True},
            ".config/Code/User/mcp.json": {"servers": {"design": {"type": "http", "url": "https://mcp.figma.com/mcp"},
                                                     "team-messages": {"type": "http", "url": "https://mcp.slack.com/mcp"}}},
            ".config/Windsurf/User/settings.json": {"windsurf.cascadeCommandsAllowList": [], "windsurf.cascadeCommandsDenyList": []},
            ".agents/skills/release-helper/SKILL.md": "Fictional example; never executed.",
            ".claude/skills/research-helper/SKILL.md": "Fictional example; never executed.",
            ".claude/agents/reviewer.md": "Fictional example; never executed.",
            ".codeium/windsurf/mcp_config.json": '{"mcpServers": '  # Demonstrates a real coverage gap.
        }
        for name, data in fixtures.items():
            path = home / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        snapshot = collect(home, [home / "project"], scope_type="copied-home")
    snapshot["startedAt"] = "2026-09-10T12:00:00+00:00"
    snapshot["completedAt"] = "2026-09-10T12:00:01+00:00"
    snapshot["scope"]["label"] = "Synthetic example — fictional configuration, not a device scan"
    snapshot["coverage"]["limitations"].insert(0, "SYNTHETIC EXAMPLE: every declaration in this report was generated from fictional test configuration, not a person's endpoint.")
    snapshot["findings"] = evaluate(snapshot)
    validate(snapshot)
    summary = summarize(snapshot)
    args.output_dir.mkdir(mode=0o700, parents=True)
    write_new(args.output_dir / "snapshot.json", json_text(snapshot))
    write_new(args.output_dir / "summary.json", json_text(summary))
    write_new(args.output_dir / "report.html", render_report(snapshot, summary))
    print(f"Synthetic preview: {(args.output_dir / 'report.html').resolve()}")


if __name__ == "__main__":
    main()
