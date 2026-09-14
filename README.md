<p align="center">
  <a href="https://palma.ai"><img src="assets/palma-logo.svg" alt="Palma AI" width="240"></a>
</p>

<h1 align="center">Palma AI access scan</h1>

<p align="center">
  See which AI tools are on your computer, what they can reach, and what to fix first.<br>
  Local, offline, no account.
</p>

<p align="center">
  <a href="https://github.com/palma-ai/palma-ai-readiness/actions/workflows/release.yml"><img src="https://github.com/palma-ai/palma-ai-readiness/actions/workflows/release.yml/badge.svg?branch=main" alt="Validate and release"></a>
  <a href="https://github.com/palma-ai/palma-ai-readiness/releases/latest"><img src="https://img.shields.io/badge/download-latest%20release-007a93" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-33c0d0" alt="Python 3.11 or newer">
  <img src="https://img.shields.io/badge/runs%20on-macOS%20%7C%20Windows%20%7C%20Linux-33c0d0" alt="macOS, Windows and Linux">
</p>

## What it does

The scan reads the configuration of the AI tools on the signed-in account and turns it into
one local report:

- **Inventory.** AI clients, MCP servers and connectors, skills, plugins, agents, hooks and
  settings, each listed once by name and tagged with the clients that declare it.
- **Findings.** What deserves attention, with a priority, why it matters, and a next step:
  credentials written into configuration, computer and browser control, connectors outside
  any governance, permission bypasses, skills without a recorded review.
- **EU AI Act review.** Four review areas that link the local evidence to the questions an
  owner has to answer, without claiming a legal risk class.
- **Coverage.** Exactly which sources were read and which could not be.

It understands Claude Code, Claude Desktop, Codex, Cursor, Gemini CLI, VS Code and GitHub
Copilot, Windsurf, Cline, Roo Code, Kiro, OpenCode, Continue, Aider, LM Studio, Antigravity,
OpenClaw and AI browser extensions, on macOS, Windows and Linux.

## Quick start

1. Download **palma-ai-readiness.zip** and **palma-ai-readiness.zip.sha256** from the
   [latest release](https://github.com/palma-ai/palma-ai-readiness/releases/latest). Both
   files come from the same release; no GitHub account, Git or package installation is
   needed. Python **3.11 or newer** is the only requirement.
2. Verify the checksum, then extract the ZIP into a new folder and keep it intact. The
   [download, verify and extract commands](references/commands.md#download-and-extract)
   do all of this in one step. On Windows use a short folder in your own profile, such as
   `%USERPROFILE%\palma-scan`.
3. Run the scan.

   macOS or Linux:

   ```bash
   bash "/path/to/palma-ai-readiness/scripts/run.sh"
   ```

   Windows:

   ```powershell
   py -3 -I -S "C:\path\palma-ai-readiness\scripts\palma-scan.py" run --open
   ```

The report opens in your browser. Results go in a new `readiness-run-<timestamp>` folder in
your home folder; `--output-dir <new-directory>` chooses another location, `--workspace <path>`
adds a project to automatic discovery, and `--no-open` keeps the browser closed. Large
machines can take several minutes. You can also double-click `scripts/run.command` on
macOS or `scripts\run.cmd` on Windows; if Gatekeeper or SmartScreen blocks it, use the
terminal command instead of removing the quarantine. `PALMA_PYTHON` selects an installed
Python. The scanner refuses to start if the folder differs from its release.

The scan covers your account: AI clients, connectors, skills and settings in your profile,
managed AI policy, installed AI apps, editor profiles, extension components, supported
runtime and browser integration metadata, and AI projects on local drives. Folders that
belong to other accounts are never opened.

## Use it from an AI assistant

A web assistant cannot scan your computer through its cloud environment. Give the
extracted folder to a desktop assistant with filesystem tools instead:

> Read SKILL.md in this Palma skill folder. Run the scan of my account on this computer
> and show me the local report, starting with the priorities and recommended actions.

Use native Windows Python for Windows. WSL, containers and SSH sessions scan their own
operating-system context. [SKILL.md](SKILL.md) holds the full workflow the assistant follows.

## Your report

Each run saves four files:

| File | What it holds | Share it? |
| --- | --- | --- |
| `report.html` | The full local report: priorities, charts, evidence, inventory, EU AI Act review, coverage | Keep private |
| `share.html` | The same report with every location reduced to its AI configuration folder and file name, without project or folder names | The only file meant for others |
| `snapshot.json` | Sanitized evidence and findings | Keep private |
| `summary.json` | Counts, coverage and priorities as rule text, without scanned names | Keep private |

These files describe your computer's AI access, including which files hold credentials.
Delete the folder when you are done.

Review priorities first, then open evidence and inventory details. Finding summaries name
connectors, not file paths; paths sit in the evidence. Access, capability and permission
findings say how many declarations apply as written: an entry in an unselected profile, a
cached policy copy, a plugin pack that is switched off or has no installation record, or an
entry that is switched off stays in the evidence without raising the priority on its own.
Skills and plugins from a marketplace outside Palma's allowlist are Critical; installed packs
whose source could not be resolved locally are High, with a verify-the-source action. MCP servers
and skills appear once per declared name with client badges and declaration counts;
matching names do not imply identical versions or access. Browser extension records are
grouped with their permission sets. Client and connector icons, the Onest typeface and the
Palma artwork are embedded, so the report works offline and makes no network requests.

The **EU AI Act overview** highlights when an AI use-case review is needed. If the scan finds
no governance layer (no connector routed through a Palma-operated gateway), the panel says
so and treats all four areas as not covered until an owner documents them; that is a stated
assumption, not proof that a control is absent. Legal risk class and compliance remain
unassessed: local access settings cannot establish the intended use or your legal role.
See the [EU AI Act review guidance](references/eu-ai-regulation.md).

Rebuild a saved report without rescanning:

```bash
python3 -I -S scripts/palma-scan.py report --run-dir /path/to/saved-run --output /path/to/new-report.html
```

## Local by design

- Reads configuration and manifests; runs nothing it finds and changes nothing.
- Makes no network request. The only download is the release you fetch yourself, verified
  by checksum and file manifest before any code runs.
- Excludes secrets, raw commands, conversations and instruction bodies from every artifact;
  the account name and home path never leave the machine.
- Sends nothing anywhere. The team view below is a separate Palma offering; this scan has
  no upload or enrollment.

Report a vulnerability privately through the [security policy](SECURITY.md).

## About Palma

[Palma](https://palma.ai) is the governance plane for AI agents: one policy layer between
your agents and every MCP server, with identity, approval policies, audit and cost control.
This scan shows one machine. The team view connects shared tools, repeated exposure and
priorities across people and devices, so the report ends with a
[Talk to Palma](https://calendar.app.google/qVE3L8fGgmQWv3Hx7) button; `--booking-url <https-url>`
can replace it with a palma.ai page. The link opens only when clicked and carries no scan data.

## Repository

| Path | Purpose |
| --- | --- |
| [SKILL.md](SKILL.md) | The skill an AI assistant follows to run the scan and present the report |
| [references/](references/) | [Commands](references/commands.md), [rules and coverage](references/risk-rules.md), [allowlisted sources](references/trusted-marketplaces.md), [EU AI Act guidance](references/eu-ai-regulation.md), [report design](references/report-design.md) |
| `scripts/` | The scanner, the report renderer and the platform launchers, with bundled JSON5 and YAML parsers |
| `assets/` | Palma's official wordmark and brand mark |
| `examples/` | A synthetic report generated from fictional configuration |
| `tests/` | The fixture suite CI runs on macOS, Windows and Linux |

[CONTRIBUTING.md](https://github.com/palma-ai/palma-ai-readiness/blob/main/CONTRIBUTING.md) covers development checks and releases;
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) lists bundled artwork, fonts and parsers.

## License

[Apache License 2.0](LICENSE); see [NOTICE](NOTICE). The Palma name, wordmark and brand mark
are trademarks of Palma AI and are not covered by the license. Product marks in the report
identify the tools found and imply no endorsement.
