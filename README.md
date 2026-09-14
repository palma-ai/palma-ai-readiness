<a href="https://palma.ai"><img src="assets/palma-logo.svg" alt="Palma AI" width="220"></a>

# Palma AI access scan

See the AI tools on your computer, the access they have, and what needs attention. Palma
combines local discovery with configuration evaluation and a clear, interactive local report.
It supports Windows, macOS, and Linux, with no account, enrollment, or backend connection.

## Run on your computer

Get the [latest Palma skill release](https://github.com/palma-ai/palma-ai-readiness/releases/latest).
Download **palma-ai-readiness.zip** and **palma-ai-readiness.zip.sha256** from that same
release. No GitHub account, Git installation, repository clone, or package installation is
needed. Python **3.11+** is required; the parsers are bundled.

The [download, verify and extract commands](references/commands.md#download-and-extract)
resolve the latest release once so both files come from the same version. Verify the
SHA-256 checksum before extracting, then keep the complete skill folder intact.
The latest release is the newest successfully validated `main` build; each release records
its source commit in `BUILD-INFO.json` and checks its files against `MANIFEST.sha256`.

On Windows, extract to a short folder in your own profile, such as
`%USERPROFILE%\palma-scan`, rather than a deeply nested agent scratch directory.
Use a new extraction folder for each release. See the
[verify, extract and run commands](references/commands.md#download-and-extract).

**macOS / Linux**

```bash
bash "/path/to/palma-ai-readiness/scripts/run.sh"
```

**Windows**

```powershell
py -3 -I -S "C:\path\palma-ai-readiness\scripts\palma-scan.py" run --open
```

The scan covers your account: AI clients, connectors, skills and settings in your profile,
managed AI policy, installed AI apps, editor profiles, extension components, supported runtime
and browser integration metadata, and AI projects on local drives. Folders that belong to
other accounts are never opened. You do not need to choose a directory. Large machines can take
several minutes. Specific unreadable sources are recorded in coverage.

The report opens in your browser. Use `--no-open` to keep it closed, `--workspace <path>`
to supplement automatic project discovery, or `--output-dir <new-directory>` to choose
where results are saved. Otherwise they go in a new `readiness-run-<timestamp>` folder in
your home folder. You can also double-click `scripts/run.command` on macOS or
`scripts\run.cmd` on Windows; if Gatekeeper or SmartScreen blocks it, use the terminal
command instead rather than removing the quarantine or choosing to run it anyway.
`PALMA_PYTHON` can select an installed compatible Python executable. The scanner refuses to
start if the folder differs from its release.

## Starting from a website or web chat

A web assistant cannot scan your computer through its cloud environment. Download the
skill and run the native command above, or give the folder to your desktop AI assistant:

> Read SKILL.md in this Palma skill folder. Run the scan of my account on this computer
> and show me the local report, starting with the priorities and recommended actions.

Use native Windows Python for Windows. WSL, containers, and SSH sessions scan their own
operating-system context. Keep the folder intact so the assistant has all matching scripts.

## Your report

Each run saves `report.html`, `share.html` (a summary without project or folder names, for
sharing), `snapshot.json` (sanitized evidence and findings), and `summary.json` (counts and
scope). These files describe your computer's AI access, including which files hold
credentials: keep them private, share only `share.html`, and delete the folder when you are
done. Review priorities first, explore access charts, then open evidence and inventory
details. Search actual skill, plugin, agent, and connector
names and their local configuration paths. MCP servers and skills appear once per
declared name, with client badges and declaration counts. Expand a row to compare
its configurations or skill contents; matching names do not imply identical versions
or access. Browser extension records are grouped with their permission sets.
All priorities remain visible, with Critical
and High first. Client and connector icons are embedded.
The report uses Palma's light visual style, with Onest typography, a client-to-component map,
prominent Critical/High callouts, clickable priority bars, and expandable evidence. Detailed sections start collapsed. Its font and artwork are embedded;
the report works offline and makes no network requests.

The **EU AI Act overview** highlights when an AI use-case review is needed.
Its compact tiles link relevant local findings to review questions, with an official
EU AI Act guidance link for further detail. Legal risk class and compliance remain
unassessed: local access settings cannot establish the intended use or your legal role.
It appears automatically in local reports. See the
[EU AI Act review guidance](references/eu-ai-regulation.md).

Rebuild a saved report without rescanning:

```bash
python3 -I -S scripts/palma-scan.py report --run-dir /path/to/saved-run --output /path/to/new-report.html
```

The collector retains useful settings and credential-presence facts while excluding
secrets, raw commands, conversations, and instruction bodies from artifacts. It does not
execute discovered code or change your configuration. You control any sharing.

Interested in the picture across your team? Palma's separate aggregated view can connect
recurring tools, exposure patterns, and priorities across participating devices. This skill
has no upload or aggregation function. The report ends with a team-view diagram and a
[Talk to Palma](https://calendar.app.google/qVE3L8fGgmQWv3Hx7) booking button.
`--booking-url <https-url>` can replace it with a palma.ai page. The link opens only when
clicked; no scan data is added to it.

Learn more about [Palma](https://palma.ai). See [commands](references/commands.md), [rules and coverage](references/risk-rules.md),
[report design and manual fallback](references/report-design.md), and
[third-party notices](THIRD_PARTY_NOTICES.md).
