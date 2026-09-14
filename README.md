# Palma AI access scan

See your machine's AI tools, the access they have, and what needs attention. Palma combines
machine-wide discovery with configuration evaluation and a clear, interactive local report.
It supports Windows, macOS, and Linux, with no account, enrollment, or backend connection.

## Run on your computer

Download and extract the **complete skill folder**. Python **3.11+** is required; parsers
are bundled, so there are no packages to install or build tools to configure.

**macOS / Linux**

```bash
bash "/path/to/palma-ai-readiness/scripts/run.sh"
```

**Windows PowerShell**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\path\palma-ai-readiness\scripts\run.ps1"
```

The scan discovers accessible user profiles, local AI projects, application installations,
managed settings, editor profiles, connectors, extension components, and supported runtime
and browser integration metadata. You do not need to choose a directory. Large machines
can take several minutes. Specific unreadable sources are recorded in coverage.

The report opens in your browser. Use `--no-open` to keep it closed, `--workspace <path>`
to supplement automatic project discovery, or `--output-dir <new-directory>` to choose
where results are saved. Otherwise they go in a new `readiness-run-<timestamp>` directory.
The `run.command` and `run.cmd` double-click launchers save results beside the skill.
`PALMA_PYTHON` can select an installed compatible Python executable.

## Starting from a website or web chat

A web assistant cannot scan your computer through its cloud environment. Download the
skill and run the native command above, or give the folder to your desktop AI assistant:

> Read SKILL.md in this Palma skill folder. Run the machine-wide scan on this computer
> and show me the local report, starting with the priorities and recommended actions.

Use native Windows Python for Windows. WSL, containers, and SSH sessions scan their own
operating-system context. Keep the folder intact so the assistant has all matching scripts.

## Your report

Each run saves `report.html`, `snapshot.json` (sanitized evidence and findings), and
`summary.json` (counts and scope). Review priorities first, explore access charts, then
open evidence and inventory details. Search actual skill, plugin, agent, and connector
names and their local configuration paths. All priorities remain visible, with Critical
and High first. Client and connector icons are embedded.
The report uses Palma's light visual style, with Onest typography, linked metric cards,
priority and access charts, and expandable evidence. Its font and artwork are embedded;
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
has no upload or aggregation function. An optional `--booking-url <https-url>` adds a
calendar link when one is supplied.

See [commands](references/commands.md), [rules and coverage](references/risk-rules.md),
[report design and manual fallback](references/report-design.md), and
[third-party notices](THIRD_PARTY_NOTICES.md).
