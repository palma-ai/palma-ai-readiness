# Publishing the Palma skill

This guide is for Palma maintainers. It is not included in the public skill download.

## Build the public folder

From the source repository, with Python 3.11 or newer:

```bash
python3 -I -S scripts/build_release.py --output /path/to/new-release/palma-ai-readiness.zip
```

The archive includes only the user instructions, runtime scripts, evidence/report
references, agent metadata, and artwork notices. It excludes this `docs/` directory,
tests, sample reports, development scripts, caches, and platform binaries. Pinned pure-Python
JSON5/YAML parser sources and their licenses are bundled with the runtime.
Repeated builds of the same source produce identical bytes and a `.sha256` companion. The
archive contains `MANIFEST.sha256`, which the entrypoint checks before running any skill
code; the build marks the entrypoint as a release, so a copy without its manifest, or with
any file that is not part of the release, is refused. The build stops if a bundled parser file differs from its reviewed SHA-256 in
`scripts/palma_scan/_vendor/sources.json`; update that file only after reviewing a parser change.

Host the archive, its `.sha256` file and the extracted folder together at one palma.ai HTTPS
path; SKILL.md tells assistants to use only that origin and to stop when the checksum
differs. Serve the extracted release folder, not the entire source repository. An agent
needs the matching runtime scripts and references; `SKILL.md` alone cannot perform a scan.
The manifest check catches incomplete or edited copies but is not a signature.

The website owns the marketing form and consent record. They are not scanner inputs.
Replace the bracketed URL in this suggested website prompt before publication:

> I want a Palma AI access scan of my account on this computer. Read the skill at [hosted SKILL.md URL], download its matching complete release from the same palma.ai page, and check the archive with its published `.sha256` file before extracting it. Run the native scan and show me the local report with its priorities and actions. If this chat only has cloud execution, give me the download, checksum step and native run command for my computer instead.

The team-view invitation is included at the end of each report. When the calendar URL
is available, `--booking-url https://...` adds an ordinary optional booking link to a palma.ai page. No
calendar destination or aggregation connection is built in.

## Check a release

```bash
python3 -B -m unittest discover -s tests -v
python3 -I -S scripts/create_demo.py --output-dir /path/to/new-demo
```

The demo uses fictional configuration. Optional DOM behavior checks use a separate
development installation of `jsdom`:

```bash
NODE_PATH=/path/to/development/node_modules node tests/report-interactions.cjs /path/to/new-demo/report.html
```

Before publishing, inspect the generated report at desktop and mobile sizes and run
the extracted release on each supported operating system. Fixture-based path checks
and DOM behavior checks do not establish native execution or browser layout quality.
The public skill needs no Node.js or separate Python package installation.
