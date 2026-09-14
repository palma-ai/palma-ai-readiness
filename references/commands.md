# Local commands

Use `python3 -I -S <skill>/scripts/palma-scan.py` with Python 3.11+ (`py -3 -I -S` on
Windows), or `run.sh` to find a compatible installed interpreter. JSON5 and YAML parsers are
included in the release. There is no package installation or backend setup. The entrypoint
runs only under `-I -S`. In a release folder it first checks every file against
`MANIFEST.sha256` and exits with code 2 if a listed file differs or is missing,
an unexpected file or folder is present inside `scripts`, or the manifest is missing.

## Download and extract

Use the [official Palma release](https://github.com/palma-ai/palma-ai-readiness/releases/latest).
The ZIP contains `palma-ai-readiness/SKILL.md`, runtime, references, brand assets, notices,
`BUILD-INFO.json`, and `MANIFEST.sha256`. It needs no Git clone, GitHub account, package
installation or build step. Keep the extracted folder intact. An installed release works
offline; downloading a new version is a separate action.

Resolve the latest release once, then get the ZIP and checksum from that exact tag. The
commands below do this, verify the checksum, refuse an existing extraction directory, and
run the scan. Run them on the computer you want to assess, after installing Python 3.11+
if it is not already available. The checksum detects changed bytes; it is not a publisher
signature. Download only from the official repository and its GitHub asset redirects.

### macOS or Linux

Run this in Bash. `curl` and Python 3.11+ must already be installed:

```bash
set -euo pipefail
palma_repo="https://github.com/palma-ai/palma-ai-readiness"
palma_release_url="$(curl --proto '=https' --proto-redir '=https' --fail --silent --show-error --location --output /dev/null --write-out '%{url_effective}' "$palma_repo/releases/latest")"
if [[ "$palma_release_url" =~ ^https://github\.com/palma-ai/palma-ai-readiness/releases/tag/(build-[1-9][0-9]*-[0-9a-f]{40})$ ]]; then
  palma_tag="${BASH_REMATCH[1]}"
else
  echo "Could not resolve an official Palma release." >&2
  exit 1
fi
palma_directory="$HOME/palma-scan-$palma_tag"
mkdir "$palma_directory"
cd "$palma_directory"
for palma_asset in palma-ai-readiness.zip palma-ai-readiness.zip.sha256; do
  curl --proto '=https' --proto-redir '=https' --fail --silent --show-error --location --output "$palma_asset" "$palma_repo/releases/download/$palma_tag/$palma_asset"
done
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c palma-ai-readiness.zip.sha256
else
  shasum -a 256 -c palma-ai-readiness.zip.sha256
fi
python3 -I -S -m zipfile -e palma-ai-readiness.zip .
bash "$palma_directory/palma-ai-readiness/scripts/run.sh"
```

A failed command stops the process. If Python has another executable name, use that
installed Python 3.11+ executable for extraction and set `PALMA_PYTHON` before running.

### Windows PowerShell

Use native Windows Python. This avoids deep clone paths and needs no execution-policy
change. The Python launcher `py` must already be installed:

```powershell
$ErrorActionPreference = "Stop"
$palmaRepository = "https://github.com/palma-ai/palma-ai-readiness"
$palmaRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/palma-ai/palma-ai-readiness/releases/latest"
$palmaTag = $palmaRelease.tag_name
if ($palmaTag -cnotmatch '^build-[1-9][0-9]*-[0-9a-f]{40}$') {
    throw "Could not resolve an official Palma release."
}
$palmaDirectory = Join-Path $env:USERPROFILE "palma-scan-$palmaTag"
if (Test-Path -LiteralPath $palmaDirectory) { throw "Choose a new extraction folder." }
New-Item -ItemType Directory -Path $palmaDirectory | Out-Null
foreach ($palmaAsset in @("palma-ai-readiness.zip", "palma-ai-readiness.zip.sha256")) {
    Invoke-WebRequest -Uri "$palmaRepository/releases/download/$palmaTag/$palmaAsset" -OutFile (Join-Path $palmaDirectory $palmaAsset)
}
$palmaArchive = Join-Path $palmaDirectory "palma-ai-readiness.zip"
$palmaChecksum = (Get-Content -LiteralPath "$palmaArchive.sha256" -Raw).Trim()
if (-not ($palmaChecksum -cmatch '^([0-9a-f]{64})  palma-ai-readiness\.zip$')) {
    throw "Invalid checksum file. Do not extract or run this download."
}
$palmaExpected = $Matches[1]
$palmaActual = (Get-FileHash -LiteralPath $palmaArchive -Algorithm SHA256).Hash
if ($palmaActual -ne $palmaExpected) { throw "Checksum mismatch. Do not extract or run this download." }
Expand-Archive -LiteralPath $palmaArchive -DestinationPath $palmaDirectory
py -3 -I -S "$palmaDirectory\palma-ai-readiness\scripts\palma-scan.py" run --open
if ($LASTEXITCODE -ne 0) { throw "Palma stopped. Review the command output above." }
```

If you download through a browser, get both assets from the same versioned release page.
On macOS use `shasum -a 256 -c palma-ai-readiness.zip.sha256`; on Linux use
`sha256sum -c palma-ai-readiness.zip.sha256`. On Windows compare `Get-FileHash -Algorithm
SHA256` with the checksum as above. Continue only when it matches, then extract into a
new short directory and run the matching native command in README.md.

A website or cloud chat cannot run the local scan for you. Use the extracted skill with
your desktop assistant or local terminal. A source checkout is for development; an
assistant handling a machine-scan request should acquire the released skill first.

## Commands

| Command | Input | Output |
| --- | --- | --- |
| `run` | Local discovery for the signed-in account | New directory with evidence, summary, local report and shareable summary |
| `collect --output FILE` | Same discovery as run | New snapshot with evidence and evaluated findings |
| `summary --report FILE` | Saved snapshot | Counts, coverage and `priorities` (rule text, declaration and applies-as-written counts, no scanned names) on stdout, or `--output FILE` |
| `report --report FILE --output FILE` | Saved snapshot | New self-contained HTML report; `--share` renders the shareable summary |
| `evaluate --report FILE --output FILE` | Saved endpoint snapshot | New snapshot evaluated with the bundled rules |

`summary`, `report`, and `evaluate` also accept `--run-dir DIR` instead of `--report`.
Without `--output`, `report` writes `report-rebuilt.html` (`share-rebuilt.html` with `--share`) beside the snapshot. Existing
files are refused. Rendering preserves stored findings; use `evaluate` for an explicit
re-evaluation. Neither performs a fresh endpoint scan.

## Discovery scope

The scan covers the account that runs it on the machine visible to the native launching
process: its profile, AI project markers on local volumes, supported application and editor
installations, configuration layers, managed policy, profiles/state, extension components,
browser integrations, the AI apps it is running, and known AI runtime/service metadata.
Folders that belong to other accounts (their homes wherever they are, and on macOS and
Linux any folder another person's account owns), backups, OS temporary folders, `.tmp`
folders, client-managed marketplace clones and the scanner's own folder are not traversed. The report's coverage section says when any were
skipped; scan such a project with `--workspace`.

- `--workspace DIR` supplements automatic discovery with another project (repeatable).
- `--output-dir DIR` chooses a new run directory; by default `run` creates a new
  `readiness-run-<timestamp>` folder in the home folder. It does not change scan scope.
- `--copied-home DIR` explicitly inspects an offline home copy **instead of this machine**.
  This option is for supplied evidence copies, not a shortcut for a machine scan.

Traversal looks for AI markers using metadata. Content reads target supported configuration
and manifests. Virtual/network filesystems, dependency trees, and bulk caches are excluded
from general traversal; supported AI cache/state locations have dedicated adapters.
Symlinks and Windows reparse points are handled conservatively. Specific skipped/denied
sources and discovery limits are recorded.

The launching account's OS permissions apply. Folders that belong to other accounts are
never opened, even when readable. WSL is a separate operating-system context.
A hosted chat, container, or remote shell does not automatically see the physical host.
For web requests, follow the native run workflow in SKILL.md.

## Rendering

`--open` opens the generated **local** report. Shell launchers supply it by default;
`--no-open` keeps it closed. Direct Python commands require `--open` to launch it.

`share.html` and `report --share` render the shareable summary: the same findings and names,
with every location reduced to its AI configuration folder and file name, names that are
paths or web addresses withheld, and no project, folder or volume names.

The bottom team-view panel includes [Palma's booking link](https://calendar.app.google/qVE3L8fGgmQWv3Hx7)
by default. `--booking-url https://...` can replace it with a palma.ai page. Only that
exact Google calendar URL and HTTPS palma.ai pages are accepted. Rendering neither
fetches the destination nor appends inventory; the link opens only when clicked.
Use the same options for identical HTML.

The EU AI Act overview and EU AI Act review appear automatically in `run`
and `report` output. Rebuild a saved run to add them without rescanning. This uses
bundled, dated guidance; it does not reassess legal applicability or modify saved findings.

## Evidence

Schema `2.0` records collector/rules versions, timestamps, scope and discovery counters,
sources, observations, and findings. IDs link records within the artifact; no persistent
device identity or organization metadata is needed. Evidence distinguishes installation,
configuration, cached state, and observed runtime activity.

Each declaration is recorded once. Identical copies in other files (git worktrees, desktop
agent session copies, cached plugin versions) merge into one observation: `locations`
lists where it is declared and `copyCount` counts the merged declarations. Copies whose
content, state or applicability differ stay separate. Each AI client is one observation
with its installed `versions`, `processObserved` and the `projectCount` of projects that
configure it. Sources are kept when they back evidence or record a read problem;
`coverage.sourcesInspected` counts every source read.

On POSIX, new result directories use `0700` and files `0600`; Windows access depends on
the destination ACL. Use a private folder. Secrets and raw configuration are excluded,
but artifacts still describe your AI environment.

Exit `0` means artifacts were generated. Actual coverage is recorded per source. Exit
`2` means invalid input, a missing prerequisite, or a command/filesystem failure.
Exit `130` means the command was interrupted before it completed.
A malformed document or a failing adapter ends only that source: it is recorded as a
read error and the scan continues with partial status. Error messages never repeat
file contents.
The scanner does not install software, upload evidence, or change configuration.
