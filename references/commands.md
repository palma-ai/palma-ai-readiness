# Local commands

Use `python3 -I -S <skill>/scripts/palma-scan.py` with Python 3.11+ (`py -3 -I -S` on
Windows), or `run.sh` to find a compatible installed interpreter. JSON5 and YAML parsers are
included in the release. There is no package installation or backend setup. The entrypoint
runs only under `-I -S`. In a release folder it first checks every file against
`MANIFEST.sha256` and exits with code 2 if a file differs, a file or folder that is not part
of the release is present, or the manifest is missing.

| Command | Input | Output |
| --- | --- | --- |
| `run` | Local discovery for the signed-in account | New directory with evidence, summary, local report and shareable summary |
| `collect --output FILE` | Same discovery as run | New snapshot with evidence and evaluated findings |
| `summary --report FILE` | Saved snapshot | Counts, coverage and `priorities` (rule text only, no scanned names) on stdout, or `--output FILE` |
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
Linux any folder another person's account owns), backups, OS temporary folders and the
scanner's own folder are not traversed. The report's coverage section says when any were
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

`--booking-url https://...` includes an optional link to a palma.ai page; other hosts are refused. No destination is built in.
Rendering neither fetches it nor appends inventory. Use the same options for identical HTML.

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
