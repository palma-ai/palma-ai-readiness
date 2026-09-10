# Local commands

Use `python3 -I -S <skill>/scripts/palma-scan.py` with Python 3.11+, or use `run.sh` /
`run.ps1` to find a compatible installed interpreter. JSON5 and YAML parsers are included
in the release. There is no package installation or backend setup.

| Command | Input | Output |
| --- | --- | --- |
| `run` | Machine-wide local discovery | New directory with evidence, summary, and HTML |
| `collect --output FILE` | Same discovery as run | New snapshot with evidence and evaluated findings |
| `summary --report FILE` | Saved snapshot | Counts and scope on stdout, or `--output FILE` |
| `report --report FILE --output FILE` | Saved snapshot | New self-contained HTML report |
| `evaluate --report FILE --output FILE` | Saved endpoint snapshot | New snapshot evaluated with the bundled rules |

`summary`, `report`, and `evaluate` also accept `--run-dir DIR` instead of `--report`.
Without `--output`, `report` writes `report-rebuilt.html` beside the snapshot. Existing
files are refused. Rendering preserves stored findings; use `evaluate` for an explicit
re-evaluation. Neither performs a fresh endpoint scan.

## Discovery scope

The default scans the machine visible to the native launching process. It discovers local
volumes, accessible OS profiles, AI project markers, supported application and editor
installations, configuration layers, managed policy, profiles/state, extension components,
browser integrations, and known AI runtime/service metadata.

- `--workspace DIR` supplements automatic discovery with another project (repeatable).
- `--output-dir DIR` chooses a new run directory. It does not change scan scope.
- `--copied-home DIR` explicitly inspects an offline home copy **instead of this machine**.
  This option is for supplied evidence copies, not a shortcut for a machine scan.

Traversal looks for AI markers using metadata. Content reads target supported configuration
and manifests. Virtual/network filesystems, dependency trees, and bulk caches are excluded
from general traversal; supported AI cache/state locations have dedicated adapters.
Symlinks and Windows reparse points are handled conservatively. Specific skipped/denied
sources and discovery limits are recorded.

The launching account's OS permissions apply. Other profiles are inspected when accessible;
protected accounts are reported as such. WSL is a separate operating-system context.
A hosted chat, container, or remote shell does not automatically see the physical host.
For web requests, follow the native run workflow in SKILL.md.

## Rendering

`--open` opens the generated **local** report. Shell launchers supply it by default;
`--no-open` keeps it closed. Direct Python commands require `--open` to launch it.

`--booking-url https://...` includes an optional calendar link. No destination is built in.
Rendering neither fetches it nor appends inventory. Use the same options for identical HTML.

## Evidence

Schema `2.0` records collector/rules versions, timestamps, scope and discovery counters,
sources, observations, and findings. IDs link records within the artifact; no persistent
device identity or organization metadata is needed. Evidence distinguishes installation,
configuration, cached state, and observed runtime activity.

On POSIX, new result directories use `0700` and files `0600`; Windows access depends on
the destination ACL. Use a private folder. Secrets and raw configuration are excluded,
but artifacts still describe your AI environment.

Exit `0` means artifacts were generated. Actual coverage is recorded per source. Exit
`2` means invalid input, a missing prerequisite, or a command/filesystem failure.
The scanner does not install software, upload evidence, or change configuration.
