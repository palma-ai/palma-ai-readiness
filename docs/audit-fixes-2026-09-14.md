# Audit fixes — 14 September 2026

Reviewed and patched on `saikat/eu-ai-act`, starting from `0a5c348`.
Scope: the nine concrete findings from the preceding audit. Collection was tested
only against temporary fixtures and fictional examples; no machine scan was run.

## Disposition

| Finding | Outcome and evidence |
| --- | --- |
| Other-account reads | Fixed. A shared boundary rejects foreign personal owners, excluded paths and directory identities before reads/listings, and checks opened descriptors. Native configuration, editor state, managed policy and discovery use it. Linked-home targets remain excluded when explicitly supplied as workspaces. |
| Windows launcher exits early | Control flow corrected; native verification blocked on this macOS host. Five `cmd.exe` tests cover explicit Python, PATH fallback, invalid overrides, scanner exit codes and current-directory impostors. |
| Login name in connector labels | `no_change`: already fixed at the starting revision. Existing identity/redaction tests and the investigator's collection-to-share fixture confirm the original freeform-name leak no longer reproduces. |
| False Git provenance | Fixed for the reported repository-local cases. Incomplete/dangling repositories cannot lower the rating. Real linked worktrees, nested ignores, globstars, directory-only patterns, negation and local `core.ignoreCase` are checked against Git fixtures. |
| Credential-reference deduplication | Fixed. Transient identity preserves the original declaration before parser normalization. Different environment/file/secret references stay separate; exact copies still merge. Reference values and the transient identity are not exported. |
| Single installation version lost | Fixed. An observed version survives merging with an unversioned installation. |
| Client-only inventory disappears | Fixed. Client names and facts participate in search independently of member rows; reset and client links restore the group. |
| Mobile client facts hidden | Fixed. Facts wrap below the client heading. Desktop and mobile browser inspection found them visible without horizontal overflow. |
| Missing release manifest | `no_change`: already fixed at the starting revision. The extracted-release regression verifies missing and edited manifests/files are refused. The manifest remains an integrity check, not a signature. |

The narrow security change shares the existing file-access boundary between the
two reader families; it does not introduce a new scanner or execute discovered
commands. Copied-home owner behavior, system-owned paths (including hardlinks),
valid Git branch names, exact declaration copies and report disclosure state have
positive controls alongside the malicious fixtures.

One independent investigator examined the read boundary before implementation.
One fresh reviewer then inspected the candidate for bypasses and regressions.
Its linked-home target, case-insensitive/bracket ignore, system hardlink and dotted
branch cases were reproduced, added as regressions and addressed in this change.

## Verification

Run with Python 3.14 on macOS:

```sh
python3 -B -m unittest discover -s tests -v
python3 -I -S scripts/create_demo.py --output-dir /path/to/new-demo
NODE_PATH=/path/to/development/node_modules node tests/report-interactions.cjs /path/to/new-demo/report.html
NODE_PATH=/path/to/development/node_modules node tests/report-interactions.cjs /path/to/new-demo/share.html
PALMA_TEST_PYTHON=python3 NODE_PATH=/path/to/development/node_modules node tests/report-client-only.cjs
git diff --check
```

- Full suite: **394 tests; 389 passed, 5 native Windows tests skipped**. This includes
  packaged-runtime import/execution, reproducible release builds, manifest refusal,
  bundled parser hashes and existing privacy/security regressions.
- Focused ownership, Git provenance, declaration/version and client-only DOM cases
  failed before their fixes and passed afterward. Git served only as a development
  test oracle, in isolated temporary repositories.
- Both report variants passed the DOM interaction checks, including search, reset,
  disclosures, anchor reveal, printing and rejection of outbound browser APIs.
  The refreshed checked-in HTML examples passed the same checks.
- Synthetic report inspected at **390 × 844** and **1280 × 900**. Client facts were
  visible at both widths, with no horizontal page overflow.
- `git diff --check` passed. No vendor parser changes, runtime dependency installs,
  real scan results, release archives or credentials are included in the change.

## Remaining limits

Native Windows launcher execution remains unverified. Run
`python -B -m unittest discover -s tests -p test_windows_launcher.py -v` on Windows;
also follow the existing release procedure's native checks on each supported OS
before publishing. Linux ownership behavior was exercised through fixtures, not
on a native Linux host in this session.

Repository provenance remains a conservative metadata indicator. It does not prove
that a skill is tracked, committed or reviewed, and does not resolve global Git
configuration or ignore files. Unsupported repository configuration/ignore syntax
retains Critical priority; the exact limits are in
[risk-rules.md](../references/risk-rules.md). The implementation follows the
[Git ignore rules](https://git-scm.com/docs/gitignore) and
[repository layout](https://git-scm.com/docs/gitrepository-layout) for the supported
repository-local cases.

This closes the tested findings; it is not a claim that public software can have
zero risk. No publication or remote push is part of this change.
