# Contributing

Use Python 3.11 or newer. Development checks use temporary fixtures and fictional
configuration; they do not require a scan of your computer.

```bash
python3 -B -m unittest discover -s tests -v
python3 -I -S scripts/create_demo.py --output-dir /path/to/new-demo
```

For report changes, inspect the fictional report at desktop and mobile sizes.
Optional DOM checks require a separate development installation of `jsdom`:

```bash
NODE_PATH=/path/to/development/node_modules node tests/report-interactions.cjs /path/to/new-demo/report.html
NODE_PATH=/path/to/development/node_modules node tests/report-interactions.cjs /path/to/new-demo/share.html
PALMA_TEST_PYTHON=python3 NODE_PATH=/path/to/development/node_modules node tests/report-client-only.cjs
PALMA_TEST_PYTHON=python3 NODE_PATH=/path/to/development/node_modules node tests/report-grouped-inventory.cjs
```

Keep scan results, credentials, local environments, caches and generated archives
out of commits. Preserve the bundled parsers and their license notices; the public
skill requires no package installation.

## Releases

The [Validate and release workflow](.github/workflows/release.yml) runs for every pushed
branch head and pull request. It runs the fixture suite and generates a fictional report
on native Windows, macOS and Linux with Python 3.11 and 3.14. The suite builds, extracts,
and runs the standalone release against synthetic configuration on each platform.
No job scans the runner's account.

After all matrix jobs pass, the workflow builds the canonical ZIP with Python 3.11 on
Ubuntu and saves it with its matching checksum as an Actions artifact named by commit and run attempt for
30 days. Branch and pull-request artifacts are previews and require GitHub sign-in to
download. Pull requests have read-only repository permissions and never publish.

Each successful `main` push also publishes the same ZIP and checksum as a GitHub Release
with tag `build-<workflow-run-number>-<full-commit-sha>`. Assets are uploaded to a draft,
verified, then published together. Existing published assets are never replaced. Only
the release job receives `contents: write`; no personal access token is required.
Publication is serialized with `queue: max` (GitHub permits up to 100 pending jobs).
The workflow run number prevents an older completion or retry from moving `latest` back.
Rerun a failed publication job after resolving its stated error; matching draft uploads
are reused, and conflicting assets cause a stop.

Public downloads use GitHub Release assets, which are accessible without an account
when the repository is public. GitHub's automatic source-code archives are development
checkouts and are not the standalone skill. Palma's website can link to the stable assets:

- [Latest skill ZIP](https://github.com/palma-ai/palma-ai-readiness/releases/latest/download/palma-ai-readiness.zip)
- [Latest ZIP checksum](https://github.com/palma-ai/palma-ai-readiness/releases/latest/download/palma-ai-readiness.zip.sha256)

For an automated download, resolve the latest release tag once and fetch both assets from
that tag, following [the public download procedure](references/commands.md#download-and-extract).
This avoids mixing files if a new release is published between requests.

Build a local package for verification:

```bash
python3 -I -S scripts/build_release.py --source-commit "$(git rev-parse HEAD)" --output /path/to/new-release/palma-ai-readiness.zip
```

The builder uses an explicit allowlist, verifies bundled parser hashes, fixes ZIP metadata,
and creates a reproducible archive, SHA-256 companion and `MANIFEST.sha256`. Identical source
bytes and source commit produce identical ZIP bytes with the same Python/zlib toolchain.
`BUILD-INFO.json` records the supplied full commit SHA without timestamps or local paths;
it is covered by the manifest. Omit `--source-commit` for an unversioned local development
build. A supplied SHA identifies the intended source; the local builder does not assert
that a working tree is clean. CI builds the checked-out commit.

New runtime files and assets must be added to the builder's allowlist. Development
instructions, publication helpers, tests, examples, and scan results are excluded.
The checksum and manifest detect integrity problems; they are not publisher signatures.
Release archives must never contain verification reports or snapshots.

Actions are pinned to full upstream commit SHAs. Check the official action repositories
before updating them. The workflow follows GitHub's guidance for
[concurrency queues](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency),
[release links](https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases),
and [artifact access](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts).
