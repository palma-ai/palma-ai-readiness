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
```

Keep scan results, credentials, local environments, caches and generated archives
out of commits. Preserve the bundled parsers and their license notices; the public
skill requires no package installation.

## Releases

```bash
python3 -I -S scripts/build_release.py --output /path/to/new-release/palma-ai-readiness.zip
```

The builder uses an explicit allowlist, verifies bundled parser hashes and creates
a reproducible archive, a SHA-256 companion file and an internal file manifest.
It excludes development guidance, tests and examples.

Before publishing, verify the checksum and run the extracted release on Windows,
macOS and Linux. Fixture tests cannot establish native platform behavior. Keep
reports generated during verification private.

Publish the matching archive, checksum and extracted release together on palma.ai
over HTTPS. Serve the extracted release folder rather than the source repository.
Keep the release structure intact. The checksum and manifest detect integrity
problems; they are not publisher signatures.
