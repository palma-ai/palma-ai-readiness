# Security policy

The Palma AI access scan reads local AI configuration and writes a local report. It
runs nothing it finds, makes no network requests, and sends nothing anywhere. A defect
that breaks one of those guarantees, leaks a credential or an account name into an
artifact, or lets scanned content steer the agent that presents the report is a
security issue.

## Reporting a vulnerability

Report it privately through
[GitHub private vulnerability reporting](https://github.com/palma-ai/palma-ai-readiness/security/advisories/new)
for this repository. Do not open a public issue for a security problem, and do not
attach a real scan result: describe the configuration shape that triggers the defect,
or build a fictional fixture the way `tests/` does.

Include the release tag (`build-<run>-<commit>` from `BUILD-INFO.json`), the operating
system, the Python version, and the smallest configuration that reproduces the problem.

## Scope

- The scanner and report renderer in `scripts/`, including the bundled parsers.
- The release build and publication workflow.
- The guidance in `SKILL.md` and `references/` that an AI assistant follows.

Findings about the AI clients the scanner inventories belong to those vendors. A report
that lists a connector, skill or setting is an inventory, not a vulnerability claim.

## Supported releases

Only the latest release published from `main` is supported. Each release is a
reproducible ZIP with a SHA-256 checksum and a file manifest; verify both before running.
