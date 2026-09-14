# Allowlisted skill and plugin sources

Palma uses the versioned, local [source allowlist](../scripts/palma_scan/marketplaces.json)
to distinguish approved distribution origins from sources that need an audit before use.
The runtime makes no network requests to resolve a marketplace or validate installed code.

**Allowlisted source** means that supported local source metadata matches a maintainer
entry. It does not mean that the installed contents are signed, unchanged, audited, or
safe. The report keeps `auditStatus: not-assessed`. Credential literals, hooks, MCP access,
and browser or computer permissions are evaluated separately.

## Current entries

Reviewed **14 September 2026**; allowlist version **2026-09-14.1**.

| Policy ID | Exact source | Accepted evidence |
| --- | --- | --- |
| `anthropic-official-plugins` | `github.com/anthropics/claude-plugins-official` | Claude's registered marketplace source, or Codex's explicit Git marketplace source. The declared source must select the repository root with no ref or `main`. |
| `openai-plugins` | `github.com/openai/plugins` | Codex's explicit Git marketplace source, selecting the repository root with no ref or `main`. |
| `openai-curated-remote` | Codex's reserved global remote marketplace | Exact cache layout plus schema version 1 of Codex's persisted remote installation record, with a nonempty valid remote plugin ID and no conflicting configured marketplace source. |
| `openai-curated-skills` | `github.com/openai/skills`, `skills/.curated/<skill>` | A bounded repository metadata check and the exact Git `origin` repository alongside the curated skill path. Experimental skills are excluded. |

The remote Codex marketplace is distinct from the public `openai/plugins` Git
marketplace. Codex maps its global remote scope to `openai-curated-remote` and stores
`.codex-remote-plugin-install.json` alongside each plugin's cached version directories.
The record identifies a remote installation; it is not a cryptographic attestation.
A cache folder named `openai-curated-remote` without that record stays unresolved.

Claude uses `known_marketplaces.json` and `extraKnownMarketplaces` to identify a
marketplace source. Cached manifests join only through exact marketplace, plugin and
version path components beneath a collected plugin-cache root. Supported version 2
`installed_plugins.json` records establish an installation declaration only when their
`installPath` exactly matches that cache directory; they do not establish live activation.
Bundled skills and agents inherit their parent plugin's source classification. Configured
Claude plugin keys retain their explicit enabled or disabled state.

A standalone skill copied by an installer may have no retained origin metadata. Its name,
`SKILL.md`, `agents/openai.yaml`, `.curated` folder name, or location below `.codex` alone
cannot establish an allowlisted origin. Such local skills retain High source-review priority.
The older `openai/skills` catalog is deprecated in favor of `openai/plugins`; its curated
path remains recognized when supported repository evidence is present.

## Exact matching and unresolved sources

Palma recognizes a GitHub `owner/repository` declaration or an HTTPS URL for exactly
`github.com` on the default port or port 443, optionally ending in `.git`. It rejects
credentials in the authority, lookalike domains, query strings, fragments, extra path
components, path selectors, and refs outside the entry's explicit list. A local directory,
custom marketplace name, repository fork, or a label containing an official name cannot
establish trust. Conflicting source declarations prevent an allowlisted classification.
Source URLs and installation IDs are used only in memory; the report retains fixed policy
IDs, reason codes and the sanitized marketplace name.

Artifacts with an allowlisted source receive an Info source finding and remain in inventory.
Marketplace artifacts with unapproved or unresolved provenance receive Critical priority
and an audit-before-use action. Local skills outside a marketplace receive High source-review
priority. These priorities describe the source policy, not proof of malicious behavior.

## Maintaining the allowlist

1. Verify the exact source and supported metadata schema against official documentation or
   vendor source code. Record a primary-source link in the entry.
2. Add or change the entry in `scripts/palma_scan/marketplaces.json`. Keep a stable policy ID,
   explicit client list, exact repository and permitted refs; never add hostname wildcards.
3. Add fixtures for the supported metadata join and its spoofed, conflicting, malformed and
   missing forms. A new source mechanism needs a parser change and tests; adding a display
   name to JSON is insufficient.
4. Increment the allowlist version and reviewed date; update this reference. Run the Python
   test suite and the release checks in the source repository’s `CONTRIBUTING.md`.
5. Review and commit the policy change through the repository's normal review process, then
   publish a newly verified release when authorized. Runtime user configuration cannot add
   entries to Palma's allowlist.

## Primary references

- [Claude marketplace sources and restrictions](https://code.claude.com/docs/en/plugin-marketplaces)
- [Anthropic's official marketplace manifest](https://github.com/anthropics/claude-plugins-official/blob/main/.claude-plugin/marketplace.json)
- [OpenAI plugin catalog](https://github.com/openai/plugins)
- [Codex Git marketplace registration metadata](https://github.com/openai/codex/blob/main/codex-rs/core-plugins/src/marketplace_add/metadata.rs)
- [Codex remote marketplace scope](https://github.com/openai/codex/blob/main/codex-rs/core-plugins/src/remote.rs)
- [Codex remote installation metadata](https://github.com/openai/codex/blob/main/codex-rs/core-plugins/src/store.rs)
- [Codex reserved marketplace policy](https://github.com/openai/codex/blob/main/codex-rs/core-plugins/src/marketplace_policy.rs)
- [OpenAI skills catalog and installation guidance](https://github.com/openai/skills)
