# Allowlisted skill and plugin sources

Palma uses the versioned, local [source allowlist](../scripts/palma_scan/marketplaces.json)
to distinguish approved distribution origins from sources that need an audit before use.
The runtime makes no network requests to resolve a marketplace or validate installed code.

**Allowlisted source** means that supported local source metadata matches a maintainer
entry. It does not mean that the installed contents are signed, unchanged, audited, or
safe. The report keeps `auditStatus: not-assessed`. Credential literals, hooks, MCP access,
and browser or computer permissions are evaluated separately.

## Current entries

Reviewed **14 September 2026**; allowlist version **2026-09-14.3**.

| Policy ID | Exact source | Accepted evidence |
| --- | --- | --- |
| `anthropic-official-plugins` | `github.com/anthropics/claude-plugins-official` | Claude's registered marketplace source, or Codex's explicit Git marketplace source. The declared source must select the repository root with no ref or `main`. |
| `openai-plugins` | `github.com/openai/plugins` | Codex's explicit Git marketplace source, selecting the repository root with no ref or `main`. |
| `openai-curated-remote` | Codex's reserved global remote marketplace | Exact cache layout plus schema version 1 of Codex's persisted remote installation record, with a nonempty valid remote plugin ID and no conflicting configured marketplace source. |
| `openai-curated-skills` | `github.com/openai/skills`, `skills/.curated/<skill>` | A bounded repository metadata check and the exact Git `origin` repository alongside the curated skill path. Experimental skills are excluded. |
| `openai-codex-bundled-plugins` | Codex's reserved `openai-bundled` and `openai-bundled-alpha` marketplaces | A `[marketplaces.<name>]` entry in the account's `config.toml` with `source_type = "local"` whose source is exactly `<CODEX_HOME>/.tmp/bundled-marketplaces/<name>`, the managed path in [Codex's marketplace policy](https://github.com/openai/codex/blob/main/codex-rs/core-plugins/src/marketplace_policy.rs). Codex refuses user-added marketplaces with reserved names, so the entry is Codex-written; the same name at another path in the home is unapproved. A home copied elsewhere keeps its original absolute paths, so a source outside the scanned home is compared by the managed folders at its end. |
| `openai-codex-primary-runtime` | Codex's reserved `openai-primary-runtime` marketplace | The same `config.toml` shape with the source exactly at `<home>/.cache/codex-runtimes/codex-primary-runtime/plugins/openai-primary-runtime`; a source outside the scanned home (a copied home, or a cache folder Codex resolved elsewhere) is compared by the managed folders at its end. |
| `openai-codex-system-skills` | Codex's embedded system skills, installed by Codex into `<CODEX_HOME>/skills/.system/<skill>` | The exact `skills/.system` folder in the account's own Codex home together with Codex's `.codex-system-skills.marker` file, the hexadecimal fingerprint Codex writes when it installs its embedded skills ([source](https://github.com/openai/codex/blob/main/codex-rs/skills/src/lib.rs)). The marker is checked for presence and shape only and is never exported. A `.system` folder inside a project checkout, or one without the marker, keeps ordinary local review. |

The remote Codex marketplace is distinct from the public `openai/plugins` Git
marketplace. Codex maps its global remote scope to `openai-curated-remote` and stores
`.codex-remote-plugin-install.json` alongside each plugin's cached version directories,
holding `schema_version` 1 and a nonempty `remote_plugin_id` of printable characters without
spaces. The id's format is Codex's, and its value is never exported.
The record identifies a remote installation; it is not a cryptographic attestation.
A cache folder named `openai-curated-remote` without that record stays unresolved.

Claude uses `known_marketplaces.json` and `extraKnownMarketplaces` to identify a
marketplace source. Cached manifests join only through exact marketplace, plugin and
version path components beneath a collected plugin-cache root. Supported version 2
`installed_plugins.json` records establish an installation declaration only when their
`installPath` matches that cache directory (or, for a home copied elsewhere, its marketplace,
plugin and version folders); they do not establish live activation. A project's own
`enabledPlugins` entries are resolved against the account's registry, since a project
folder has no registry of its own, and a Codex `[plugins]` entry without a cached pack takes
the provenance of the marketplace entry in the account's `config.toml`, wherever the entry
itself is declared; without such an entry, a `[plugins]` switch naming one of Codex's
reserved marketplaces names Codex's own catalog and is allowlisted on that basis. A
marketplace entry in a shape this scan does not read is unresolved, not unapproved. Codex packs count as
installed through their remote installation record or a `[plugins."<plugin>@<marketplace>"]`
entry in `config.toml`. The `enabledPlugins` and `[plugins]` switches give a cached pack its
enabled or disabled state; an account-level switch whose pack is present is listed as that
pack, not as a second entry, while a switch in a project's own settings stays a separate
declaration. Bundled connectors inherit the pack's state when the priority policy
decides whether they apply as written.
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
Installed marketplace artifacts whose declared source is outside the allowlist receive
Critical priority and an audit-before-use action. Installed artifacts whose marketplace
source could not be resolved locally receive High priority and a verify-the-source action:
their origin is unknown, not known to be unapproved. A pack that is only downloaded, with
no installation record and no enabled switch, stays in the Info cached-packs finding,
whatever its source record says, until it is installed or switched on. Local skills outside a marketplace receive High source-review
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
