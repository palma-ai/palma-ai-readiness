"""Local source provenance joined to an explicit maintainer allowlist.

A source match is neither a content audit nor a signature. No discovered URL is
contacted; only typed source metadata and bounded local files are inspected.
"""
import configparser
from dataclasses import replace
from functools import lru_cache
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from urllib.parse import urlsplit

from .engine.git_provenance import version_controlled
from .engine.filesystem import ReadGap

TRUST_FIELDS = ('sourceTrust', 'sourcePolicyId', 'sourceEvidence', 'marketplaceId')
SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z')
# Codex writes a hexadecimal fingerprint (a hashed u64) when it installs its embedded skills.
SYSTEM_SKILLS_MARKER = re.compile(rb'[0-9a-f]{1,32}\s*\Z')
REPOSITORY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*\Z')


@lru_cache(maxsize=1)
def policy():
    return json.loads(Path(__file__).with_name('marketplaces.json').read_text(encoding='utf-8'))


def repository_origin(value):
    """An exact GitHub repository, never URL substrings or arbitrary paths."""
    if not isinstance(value, str) or value != value.strip() or any(ord(c) < 33 for c in value):
        return None
    if REPOSITORY.fullmatch(value):
        return value.removesuffix('.git').lower()
    try:
        url = urlsplit(value)
        if (url.scheme != 'https' or url.netloc not in {'github.com', 'github.com:443'}
                or '?' in value or '#' in value or url.username or url.password):
            return None
        path = url.path.removeprefix('/')
        if not REPOSITORY.fullmatch(path):
            return None
        return path.removesuffix('.git').lower()
    except ValueError:
        return None


def _managed_local_policy(client, source):
    """Codex's reserved marketplaces live at paths Codex manages and refuses to let a person add.

    Codex compares the configured local source with the managed path; a home copied
    elsewhere keeps the original absolute path, so the managed folders at the end of the
    path are compared, as for Claude's installation records.
    """
    record, home = _record_path(source.get('root')), source.get('codexHome')
    if record is None or not isinstance(home, str) or any(ord(c) < 32 for c in source['root']):
        return None
    for entry in policy()['sources']:
        expected = entry.get('managedLocal', {}).get(source.get('marketplace'))
        if client not in entry['clients'] or not expected:
            continue
        managed = Path(os.path.normpath(os.path.join(home, expected)))
        if _same_tail(record, managed, len(managed.parts) - len(Path(home).parent.parts)):
            return entry
    return None


def _same_tail(record, local, depth):
    """Whether a recorded path ends in the same ``depth`` folders as a local one. Windows
    records compare case-insensitively, as the recording client resolved them."""
    if depth <= 0 or len(record.parts) < depth or len(local.parts) < depth:
        return False
    fold = str.casefold if isinstance(record, PureWindowsPath) or os.name == 'nt' else str
    return [fold(part) for part in record.parts[-depth:]] == [fold(part) for part in local.parts[-depth:]]


def source_policy(client, source):
    if not isinstance(source, dict):
        return None
    if source.get('source') == 'managed-local':
        return _managed_local_policy(client, source)
    # A ref/subdirectory changes the source selection. Only listed refs and the
    # marketplace's root are accepted, never attacker-selected nested catalogs.
    if (source.get('source') == 'github' and set(source) <= {'source', 'repo', 'ref'}
            and isinstance(source.get('repo'), str) and REPOSITORY.fullmatch(source['repo'])):
        repository = repository_origin(source.get('repo'))
    elif (source.get('source') == 'git' and set(source) <= {'source', 'url', 'ref'}
          and isinstance(source.get('url'), str) and source['url'].startswith('https://')):
        repository = repository_origin(source.get('url'))
    else:
        return None
    if repository is None:
        return None
    return next((item for item in policy()['sources'] if client in item['clients']
                 and not item.get('skillPath') and item.get('repository') == repository
                 and source.get('ref') in item.get('refs', [])), None)


def _decision(client, market, sources, evidence):
    facts = {'marketplaceId': market, 'sourceTrust': 'unresolved', 'sourceEvidence': evidence}
    if not sources:
        return facts
    approved = [source_policy(client, source) for source in sources]
    # Conflicting sources do not acquire trust from one matching declaration.
    if all(approved) and len({item['id'] for item in approved}) == 1:
        facts.update(sourceTrust='allowlisted', sourcePolicyId=approved[0]['id'])
    else:
        facts['sourceTrust'] = 'unapproved'
    return facts


def _config_sources(builder, root, market):
    sources = []
    for identity, data in builder.documents.items():
        candidate = builder.candidates[identity]
        if candidate.family != 'codex' or candidate.path != root / 'config.toml':
            continue
        markets = data.get('marketplaces')
        if isinstance(markets, dict) and market in markets:
            item = markets[market]
            if not isinstance(item, dict) or set(item) - {'source_type', 'source', 'ref', 'sparse_paths'}:
                sources.append(None)
            elif item.get('sparse_paths'):
                sources.append(None)
            elif item.get('source_type') == 'local':
                sources.append({'source': 'managed-local', 'marketplace': market, 'root': item.get('source'), 'codexHome': str(root)})
            else:
                sources.append({'source': item.get('source_type'), 'url': item.get('source'), 'ref': item.get('ref')})
    return sources


def _claude_sources(builder, root, market):
    sources = []
    registry = root / 'known_marketplaces.json'
    for identity, data in builder.documents.items():
        candidate = builder.candidates[identity]
        if candidate.family != 'claude-code':
            continue
        entries = data if candidate.path == registry else data.get('extraKnownMarketplaces') if candidate.path == root.parent / 'settings.json' else None
        if isinstance(entries, dict) and market in entries:
            item = entries[market]
            sources.append(item.get('source') if isinstance(item, dict) else None)
    return sources


def _record_path(value):
    """An installation record's absolute path as the recording client wrote it, on any host."""
    if not isinstance(value, str):
        return None
    record = PureWindowsPath(value) if re.match(r'[A-Za-z]:[\\/]', value) or '\\' in value else PurePosixPath(value)
    return record if record.is_absolute() and '..' not in record.parts else None


def _installed(builder, root, market, plugin, directory):
    """Claude's installation record names the cache directory. A home copied elsewhere keeps
    the original absolute path, so the marketplace, plugin and version folders are compared."""
    for identity, data in builder.documents.items():
        candidate = builder.candidates[identity]
        if candidate.path != root / 'installed_plugins.json' or data.get('version') != 2:
            continue
        plugins = data.get('plugins')
        entries = plugins.get(plugin + '@' + market) if isinstance(plugins, dict) else None
        if isinstance(entries, list):
            for entry in entries:
                record = _record_path(entry.get('installPath') if isinstance(entry, dict) else None)
                if record is not None and _same_tail(record, directory, 3):
                    return True
    return False


def _plugin_switch(builder, home, family, market, plugin):
    """The configured state of ``plugin@market``: Claude's ``enabledPlugins`` in the settings
    files beside the plugin folder, or Codex's ``[plugins]`` table in ``config.toml``."""
    name = plugin + '@' + market
    for identity, data in builder.documents.items():
        candidate = builder.candidates[identity]
        if candidate.family != family:
            continue
        if family == 'claude-code':
            if candidate.path.parent != home or candidate.path.name not in {'settings.json', 'settings.local.json'}:
                continue
            entry = data.get('enabledPlugins', {}).get(name) if isinstance(data.get('enabledPlugins'), dict) else None
        else:
            if candidate.path != home / 'config.toml':
                continue
            entries = data.get('plugins')
            entry = entries.get(name) if isinstance(entries, dict) else None
            if isinstance(entry, dict):
                entry = entry.get('enabled', 'configured')
        if entry is True:
            return 'enabled'
        if entry is False:
            return 'disabled'
        if entry is not None:
            return 'configured'
    return None


def _probe(builder, candidate, *, document=False):
    """An optional provenance read must not discard already collected evidence."""
    try:
        return builder.document(candidate) if document else builder.read(candidate)
    except ReadGap as error:
        builder.gap(candidate, error.reason, error.status)
        if error.reason in {'count_limit', 'time_limit'}:
            builder.limit_reason = error.reason
        return None, None


def _curated_skill(collection, item, candidate):
    if candidate is None or candidate.family not in {'codex', 'shared'}:
        return
    builder = collection.builder
    for root in candidate.path.parents:
        if root == collection.home or not root.is_relative_to(collection.home):
            break
        relative = candidate.path.relative_to(root).parts
        allowed = next((entry for entry in policy()['sources'] if entry.get('skillPath')
                        and relative[:2] == tuple(entry['skillPath'].split('/'))
                        and len(relative) == 4), None)
        if not allowed:
            continue
        if not version_controlled(candidate.path, collection.home, builder.files, {}):
            return
        metadata = replace(candidate, path=root / '.git/config', role='registry-probe', format='text')
        source, raw = _probe(builder, metadata)
        if raw is None:
            return
        try:
            parsed = configparser.RawConfigParser(interpolation=None)
            parsed.read_string(raw.decode('utf-8'))
            # Git has no ConfigParser DEFAULT inheritance for remote options.
            if parsed.defaults() or any(name.strip().lower().startswith(('include', 'url', 'extensions')) for name in parsed.sections()):
                return
            repository = repository_origin(parsed.get('remote "origin"', 'url', fallback=None))
            if repository == allowed['repository']:
                item.update(sourceTrust='allowlisted', sourcePolicyId=allowed['id'], sourceEvidence=['curated-skill-repository'])
        except (UnicodeError, configparser.Error):
            source.update(status='unsupported', reason='unknown_schema')
        return


def _system_skill(collection, item, candidate, verified):
    """Codex installs its embedded skills into ``<CODEX_HOME>/skills/.system`` beside a marker.

    The marker file holds the fingerprint Codex uses to skip reinstalling; only its
    presence and shape are checked here, once per folder, and nothing from it is exported.
    Only the account's own Codex home qualifies: a ``.system`` folder inside a project
    checkout, a folder without the marker, or a skill elsewhere keeps ordinary local review.
    """
    if candidate is None or candidate.scope != 'user' or item.get('sourceTrust') == 'allowlisted':
        return
    folder = candidate.path.parent.parent
    # Another client (Cursor reads .codex/skills too) inventories the same Codex-managed folder.
    owner = candidate.family if '.codex' not in folder.parts else 'codex'
    entry = next((x for x in policy()['sources'] if x.get('systemSkillsDir') and owner in x['clients']
                  and folder.match(x['systemSkillsDir'])), None)
    if entry is None:
        return
    if folder not in verified:
        marker = replace(candidate, path=folder / entry['markerFile'], role='registry-probe', format='text',
                         location=str(PurePosixPath(candidate.location).parent.parent / entry['markerFile']))
        source, raw = _probe(collection.builder, marker)
        verified[folder] = raw is not None and SYSTEM_SKILLS_MARKER.fullmatch(raw) is not None
        if raw is not None and not verified[folder]:
            source.update(status='unsupported', reason='unknown_schema')
    if verified[folder]:
        item.update(sourceTrust='allowlisted', sourcePolicyId=entry['id'], sourceEvidence=['codex-system-skills-marker'])


def _configured(builder, item, candidate, roots):
    name = item.get('name', '')
    if not isinstance(name, str) or name.count('@') != 1:
        return
    plugin, market = name.split('@')
    if not all(SEGMENT.fullmatch(part) for part in (plugin, market)):
        return
    # Join the actual configured key, never a substring of its display label.
    data = builder.documents.get(item['sourceId'], {})
    enabled = data.get('enabledPlugins')
    if candidate.family == 'claude-code' and isinstance(enabled, dict) and name in enabled:
        beside = [root for root in roots if root.family == candidate.family and root.path.parent.parent == candidate.path.parent]
        # A project's settings file has no registry of its own; the account's registry applies.
        roots = beside or [root for root in roots if root.family == candidate.family]
        source_records = [source for root in roots for source in _claude_sources(builder, root.path.parent, market)]
        item.update(_decision(candidate.family, market, source_records, ['marketplace-registry'] if source_records else []))
    elif candidate.family == 'codex' and candidate.path.name == 'config.toml' and isinstance(data.get('plugins'), dict) and name in data['plugins']:
        # Marketplace sources come from the account's Codex home only: a project's own
        # config.toml cannot declare where a reserved marketplace lives.
        homes = [candidate.path.parent] if candidate.scope == 'user' else sorted({root.path.parent.parent for root in roots if root.family == 'codex'})
        source_records = [source for home in homes for source in _config_sources(builder, home, market)]
        item.update(_decision(candidate.family, market, source_records, ['marketplace-config'] if source_records else []))


def annotate(collection):
    """Join manifests to source records after collection, before sanitization.

    Only exact cache-relative marketplace/plugin/version paths beneath collected
    cache candidates qualify. Parent provenance is inherited by bundled content.
    """
    builder = collection.builder
    roots = [candidate for candidate in collection.pending if candidate.role == 'plugins'
             and candidate.family in {'claude-code', 'codex'} and candidate.path.name == 'cache']
    system_folders = {}
    for item in list(builder.observations.values()):
        candidate = builder.candidates.get(item['sourceId'])
        if item['kind'] == 'skill' and not item.get('parentId'):
            _curated_skill(collection, item, candidate)
            _system_skill(collection, item, candidate, system_folders)
        if item['kind'] != 'plugin' or item.get('parentId') or candidate is None:
            continue
        if candidate.role != 'plugin':
            _configured(builder, item, candidate, roots)
            continue
        directory = candidate.path.parent.parent
        matches = [root for root in roots if root.family == candidate.family and directory.is_relative_to(root.path)]
        for root in sorted(matches, key=lambda x: len(x.path.parts), reverse=True):
            parts = directory.relative_to(root.path).parts
            if len(parts) != 3 or not all(SEGMENT.fullmatch(part) for part in parts):
                continue
            market, plugin, _ = parts
            if candidate.family == 'claude-code':
                sources = _claude_sources(builder, root.path.parent, market)
                evidence = ['marketplace-registry'] if sources else []
            else:
                sources = _config_sources(builder, root.path.parent.parent, market)
                evidence = ['marketplace-config'] if sources else []
            facts = _decision(candidate.family, market, sources, evidence)
            if item.get('name') != plugin:
                facts.update(sourceTrust='unresolved', sourceEvidence=['plugin-name-mismatch'])
                facts.pop('sourcePolicyId', None)
            elif not sources and candidate.family == 'codex':
                allowed = next((x for x in policy()['sources'] if x.get('remoteMarketplace') == market), None)
                if allowed:
                    metadata = replace(candidate, path=directory.parent / '.codex-remote-plugin-install.json',
                                       role='registry-probe', format='json', location=root.location + '/remote-install')
                    source, data = _probe(builder, metadata, document=True)
                    if (isinstance(data, dict) and set(data) == {'schema_version', 'remote_plugin_id'}
                            and type(data.get('schema_version')) is int and data['schema_version'] == 1
                            and isinstance(data.get('remote_plugin_id'), str)
                            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.~:@+-]{0,199}', data['remote_plugin_id'])):
                        facts.update(sourceTrust='allowlisted', sourcePolicyId=allowed['id'], sourceEvidence=['codex-remote-install'])
                    elif data is not None:
                        source.update(status='unsupported', reason='unknown_schema')
            item.update(facts)
            # Installation and switch state: Claude's registry and settings, Codex's remote
            # installation record and [plugins] table. A pack with neither stays cached.
            home = root.path.parent if candidate.family == 'claude-code' else root.path.parent.parent
            switch = _plugin_switch(builder, home.parent if candidate.family == 'claude-code' else home, candidate.family, market, plugin)
            installed = (_installed(builder, root.path.parent, market, plugin, directory) if candidate.family == 'claude-code'
                         else switch is not None or 'codex-remote-install' in facts.get('sourceEvidence', []))
            if installed:
                item['installationState'] = 'installed'
            if switch in {'enabled', 'disabled'}:
                item['enabled'] = switch
            break
    for item in builder.observations.values():
        parent = builder.observations.get(item.get('parentId'))
        if item['kind'] in {'skill', 'agent'} and parent:
            item.update({key: parent[key] for key in TRUST_FIELDS if key in parent})
            if 'sourceTrust' in item:
                item['sourceEvidence'] = [*item.get('sourceEvidence', []), 'plugin-parent']
    # Include any new probe gaps and sanitize metadata learned by those reads.
    builder.finish()
