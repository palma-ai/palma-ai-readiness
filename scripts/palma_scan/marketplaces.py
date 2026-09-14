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


MANAGED_BASES = {'<codexHome>', '<cacheHome>'}


def _managed_local_policy(client, source):
    """Codex's reserved marketplaces live at paths Codex manages and refuses to let a person add.

    Inside the scanned home the configured source must be exactly the managed path below
    Codex's home or the account's cache folder. A home copied elsewhere keeps its original
    absolute paths, so a source outside the scanned home is compared by the managed folders
    at its end, as for Claude's installation records.
    """
    record = _record_path(source.get('root'))
    if record is None or any(ord(c) < 32 for c in source['root']):
        return None
    home = Path(source['home'])
    native = isinstance(record, PurePosixPath) != (os.name == 'nt')
    inside = native and Path(str(record)).is_relative_to(home)
    for entry in policy()['sources']:
        base, _, relative = entry.get('managedLocal', {}).get(source.get('marketplace'), '').partition('/')
        managed = PurePosixPath(relative)
        if client not in entry['clients'] or base not in MANAGED_BASES or not managed.parts:
            continue
        if inside:
            expected = (Path(source['codexHome']) if base == '<codexHome>' else home / '.cache') / managed
            if os.path.normcase(str(Path(str(record)))) == os.path.normcase(str(expected)):
                return entry
        elif _same_tail(record, managed, len(managed.parts)):
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


def _decision(client, market, sources):
    evidence = ['marketplace-registry' if client == 'claude-code' else 'marketplace-config'] if sources else []
    facts = {'marketplaceId': market, 'sourceTrust': 'unresolved', 'sourceEvidence': evidence}
    if not sources:
        return facts
    if any(source is None for source in sources):
        # A declaration in a shape this scan does not read is an unknown source, not a known one.
        facts['sourceEvidence'] = ['unsupported-source-shape']
        return facts
    approved = [source_policy(client, source) for source in sources]
    # Conflicting sources do not acquire trust from one matching declaration.
    if all(approved) and len({item['id'] for item in approved}) == 1:
        facts.update(sourceTrust='allowlisted', sourcePolicyId=approved[0]['id'])
    else:
        facts['sourceTrust'] = 'unapproved'
    return facts


def _documents_by_path(builder):
    """The collected documents by path, so each registry lookup is one dictionary read."""
    index = {}
    for identity, data in builder.documents.items():
        index.setdefault(builder.candidates[identity].path, (identity, builder.candidates[identity], data))
    return index


def _document(index, path, family):
    _, candidate, data = index.get(path, (None, None, None))
    return data if candidate is not None and candidate.family == family and isinstance(data, dict) else None


def _reserved(market):
    """The policy entry for a marketplace name Codex reserves for its own catalogs."""
    return next((entry for entry in policy()['sources'] if entry.get('remoteMarketplace') == market
                 or market in entry.get('managedLocal', {})), None)


def _config_sources(index, root, market, home):
    data = _document(index, root / 'config.toml', 'codex')
    markets = data.get('marketplaces') if data else None
    if not isinstance(markets, dict) or market not in markets:
        return []
    item = markets[market]
    if not isinstance(item, dict) or set(item) - {'source_type', 'source', 'ref', 'sparse_paths'}:
        return [None]
    if item.get('sparse_paths'):
        # A path selection inside a repository is a source of its own, never the listed root.
        return [{'source': 'sparse-paths'}]
    if item.get('source_type') == 'local':
        return [{'source': 'managed-local', 'marketplace': market, 'root': item.get('source'), 'codexHome': str(root), 'home': str(home)}]
    return [{'source': item.get('source_type'), 'url': item.get('source'), 'ref': item.get('ref')}]


def _claude_sources(index, root, market):
    sources = []
    registry = _document(index, root / 'known_marketplaces.json', 'claude-code')
    settings = _document(index, root.parent / 'settings.json', 'claude-code')
    for entries in (registry, settings.get('extraKnownMarketplaces') if settings else None):
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


def _installed(index, root, market, plugin, directory):
    """Claude's installation record names the cache directory. A home copied elsewhere keeps
    the original absolute path, so the marketplace, plugin and version folders are compared."""
    data = _document(index, root / 'installed_plugins.json', 'claude-code')
    if not data or data.get('version') != 2:
        return False
    plugins = data.get('plugins')
    entries = plugins.get(plugin + '@' + market) if isinstance(plugins, dict) else None
    for entry in entries if isinstance(entries, list) else ():
        record = _record_path(entry.get('installPath') if isinstance(entry, dict) else None)
        if record is not None and _same_tail(record, directory, 3):
            return True
    return False


def _plugin_switch(index, home, family, market, plugin):
    """The configured state of ``plugin@market``, with the identity of the document declaring
    it: Claude's ``enabledPlugins`` in the settings files of the client home, or Codex's
    ``[plugins]`` table in ``config.toml``."""
    name = plugin + '@' + market
    files = ('settings.json', 'settings.local.json') if family == 'claude-code' else ('config.toml',)
    for file in files:
        data = _document(index, home / file, family)
        if data is None:
            continue
        if family == 'claude-code':
            entry = data.get('enabledPlugins', {}).get(name) if isinstance(data.get('enabledPlugins'), dict) else None
        else:
            entries = data.get('plugins')
            entry = entries.get(name) if isinstance(entries, dict) else None
            if isinstance(entry, dict):
                entry = entry.get('enabled', 'configured')
        state = 'enabled' if entry is True else 'disabled' if entry is False else 'configured' if entry is not None else None
        if state is not None:
            return state, index[home / file][0]
    return None, None


def _probe(builder, candidate, *, document=False):
    """An optional provenance read must not discard already collected evidence."""
    try:
        return builder.document(candidate) if document else builder.read(candidate)
    except ReadGap as error:
        builder.gap(candidate, error.reason, error.status)
        if error.reason in {'count_limit', 'time_limit'}:
            builder.limit_reason = error.reason
        return None, None


def _curated_skill(collection, item, candidate, codex_roots):
    # Another client (Cursor reads Codex's skills folders too) inventories the same checkout.
    if candidate is None or (candidate.family not in {'codex', 'shared'} and not any(candidate.path.is_relative_to(root) for root in codex_roots)):
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


def _system_skill(collection, item, candidate, verified, codex_homes):
    """Codex installs its embedded skills into ``<CODEX_HOME>/skills/.system`` beside a marker.

    The marker file holds the fingerprint Codex uses to skip reinstalling; only its
    presence and shape are checked here, once per folder, and nothing from it is exported.
    Only the account's own Codex home qualifies: a ``.system`` folder inside a project
    checkout, a folder without the marker, or a skill elsewhere keeps ordinary local review.
    """
    if candidate is None or candidate.scope != 'user' or item.get('sourceTrust') == 'allowlisted':
        return
    folder = candidate.path.parent.parent
    # Only the account's own Codex home qualifies, whichever client reads the folder.
    entry = next((x for x in policy()['sources'] if x.get('systemSkillsDir') and 'codex' in x['clients']
                  and any(folder == home / x['systemSkillsDir'] for home in codex_homes)), None)
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


def _configured(builder, index, item, candidate, roots, home):
    name = item.get('name', '')
    if not isinstance(name, str) or name.count('@') != 1:
        return
    plugin, market = name.split('@')
    if not all(SEGMENT.fullmatch(part) for part in (plugin, market)):
        return
    # Join the actual configured key, never a substring of its display label.
    data = builder.documents.get(item['sourceId'], {})
    enabled = data.get('enabledPlugins')
    family_roots = [root for root in roots if root.family == candidate.family]
    # A CLAUDE_CONFIG_DIR or CODEX_HOME override replaces the default home's registry.
    overrides = [root for root in family_roots if root.location.startswith('override:')]
    if candidate.family == 'claude-code' and isinstance(enabled, dict) and name in enabled:
        beside = [root for root in family_roots if root.path.parent.parent == candidate.path.parent]
        # A project's settings file has no registry of its own; the account's registry applies.
        source_records = [source for root in beside or overrides or family_roots for source in _claude_sources(index, root.path.parent, market)]
        item.update(_decision(candidate.family, market, source_records))
    elif candidate.family == 'codex' and candidate.path.name == 'config.toml' and isinstance(data.get('plugins'), dict) and name in data['plugins']:
        # Marketplace sources come from the account's Codex home only: a project's own
        # config.toml cannot declare where a reserved marketplace lives.
        homes = [candidate.path.parent] if candidate.scope == 'user' else sorted({root.path.parent.parent for root in overrides or family_roots})
        source_records = [source for codex_home in homes for source in _config_sources(index, codex_home, market, home)]
        facts = _decision(candidate.family, market, source_records)
        if not source_records and _reserved(market):
            # Codex refuses user-added marketplaces with its reserved names, so the entry names Codex's own catalog.
            facts.update(sourceTrust='allowlisted', sourcePolicyId=_reserved(market)['id'], sourceEvidence=['reserved-marketplace-name'])
        item.update(facts)


def annotate(collection):
    """Join manifests to source records after collection, before sanitization.

    Only exact cache-relative marketplace/plugin/version paths beneath collected
    cache candidates qualify. Parent provenance is inherited by bundled content.
    """
    builder = collection.builder
    roots = [candidate for candidate in collection.pending if candidate.role == 'plugins'
             and candidate.family in {'claude-code', 'codex'} and candidate.path.name == 'cache']
    codex_roots = {candidate.path for candidate in collection.pending if candidate.family == 'codex' and candidate.role == 'skills'}
    codex_homes = {candidate.path.parent for candidate in collection.pending
                   if candidate.family == 'codex' and candidate.scope == 'user' and candidate.path.name == 'config.toml'}
    index = _documents_by_path(builder)
    builder.consumed_switches = set()
    system_folders = {}
    for item in list(builder.observations.values()):
        candidate = builder.candidates.get(item['sourceId'])
        if item['id'] not in builder.observations:
            continue
        if item['kind'] == 'skill' and not item.get('parentId'):
            _curated_skill(collection, item, candidate, codex_roots)
            _system_skill(collection, item, candidate, system_folders, codex_homes)
        if item['kind'] != 'plugin' or item.get('parentId') or candidate is None:
            continue
        if candidate.role != 'plugin':
            _configured(builder, index, item, candidate, roots, collection.home)
            continue
        directory = candidate.path.parent.parent
        matches = [root for root in roots if root.family == candidate.family and directory.is_relative_to(root.path)]
        for root in sorted(matches, key=lambda x: len(x.path.parts), reverse=True):
            parts = directory.relative_to(root.path).parts
            if len(parts) != 3 or not all(SEGMENT.fullmatch(part) for part in parts):
                continue
            market, plugin, _ = parts
            sources = (_claude_sources(index, root.path.parent, market) if candidate.family == 'claude-code'
                       else _config_sources(index, root.path.parent.parent, market, collection.home))
            facts = _decision(candidate.family, market, sources)
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
                            # The id is Codex's opaque value, never exported: a bounded printable token.
                            and 0 < len(data['remote_plugin_id']) <= 200 and all(32 < ord(c) < 127 for c in data['remote_plugin_id'])):
                        facts.update(sourceTrust='allowlisted', sourcePolicyId=allowed['id'], sourceEvidence=['codex-remote-install'])
                    elif data is not None:
                        source.update(status='unsupported', reason='unknown_schema')
            item.update(facts)
            # Installation and switch state: Claude's registry and settings, Codex's remote
            # installation record and [plugins] table. A pack with neither stays cached.
            switch, declared_by = _plugin_switch(index, root.path.parent.parent, candidate.family, market, plugin)
            installed = (_installed(index, root.path.parent, market, plugin, directory) if candidate.family == 'claude-code'
                         else switch is not None or 'codex-remote-install' in facts.get('sourceEvidence', []))
            if installed:
                item['installationState'] = 'installed'
            if switch in {'enabled', 'disabled'}:
                item['enabled'] = switch
            if declared_by is not None:
                # The switch is this pack's state, carried by the pack row; its own row would list the pack twice.
                builder.consumed_switches.add((declared_by, plugin + '@' + market))
                for key in [key for key, other in builder.observations.items() if other['kind'] == 'plugin'
                            and other['sourceId'] == declared_by and other['name'] == plugin + '@' + market]:
                    del builder.observations[key]
            break
    for item in builder.observations.values():
        parent = builder.observations.get(item.get('parentId'))
        if item['kind'] in {'skill', 'agent'} and parent:
            item.update({key: parent[key] for key in TRUST_FIELDS if key in parent})
            if 'sourceTrust' in item:
                item['sourceEvidence'] = [*item.get('sourceEvidence', []), 'plugin-parent']
    # Include any new probe gaps and sanitize metadata learned by those reads.
    builder.finish()
