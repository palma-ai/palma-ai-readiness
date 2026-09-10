"""Local-only v2 bridge over Palma's original collection adapters.

The original engine retains path discovery, safe reads, installation/version
probes, profile/state settings, extension components and bundle fingerprints.
Parsed documents remain in memory for the exact typed governance evaluator.
Only sanitized v2 observations leave this bridge; there is no enrollment,
persistent device identity, network request, command execution or upload.
"""
from dataclasses import replace
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import sys
import time

from . import __version__
from .engine.collection import CollectOptions, Collection, HOST_OS
from .engine.paths import Candidate, user_candidates, workspace_candidates
from .engine.supplemental_paths import supplemental_candidates
from .engine.installation_paths import installed_client_candidates
from .engine.paths import installation_candidates, bounded_environment
from .engine.parsing import validate_tree, ParseError
from .engine.filesystem import SafeFiles, Budget, ReadGap
from .engine.adapters.configs import collect_config, collect_cached_settings


def _extra():
    from . import extra_clients
    return extra_clients


class _LocalCollection(Collection):
    """Adapt documented additional MCP shapes before the original adapters run."""
    def __init__(self, *args, **kwargs):
        from .collector import _LocalRedactor
        super().__init__(*args, **kwargs)
        self.builder.redactor = _LocalRedactor()

    def _candidate(self, candidate):
        if candidate.family not in {"continue", "opencode", "antigravity"} or candidate.role != "config":
            return super()._candidate(candidate)
        source, data = self.builder.document(candidate)
        if data is not None:
            normalized = _extra().normalize_extra_data(candidate.family, data)
            collect_config(self.builder, candidate, source, normalized, self.add_workspace)


def _context(candidate):
    if candidate.role == 'settings-cache':
        return 'cached'
    if candidate.scope == 'plugin' or candidate.role in {'plugin', 'skill', 'agent'} and '/plugins/' in candidate.location:
        return 'package'
    if candidate.context.startswith('profile:'):
        return 'profile'
    if candidate.scope == 'managed':
        return 'managed'
    if candidate.scope == 'project' or candidate.context.startswith('project:'):
        return 'project'
    if candidate.path.name in {'.claude.json', '.codex-global-state.json', 'trustedFolders.json'}:
        return 'state'
    return 'base'


def _known_candidates(root, alias, workspace=False):
    from .collector import USER_CONFIGS, WORKSPACE_CONFIGS, SKILLS, AGENTS
    extra = _extra()
    scope = 'project' if workspace else 'user'
    context = 'project:' + alias if workspace else 'user'
    candidates = []
    if workspace:
        candidates.extend(workspace_candidates(root))
    else:
        # Inspect copied cross-platform trees as well as the current OS layout.
        for platform in ('macos', 'linux', 'windows'):
            candidates.extend(user_candidates(root, platform, {}))
            candidates.extend(c for c in supplemental_candidates(root, platform, {}) if c.path.is_relative_to(root))
    configs = (WORKSPACE_CONFIGS + getattr(extra, 'EXTRA_WORKSPACE_CONFIGS', [])) if workspace else (USER_CONFIGS + getattr(extra, 'EXTRA_USER_CONFIGS', []))
    for client, relative, fmt in configs:
        role = 'settings-cache' if relative == '.claude/remote-settings.json' else 'config'
        candidates.append(Candidate(client, scope, root / relative, alias + '/' + relative, fmt, role, context))
    for role, records in [('skills', SKILLS + getattr(extra, 'EXTRA_SKILLS', [])), ('agents', AGENTS + getattr(extra, 'EXTRA_AGENTS', [])), ('plugins', getattr(extra, 'EXTRA_PLUGINS', []))]:
        for client, relative in records:
            if workspace and relative.startswith(('.config/', '.copilot/', '.openclaw/')):
                continue
            candidates.append(Candidate(client, scope, root / relative, alias + '/' + relative, 'directory', role, context))
    result = {}
    for candidate in candidates:
        if not candidate.path.is_relative_to(root):
            continue
        if candidate.family == 'codex' and candidate.path.name == 'hooks.json':
            candidate = replace(candidate, role='config')
        # Shared skill locations represent the same manifest once, while the
        # supported consumer families remain documented in the source catalog.
        if candidate.role == 'skills' and candidate.path == root / '.agents/skills':
            candidate = replace(candidate, family='shared')
        if candidate.role == 'skills' and candidate.path == root / '.claude/skills':
            candidate = replace(candidate, family='claude-code')
        if candidate.role == 'skills' and candidate.path == root / '.codex/skills':
            candidate = replace(candidate, family='codex')
        if candidate.role == 'skills' and candidate.path == root / '.copilot/skills':
            candidate = replace(candidate, family='copilot-cli')
        location = alias + '/' + candidate.path.relative_to(root).as_posix()
        candidate = replace(candidate, location=location, scope=scope if candidate.role != 'settings-cache' else 'managed', context=context)
        result.setdefault((candidate.family, candidate.path, candidate.role), candidate)
    return list(result.values())


def _safe_version(value):
    return value if isinstance(value, str) and re.fullmatch(r'\d{1,5}(?:\.\d{1,7}){0,4}(?:[-+][A-Za-z0-9.-]{1,32})?', value) else None


def _artifact_index(builder):
    packages, mcp_paths = {}, {candidate.path for candidate, _, _, _ in builder.mcp_documents}
    for observation in builder.observations.values():
        if observation["kind"] != "plugin":
            continue
        origin = builder.candidates.get(observation["sourceId"])
        if origin is None or origin.role != "plugin":
            continue
        directory = origin.path.parent.parent if origin.path.parent.name in {".codex-plugin", ".claude-plugin", ".cursor-plugin"} else origin.path.parent
        packages[directory] = observation.get("installationState", "unknown")
    for identity, data in builder.documents.items():
        candidate = builder.candidates.get(identity)
        if candidate and any(key in data for key in ("mcpServers", "mcp_servers", "servers")):
            mcp_paths.add(candidate.path)
    return packages, mcp_paths


def _source_artifact_metadata(builder, candidate, old, collection, index):
    """Fixed artifact labels and stat-backed byte counts for concrete gaps."""
    if candidate is None:
        return {}
    role = candidate.role
    artifact = role if role in {"skill", "agent", "plugin", "skills", "agents", "plugins"} else "installation" if role.startswith("installed-") or role == "installation" else "configuration"
    kind = {"skills": "skill", "agents": "agent", "plugins": "plugin"}.get(artifact, artifact)
    result = {"artifactRole": artifact, "componentKind": kind}
    packages, mcp_paths = index
    for directory in (candidate.path, *candidate.path.parents):
        if directory in packages:
            result["packageState"] = packages[directory]
            break
    is_mcp = candidate.path in mcp_paths
    is_mcp |= candidate.path.name in {".mcp.json", "mcp.json", "mcp_config.json", "mcp-config.json", "cline_mcp_settings.json", "mcp_settings.json"}
    if is_mcp:
        result.update(classification="mcp-configuration", componentKind="mcp")
        if old["reason"] == "unknown_schema":
            result["issueKind"] = "unsupported-mcp-shape"
    elif old["id"] in builder.component_parents and candidate.path.name == "hooks.json":
        result["componentKind"] = "hook"
    if old["reason"] == "size_limit":
        try:
            path = collection.files.approve(candidate.path)
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_size >= 0:
                result["sizeBytes"] = info.st_size
                result["limitBytes"] = collection.options.max_file_bytes
        except (ReadGap, OSError, ValueError):
            pass
    return result


def _source_location(collector, candidate, old, home, alias):
    """Publish the actual local declaration path, with only the home abbreviated."""
    if candidate is None or candidate.format == "registry" or any(part in {".palma-in-memory", ".palma-scan-discovery"} for part in candidate.path.parts):
        location = old["location"]
    elif alias == "~" and candidate.path.is_relative_to(home):
        location = "~/" + candidate.path.relative_to(home).as_posix()
    else:
        location = candidate.path.as_posix()
    if candidate and candidate.format == "sqlite" and "#" in old["location"]:
        location += "#" + old["location"].rsplit("#", 1)[1]
    return collector.display_text(location, maximum=4096)


def _merge(collector, collection, alias, workspaces):
    """Translate complete sanitized evidence and actionable local item labels."""
    from .collector import _id, SETTING_TYPES
    builder = collection.builder
    collector.redactor = builder.redactor
    artifact_index = _artifact_index(builder)
    extra = _extra()
    for client, definitions in getattr(extra, 'EXTRA_SETTING_TYPES', {}).items():
        SETTING_TYPES.setdefault(client, {}).update(definitions)
    sources = {}
    for old in builder.sources.values():
        candidate = builder.candidates.get(old['id'])
        context = _context(candidate) if candidate else 'base'
        status = {'absent': 'missing', 'invalid': 'error', 'unreadable': 'error', 'unsupported': 'skipped'}.get(old['status'], old['status'])
        system_owned = candidate and ((candidate.scope == 'managed' and context != 'cached') or (candidate.scope == 'installation' and not candidate.path.is_relative_to(collection.home)))
        account = 'system' if system_owned else alias
        source = {'id': 'src-' + old['id'][:24], 'client': old['family'], 'scope': 'system' if account == 'system' else 'workspace' if context == 'project' else 'user',
                  'location': _source_location(collector, candidate, old, collection.home, alias), 'status': status, 'reason': '' if old['reason'] == 'none' else old['reason'], 'context': context, 'accountAlias': account}
        source.update(_source_artifact_metadata(builder, candidate, old, collection, artifact_index))
        if candidate and candidate.format == 'sqlite':
            source['storage'] = 'editor-state'
        if old.get('sizeBytes') is not None:
            source['sizeBytes'] = old['sizeBytes']
        if old.get('modifiedAt') is not None:
            source['modifiedAt'] = old['modifiedAt']
        collector.sources.append(source)
        sources[old['id']] = source
        if status not in {'collected', 'missing'}:
            collector.gaps.add(source['location'] + ': ' + source['reason'])
    processed_mcps = set()
    for identity, data in builder.documents.items():
        source, candidate = sources.get(identity), builder.candidates.get(identity)
        if not source or not candidate or candidate.role.startswith('installed-') or candidate.role in {'registry-probe', 'installation'}:
            continue
        context = source['context']
        start = len(collector.observations)
        normalizer = getattr(extra, 'normalize_extra_data', None)
        normalized = normalizer(source['client'], data) if normalizer else data
        if candidate.role in {'agent', 'plugin', 'skill'} or candidate.scope == 'plugin':
            # A package declaration is not a client settings file. Only its
            # documented integration/hooks blocks and credential presence apply.
            from .collector import _credential_counts
            literal, references = _credential_counts(normalized)
            if literal or references:
                counts = {'literalCredentialCount': literal, 'credentialReferenceCount': references}
                collector.observe(source, 'setting', 'Package credential storage', {'key': 'credentialStorage', 'value': counts, **counts}, discriminator='package-credentials')
            collector.extensions(source, normalized, context)
            key = 'mcp_servers' if 'mcp_servers' in normalized else 'mcpServers'
            if key in normalized:
                collector.mcps(source, normalized[key], context=context, map_key=key)
        else:
            collector.process_data(collection.home, source, normalized, context, candidate.path.name)
        for item in collector.observations[start:]:
            if context == 'profile':
                item['details'].update(applicability='named profile selection not observed', profileId='profile-' + _id(candidate.context))
            if identity in builder.component_parents and item['kind'] in {'hook', 'mcp'}:
                item['details']['parentId'] = 'obs-' + _id('engine', alias, builder.component_parents[identity])
        if any(item['kind'] == 'mcp' for item in collector.observations[start:]):
            processed_mcps.add((identity, candidate.context))
        # The extension extractor adds typed summaries to the raw allowlisted
        # extraction, never body text or arbitrary connection identifiers.
        extractor = getattr(extra, 'extract_extra', None)
        if extractor and candidate.role not in {'agent', 'plugin', 'skill'} and candidate.scope != 'plugin':
            extractor(collector, source, data)
        if context == 'profile':
            for item in collector.observations[start:]:
                item['details'].update(applicability='named profile selection not observed', profileId='profile-' + _id(candidate.context))
        if candidate.format == 'sqlite':
            for item in collector.observations[start:]:
                item['details']['provenance'] = 'persisted-editor-extension-settings'
    for candidate, old_source, entries, parent_id in builder.mcp_documents:
        if (old_source['id'], candidate.context) in processed_mcps:
            if parent_id:
                for item in collector.observations:
                    if item['kind'] == 'mcp' and item['sourceId'] == sources[old_source['id']]['id']:
                        item['details']['parentId'] = 'obs-' + _id('engine', alias, parent_id)
            continue
        source = sources.get(old_source['id'])
        if not source:
            continue
        normalized = {}
        for name, entry in entries.items():
            if isinstance(entry, dict) and candidate.family == 'cline' and isinstance(entry.get('transport'), dict):
                entry = {**entry, **entry['transport']}
            normalized[name] = entry
        context = 'package' if parent_id else _context(candidate)
        source_view = dict(source, context=context)
        start = len(collector.observations)
        collector.mcps(source_view, normalized, context=context, map_key='mcpServers' if candidate.family != 'codex' else 'mcp_servers')
        for item in collector.observations[start:]:
            item['id'] = 'obs-' + _id(item['id'], candidate.context, parent_id)
            item['details']['contextId'] = 'context-' + _id(candidate.context)
            if parent_id:
                item['details']['parentId'] = 'obs-' + _id('engine', alias, parent_id)
        processed_mcps.add((old_source['id'], candidate.context))
    typed_keys = {(item['sourceId'], item['details'].get('key')) for item in collector.observations if item['kind'] == 'setting'}
    hook_sources = {item['sourceId'] for item in collector.observations if item['kind'] == 'hook'}
    for old in builder.observations.values():
        source = sources.get(old.get('sourceId'))
        if not source:
            continue
        kind = old['kind']
        candidate = builder.candidates.get(old['sourceId'])
        context = source['context']
        details = {'context': context, 'accountAlias': source['accountAlias'], 'contextId': 'context-' + _id(old.get('contextId', ''))}
        enabled = old.get('enabled', 'unknown')
        name = kind.title()
        if kind == 'client':
            details.update(installationState=old.get('installationState', 'config_only'), activation='installed' if old.get('installationState') == 'installed' else 'present', variant=old.get('variant', 'unknown'), authModes=old.get('authModes', ['unknown']), authEvidence=old.get('authEvidence', 'unknown'))
            version = _safe_version(old.get('version'))
            if version:
                details['version'] = version
            name = source['client']
        elif kind == 'mcp':
            continue  # Exact sanitized facts above supersede the old MCP shape.
        elif kind == 'setting':
            key = old.get('nativeKey')
            if not key or key == 'profiles' or (source['id'], key) in typed_keys or (not old.get('valueCollected') and any(identity == source['id'] and typed.startswith(key + '.') for identity, typed in typed_keys if isinstance(typed, str))):
                continue
            if key == 'hooks' and not old.get('valueCollected') and source['id'] in hook_sources:
                continue  # Typed hook evidence already represents this block.
            # A recognized key with the wrong type is a gap, not fallback fact.
            if key in SETTING_TYPES.get(source['client'], {}):
                continue
            details.update(key=key, nativeKey=key, effectiveState=old.get('effectiveState', 'unknown'), value=old.get('value'), valueCollected=old.get('valueCollected', False), valueType=old.get('valueType', 'unknown'), category=old.get('category', 'other'), interpretation='inventory-only', declaredState=old.get('effectiveState', 'unknown'))
            name = key
        elif kind in {'skill', 'agent', 'plugin'}:
            # Configured plugin declarations already have exact enabled flags.
            if kind == 'plugin' and old.get('installationState') == 'config_only' and any(o['kind'] == 'plugin' and o['sourceId'] == source['id'] for o in collector.observations):
                continue
            details.update(activation={'config_only': 'configured', 'cached': 'cached', 'installed': 'installed'}.get(old.get('installationState'), 'present'), auditStatus='not-assessed', origin=old.get('origin', 'unknown'))
            if type(source.get('sizeBytes')) is int:
                details['manifestSizeBytes'] = source['sizeBytes']
            if kind == 'plugin':
                details.update(artifactType=old.get('artifactType', 'plugin'), installationState=old.get('installationState', 'unknown'))
            version = _safe_version(old.get('version'))
            if version:
                details['version'] = version
            if kind == 'skill':
                details.update(digest=old.get('digest'), digestAlgorithm=old.get('digestAlgorithm'), filesHashed=old.get('filesHashed', 0), manifestType='SKILL.md')
            if kind == 'agent':
                details.update(toolCount=len(old.get('toolNames', [])), declaredToolCount=len(old.get('toolNames', [])), modelConfigured=bool(old.get('model')))
                data = builder.documents.get(old['sourceId'], {})
                if data.get('kind') == 'remote' and (isinstance(data.get('agent_card_url'), str) or isinstance(data.get('agent_card_json'), dict)):
                    details['delegation'] = 'remote'
                    details['activation'] = 'configured'
                details['declaredToolCategories'] = sorted({category for name in old.get('toolNames', []) for category, names in {'filesystem': {'Read', 'Write', 'Edit', 'Grep', 'Glob'}, 'execution': {'Bash', 'run_shell_command'}, 'browser': {'browser', 'browser_use', 'computer'}}.items() if name in names})
            if old.get('parentId'):
                details['parentId'] = 'obs-' + _id('engine', alias, old['parentId'])
                details['context'] = 'package'
            fallback = candidate.path.parent.name if candidate and kind == 'skill' else candidate.path.stem if candidate else kind.title()
            name = old.get('name') or fallback
            details['declaration'] = source['location']
        else:
            continue
        item = collector.observe(source, kind, name, details, enabled, discriminator='engine:' + old['id'])
        item['id'] = 'obs-' + _id('engine', alias, old['id'])



def _add_editor_state(collection, alias):
    helper = getattr(_extra(), 'extra_state_documents', None)
    if helper is None:
        return
    options = replace(collection.options, max_file_bytes=64 * 1024 * 1024, max_total_bytes=128 * 1024 * 1024)
    files = SafeFiles([collection.home], Budget(options, time.monotonic()))
    from .collector import _id
    for record in helper(collection.home, files=files):
        relative = Path(record['relative'])
        path = collection.home / relative
        if relative.is_absolute() or '..' in relative.parts or not path.is_relative_to(collection.home):
            raise ValueError('invalid state source boundary')
        location = alias + '/' + record.get('location', relative.as_posix())
        context = record.get('context', 'base')
        candidate = Candidate(record['client'], 'user', path, location, 'sqlite', 'editor-state:' + _id(record.get('extensionId', record['client'])), 'profile:' + location if context == 'profile' else 'user')
        source = collection.builder.source(candidate)
        status = {'error': 'invalid', 'skipped': 'skipped', 'collected': 'collected'}.get(record.get('status'), 'invalid')
        source.update(status=status, reason=record.get('reason') or 'none')
        if type(record.get('sizeBytes')) is int:
            source['sizeBytes'] = record['sizeBytes']
        data = record.get('data')
        if isinstance(data, dict) and data:
            try:
                validate_tree(data)
                collection.builder.adopt_document(source, data)
                collect_config(collection.builder, candidate, source, data, lambda _: False)
            except (ValueError, TypeError, RecursionError):
                source.update(status='invalid', reason='parse_error')
    collection.builder.finish()

def collect_scopes(profiles, system_sources=None, workspaces=None, *, scope_type='machine', discovery_gaps=None, include_installations=False):
    from .collector import _Collector, _id, MAX_MANIFESTS
    from .governance import RULES_VERSION
    started = datetime.now(timezone.utc).isoformat()
    selected = []
    for index, profile in enumerate(profiles):
        root = Path(profile['root']).absolute()
        alias = profile.get('alias', '~' if index == 0 else 'user-' + str(index))
        if root.parent == root or '..' in root.parts or not (alias == '~' or re.fullmatch(r'user-\d+', alias)):
            raise ValueError('invalid profile root or alias')
        selected.append((root, alias))
    if len({a for _, a in selected}) != len(selected) or len({str(p) for p, _ in selected}) != len(selected):
        raise ValueError('duplicate profile')
    roots = list(dict.fromkeys(Path(p).absolute() for p in (workspaces or [])))
    if any(root.parent == root or '..' in root.parts for root in roots):
        raise ValueError('invalid workspace root')
    collector = _Collector()
    collector.gaps.update(discovery_gaps or [])
    machine = include_installations
    platform = HOST_OS.get(sys.platform, 'linux')
    owned = set()
    anchor = selected[0][0] if selected else roots[0] if roots else Path(__file__).absolute().parent
    processing = selected or [(anchor, '~')]
    for root, alias in processing:
        assigned = [p for p in roots if p.is_relative_to(root) and not any(p.is_relative_to(other) for other, _ in selected if other != root and other.is_relative_to(root))]
        if root == processing[0][0]:
            assigned += [p for p in roots if not any(p.is_relative_to(other) for other, _ in selected)]
        candidates = _known_candidates(root, alias) if selected else []
        for workspace in assigned:
            owned.add(workspace)
            candidates += _known_candidates(workspace, 'workspace-' + str(roots.index(workspace) + 1), True)
        if machine:
            env = dict(os.environ) if alias == '~' else {}
            env, rejected = bounded_environment(env, platform, root)
            for key in rejected:
                source = {'id': 'src-' + _id('environment-override', alias, key), 'client': 'machine',
                          'scope': 'user', 'location': alias + ': environment override ' + key,
                          'status': 'collected', 'accountAlias': alias}
                collector.sources.append(source)
                collector.gap(source, 'unsupported environment directory override; value withheld')
            overrides = user_candidates(root, platform, env) + supplemental_candidates(root, platform, env)
            overrides = [replace(c, role='config') if c.family == 'codex' and c.path.name == 'hooks.json' else c for c in overrides]
            known = {(c.family, c.path, c.role) for c in candidates}
            candidates += [replace(c, location=alias + '/' + c.location) for c in overrides if (c.family, c.path, c.role) not in known]
            installed = installed_client_candidates(root, platform, env, discover_os_packages=True)
            if alias != '~':
                installed = [c for c in installed if c.path.is_relative_to(root)]
            candidates = installed + (installation_candidates(platform, env) if alias == '~' else []) + candidates
        else:
            env = {}
            # Preserve native/package installation metadata inside a copied home
            # without reading this scanner host's package registries or paths.
            for layout in (('macos', 'linux', 'windows') if selected else ()):
                candidates += [c for c in installed_client_candidates(root, layout, {}, discover_os_packages=False) if c.path.is_relative_to(root) and c.format != 'registry' and not getattr(c, 'query_status', None)]
        candidates = list({(c.family, c.path, c.role, c.context): c for c in candidates}.values())
        # Dynamic project candidates from original state maps use these roots.
        options = CollectOptions(home=root, os_name=platform, environ=env, workspaces=assigned, discover_os_packages=machine, max_manifests=MAX_MANIFESTS)
        collection = _LocalCollection(options, ('local', alias), candidates)
        # Initial candidates already contain full workspace layouts. Original
        # state discovery may add further in-scope project roots while running.
        collection.run()
        if selected:
            _add_editor_state(collection, alias)
        _merge(collector, collection, alias, roots)
    if system_sources:
        root = anchor
        candidates, memory = [], []
        for index, entry in enumerate(system_sources):
            location = entry.get('location', 'system:source-' + str(index + 1))
            if not isinstance(location, str) or not location.startswith('system:'):
                raise ValueError('system source requires a fixed safe location')
            context = entry.get('context', 'managed')
            candidate = Candidate(entry['client'], 'managed' if context == 'managed' else 'system', Path(entry.get('path', root / '.palma-in-memory' / str(index))), location, entry.get('format', 'json'), entry.get('role', 'config'), context)
            (memory if 'data' in entry else candidates).append((candidate, entry['data']) if 'data' in entry else candidate)
        options = CollectOptions(home=root, os_name=platform, environ={}, max_manifests=MAX_MANIFESTS)
        collection = _LocalCollection(options, ('local', 'system'), candidates)
        collection.run()
        for candidate, data in memory:
            source = collection.builder.source(candidate)
            try:
                validate_tree(data)
                if not isinstance(data, dict):
                    raise ParseError('root must be an object')
                collection.builder.adopt_document(source, data)
                normalized = _extra().normalize_extra_data(candidate.family, data)
                collect_config(collection.builder, candidate, source, normalized, lambda _: False)
            except (ValueError, TypeError, RecursionError):
                source.update(status='invalid', reason='parse_error')
        collection.builder.finish()
        _merge(collector, collection, 'system', roots)
    # Shared graph edges and repeated candidates resolve to one deterministic row.
    sources = list({s['id']: s for s in collector.sources}.values())
    observations = list({o['id']: o for o in collector.observations}.values())
    return {'schemaVersion': '2.0', 'collector': {'name': 'palma-ai-readiness', 'version': __version__, 'rulesVersion': RULES_VERSION}, 'mode': 'endpoint', 'startedAt': started, 'completedAt': datetime.now(timezone.utc).isoformat(), 'status': 'partial' if collector.gaps else 'complete', 'scope': {'type': scope_type, 'workspaceCount': len(roots), 'profileCount': len(selected)}, 'sources': sources, 'observations': observations, 'coverage': {'limitations': sorted(collector.gaps)}}
