"""Process recognized document roots without interpreting instructions."""
from dataclasses import replace
import os
from pathlib import Path

from ..identity import fingerprint
from ..filesystem import ReadGap
from .mcp import collect_mcps
from .settings import (CLAUDE_PROJECT_SWITCHES, CODEX_PROJECT_SWITCHES, category, claude_state_switches, client_auth,
                       collect_settings, safe_value, value_type)


def collect_cached_settings(builder, candidate, source, data):
    """A cached policy declares settings, not client sign-in or installed plugins."""
    builder.ensure_client(candidate, source)
    collect_settings(builder, candidate, source, data)


def collect_config(builder, candidate, source, data, approved_workspace):
    builder.ensure_client(candidate, source)
    if candidate.path.name == "trustedFolders.json":
        _trusted_folders(builder, candidate, source, data)
        return
    field = "mcp_servers" if candidate.family == "codex" else "mcpServers"
    if candidate.family == "vscode" or (candidate.path.name == "mcp.json" and "servers" in data):
        field = "servers"
    if field in data:
        collect_mcps(builder, candidate, source, data[field])
    if candidate.family in {"claude-code", "codex"} and isinstance(data.get("projects"), dict):
        _project_entries(builder, candidate, source, data["projects"], approved_workspace)
    collect_settings(builder, candidate, source, claude_state_switches(data) if candidate.path.name == ".claude.json" else data)
    client_auth(builder, candidate, source, data)
    configured_plugins(builder, candidate, source, data)


def _roots(builder):
    """Where per-folder client state may be exported from: the user's home plus the operator's approved workspaces and search roots."""
    options = builder.options
    home = getattr(options, "home", None)
    # Normalised exactly as the collection normalises its scan roots, so a relative --workspace still counts.
    roots = [(Path(home) if home is not None else Path.home()).expanduser().absolute()]
    for group in ("workspaces", "search_roots"):
        roots.extend(Path(item).expanduser().absolute() for item in getattr(options, group, ()) or ())
    return roots


def _in_scope(path, roots):
    try:
        return any(Path(path).is_relative_to(root) for root in roots)
    except (RuntimeError, OSError, ValueError):
        return False


def _folder_state(path):
    """`stale` when the folder a client entry refers to is gone while its parent folder is present:
    direct evidence of a removal on every layout. A folder whose parent is absent too (an unmounted
    share, an unplugged drive) or a path that cannot be checked (malformed, too long, unreadable)
    is not stale: it stays `unknown`."""
    try:
        os.stat(path)
        return "unknown"
    except (FileNotFoundError, NotADirectoryError):
        pass
    except (RuntimeError, OSError, ValueError):
        return "unknown"
    try:
        return "stale" if Path(path).parent.is_dir() else "unknown"
    except (RuntimeError, OSError, ValueError):
        return "unknown"


def _project_context(candidate, workspace):
    return replace(candidate, scope="project", context="project:" + fingerprint(str(workspace)))


def _project_entries(builder, candidate, source, projects, approved_workspace):
    """Per-folder client state: Claude Code's `projects` map (trust dialog, allowed tools, project MCP
    servers) and Codex's `[projects."<path>"]` trust levels. An entry whose folder is missing is stale:
    it is inventoried with `effectiveState: stale` so the audit can remove it, and nothing else.
    Claude Code entries approve their folder for scanning (as before); Codex entries only export
    the folder's trust level, for folders inside the user's home or an approved root, without
    enqueuing a scan."""
    switches = CODEX_PROJECT_SWITCHES if candidate.family == "codex" else CLAUDE_PROJECT_SWITCHES
    roots = _roots(builder)
    stale = 0
    for path, config in projects.items():
        if not isinstance(config, dict):
            continue
        workspace = Path(path)
        if not workspace.is_absolute():
            builder.gap(candidate, "unknown_schema", "unsupported")
            continue
        if not _in_scope(workspace, roots):
            continue
        try:
            builder.files.approve(workspace)
        except ReadGap:
            continue
        state = _folder_state(workspace)
        if state == "unknown":
            approved = approved_workspace(workspace) if candidate.family == "claude-code" else _in_scope(workspace, roots)
            if not approved:
                builder.gap(candidate, "outside_scope")
                continue
        project = _project_context(candidate, workspace)
        if state == "stale":
            # An ordinal, not a hash of the path: a hash would let anyone confirm a guessed folder.
            stale += 1
            label = f"projects.stale-{stale}"
            builder.emit(project, source, "setting", label, nativeKey=label, category="other", valueType="object",
                         value=None, valueCollected=False, effectiveState="stale")
        elif candidate.family == "claude-code" and "mcpServers" in config:
            collect_mcps(builder, project, source, config["mcpServers"])
        collect_settings(builder, project, source, {key: config[key] for key in switches if key in config}, "projects.", state=state)


def _trusted_folders(builder, candidate, source, data):
    """Gemini CLI's `trustedFolders.json`: `{"<folder>": "TRUST_FOLDER" | "TRUST_PARENT" | "DO_NOT_TRUST"}`.
    Exported for folders inside the user's home or an approved root (or gone ones); nothing under them is read."""
    roots = _roots(builder)
    for path, level in data.items():
        if not isinstance(path, str) or not Path(path).is_absolute():
            builder.gap(candidate, "unknown_schema", "unsupported")
            continue
        if not _in_scope(path, roots):
            continue
        try:
            builder.files.approve(Path(path))
        except ReadGap:
            continue
        state = _folder_state(path)
        if state == "unknown" and not _in_scope(path, roots):
            builder.gap(candidate, "outside_scope")
            continue
        safe, collected = safe_value("trustedFolders", level)
        builder.emit(_project_context(candidate, Path(path)), source, "setting", "trustedFolders", nativeKey="trustedFolders",
                     category=category("trustedFolders"), valueType=value_type(level), value=safe, valueCollected=collected,
                     effectiveState=state)


def configured_plugins(builder, candidate, source, data):
    entries = data.get("enabledPlugins") if candidate.family == "claude-code" else data.get("plugins")
    if not isinstance(entries, dict):
        return
    for name, entry in entries.items():
        value = entry if isinstance(entry, bool) else entry.get("enabled") if isinstance(entry, dict) else None
        enabled = "enabled" if value is True else "disabled" if value is False else "unknown"
        builder.emit(candidate, source, "plugin", name, artifactType="plugin", version=None,
                     origin="unknown", installationState="config_only", enabled=enabled)
