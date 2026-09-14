"""Inspect plugin manifests and bundled declarations without loading any code."""
import stat

from ..filesystem import ReadGap
from .artifacts import metadata_name
from .mcp import collect_mcps
from .plugin_components import component_path, component_references, scan_plugin_agents, scan_plugin_skills

MANIFEST_DIRS = {".claude-plugin", ".codex-plugin", ".cursor-plugin"}
SKIP_DIRS = {"node_modules", ".git", ".venv", "__pycache__"}


def scan_plugins(builder, candidate, depth=0):
    if depth > 6:
        builder.gap(candidate, "count_limit")
        return
    _, children = builder.directory(candidate)
    if children is None:
        return
    manifest = next((path for path in children if path.name == "gemini-extension.json"), None)
    for path in children:
        if path.name in MANIFEST_DIRS:
            manifest = path / "plugin.json"
            break
    if manifest:
        collect_plugin(builder, candidate, manifest)
        return
    for path in children:
        if path.name in SKIP_DIRS:
            continue
        child = candidate.child(path, "plugins", "directory")
        try:
            if stat.S_ISDIR(builder.files.info(path).st_mode):
                with builder.isolated(child):
                    scan_plugins(builder, child, depth + 1)
        except ReadGap as error:
            builder.gap(child, error.reason, error.status)


def collect_plugin(builder, directory, manifest):
    candidate = directory.child(manifest, "plugin", "json", "plugin")
    source, data = builder.document(candidate)
    if data is None:
        return
    gemini = manifest.name == "gemini-extension.json"
    # Copilot's install directory is literally named installed-plugins; Codex's cache
    # is joined to its configuration and remote-install records by the marketplace policy.
    installed = gemini or directory.role == "skills" or "installed-plugins" in directory.path.parts
    plugin = builder.emit(candidate, source, "plugin", metadata_name(data, directory.path.name),
                          artifactType="extension" if gemini else "plugin",
                          version=data.get("version") if isinstance(data.get("version"), str) else None,
                          origin="unknown", installationState="installed" if installed else "cached", enabled="unknown")
    if not plugin:
        return
    parent = plugin["id"]
    scan_plugin_skills(builder, directory, data, parent, manifest.parent.name == ".claude-plugin")
    scan_plugin_agents(builder, directory, data, parent)
    if isinstance(data.get("mcpServers"), dict):
        collect_mcps(builder, candidate, source, data["mcpServers"], parent)
    hooks = data.get("hooks")
    if isinstance(hooks, (str, list)):
        for reference in component_references(builder, directory, hooks):
            read_hook_reference(builder, directory, reference, parent)
    else:
        read_hook_reference(builder, directory, "./hooks/hooks.json", parent)
    builder.component_parents[source["id"]] = parent
    files = data.get("mcpServers") if "mcpServers" in data and not isinstance(data["mcpServers"], dict) else ["./.mcp.json"]
    for file in component_references(builder, directory, files):
        read_mcp_reference(builder, directory, file, parent)


def read_mcp_reference(builder, directory, relative, parent_id):
    path = component_path(builder, directory, relative)
    if path is None:
        return
    child = directory.child(path, "config", "json", "plugin")
    source, data = builder.document(child)
    if data is not None:
        entries = data["mcp_servers"] if directory.family == "codex" and "mcp_servers" in data else data.get("mcpServers", data)
        collect_mcps(builder, child, source, entries, parent_id)


def read_hook_reference(builder, directory, relative, parent_id):
    path = component_path(builder, directory, relative)
    if path is None:
        return
    child = directory.child(path, "config", "json", "plugin")
    source, data = builder.document(child)
    if data is not None:
        builder.component_parents[source["id"]] = parent_id
