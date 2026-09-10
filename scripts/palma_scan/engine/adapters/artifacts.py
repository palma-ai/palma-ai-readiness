"""Passive skill/agent metadata and raw bundle hashes.

sha256-raw-manifest-v1 is SHA256 of UTF-8 compact JSON (ensure_ascii=False,
separators=(',', ':')) containing [POSIX relative filename, sha256(raw bytes)]
entries sorted by relative filename. The manifest itself is never exported.
Every regular file in a skill bundle participates; incomplete hashes are null.
"""
import hashlib
import json
import stat

from ..filesystem import ReadGap
from ..parsing import ParseError, parse_document
from .mcp import collect_mcps


def metadata_name(data, fallback):
    return data["name"] if isinstance(data.get("name"), str) and data["name"].strip() else fallback


def scan_skills(builder, candidate, parent_id=None, depth=0, allow_plugin=True):
    if depth > 12:
        builder.gap(candidate, "count_limit")
        return
    _, children = builder.directory(candidate)
    if children is None:
        return
    if allow_plugin and depth == 1 and candidate.family == "claude-code" and any(path.name == ".claude-plugin" for path in children):
        from .plugins import collect_plugin
        collect_plugin(builder, candidate, candidate.path / ".claude-plugin/plugin.json")
        return
    manifest = next((child for child in children if child.name == "SKILL.md"), None)
    if manifest:
        collect_skill(builder, candidate, manifest, parent_id)
        return
    for path in children:
        # Resource-like names can identify installed skills or skill namespaces.
        # Once a manifest is found above, its resources are hashed, not inventoried.
        if path.name in {"node_modules", ".git", ".venv", "__pycache__"}:
            continue
        child = candidate.child(path, "skills", "directory")
        try:
            if stat.S_ISDIR(builder.files.info(path).st_mode):
                scan_skills(builder, child, parent_id, depth + 1, allow_plugin=allow_plugin)
        except ReadGap as error:
            builder.gap(child, error.reason, error.status)


def collect_skill(builder, directory, manifest, parent_id):
    candidate = directory.child(manifest, "skill", "markdown")
    source, raw = builder.read(candidate)
    if raw is None:
        return
    try:
        data = parse_document(raw, "markdown")
        builder.redactor.learn(data)
    except ParseError:
        source.update(status="invalid", reason="parse_error")
        return
    digest, count = bundle_digest(builder, directory, manifest, raw)
    builder.emit(candidate, source, "skill", metadata_name(data, directory.path.name),
                 origin=candidate.scope, digest=digest, digestAlgorithm="sha256-raw-manifest-v1",
                 filesHashed=count, enabled="unknown", parentId=parent_id)


def bundle_digest(builder, directory, manifest, manifest_raw):
    entries, pending, complete = [], [(directory.path, 0)], True
    while pending:
        current, depth = pending.pop()
        try:
            if depth > 20:
                raise ReadGap("count_limit")
            for path in builder.files.children(current):
                info = builder.files.info(path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append((path, depth + 1))
                elif stat.S_ISREG(info.st_mode):
                    if len(entries) >= 2000:
                        raise ReadGap("count_limit")
                    raw = manifest_raw if path == manifest else builder.files.read(path)[0]
                    entries.append([path.relative_to(directory.path).as_posix(), hashlib.sha256(raw).hexdigest()])
                else:
                    raise ReadGap("unknown_schema", "unsupported")
        except ReadGap as error:
            complete = False
            builder.gap(directory, error.reason, error.status)
            if error.reason in {"time_limit", "count_limit", "size_limit"}:
                break
    try:
        encoded = json.dumps(sorted(entries), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest() if complete else None, len(entries)
    except UnicodeError:
        builder.gap(directory, "unknown_schema", "unsupported")
        return None, len(entries)


def scan_agents(builder, candidate, parent_id=None):
    _, children = builder.directory(candidate)
    if children is None:
        return
    for path in children:
        collect_agent(builder, candidate, path, parent_id)


def collect_agent(builder, candidate, path, parent_id=None):
    suffix = path.suffix.lower()
    if suffix not in {".md", ".json", ".yaml", ".yml"}:
        return
    fmt = "markdown" if suffix == ".md" else "json" if suffix == ".json" else "yaml"
    child = candidate.child(path, "agent", fmt)
    source, data = builder.document(child)
    if data is None:
        return
    tools = data.get("tools", data.get("allowedTools", []))
    tools = [part.strip() for part in tools.split(",")] if isinstance(tools, str) else tools
    tools = [tool for tool in tools if isinstance(tool, str)][:100] if isinstance(tools, list) else []
    model = data.get("model") if isinstance(data.get("model"), str) else None
    agent = builder.emit(child, source, "agent", metadata_name(data, path.stem),
                         model=model, toolNames=tools, enabled="unknown", parentId=parent_id)
    if agent and "mcpServers" in data:
        collect_mcps(builder, child, source, data["mcpServers"], agent["id"])
