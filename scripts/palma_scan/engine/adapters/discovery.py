"""Bounded project and profile discovery inside explicitly selected roots."""
import stat
import re
from dataclasses import replace

from ..filesystem import ReadGap
from ..identity import fingerprint
from ..paths import Candidate

SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__", "Library", "AppData", ".cache"}
MARKERS = {".git", ".agents", ".claude", ".codex", ".cursor", ".gemini", ".kiro", ".vscode", ".roo", ".cline"}


def search_workspaces(builder, roots, add_workspace):
    pending = [(root, 0) for root in roots]
    while pending:
        directory, depth = pending.pop()
        candidate = Candidate("unknown", "project", directory, "search:" + fingerprint(str(directory))[:16], "directory")
        try:
            children = builder.files.children(directory)
            if any(child.name in MARKERS for child in children):
                add_workspace(directory)
            if depth >= 8:
                builder.gap(candidate, "count_limit")
                continue
            for child in children:
                if child.name in SKIP or child.name.startswith("."):
                    continue
                if stat.S_ISDIR(builder.files.info(child).st_mode):
                    pending.append((child, depth + 1))
        except ReadGap as error:
            builder.gap(candidate, error.reason, error.status)
            if error.reason in {"time_limit", "count_limit"}:
                break


def profile_configs(builder, candidate):
    _, children = builder.directory(candidate)
    if children is None:
        return []
    result = []
    for directory in children:
        try:
            if not stat.S_ISDIR(builder.files.info(directory).st_mode):
                continue
            for name in ("settings.json", "mcp.json"):
                child = candidate.child(directory / name, "config", "jsonc")
                result.append(replace(child, context="profile:" + fingerprint(str(directory))))
        except ReadGap as error:
            builder.gap(candidate, error.reason, error.status)
    return result


def dropin_configs(builder, candidate):
    _, children = builder.directory(candidate)
    if children is None:
        return []
    return [candidate.child(child) for child in children if child.suffix == ".json" and not child.name.startswith(".")]


def codex_profile_configs(builder, candidate):
    _, children = builder.directory(candidate)
    if children is None:
        return []
    return [replace(candidate.child(path, "config", "toml"), context="profile:" + fingerprint(str(path)))
            for path in children if re.fullmatch(r"[A-Za-z0-9_-]+\.config\.toml", path.name)]
