"""Select declared plugin components without interpreting or executing paths."""
import stat
from pathlib import PureWindowsPath

from ..filesystem import ReadGap
from .artifacts import collect_agent, collect_skill, scan_agents, scan_skills

MAX_REFERENCES = 20


def component_references(builder, directory, value):
    references = [value] if isinstance(value, str) else value
    if not isinstance(references, list):
        builder.gap(directory, "unknown_schema", "unsupported")
        return []
    if len(references) > MAX_REFERENCES:
        builder.gap(directory, "count_limit")
    return references[:MAX_REFERENCES]


def component_path(builder, directory, relative):
    if not isinstance(relative, str) or not relative:
        builder.gap(directory, "unknown_schema", "unsupported")
        return None
    if "\x00" in relative:
        builder.gap(directory, "parse_error", "invalid")
        return None
    path = directory.path / relative
    windows = PureWindowsPath(relative)
    if windows.drive or windows.root or ".." in windows.parts or not path.is_relative_to(directory.path):
        builder.gap(directory, "outside_scope")
        return None
    return path


def scan_plugin_skills(builder, directory, data, parent_id, claude):
    references = component_references(builder, directory, data["skills"]) if "skills" in data else []
    if claude or "skills" not in data:
        references.insert(0, "./skills")
    seen = set()
    for relative in references:
        path = component_path(builder, directory, relative)
        if path is None or path in seen:
            continue
        seen.add(path)
        child = directory.child(path, "skills", "directory", "plugin")
        scan_skills(builder, child, parent_id, allow_plugin=False)
    if claude and "skills" not in data:
        collect_root_skill(builder, directory, parent_id)


def collect_root_skill(builder, directory, parent_id):
    # Claude's root fallback is exact: arbitrary nested libraries are not skills.
    try:
        if stat.S_ISDIR(builder.files.info(directory.path / "skills").st_mode):
            return
    except ReadGap as error:
        if error.reason != "not_found":
            builder.gap(directory, error.reason, error.status)
            return
    child = directory.child(directory.path, "skills", "directory", "plugin")
    collect_skill(builder, child, directory.path / "SKILL.md", parent_id)


def scan_plugin_agents(builder, directory, data, parent_id):
    if "agents" not in data:
        scan_agents(builder, directory.child(directory.path / "agents", "agents", "directory", "plugin"), parent_id)
        return
    seen = set()
    for relative in component_references(builder, directory, data["agents"]):
        path = component_path(builder, directory, relative)
        if path is None or path in seen:
            continue
        seen.add(path)
        child = directory.child(path, "agents", "directory", "plugin")
        try:
            if stat.S_ISDIR(builder.files.info(path).st_mode):
                scan_agents(builder, child, parent_id)
            else:
                collect_agent(builder, directory.child(directory.path, "agents", "directory", "plugin"), path, parent_id)
        except ReadGap as error:
            builder.gap(child, error.reason, error.status)
