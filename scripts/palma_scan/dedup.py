"""Count each declaration once, however many files repeat it.

The same configuration often exists in many files: git worktrees each carry a copy of
a project's .claude/, .mcp.json and skills; desktop agent sessions keep per-session
copies of MCP configuration; plugin caches keep every downloaded version. Recording one
observation per file multiplied every inventory count and finding. Copies whose kind,
client, name, state, typed facts and content are identical become one observation that
lists where it is declared. Anything that differs, including content, stays separate.
A hook with identical handlers also merges across the user and project layers: the
same notification command in a user file and a project file is one command to review.
A cached or managed policy copy of a hook stays a separate declaration.
"""
import hashlib
import json
import re

MAX_LOCATIONS = 100
# Detail fields that identify one copy's position rather than what it declares.
_PER_COPY = frozenset({"contextId", "parentId", "declaration", "profileId", "locations", "locationCount", "copyCount"})
# Layers whose identical hook declarations describe one command; other contexts stay apart.
_LOCAL_LAYERS = frozenset({"base", "project"})
# Their typed facts do not capture everything that matters, so identical copies also need
# identical content. Without a content digest such observations are never merged.
_CONTENT_REQUIRED = frozenset({"mcp", "hook", "agent"})
_CLIENT_EVIDENCE = {"installed": 0, "running": 1}


def content_digest(value):
    """Identity for grouping identical declarations. Held in memory, never exported."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _order(item):
    # Prefer the shortest, least nested path: normally the main checkout, not a copy.
    location = item.get("location", "")
    return (location.count("/"), len(location), location, item["id"])


def _key(item, malformed):
    details = {key: value for key, value in item.get("details", {}).items() if key not in _PER_COPY}
    if item["kind"] == "hook" and details.get("context") in _LOCAL_LAYERS:
        details["context"] = "local"
    content = details.get("digest") if item["kind"] == "skill" else item.get("_content")
    # Credential counts alone cannot tell two different secrets apart.
    credential = type(details.get("literalCredentialCount")) is int and details["literalCredentialCount"] > 0
    if not content and (item["kind"] in _CONTENT_REQUIRED or item["kind"] == "skill" or credential):
        return ("unique", item["id"])
    # A copy in a malformed file stays separate, so it cannot stand in for a well-formed one.
    return json.dumps([item["kind"], item["client"], item["name"], item["enabled"], details, content, item.get("_marketplaceIdentity"), item["sourceId"] in malformed],
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _record_locations(canonical, items):
    locations = [canonical["location"]]
    for item in items:
        locations.append(item["location"])
        locations.extend(item.get("details", {}).get("locations", []))
    unique = list(dict.fromkeys(locations))
    if len(unique) > 1:
        rest = sorted(unique[1:], key=lambda value: (value.count("/"), len(value), value))
        canonical["details"]["locations"] = [unique[0], *rest][:MAX_LOCATIONS]
        canonical["details"]["locationCount"] = len(unique)


def fold_pack_switches(observations):
    """An account-level ``plugin@marketplace`` switch whose pack is installed is that pack's
    enabled state, already carried by the pack row; it is not a second pack. A switch in a
    project's own settings, or one whose pack is not installed, stays its own declaration."""
    installed = {(item["client"], item["details"].get("marketplaceId"), item["name"]) for item in observations
                 if item["kind"] == "plugin" and item.get("details", {}).get("installationState") == "installed"
                 and item["details"].get("marketplaceId")}
    result = []
    for item in observations:
        details = item.get("details", {})
        if item["kind"] == "plugin" and details.get("activation") == "configured" and details.get("context") == "base" and "@" in item["name"]:
            plugin, market = item["name"].rsplit("@", 1)
            if (item["client"], market, plugin) in installed:
                continue
        result.append(item)
    return result


def collapse_declarations(observations, malformed=frozenset()):
    """Merge identical copies of declarations; client rows are merged separately.

    Copies merge across files, and across contexts within one file (the same server
    configured for several projects in one state file). Two identical entries in the
    same file and context are distinct declarations, and that repetition is itself
    worth seeing. ``copyCount`` records how many declarations merged; ``locations``
    lists the distinct files. ``malformed`` holds the ids of sources with unsupported shapes.
    """
    groups, members = {}, {}
    for item in observations:
        key = ("client", item["id"]) if item["kind"] == "client" else _key(item, malformed)
        position = (item["sourceId"], item.get("details", {}).get("contextId"))
        index = 0
        while position in members.get((key, index), ()):
            index += 1
        groups.setdefault((key, index), []).append(item)
        members.setdefault((key, index), set()).add(position)
    result, replaced = [], {}
    for items in groups.values():
        items.sort(key=_order)
        canonical = items[0]
        if len(items) > 1:
            canonical["details"]["copyCount"] = len(items)
            _record_locations(canonical, items)
            replaced.update((item["id"], canonical["id"]) for item in items[1:])
        result.append(canonical)
    for item in result:
        item.pop("_content", None)
        item.pop("_marketplaceIdentity", None)
        parent = item.get("details", {}).get("parentId")
        if parent in replaced:
            item["details"]["parentId"] = replaced[parent]
    return result


def _version_key(value):
    # Numeric parts compare as numbers and before text parts, so "1.2.3-rc.1" and
    # "1.2.3-1" never compare an int with a str.
    return [(0, int(part), "") if part.isdigit() else (1, 0, part) for part in re.split(r"[.\-+]", value)]


def merge_clients(observations):
    """One row per AI client family, with installation, runtime and use as facts.

    A client used in many projects, installed in several versions or observed running
    is one client. Installation evidence anywhere means the client is not merely
    configuration left behind. Call once, after every client observation is present.
    """
    families = {}
    for item in observations:
        if item["kind"] == "client":
            families.setdefault(item["client"], []).append(item)
    merged = {}
    for family, items in families.items():
        items.sort(key=lambda item: (_CLIENT_EVIDENCE.get(item.get("details", {}).get("activation"), 2), _order(item)))
        canonical = items[0]
        details = canonical.setdefault("details", {})
        activations = {item.get("details", {}).get("activation") for item in items}
        states = {item.get("details", {}).get("installationState") for item in items}
        if "installed" in activations or "installed" in states:
            details.update(activation="installed", installationState="installed")
        elif "running" in activations:
            details["installationState"] = "unknown"
        if "running" in activations:
            details["processObserved"] = True
        versions = sorted({version for item in items if isinstance(version := item.get("details", {}).get("version"), str)}, key=_version_key)
        if versions:
            details["version"] = versions[-1]
        if len(versions) > 1:
            details["versions"] = versions
        modes = sorted({mode for item in items for mode in item.get("details", {}).get("authModes", []) if isinstance(mode, str)})
        if modes:
            details["authModes"] = [mode for mode in modes if mode != "unknown"] or ["unknown"]
        projects = {item["details"].get("contextId") for item in items
                    if item.get("details", {}).get("projectScoped") or item.get("details", {}).get("context") == "project"}
        details.pop("projectScoped", None)
        if projects:
            details["projectCount"] = len(projects)
        if len(items) > 1:
            details["context"] = "base"  # One client row, not the project it was first seen in.
            _record_locations(canonical, items)
        merged[family] = canonical
    emitted, result = set(), []
    for item in observations:
        if item["kind"] != "client":
            result.append(item)
        elif item["client"] not in emitted:
            emitted.add(item["client"])
            result.append(merged[item["client"]])
    return result
