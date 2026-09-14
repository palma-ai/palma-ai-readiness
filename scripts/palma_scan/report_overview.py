"""Pure inventory aggregates for the offline visual overview.

Name counts describe declared labels. Reach counts describe configuration variants;
they never assert a running process, live connection or verified publisher identity.
"""
from .engine.redaction import visible


def _label(value):
    return visible(value)[:4096] if isinstance(value, str) else "unknown"


def _name(item, share):
    group = item.get("_reportNameGroup")
    return group if share and type(group) is int else _label(item.get("name"))


def _reach(item):
    if item.get("enabled") == "disabled":
        return "disabled"
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    if details.get("endpointScope") == "loopback" or details.get("execution") == "local" or details.get("transport") in ("stdio", "sdk"):
        return "local"
    if details.get("execution") == "remote":
        return "remote"
    return "unknown"


def _counts(items, share):
    mcps = [item for item in items if item.get("kind") == "mcp"]
    skills = [item for item in items if item.get("kind") == "skill"]
    reach = dict.fromkeys(("local", "remote", "unknown", "disabled"), 0)
    for item in mcps:
        reach[_reach(item)] += 1
    return {"mcpNames": len({_name(item, share) for item in mcps}),
            "mcpConfigurations": len(mcps), "skillNames": len({_name(item, share) for item in skills}),
            "skillConfigurations": len(skills),
            "plugins": sum(item.get("kind") == "plugin" for item in items), "reach": reach}


def inventory_graph(observations, *, share=False):
    by_client = {}
    for item in observations:
        client = _label(item.get("client") or "unknown").casefold()
        by_client.setdefault(client, []).append(item)
    clients = [{"client": client, **_counts(items, share)} for client, items in sorted(by_client.items())]
    # A family observed only through its configuration still participates in the map.
    return {"clients": clients, **_counts(observations, share)}
