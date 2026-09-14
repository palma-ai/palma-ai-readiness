"""Inspect bounded registry metadata; declarations are not activation proof."""


def probe_registry(builder, candidate):
    source, data = builder.document(candidate)
    if data is None:
        return
    installed = (candidate.path.name == "installed_plugins.json" and type(data.get("version")) is int
                 and data["version"] == 2 and isinstance(data.get("plugins"), dict)
                 and all(isinstance(key, str) and isinstance(entries, list)
                         and all(isinstance(entry, dict) and isinstance(entry.get("installPath"), str)
                                 for entry in entries)
                         for key, entries in data["plugins"].items()))
    marketplaces = (candidate.path.name == "known_marketplaces.json"
                    and all(isinstance(name, str) and isinstance(item, dict)
                            and isinstance(item.get("source"), dict) for name, item in data.items()))
    if not installed and not marketplaces:
        source.update(status="unsupported", reason="unknown_schema")
