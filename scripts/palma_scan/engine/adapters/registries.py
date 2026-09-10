"""Probe empirical registries without inventing undocumented record semantics."""


def probe_registry(builder, candidate):
    source, data = builder.document(candidate)
    if data is None:
        return
    # Empty v2 was independently observed on the audited Claude Code host.
    # Nonempty installation records need a release-qualified fixture and join
    # with settings/cache before they can establish installed capability state.
    empty_install = candidate.path.name == "installed_plugins.json" and data == {"version": 2, "plugins": {}}
    empty_marketplaces = candidate.path.name == "known_marketplaces.json" and data == {}
    if not empty_install and not empty_marketplaces:
        source.update(status="unsupported", reason="unknown_schema")
