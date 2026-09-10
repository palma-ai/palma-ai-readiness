"""Additional vendor stores, retaining explicit profile and cache provenance."""
from pathlib import Path

from .paths import Candidate


def supplemental_candidates(home, os_name, environ):
    result = []
    if os_name == "windows":
        local = Path(environ.get("LOCALAPPDATA", str(home / "AppData/Local")))
        # Claude Desktop's MSIX can virtualize its Roaming store here. Keep it
        # separate from the unpackaged AppData/Roaming/Claude declaration.
        relative = "Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude_desktop_config.json"
        result.append(Candidate("claude-desktop", "user", local / relative,
                                "user:windows-msix/Claude/claude_desktop_config.json", variant="desktop"))
    codex_roots = [(home / ".codex", "user:.codex")]
    if environ.get("CODEX_HOME"):
        codex_roots.append((Path(environ["CODEX_HOME"]).expanduser(), "override:CODEX_HOME"))
    for root, label in codex_roots:
        result.append(Candidate("codex", "user", root, label + "/named-profiles", "directory", "codex-profiles"))
        result.append(Candidate("codex", "user", root / "hooks.json", label + "/hooks.json", role="settings-cache"))
    if os_name != "windows":
        result.append(Candidate("codex", "managed", Path("/etc/codex/skills"),
                                "managed:codex/skills", "directory", "skills"))
    # Observed in Cursor 3.19.7: synchronized built-in skill bundles. Presence
    # establishes a local declaration; the sync index is not activation proof.
    for relative, role in [(".cursor/skills-cursor", "skills"), (".cursor/agents", "agents"),
                           (".cursor/plugins/local", "plugins")]:
        result.append(Candidate("cursor", "user", home / relative, "user:" + relative, "directory", role))
    if os_name == "linux" and environ.get("XDG_CONFIG_HOME"):
        result.append(Candidate("cursor", "user", Path(environ["XDG_CONFIG_HOME"]) / "cursor/cli-config.json",
                                "override:XDG_CONFIG_HOME/cursor/cli-config.json", variant="cli"))
    for root, label in claude_plugin_roots(home, os_name, environ):
        result.append(Candidate("claude-code", "user", root / "cache", label + "/cache", "directory", "plugins"))
        for filename in ("installed_plugins.json", "known_marketplaces.json"):
            result.append(Candidate("claude-code", "user", root / filename, label + "/" + filename,
                                    role="registry-probe"))
    return result


def claude_plugin_roots(home, os_name, environ):
    roots = [(home / ".claude/plugins", "user:.claude/plugins")]
    if environ.get("CLAUDE_CONFIG_DIR"):
        roots.append((Path(environ["CLAUDE_CONFIG_DIR"]).expanduser() / "plugins", "override:CLAUDE_CONFIG_DIR/plugins"))
    if environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR"):
        roots.append((Path(environ["CLAUDE_CODE_PLUGIN_CACHE_DIR"]).expanduser(), "override:CLAUDE_CODE_PLUGIN_CACHE_DIR"))
    separator = ";" if os_name == "windows" else ":"
    for index, value in enumerate(environ.get("CLAUDE_CODE_PLUGIN_SEED_DIR", "").split(separator)[:32]):
        if value:
            roots.append((Path(value).expanduser(), "override:CLAUDE_CODE_PLUGIN_SEED_DIR/" + str(index)))
    return roots
