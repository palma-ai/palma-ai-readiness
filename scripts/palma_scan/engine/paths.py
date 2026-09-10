"""Vendor-documented candidate paths, never commands to discover credentials."""
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath, PureWindowsPath

from .identity import fingerprint


@dataclass(frozen=True)
class Candidate:
    family: str
    scope: str
    path: Path
    location: str
    format: str = "json"
    role: str = "config"
    context: str = "user"
    variant: str = "unknown"

    def child(self, path, role="config", format_name="json", scope=None):
        label = fingerprint(str(path.relative_to(self.path)))[:16]
        return Candidate(self.family, scope or self.scope, path,
                         self.location + "/item-" + label, format_name, role, self.context, self.variant)


CONFIGS = {
    "claude-code": [(".claude/settings.json", "json"), (".claude.json", "json")],
    "codex": [(".codex/config.toml", "toml")],
    "cursor": [(".cursor/mcp.json", "jsonc"), (".cursor/cli-config.json", "json")],
    "gemini-cli": [(".gemini/settings.json", "json"), (".gemini/trustedFolders.json", "json")],
    "kiro": [(".kiro/settings/mcp.json", "jsonc")],
    "windsurf": [(".codeium/windsurf/mcp_config.json", "json")],
    "cline": [(".cline/mcp.json", "json"), (".cline/data/settings/cline_mcp_settings.json", "json"),
              (".cline/data/settings/global-settings.json", "json")],
}
SKILLS = {"claude-code": [".claude/skills"], "codex": [".agents/skills", ".codex/skills"],
          "cursor": [".cursor/skills", ".agents/skills", ".claude/skills", ".codex/skills"],
          "gemini-cli": [".gemini/skills", ".agents/skills"], "kiro": [".kiro/skills"],
          "cline": [".cline/skills"], "vscode": [".copilot/skills", ".claude/skills", ".agents/skills"]}
AGENTS = {"claude-code": ".claude/agents", "cursor": ".cursor/agents", "kiro": ".kiro/agents", "cline": ".cline/agents"}
PLUGINS = {"claude-code": ".claude/plugins/cache", "codex": ".codex/plugins/cache",
           "gemini-cli": ".gemini/extensions"}


def _candidate(family, base, relative, scope="user", format_name="json", role="config"):
    context = "user" if scope != "project" else "project:" + fingerprint(str(base))
    location = (scope if scope != "project" else context[:24]) + ":" + relative
    return Candidate(family, scope, base / relative, location, format_name, role, context)


def user_candidates(home: Path, os_name: str, environ: dict) -> list[Candidate]:
    candidates = [_candidate(family, home, path, format_name=fmt)
                  for family, paths in CONFIGS.items() for path, fmt in paths]
    for family, roots in SKILLS.items():
        candidates.extend(_candidate(family, home, root, format_name="directory", role="skills") for root in roots)
    candidates.extend(_candidate(family, home, root, format_name="directory", role="agents") for family, root in AGENTS.items())
    candidates.extend(_candidate(family, home, root, format_name="directory", role="plugins") for family, root in PLUGINS.items())
    candidates.extend(editor_candidates(home, os_name, environ))
    candidates.extend(override_candidates(environ))
    candidates.extend(managed_cache_candidates(home, environ))
    return candidates


def managed_cache_candidates(home, environ):
    roots = [(home / ".claude", "managed-cache:remote-settings.json")]
    if environ.get("CLAUDE_CONFIG_DIR"):
        roots.append((Path(environ["CLAUDE_CONFIG_DIR"]).expanduser(),
                      "managed-cache:CLAUDE_CONFIG_DIR/remote-settings.json"))
    return [Candidate("claude-code", "managed", root / "remote-settings.json", location,
                      role="settings-cache") for root, location in roots]


USER_SCOPED_OVERRIDES = ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "CURSOR_CONFIG_DIR", "CLINE_DATA_DIR",
                         "CLAUDE_CODE_PLUGIN_CACHE_DIR", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME")


def bounded_environment(environ, os_name, home):
    """Reject directory overrides that target a volume or leave the selected account.

    User-scoped overrides (CODEX_HOME, CLAUDE_CONFIG_DIR, ...) must be absolute and
    inside the selected home: a relative value resolves against the scanner's
    working directory and an outside-home value would silently pull another
    account's or project's inventory into a current-account scan. System roots
    (ProgramFiles, ProgramData) keep the volume-root rule only.
    """
    rejected = []
    variables = USER_SCOPED_OVERRIDES + ("ProgramFiles", "ProgramData")
    user_scoped = set(USER_SCOPED_OVERRIDES)
    result = dict(environ)
    if os_name == "windows":
        variables = tuple(variable.upper() for variable in variables)
        user_scoped = {variable.upper() for variable in user_scoped}
        recognized = {*variables, "PATH", "CLAUDE_CODE_PLUGIN_SEED_DIR", "GEMINI_CLI_SYSTEM_SETTINGS_PATH", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH"}
        result = {key.upper() if key.upper() in recognized else key: value for key, value in result.items()}
    for variable in variables:
        value = result.get(variable)
        if not value:
            continue
        if _volume_root(value) or (variable in user_scoped and _outside_account(value, home)):
            rejected.append(variable)
            del result[variable]
    separator = ";" if os_name == "windows" else ":"
    # Search-path entries feed installation probes, so an entry under ANOTHER
    # account's profile directory would read that account's install metadata.
    unsafe = lambda part: _volume_root(part) or _foreign_profile(part, home, os_name)
    seeds = result.get("CLAUDE_CODE_PLUGIN_SEED_DIR", "").split(separator)
    if any(part and unsafe(part) for part in seeds) or len(seeds) > 32:
        rejected.append("CLAUDE_CODE_PLUGIN_SEED_DIR")
        result["CLAUDE_CODE_PLUGIN_SEED_DIR"] = separator.join(part for part in seeds[:32] if part and not unsafe(part))
    parts = result.get("PATH", "").split(separator)
    if any(part and unsafe(part) for part in parts):
        rejected.append("PATH")
        result["PATH"] = separator.join(part for part in parts if part and not unsafe(part))
    return result, rejected


def _profile_directory(path, pure):
    """The account profile directory a path sits in (/Users/<x>, /home/<x>, <drive>:\\Users\\<x>), or None."""
    parts = path.parts
    if len(parts) < 3:
        return None
    root, users, name = parts[0], parts[1], parts[2]
    if pure is PurePosixPath and root == "/" and users in {"Users", "home"}:
        return pure(root, users, name)
    # Drive-qualified, UNC and drive-relative rooted forms (\\Users\\x resolves against the
    # current drive on Windows) all name a profile directory.
    if pure is PureWindowsPath and (path.drive or root in ("\\", "/")) and users.lower() == "users":
        return pure(root, users, name)
    return None


def _foreign_profile(value, home, os_name):
    """True when a search-path entry lies inside another account's profile directory."""
    pure = PureWindowsPath if os_name == "windows" else PurePosixPath
    try:
        # Judge the entry in the modeled OS's own path syntax. Routing it through the
        # host's concrete Path first lets a Windows host rewrite a POSIX entry (current
        # drive prefixed, separators flipped) into one component that names no profile.
        target = pure(str(Path(value).expanduser()) if value.startswith("~") else value)
        if not target.is_absolute():
            target = pure(str(Path.cwd())) / target  # a relative "Users/other/bin" resolves against the working directory
        account = pure(str(Path(home).expanduser().absolute()))
    except (RuntimeError, OSError, ValueError):
        return True
    profile = _profile_directory(target, pure)
    if profile is None:
        return False
    return profile != account and profile not in account.parents


def _outside_account(value, home):
    """True when a user-scoped override is relative or not inside the selected home."""
    try:
        path = Path(value).expanduser()
        if not path.is_absolute():
            return True
        if home is None:
            return False
        account = Path(home).expanduser().absolute()
        target = path.absolute()
        return target != account and account not in target.parents
    except (RuntimeError, OSError, ValueError):
        return True


def _volume_root(value):
    if value.startswith("~") and len(value) > 1 and value[1] not in {"/", "\\"}:
        return True
    try:
        path = Path(value).expanduser().absolute()
        return path.parent == path or ".." in path.parts
    except (RuntimeError, OSError, ValueError):
        return True


def editor_candidates(home: Path, os_name: str, environ: dict) -> list[Candidate]:
    base = home / ".config"
    if os_name == "macos":
        base = home / "Library/Application Support"
    elif os_name == "windows":
        base = Path(environ.get("APPDATA", str(home / "AppData/Roaming")))
    elif environ.get("XDG_CONFIG_HOME"):
        base = Path(environ["XDG_CONFIG_HOME"])
    result = []
    for product, family in [("Code", "vscode"), ("Code - Insiders", "vscode"), ("Cursor", "cursor"), ("Kiro", "kiro"), ("Windsurf", "windsurf")]:
        root = base / product / "User"
        for file in ("settings.json", "mcp.json"):
            result.append(replace(_candidate(family, root, file, format_name="jsonc"), variant="ide"))
        result.append(replace(_candidate(family, root, "profiles", format_name="directory", role="profiles"), variant="ide"))
        for extension, owner, file in [("saoudrizwan.claude-dev", "cline", "cline_mcp_settings.json"),
                                       ("rooveterinaryinc.roo-cline", "roo-code", "mcp_settings.json")]:
            result.append(replace(_candidate(owner, root, "globalStorage/" + extension + "/settings/" + file), variant="extension"))
    if os_name in {"macos", "windows"}:
        result.append(_candidate("claude-desktop", base, "Claude/claude_desktop_config.json"))
    return result


def override_candidates(environ: dict) -> list[Candidate]:
    result = []
    matrix = {"CLAUDE_CONFIG_DIR": ("claude-code", [("settings.json", "json"), (".claude.json", "json")]),
              "CODEX_HOME": ("codex", [("config.toml", "toml")]),
              "CURSOR_CONFIG_DIR": ("cursor", [("cli-config.json", "json")]),
              "CLINE_DATA_DIR": ("cline", [("settings/cline_mcp_settings.json", "json"), ("settings/global-settings.json", "json")])}
    for variable, (family, files) in matrix.items():
        if environ.get(variable):
            root = Path(environ[variable]).expanduser()
            for file, fmt in files:
                result.append(Candidate(family, "user", root / file, "override:" + variable + "/" + file, fmt))
            if family in {"claude-code", "codex"}:
                for folder, role in [("skills", "skills"), ("plugins/cache", "plugins"), ("agents", "agents")]:
                    result.append(Candidate(family, "user", root / folder, "override:" + variable + "/" + folder, "directory", role))
    return result


def workspace_candidates(workspace: Path) -> list[Candidate]:
    matrix = {"claude-code": [(".mcp.json", "json"), (".claude/settings.json", "json"), (".claude/settings.local.json", "json")],
              "codex": [(".codex/config.toml", "toml")], "cursor": [(".cursor/mcp.json", "jsonc"), (".cursor/cli.json", "json")],
              "gemini-cli": [(".gemini/settings.json", "json")], "kiro": [(".kiro/settings/mcp.json", "jsonc")],
              "vscode": [(".vscode/mcp.json", "jsonc"), (".vscode/settings.json", "jsonc")],
              "roo-code": [(".roo/mcp.json", "jsonc")]}
    result = [_candidate(family, workspace, path, "project", fmt) for family, entries in matrix.items() for path, fmt in entries]
    result.append(_candidate("codex", workspace, ".codex/hooks.json", "project", role="settings-cache"))
    for family, roots in SKILLS.items():
        for root in roots:
            root = ".github/skills" if root == ".copilot/skills" else root
            result.append(_candidate(family, workspace, root, "project", "directory", "skills"))
    result.extend(_candidate(family, workspace, root, "project", "directory", "agents") for family, root in AGENTS.items())
    return result


def managed_candidates(os_name: str, environ: dict) -> list[Candidate]:
    claude, gemini, codex = Path("/etc/claude-code"), Path("/etc/gemini-cli"), Path("/etc/codex")
    if os_name == "macos":
        claude, gemini = Path("/Library/Application Support/ClaudeCode"), Path("/Library/Application Support/GeminiCli")
    elif os_name == "windows":
        claude = Path(environ.get("PROGRAMFILES", "C:/Program Files")) / "ClaudeCode"
        data = Path(environ.get("PROGRAMDATA", "C:/ProgramData"))
        gemini, codex = data / "gemini-cli", data / "OpenAI/Codex"
    result = [_candidate("claude-code", claude, name, "managed") for name in ["managed-settings.json", "managed-mcp.json"]]
    result.append(_candidate("claude-code", claude, "managed-settings.d", "managed", "directory", "dropins"))
    result.extend(_candidate("codex", codex, name, "managed", "toml") for name in ["requirements.toml", "config.toml", "managed_config.toml"])
    for name, variable in [("settings.json", "GEMINI_CLI_SYSTEM_SETTINGS_PATH"), ("system-defaults.json", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH")]:
        path = Path(environ[variable]) if environ.get(variable) else gemini / name
        result.append(Candidate("gemini-cli", "managed", path, "managed:gemini/" + name))
    return result


def installation_candidates(os_name: str, environ: dict) -> list[Candidate]:
    result = []
    binaries = {"claude-code": "claude", "codex": "codex", "cursor": "cursor", "gemini-cli": "gemini",
                "kiro": "kiro-cli", "vscode": "code", "windsurf": "windsurf", "cline": "cline"}
    separator = ";" if os_name == "windows" else ":"
    for directory in environ.get("PATH", "").split(separator)[:100]:
        root = Path(directory)
        if not directory or not root.is_absolute():
            continue
        for family, binary in binaries.items():
            suffixes = [".exe", ".cmd"] if os_name == "windows" else [""]
            for suffix in suffixes:
                result.append(Candidate(family, "installation", root / (binary + suffix),
                                        "installation:PATH/" + binary + suffix, "executable", "installation",
                                        variant="ide" if family in {"cursor", "vscode", "windsurf"} else "cli"))
    return result
