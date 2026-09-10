"""Safe settings evidence, keeping unknown values on the endpoint."""
import re

from ..redaction import SECRET_KEY, utf16_length

ENUMS = {"default", "ask", "auto", "never", "always", "on", "off", "read-only", "workspace-write",
         "danger-full-access", "bypassPermissions", "acceptEdits", "plan", "dontAsk", "trusted",
         "untrusted", "restricted", "unrestricted", "enabled", "disabled",
         # Gemini CLI approval modes and folder trust; Kiro agent autonomy.
         "auto_edit", "Autopilot", "Supervised", "autopilot", "supervised",
         "TRUST_FOLDER", "TRUST_PARENT", "DO_NOT_TRUST"}
# Inventory categories group the lower-cased key path by subject, first match
# wins. A browser confirmation or sandbox restriction remains in that subject's
# inventory. These labels do not establish capability enablement, sandbox
# removal, or hook handlers; governance qualifies those claims by native key.
CATEGORIES = [("browser", ("browser", "chrome", "cdp")),
              # Claude Desktop's local agent mode and ChatGPT's "work with apps" act on the host like computer use.
              ("computer", ("computer", "desktop_control", "screen_control", "localagentmode", "workwithapps")),
              ("sandbox", ("sandbox", "permission_profile", "permissionprofile")),
              ("permissions", ("permission", "approv", "autoaccept", "alwaysallow", "allowedtools", "excludedtools",
                               "trust", "yolo", "autonomy", "dangerously", "skippermission")),
              ("hooks", ("hook",)), ("experimental", ("experimental", "features.", "beta")),
              ("telemetry", ("telemetry", "privacy", "analytics")), ("mcp", ("mcp",)),
              ("network", ("network", "internet", "proxy")), ("filesystem", ("filesystem", "file_access")),
              ("model", ("model",))]
# Keys another adapter turns into their own observations (MCP servers, project entries, plugins).
SKIP_KEYS = {"mcp", "agent", "agents", "mcpServers", "mcp_servers", "servers", "projects", "plugins", "enabledPlugins", "extraKnownMarketplaces"}
# Containers whose property names are user data, recognised on EVERY dotted segment of a key path
# (VS Code and its forks store flat dotted keys such as `terminal.integrated.env.osx`), case-insensitively:
# environment blocks, header maps, per-host or per-URL rules, credential stores, user-named
# profiles, providers and accounts. Their contents are inventoried as one object whose contents stay on the endpoint.
OPAQUE_SEGMENTS = {"accounts", "channels", "tenants", "teams", "bots", "permission", "permissions", "hooks", "origins", "bundle_ids", "aumids", "connections", "env", "environment", "environmentvariables", "headers", "args", "hosts", "domains", "urls", "paths",
                   "commands", "profiles", "providers", "model_providers", "workspaces", "folders", "oauthaccount",
                   "auth", "credentials", "accesstoken", "refreshtoken", "remoteplatform"}
OPAQUE_NEEDLES = ("env", "header", "host", "token", "secret", "cred", "password", "cookie", "proxy", "registr", "repositor")
# Numbers under keys like these identify or meter a person rather than configure a tool; they stay on the endpoint.
IDENTIFYING_KEY = re.compile(r"(?:^|[._-])(?:[a-z]*id|uuid|guid|serial)$|cost|usd|spend|billing|usage|telemetryid", re.I)
# A nested property name that is a plain identifier; never a path, URL, command, token or hash.
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
BLOB = re.compile(r"[0-9]{6,}|^[A-Fa-f0-9]{16,}$")
SETTING_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
# `~/.claude.json` is Claude Code's runtime state (projects, caches, account), not a settings file;
# only its switches are settings evidence: Claude in Chrome, computer use (the built-in MCP
# server), the accepted bypass-permissions mode, the auto-approved server list, auto-updates.
CLAUDE_STATE_SWITCHES = ("claudeInChromeEnabled", "computerUse", "computerUseMcpState",
                         "bypassPermissionsModeAccepted", "autoApprovedServers", "autoUpdates")
# Per-folder switches inside Claude Code's `projects` map and Codex's `[projects."<path>"]` tables.
CLAUDE_PROJECT_SWITCHES = ("hasTrustDialogAccepted", "hasClaudeMdExternalIncludesApproved", "hasCompletedProjectOnboarding",
                           "allowedTools", "enabledMcpjsonServers", "disabledMcpjsonServers")
CODEX_PROJECT_SWITCHES = ("trust_level",)


def claude_state_switches(data):
    return {key: data[key] for key in CLAUDE_STATE_SWITCHES if key in data}


def _opaque_segment(segment):
    lowered = segment.lower()
    return lowered in OPAQUE_SEGMENTS or any(needle in lowered for needle in OPAQUE_NEEDLES)


def structural(native, value):
    """Descend into a nested object only when no segment of its key path names user-data
    container and every property name is a plain identifier.

    Documented settings groups look like that; maps keyed by commands, paths, hosts, URLs,
    tokens or user-chosen names do not, and stay one withheld object. An empty object is
    inventoried as itself.
    """
    if not value or any(_opaque_segment(segment) for segment in native.split(".")):
        return False
    return all(isinstance(key, str) and IDENTIFIER.fullmatch(key) and not BLOB.search(key) for key in value)


def category(key):
    lowered = key.lower()
    return next((label for label, needles in CATEGORIES if any(needle in lowered for needle in needles)), "other")


def value_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (float, int)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "object" if isinstance(value, dict) else "array"


def safe_value(key, value):
    """Booleans, bounded numbers and known enum words are safe in any category; every other value
    stays on the endpoint, as does anything under a credential-looking key."""
    if SECRET_KEY.search(key):
        return None, False
    if isinstance(value, bool):
        return value, True
    if isinstance(value, (int, float)) and -1_000_000 <= value <= 1_000_000 and not IDENTIFYING_KEY.search(key):
        return value, True
    if isinstance(value, str) and value in ENUMS:
        return value, True
    return None, False


def collect_settings(builder, candidate, source, data, prefix="", depth=0, state="unknown"):
    """Inventory every configuration key, including the stale and the irrelevant: an audit needs
    to see what is declared before it can remove it. Values travel only when `safe_value` says so."""
    if depth > 12:
        builder.gap(candidate, "count_limit")
        return
    for key, value in data.items():
        if key in SKIP_KEYS:
            continue
        native = prefix + key
        if utf16_length(native) > 256:
            builder.gap(candidate, "size_limit")
            continue
        if not SETTING_KEY.fullmatch(key):
            builder.gap(candidate, "unknown_schema", "unsupported")
            continue
        # Commands, environment values and arbitrary array elements stay local.
        if isinstance(value, dict) and structural(native, value):
            collect_settings(builder, candidate, source, value, native + ".", depth + 1, state)
        else:
            safe, collected = safe_value(native, value)
            builder.emit(candidate, source, "setting", native, nativeKey=native,
                         category=category(native), valueType=value_type(value), value=safe,
                         valueCollected=collected, effectiveState=state)


def client_auth(builder, candidate, source, data):
    modes = set()
    env = data.get("env", {})
    if isinstance(env, dict):
        if any(env.get(key) for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY")):
            modes.add("api_key")
        if any(env.get(key) for key in ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")):
            modes.add("cloud_provider")
    selected = data.get("security", {})
    selected = selected.get("auth", {}) if isinstance(selected, dict) else {}
    selected = selected.get("selectedType") if isinstance(selected, dict) else None
    if selected is not None and not isinstance(selected, str):
        builder.gap(candidate, "unknown_schema", "unsupported")
        selected = None
    if selected in {"oauth-personal", "oauth", "google-login"}:
        modes.add("vendor_login")
    elif selected == "gemini-api-key":
        modes.add("api_key")
    elif selected == "vertex-ai":
        modes.add("cloud_provider")
    if data.get("forced_login_method") == "chatgpt" or data.get("forceLoginMethod") == "claudeai":
        modes.add("vendor_login")
    if isinstance(data.get("oauthAccount"), dict):
        modes.add("vendor_login")
    if data.get("forced_login_method") == "api" or data.get("apiKeyHelper"):
        modes.add("api_key")
    if modes:
        client = builder.ensure_client(candidate, source)
        client["authModes"] = sorted((set(client["authModes"]) - {"unknown"}) | modes)
        client["authEvidence"] = "declared"
