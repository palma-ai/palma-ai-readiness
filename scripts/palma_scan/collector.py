"""Exact typed governance extraction over the original local collection engine.

No discovered command executes and no credential reference resolves. The bridge
retains broad inventories while this module emits precise sanitized rule facts.
"""
import hashlib
import json
from functools import lru_cache
import ipaddress
from pathlib import Path
import re
import stat
from urllib.parse import parse_qsl, urlsplit

from .dedup import content_digest, merge_clients
from .engine.redaction import Redactor

MAX_MANIFESTS = 20000

USER_CONFIGS = [
    ("codex", ".codex/config.toml", "toml"),
    ("codex", ".codex/hooks.json", "json"),
    ("claude-code", ".claude/settings.json", "json"),
    ("claude-code", ".claude/remote-settings.json", "json"),
    ("claude-code", ".claude.json", "json"),
    ("cursor", ".cursor/mcp.json", "jsonc"),
    ("cursor", ".cursor/permissions.json", "jsonc"),
    ("cursor", ".cursor/cli-config.json", "json"),
    ("gemini-cli", ".gemini/settings.json", "json"),
    ("windsurf", ".codeium/windsurf/mcp_config.json", "json"),
]
WORKSPACE_CONFIGS = [
    ("codex", ".codex/config.toml", "toml"),
    ("codex", ".codex/hooks.json", "json"),
    ("claude-code", ".claude/settings.json", "json"),
    ("claude-code", ".claude/settings.local.json", "json"),
    ("claude-code", ".mcp.json", "json"),
    ("cursor", ".cursor/mcp.json", "jsonc"),
    ("cursor", ".cursor/permissions.json", "jsonc"),
    ("cursor", ".cursor/cli.json", "json"),
    ("gemini-cli", ".gemini/settings.json", "json"),
    ("vscode", ".vscode/settings.json", "jsonc"),
    ("vscode", ".vscode/mcp.json", "jsonc"),
]
SKILLS = [("shared", ".agents/skills"), ("codex", ".codex/skills"),
          ("claude-code", ".claude/skills"), ("cursor", ".cursor/skills"),
          ("gemini-cli", ".gemini/skills"), ("vscode", ".copilot/skills")]
AGENTS = [("claude-code", ".claude/agents"), ("cursor", ".cursor/agents"),
          ("codex", ".codex/agents"), ("gemini-cli", ".gemini/agents")]

# These are exact documented settings, not keyword matches on arbitrary booleans.
SETTING_TYPES = {
    "codex": {
        "approval_policy": {"untrusted", "on-failure", "on-request", "never"},
        "sandbox_mode": {"read-only", "workspace-write", "danger-full-access"},
        "default_permissions": {":read-only", ":workspace", ":danger-full-access"},
        "sandbox_workspace_write.network_access": bool,
        "shell_environment_policy.inherit": {"all", "core", "none"},
        "shell_environment_policy.ignore_default_excludes": bool,
        "features.apps": bool, "features.hooks": bool, "features.codex_hooks": bool,
        "features.code_mode.enabled": bool, "features.context_management.experimental_mode": bool,
        "features.network_proxy": bool, "features.network_proxy.enabled": bool,
        "features.network_proxy.dangerously_allow_all_unix_sockets": bool,
        "features.network_proxy.dangerously_allow_non_loopback_proxy": bool,
        "features.browser_use": bool, "features.browser_use_external": bool,
        "features.browser_use_full_cdp_access": bool, "features.computer_use": bool,
        "browser_use.disable_auto_review": bool, "browser_use.allow_global_persistent_approval": bool,
        "browser_use.allow_history_access": bool, "computer_use.allow_persistent_approval": bool,
        "computer_use.default_app_access": {"allow", "deny"},
        **{"browser_use.default_origin_policy." + key: {"allow", "deny"}
           for key in ("access", "uploads", "downloads", "full_cdp_access", "auto_review")},
        "browser_use.default_origin_policy.persistent_approval": bool,
    },
    "claude-code": {
        "permissions.defaultMode": {"default", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions"},
        "permissions.disableBypassPermissionsMode": {"disable"},
        "sandbox.enabled": bool, "sandbox.allowUnsandboxedCommands": bool,
        "sandbox.autoAllowBashIfSandboxed": bool, "sandbox.failIfUnavailable": bool,
        "sandbox.network.allowLocalBinding": bool, "sandbox.network.allowAllUnixSockets": bool,
        "disableAllHooks": bool, "enableAllProjectMcpServers": bool,
        "remoteControlAtStartup": bool, "disableRemoteControl": bool,
    },
    "gemini-cli": {
        "general.defaultApprovalMode": {"default", "auto_edit", "plan"},
        "tools.sandbox": bool, "security.folderTrust.enabled": bool,
        "security.toolSandboxing": bool,
        "security.disableYoloMode": bool, "security.enablePermanentToolApproval": bool,
        "experimental.enableAgents": bool,
        "agents.overrides.browser_agent.enabled": bool,
        "agents.browser.sessionMode": {"persistent", "isolated", "existing"},
        "agents.browser.confirmSensitiveActions": bool, "agents.browser.blockFileUploads": bool,
    },
    "vscode": {
        "chat.tools.global.autoApprove": bool,
        "chat.permissions.default": {"default", "autoApprove", "autopilot"},
        "chat.tools.terminal.enableAutoApprove": bool,
        "chat.agent.sandbox.enabled": {"off", "on", "allowNetwork"},
        "chat.agent.sandbox.allowNetwork": bool,
        "chat.agent.networkFilter": bool,
        "workbench.browser.enableChatTools": bool,
        "github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions": bool,
        "chat.mcp.autostart": {"never", "onlyNew", "newAndOutdated"},
        "chat.plugins.enabled": bool, "chat.useHooks": bool,
    },
}
ABSENT = object()
SENSITIVE_KEY = re.compile(r"(?:^|[_\-.])(?:api[_-]?key|token|secret|password|passwd|authorization|bearer|cookie)(?:$|[_\-.])", re.I)
CREDENTIAL_FLAGS = {"--api-key", "--apikey", "--token", "--access-token", "--password", "--secret", "--bearer-token"}
REFERENCE = re.compile(r"^(?:\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\}|\$\{input:[A-Za-z_][A-Za-z0-9_.-]*\}|\$\{file:[^{}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$")


def _id(*parts):
    return hashlib.sha256("\x1f".join(str(part) for part in parts).encode("utf-8", "replace")).hexdigest()[:16]


def _get(data, key):
    if key in data:  # VS Code uses literal dotted keys.
        return data[key]
    current = data
    for component in key.split("."):
        if not isinstance(current, dict) or component not in current:
            return ABSENT
        current = current[component]
    return current


class _Gap(Exception):
    def __init__(self, reason, status="skipped"):
        self.reason, self.status = reason, status


class _Reader:
    """Inspect only path metadata for saved-project existence; never read bodies."""
    def info(self, root, relative):
        path = root / relative
        if ".." in Path(relative).parts or not path.is_relative_to(root):
            raise _Gap("outside selected scope")
        current = root
        for part in ("", *Path(relative).parts):
            current = current / part if part else current
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise _Gap("symbolic links and reparse points are not followed")
        return info


def _credential_value(value):
    if not isinstance(value, str) or not value.strip():
        return (0, 0)
    value = value.strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    if REFERENCE.fullmatch(value):
        return (0, 1)
    if value.lower() in {"your_api_key", "your-api-key", "your_token", "your-token", "changeme", "redacted", "<redacted>", "***"} or (value.startswith("<") and value.endswith(">")):
        return (0, 0)
    return (1, 0)


# Fields whose values _credential_counts inspects; their content tells credentials apart.
_CREDENTIAL_FIELDS = ("env", "headers", "http_headers", "apiKey", "api_key", "bearerToken", "bearer_token", "accessToken",
                      "bearer_token_env_var", "env_http_headers", "args")


def credential_content(data):
    """In-memory identity of a document's credential values: different secrets never merge."""
    return content_digest({key: data[key] for key in _CREDENTIAL_FIELDS if key in data})


def _credential_counts(data):
    literal = reference = 0
    for field in ("env", "headers", "http_headers"):
        values = data.get(field, {})
        if isinstance(values, dict):
            for key, value in values.items():
                if SENSITIVE_KEY.search(key) or key.lower() in {"x-api-key", "x-auth", "apikey", "api_key"}:
                    found, refs = _credential_value(value)
                    literal, reference = literal + found, reference + refs
    for field in ("apiKey", "api_key", "bearerToken", "bearer_token", "accessToken"):
        found, refs = _credential_value(data.get(field))
        literal, reference = literal + found, reference + refs
    for field in ("bearer_token_env_var", "env_http_headers"):
        value = data.get(field)
        if isinstance(value, str) and value:
            reference += 1
        elif isinstance(value, dict):
            reference += sum(isinstance(item, str) and bool(item) for item in value.values())
    args = data.get("args", [])
    if isinstance(args, list):
        for index, arg in enumerate(args[:100]):
            if not isinstance(arg, str):
                continue
            key, separator, value = arg.partition("=")
            if key.lower() in CREDENTIAL_FLAGS:
                value = value if separator else args[index + 1] if index + 1 < len(args) else None
                found, refs = _credential_value(value)
                literal, reference = literal + found, reference + refs
    return literal, reference


def _endpoint(value):
    result = {"endpointScope": "unknown", "cleartextTransport": False, "urlCredentialCount": 0}
    if not isinstance(value, str) or not value:
        return result
    try:
        parsed = urlsplit(value)
        if parsed.scheme in {"unix", "pipe"}:
            result["endpointScope"] = "local-ipc"
            return result
        if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
            return result
        host = parsed.hostname.lower().rstrip(".")
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            # Legacy numeric IPv4 and unresolved placeholders have client-specific
            # interpretation. Do not turn them into confirmed remote endpoints.
            if not re.fullmatch(r"[a-z0-9.-]+", host) or host.rsplit(".", 1)[-1].isdigit() or re.fullmatch(r"0x[a-f0-9]+", host):
                return result
            loopback = host == "localhost"
        result["endpointScope"] = "loopback" if loopback else "remote"
        result["cleartextTransport"] = parsed.scheme in {"http", "ws"}
        if parsed.password or parsed.username:
            result["urlCredentialCount"] += 1
        for key, entry in parse_qsl(parsed.query, max_num_fields=1000):
            if SENSITIVE_KEY.search(key) or key.lower() in {"key", "apikey", "api_key"}:
                result["urlCredentialCount"] += _credential_value(entry)[0]
    except (ValueError, UnicodeError):
        result["endpointScope"] = "unknown"
    return result


@lru_cache(maxsize=1)
def _mcp_capability_catalog():
    """The unchanged Palma catalog owns its declaration-hint match patterns."""
    data = json.loads(Path(__file__).with_name("palma_catalog.json").read_text(encoding="utf-8"))
    return data["mcpCapabilities"]


def _mcp_capability_metadata(name, entry):
    """Match the original catalog before redaction; export enums only.

    Names and public-looking origins remain untrusted declaration hints. This
    does not identify a provider, establish running tools, or grant trust.
    """
    from .engine.adapters.mcp import command_metadata, endpoint
    executable, package = command_metadata(entry)
    origin, _, _ = endpoint(entry)
    fields = (("declaration-name", name), ("declared-package", package),
              ("declared-executable", executable), ("declared-endpoint-origin", origin))
    for capability in ("computer", "browser"):
        for evidence, value in fields:
            text = str(value or "").lower()
            tokens = set(re.split(r"[^a-z0-9]+", text)) - {""}
            if any((needle in text) if re.search(r"[^a-z0-9]", needle) else (needle in tokens)
                   for needle in _mcp_capability_catalog()[capability]):
                return {"capability": capability, "capabilityEvidence": evidence,
                        "capabilityInterpretation": "declaration-hint"}
    return {"capability": None, "capabilityEvidence": "not-identified",
            "capabilityInterpretation": "declaration-hint"}


def _tool_metadata(entry):
    command = entry.get("command", "")
    args = entry.get("args", [])
    if not isinstance(command, str) or not isinstance(args, list):
        return "unknown", False
    known = {"@playwright/mcp": "browser", "@modelcontextprotocol/server-puppeteer": "browser", "chrome-devtools-mcp": "browser", "@browserbasehq/mcp": "browser", "@modelcontextprotocol/server-filesystem": "filesystem"}
    family, unversioned = "unknown", False
    executable = command.replace("\\", "/").rsplit("/", 1)[-1]
    if executable in {"npx", "npx.cmd", "uvx", "uvx.exe", "bunx", "pnpx"}:
        package = next((arg for arg in args[:20] if isinstance(arg, str) and not arg.startswith("-")), "")
        for name, capability in known.items():
            if package == name or package.startswith(name + "@"):
                family = capability
                version = package[len(name) + 1:]
                unversioned = not bool(re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version))
                break
    return family, unversioned


def _provider_metadata(entry):
    """Recognize public declarations for local icons, never connection or trust.

    Only exact public HTTPS hosts and known npm launcher packages are mapped.
    Arbitrary server names, URL components, and command arguments are withheld.
    The verified source matrix is recorded in references/risk-rules.md.
    """
    hosts = {
        "api.githubcopilot.com": ("github", "GitHub"),
        "mcp.notion.com": ("notion", "Notion"),
        "mcp.linear.app": ("linear", "Linear"),
        "mcp.atlassian.com": ("atlassian", "Atlassian"),
        "mcp.slack.com": ("slack", "Slack"),
        "mcp.figma.com": ("figma", "Figma"),
        "mcp.context7.com": ("context7", "Context7"),
        "mcp.browserbase.com": ("browserbase", "Browserbase"),
    }
    packages = {
        "@playwright/mcp": ("playwright", "Playwright"),
        "chrome-devtools-mcp": ("chrome", "Chrome DevTools"),
        "@modelcontextprotocol/server-filesystem": ("filesystem", "Filesystem"),
        "@browserbasehq/mcp": ("browserbase", "Browserbase"),
        "@upstash/context7-mcp": ("context7", "Context7"),
    }
    unknown = {"provider": "unknown", "providerName": "Custom MCP", "providerEvidence": "unrecognized"}
    command, args = entry.get("command"), entry.get("args", [])
    kind = entry.get("type")
    if kind is not None and (not isinstance(kind, str) or kind not in {"stdio", "http", "sse", "streamable-http", "streamableHttp"}):
        return unknown
    url = next((entry.get(key) for key in ("httpUrl", "url", "serverUrl") if key in entry), None)
    if isinstance(url, str) and kind != "stdio" and (not isinstance(command, str) or kind in {"http", "sse", "streamable-http", "streamableHttp"}):
        try:
            parsed = urlsplit(url)
            if "\\" not in url and not any(ord(char) < 32 for char in url) and parsed.scheme == "https" and parsed.port in (None, 443) and parsed.username is None and parsed.password is None and parsed.hostname in hosts:
                provider, name = hosts[parsed.hostname]
                return {"provider": provider, "providerName": name, "providerEvidence": "declared-public-endpoint"}
        except (ValueError, UnicodeError):
            pass
        return unknown
    if isinstance(command, str) and isinstance(args, list) and kind in (None, "stdio"):
        executable = command.replace("\\", "/").rsplit("/", 1)[-1]
        if executable in {"npx", "npx.cmd", "bunx", "pnpx"}:
            package = next((arg for arg in args[:20] if isinstance(arg, str) and not arg.startswith("-")), "")
            for public_package, (provider, name) in packages.items():
                # Reject npm aliases, alternate registries and remote URLs; a tag
                # or version is a declaration hint, not verified downloaded code.
                if re.fullmatch(re.escape(public_package) + r"(?:@[A-Za-z0-9.*+^~_-]+)?", package):
                    return {"provider": provider, "providerName": name, "providerEvidence": "declared-package"}
    return unknown


# Palma-operated MCP gateway hosts, for example gateway.palma.ai or a regional form such as
# gateway.eu1.palma.ai. Only Palma controls names under palma.ai.
PALMA_GATEWAY_HOST = re.compile(r"gateway(?:-[a-z0-9]+)?(?:\.[a-z0-9]+)?\.palma\.ai")
URL_KEYS = ("httpUrl", "url", "serverUrl")


def _url_keys(client):
    """URL fields in the order the client reads them."""
    return {"gemini-cli": ("httpUrl", "url"), "windsurf": ("serverUrl", "url")}.get(client, ("url", "serverUrl", "httpUrl"))


def _palma_gateway(entry, transport):
    """Whether a remote connector is routed through a Palma-operated gateway.

    Only an exact HTTPS host on the default port qualifies, and every URL field in the
    entry must name one: a gateway address beside another URL is not trusted, whichever
    field the client reads. Connector names, paths and labels are ignored.
    """
    urls = [entry[key] for key in URL_KEYS if key in entry]
    return transport in {"http", "sse", "websocket"} and bool(urls) and all(map(_gateway_url, urls))


def _gateway_url(url):
    if not isinstance(url, str) or "\\" in url or any(ord(character) < 33 for character in url):
        return False
    try:
        parts = urlsplit(url)
        return (parts.scheme in {"https", "wss"} and parts.username is None and parts.password is None
                and parts.port in (None, 443) and parts.hostname is not None
                and PALMA_GATEWAY_HOST.fullmatch(parts.hostname) is not None)
    except (ValueError, UnicodeError):
        return False


class _LocalRedactor(Redactor):
    def _remember(self, value, level):
        # A credential reference may also contain a literal default. Keep the
        # original redactor's sensitivity/length checks for that default.
        for match in re.finditer(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-+=?]|[-+=?])([^{}]+)\}", value):
            super()._remember(match.group(1), level)
        super()._remember(value, level)


class _Collector:
    def __init__(self):
        self.reader = _Reader()
        self.sources, self.observations, self.gaps = [], [], set()
        self.clients = set()
        self.redactor = _LocalRedactor()

    def display_text(self, value, maximum=1024):
        """Keep useful local labels while removing credentials and URL details."""
        def origin(match):
            try:
                parts = urlsplit(match.group())
                host = parts.hostname
                if not host:
                    return "[redacted URL]"
                host = "[" + host + "]" if ":" in host else host
                return parts.scheme + "://" + host + (":" + str(parts.port) if parts.port else "")
            except (ValueError, UnicodeError):
                return "[redacted URL]"
        text = str(value)
        text = re.sub(r"(?:https?|wss?)://[^\s\"'<>]+", origin, text, flags=re.I)
        text = re.sub(r"\b(?:api[-_]?key|token|secret|password|authorization|credential)\s*[:=]\s*[^\s/]+", "[redacted credential]", text, flags=re.I)
        return self.redactor.text(text, maximum=maximum)

    def declaration(self, key, name):
        return key + "[" + json.dumps(self.display_text(name), ensure_ascii=False) + "]"

    def source(self, client, prefix, relative):
        location = prefix + "/" + str(relative).replace("\\", "/")
        source = {"id": "src-" + _id(client, location), "client": client, "scope": "user" if prefix == "~" else prefix, "location": location, "status": "missing", "reason": "standard location not present"}
        self.sources.append(source)
        return source

    def gap(self, source, reason, status="skipped"):
        reasons = source.setdefault("reasons", [])
        previous = source.get("reason")
        if source.get("status") in {"error", "skipped"} and previous and previous not in reasons:
            reasons.append(previous)
        if reason not in reasons:
            reasons.append(reason)
        if source.get("status") == "error":
            status = "error"
        source.update(status=status, reason=reason)
        self.gaps.add(source["location"] + ": " + reason)

    def observe(self, source, kind, name, details, enabled="unknown", discriminator="", location=None):
        location = self.display_text(location or source["location"], maximum=4096)
        name = self.display_text(name)
        details = {"context": source.get("context", "base"), "accountAlias": source.get("accountAlias", "~"), **details}
        if kind == "setting" and isinstance(details.get("key"), str):
            from .engine.adapters.settings import category, value_type
            details.setdefault("nativeKey", details["key"])
            details.setdefault("category", category(details["key"]))
            details.setdefault("effectiveState", details.get("declaredState", "unknown"))
            details.setdefault("valueCollected", isinstance(details.get("value"), (bool, int, float, str)))
            details.setdefault("valueType", value_type(details.get("value")))
        if kind == "plugin":
            details.setdefault("artifactType", "plugin")
            details.setdefault("origin", "unknown")
            details.setdefault("installationState", {"configured": "config_only", "cached": "cached", "installed": "installed"}.get(details.get("activation"), "unknown"))
        if source.get("packageState"):
            details.setdefault("packageState", source["packageState"])
        item = {"id": "obs-" + _id(source["id"], kind, discriminator or name), "kind": kind, "client": source["client"], "name": name, "sourceId": source["id"], "location": location, "enabled": enabled, "details": details}
        self.observations.append(item)
        return item

    def client(self, source):
        if source["client"] not in self.clients and source["client"] != "shared":
            self.observe(source, "client", source["client"], {"activation": "present", "version": "not-inspected"})
            self.clients.add(source["client"])

    def settings(self, source, data, context="base", profile_id=None, selected=None, selected_data=None):
        definitions = SETTING_TYPES.get(source["client"], {})
        for key, expected in definitions.items():
            value = _get(data, key)
            if value is ABSENT:
                continue
            valid = type(value) is bool if expected is bool else isinstance(value, str) and value in expected
            if source["client"] == "gemini-cli" and key == "tools.sandbox" and isinstance(value, str):
                valid = value in {"docker", "podman", "lxc", "windows-native", "sandbox-exec"}
            if key == "features.network_proxy" and isinstance(value, dict):
                continue
            if not valid:
                self.gap(source, "one or more recognized settings has an unsupported type or value", "error")
                continue
            details = {"key": key, "value": value, "context": context, "interpretation": "configured"}
            if profile_id is not None:
                details.update(profileId=profile_id, profileSelected=selected)
            if selected_data and _get(selected_data, key) is not ABSENT:
                details["shadowedBySelectedProfile"] = True
            if source["client"] == "claude-code" and context == "project" and key == "permissions.defaultMode" and value in {"auto", "bypassPermissions"}:
                details["applicability"] = "version-dependent; ignored from project settings by current clients"
            enabled = "disabled" if selected is False else "enabled"
            self.observe(source, "setting", key, details, enabled, (profile_id or context) + ":" + key)
        start = len(self.observations)
        self.structural_settings(source, data, context if profile_id is None else profile_id)
        for item in self.observations[start:]:
            if profile_id is not None:
                item["details"].update(context="profile", profileId=profile_id, profileSelected=selected)
                item["enabled"] = "disabled" if selected is False else "enabled"

    def structural_settings(self, source, data, context):
        client = source["client"]
        literal, references = _credential_counts(data)
        if literal or references:
            item = self.observe(source, "setting", "Configuration credential storage", {"key": "credentialStorage", "value": {"literalCredentialCount": literal, "credentialReferenceCount": references}, "literalCredentialCount": literal, "credentialReferenceCount": references, "context": context}, "enabled", context + ":credentials")
            item["_content"] = credential_content(data)
        for key in ({"codex": ["sandbox_workspace_write.writable_roots"], "claude-code": ["permissions.additionalDirectories", "sandbox.excludedCommands"], "gemini-cli": ["tools.allowed", "tools.discoveryCommand", "tools.callCommand", "agents.browser.allowedDomains"], "cursor": ["permissions.allow", "permissions.deny", "terminalAllowlist", "mcpAllowlist"], "windsurf": ["windsurf.cascadeCommandsAllowList", "windsurf.cascadeCommandsDenyList"], "vscode": ["chat.tools.terminal.autoApprove"]}.get(client, [])):
            value = _get(data, key)
            if value is ABSENT:
                continue
            summary = {}
            if isinstance(value, list) and all(isinstance(item, str) for item in value):
                summary = {"entryCount": len(value)}
                if key == "sandbox_workspace_write.writable_roots" or key == "permissions.additionalDirectories":
                    summary["broadFilesystemRoot"] = any(item in {"/", "~", "~/", "C:\\", "C:/"} for item in value)
                else:
                    summary["broadApproval"] = any(item in {"*", "Shell(*)", "Bash", "Bash(*)", "Mcp(*:*)", "*:*", "WebFetch(*)", "run_shell_command"} for item in value)
            elif key == "chat.tools.terminal.autoApprove" and isinstance(value, dict):
                summary = {"entryCount": len(value), "broadApproval": any(key in {"/.*/", "/^.*$/"} and item is True for key, item in value.items()), "hasApprovalRequiredRules": any(item is False for item in value.values())}
                summary["broadApprovalBlocked"] = any(key in {"/.*/", "/^.*$/"} and item is False for key, item in value.items())
                summary["autoApprovalDisabled"] = _get(data, "chat.tools.terminal.enableAutoApprove") is False
            elif key in {"tools.discoveryCommand", "tools.callCommand"} and isinstance(value, str) and value:
                summary = {"commandConfigured": True}
            else:
                self.gap(source, "one or more recognized setting lists has an unsupported shape", "error")
                continue
            self.observe(source, "setting", key, {"key": key, "value": summary, "context": context}, "enabled", context + ":" + key)
        # Broad Claude permission rules are summarized, never copied into evidence.
        if client == "claude-code":
            for key in ("permissions.allow", "permissions.deny"):
                entries = _get(data, key)
                if entries is ABSENT:
                    continue
                if not isinstance(entries, list) or not all(isinstance(item, str) for item in entries):
                    self.gap(source, "permission rules have an unsupported shape", "error")
                    continue
                value = {"entryCount": len(entries), "broadShell": any(item in {"Bash", "Bash(*)", "Bash(:*)"} for item in entries), "broadMcp": any(item in {"mcp__*", "mcp__*__*"} for item in entries)}
                self.observe(source, "setting", key, {"key": key, "value": value, "context": context}, "enabled", context + ":" + key)

    def mcps(self, source, entries, parent_disabled=False, context="base", map_key="mcpServers"):
        from .extra_clients import NormalizedConnection
        self.redactor.learn(entries)
        source["classification"] = "mcp-configuration"
        source["componentKind"] = "mcp"
        if not isinstance(entries, dict):
            source["issueKind"] = "unsupported-mcp-shape"
            self.gap(source, "MCP configuration has an unsupported shape", "error")
            return
        for ordinal, (name, entry) in enumerate(sorted(entries.items()), 1):
            if not isinstance(entry, dict):
                source["issueKind"] = "unsupported-mcp-shape"
                self.gap(source, "an MCP entry has an unsupported shape", "error")
                continue
            if source["client"] == "cline" and isinstance(entry.get("transport"), dict):
                entry = {**entry, **entry["transport"]}
            display_name = name
            declaration = self.declaration(map_key, name)
            if source["client"] == "continue" and isinstance(name, str) and re.fullmatch(r"declared-\d+", name):
                declaration = map_key + "[" + str(int(name.removeprefix("declared-")) - 1) + "]"
                display_name = entry.get("name") or declaration
                if not isinstance(display_name, str):
                    display_name = declaration
            item_id = _id(name, context)
            enabled = "disabled" if parent_disabled or entry.get("enabled") is False or entry.get("disabled") is True else "enabled" if entry.get("enabled") is True or entry.get("disabled") is False else "unknown"
            malformed = False
            for key, expected in {"type": str, "enabled": bool, "disabled": bool, "trust": bool, "command": str, "args": list, "env": dict, "headers": dict, "http_headers": dict}.items():
                if key in entry and type(entry[key]) is not expected:
                    malformed = True
                    source["issueKind"] = "unsupported-mcp-shape"
                    self.gap(source, "an MCP field has an unsupported type", "error")
            url = next((entry.get(key) for key in _url_keys(source["client"]) if key in entry), None)
            endpoint = _endpoint(url)
            transport = entry.get("type")
            explicit_transport = "type" in entry
            transport = {"streamable-http": "http", "streamableHttp": "http", "ws": "websocket"}.get(transport, transport) if isinstance(transport, str) else None
            if explicit_transport and transport not in {"stdio", "http", "sse", "websocket", "sdk"}:
                transport = "unknown"
            elif transport not in {"stdio", "http", "sse", "websocket", "sdk"}:
                transport = "stdio" if isinstance(entry.get("command"), str) else "http" if url is not None else "unknown"
                if source["client"] == "gemini-cli" and "url" in entry and "httpUrl" not in entry:
                    transport = "sse"
            execution = "local" if transport in {"stdio", "sdk"} or endpoint["endpointScope"] == "local-ipc" else "remote" if url is not None else "unknown"
            if entry.get("experimental_environment") == "remote":
                execution = "remote"
            literal, references = _credential_counts(entry)
            family, unversioned = _tool_metadata(entry)
            capability = _mcp_capability_metadata(display_name, entry)
            if capability["capability"] == "computer":
                family = "computer"
            from .engine.adapters.mcp import auth_metadata
            auth, _ = auth_metadata(entry)
            # Whether the header used to sign in holds the secret itself, not a reference.
            auth_inline = _credential_counts({key: entry[key] for key in ("headers", "http_headers") if key in entry})[0] > 0
            allow_key = "enabled_tools" if source["client"] == "codex" else "includeTools" if source["client"] == "gemini-cli" else None
            deny_key = "disabled_tools" if source["client"] == "codex" else "excludeTools" if source["client"] == "gemini-cli" else "disabledTools"
            allow = isinstance(entry.get(allow_key), list) if allow_key else False
            deny = isinstance(entry.get(deny_key), list)
            approval = "all" if source["client"] == "gemini-cli" and entry.get("trust") is True else "none" if source["client"] == "gemini-cli" and entry.get("trust") is False else "unknown"
            details = {"transport": transport, "execution": execution, **endpoint, "toolFamily": family, "literalCredentialCount": literal + endpoint["urlCredentialCount"], "credentialReferenceCount": references, "toolAllowlistConfigured": allow, "toolDenylistConfigured": deny, "autoApproval": approval, "unversionedPackage": unversioned, "activation": "configured", "auditStatus": "not-assessed", "context": context}
            details.update(capability, auth=auth, authSecretInline=auth_inline, inlineCredentialPresent=literal + endpoint["urlCredentialCount"] > 0)
            if malformed:
                details["configurationIssue"] = "unsupported-mcp-shape"
            elif transport == "unknown" or (url is not None and endpoint["endpointScope"] == "unknown"):
                details["configurationIssue"] = "uninterpreted-mcp-transport"
            details["declaration"] = declaration
            details.update(_provider_metadata(entry))
            if _palma_gateway(entry, transport):
                details["governedBy"] = "palma-gateway"
            if type(entry.get("sandboxEnabled")) is bool:
                details["sandboxConfigured"] = entry["sandboxEnabled"]
            item = self.observe(source, "mcp", display_name, details, enabled, context + ":" + item_id)
            item["_content"] = entry.content_digest if isinstance(entry, NormalizedConnection) else content_digest(entry)
            if transport == "unknown" or (url is not None and endpoint["endpointScope"] == "unknown"):
                source.setdefault("issueKind", "uninterpreted-mcp-transport")
                self.gap(source, "an MCP transport or endpoint could not be interpreted", "error")

    def extensions(self, source, data, context="base"):
        self.redactor.learn(data)
        plugins = data.get("enabledPlugins", {})
        if isinstance(plugins, dict):
            for name, enabled in sorted(plugins.items()):
                item_id = _id(name)
                state = "enabled" if enabled is True else "disabled" if enabled is False else "unknown"
                self.observe(source, "plugin", name, {"auditStatus": "not-assessed", "activation": "configured", "context": context, "declaration": self.declaration("enabledPlugins", name)}, state, item_id)
        if source["client"] == "vscode":
            for key in ("chat.pluginLocations", "chat.plugins.enabledPlugins"):
                entries = _get(data, key)
                if not isinstance(entries, dict):
                    continue
                for ordinal, (name, enabled) in enumerate(sorted(entries.items()), 1):
                    state = "disabled" if enabled is False or _get(data, "chat.plugins.enabled") is False else "enabled" if enabled is True else "unknown"
                    item_id = _id(key, name)
                    self.observe(source, "plugin", name, {"auditStatus": "not-assessed", "activation": "configured", "context": context, "declaration": self.declaration(key, name)}, state, item_id)
            hook_locations = _get(data, "chat.hookFilesLocations")
            if isinstance(hook_locations, dict) and hook_locations:
                state = "disabled" if _get(data, "chat.useHooks") is False or all(value is False for value in hook_locations.values()) else "unknown"
                names = [self.display_text(name) for name in sorted(hook_locations)]
                # Folder names stay in configuredLocations; the row name never carries a path.
                item = self.observe(source, "hook", "Hook folders", {"activation": "configured", "context": context, "auditStatus": "not-assessed", "configuredLocations": names, "typeCounts": {"configuredLocations": len(hook_locations)}}, state)
                item["_content"] = content_digest(hook_locations)
        hooks = data.get("hooks", {})
        if isinstance(hooks, dict) and hooks:
            # Event names identify the declaration; command and prompt bodies stay private.
            pending, counts = [hooks], {"command": 0, "prompt": 0, "agent": 0, "http": 0}
            while pending:
                item = pending.pop()
                if isinstance(item, dict):
                    kind = item.get("type")
                    if isinstance(kind, str) and kind in counts:
                        counts[kind] += 1
                    pending.extend(value for value in item.values() if isinstance(value, (dict, list)))
                elif isinstance(item, list):
                    pending.extend(value for value in item if isinstance(value, (dict, list)))
            state = "disabled" if data.get("disableAllHooks") is True or _get(data, "features.hooks") is False else "unknown"
            if sum(counts.values()):
                events = [self.display_text(event) for event in sorted(hooks)]
                item = self.observe(source, "hook", "Hooks: " + ", ".join(events), {"events": events, "declaration": "hooks", "typeCounts": counts, "activation": "configured", "auditStatus": "not-assessed", "context": context}, state)
                item["_content"] = content_digest(hooks)
            else:
                self.gap(source, "a declared hook block had no interpretable handler entries")
        if isinstance(data.get("notify"), list) and data["notify"]:
            item = self.observe(source, "hook", "Configured notification command", {"typeCounts": {"command": 1}, "activation": "configured", "auditStatus": "not-assessed", "context": context})
            item["_content"] = content_digest(data["notify"])

    def state(self, root, source, data):
        projects = data.get("projects")
        if not isinstance(projects, dict):
            return
        counts = {"missingWithinHomeCount": 0, "presentWithinHomeCount": 0, "notCheckedCount": 0}
        for name in projects:
            try:
                path = Path(name)
                if not path.is_absolute() or not path.is_relative_to(root) or ".." in path.parts:
                    counts["notCheckedCount"] += 1
                    continue
                self.reader.info(root, path.relative_to(root))
                counts["presentWithinHomeCount"] += 1
            except FileNotFoundError:
                counts["missingWithinHomeCount"] += 1
            except (_Gap, OSError, ValueError):
                counts["notCheckedCount"] += 1
        self.observe(source, "setting", "Saved project references", {"key": "projects.referenceInventory", "value": counts, "context": "state", "interpretation": "historical references"}, "unknown")

    def process_data(self, root, source, data, context="base", filename=""):
        client = source["client"]
        if filename == ".claude.json":
            self.state(root, source, data)
        else:
            profiles = data.get("profiles", {}) if client == "codex" else {}
            selected = data.get("profile") if context == "base" else None
            chosen = profiles.get(selected) if isinstance(profiles, dict) and isinstance(selected, str) else None
            self.settings(source, data, context, selected_data=chosen if isinstance(chosen, dict) else None)
            self.extensions(source, data, context)
            if isinstance(profiles, dict):
                for name, profile in sorted(profiles.items()):
                    if isinstance(profile, dict):
                        profile_id = "profile-" + _id(name)
                        profile_selected = name == selected if isinstance(selected, str) else None
                        self.settings(source, profile, "profile", profile_id, profile_selected)
                        if "mcp_servers" in profile:
                            start = len(self.observations)
                            self.mcps(source, profile["mcp_servers"], context=profile_id, map_key=self.declaration("profiles", name) + ".mcp_servers")
                            applicability = "selected profile declaration; runtime activation not verified" if profile_selected is True else "unselected profile declaration" if profile_selected is False else "profile selection not observed"
                            for item in self.observations[start:]:
                                item["details"].update(context="profile", profileId=profile_id,
                                                       profileSelected=profile_selected, applicability=applicability)
        key = "mcp_servers" if client == "codex" and "mcp_servers" in data else "servers" if client == "vscode" and filename == "mcp.json" else "mcpServers"
        if key in data:
            self.mcps(source, data[key], context=context, map_key=key)


def collect_scopes(profiles, system_sources=None, workspaces=None, *, scope_type="machine", discovery_gaps=None, include_installations=False, excluded_roots=()):
    """Collect discovered profile, workspace, system-file and in-memory policy sources."""
    from .baseline import collect_scopes as collect_baseline
    return collect_baseline(profiles, system_sources, workspaces, scope_type=scope_type, discovery_gaps=discovery_gaps,
                            include_installations=include_installations, excluded_roots=excluded_roots)


def collect(home: Path, workspaces=None, *, scope_type="current-user") -> dict:
    """Isolated supplied-home mode; never read the actual host's system sources."""
    home = Path(home).absolute()
    if not home.is_dir() or home.parent == home:
        raise ValueError("home must be a selected user directory")
    roots = list(dict.fromkeys(Path(path).absolute() for path in (workspaces or [])))
    if any(not path.is_dir() or path.parent == path for path in roots):
        raise ValueError("workspace must be a directory, never a filesystem root")
    snapshot = collect_scopes([{"root": home, "alias": "~"}], workspaces=roots, scope_type=scope_type)
    snapshot["observations"] = merge_clients(snapshot["observations"])
    # A copied home is usually named after its account; its paths and name stay out too.
    from .machine import identity_scrubber
    return identity_scrubber(home, (), {home.name}).scrub_snapshot(snapshot)
