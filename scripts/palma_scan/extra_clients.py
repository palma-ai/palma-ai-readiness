"""Additional AI-client configuration adapters.

Only documented configuration keys become evidence. Arbitrary instructions,
connection names, command lines, URLs, and credential values are never emitted.
The catalog is deliberately independent of the collection backend and evaluator.
"""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

from .dedup import content_digest

# Primary documentation and schemas checked when adding these adapters. These
# URLs are references for report readers, never collection or upload endpoints.
SOURCE_REFERENCES = {
    "opencode": ["https://opencode.ai/docs/config/", "https://opencode.ai/docs/permissions/",
                 "https://opencode.ai/v2/docs/config", "https://opencode.ai/v2/docs/permissions",
                 "https://opencode.ai/v2/docs/mcp-servers"],
    "copilot-cli": ["https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference",
                    "https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/configuring-local-sandbox-settings"],
    "continue": ["https://docs.continue.dev/reference", "https://docs.continue.dev/cli/configuration",
                 "https://docs.continue.dev/reference/json-reference"],
    "aider": ["https://aider.chat/docs/config.html", "https://aider.chat/docs/config/options.html",
              "https://aider.chat/docs/config/api-keys.html"],
    "lm-studio": ["https://lmstudio.ai/blog/lmstudio-v0.3.17", "https://lmstudio.ai/docs/app/mcp"],
    "antigravity": ["https://antigravity.google/docs/mcp", "https://antigravity.google/docs/cli/settings/",
                    "https://antigravity.google/docs/cli/permissions/", "https://antigravity.google/docs/plugins/"],
    "openclaw": ["https://docs.openclaw.ai/gateway/configuration", "https://docs.openclaw.ai/gateway/config-gateway",
                 "https://docs.openclaw.ai/gateway/config-agents/sandbox", "https://docs.openclaw.ai/gateway/config-browser-ui-desktop",
                 "https://docs.openclaw.ai/tools/exec-approvals"],
    "cline": ["https://github.com/cline/cline/blob/main/sdk/packages/shared/src/storage/paths.ts",
              "https://github.com/cline/cline/blob/main/sdk/packages/core/src/services/global-settings.ts",
              "https://github.com/cline/cline/blob/main/apps/vscode/src/shared/AutoApprovalSettings.ts",
              "https://github.com/cline/cline/blob/main/apps/vscode/src/core/controller/state/updateAutoApprovalSettings.ts"],
    "roo-code": ["https://github.com/RooCodeInc/Roo-Code/blob/main/packages/types/src/global-settings.ts",
                 "https://github.com/RooCodeInc/Roo-Code/blob/main/src/core/config/ContextProxy.ts"],
    "kiro": ["https://kiro.dev/docs/mcp/configuration/", "https://kiro.dev/docs/mcp/security/"],
    "ollama": ["https://docs.ollama.com/faq"],
}

# VS Code stores extension globalState JSON under the extension identifier in
# the profile-scoped ItemTable. These references establish the storage mapping,
# not a claim that a saved extension/profile is currently loaded.
EDITOR_STATE_REFERENCES = (
    "https://github.com/microsoft/vscode/blob/main/src/vs/workbench/api/common/extHostMemento.ts",
    "https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/common/extensionStorage.ts",
    "https://github.com/microsoft/vscode/blob/main/src/vs/base/parts/storage/node/storage.ts",
    "https://github.com/cline/cline/blob/main/apps/vscode/package.json",
    "https://github.com/RooCodeInc/Roo-Code/blob/main/src/package.json",
)

_EDITOR_STATE_ROWS = {
    "saoudrizwan.claude-dev": "cline",
    "rooveterinaryinc.roo-cline": "roo-code",
    "RooVeterinaryInc.roo-cline": "roo-code",
}
_EDITOR_STATE_PRODUCTS = {
    "Code": "vscode", "Code - Insiders": "vscode", "Cursor": "cursor",
    "Windsurf": "windsurf", "Kiro": "kiro",
}

EXTRA_USER_CONFIGS = [
    ("opencode", ".config/opencode/opencode.json", "jsonc"),
    ("opencode", ".config/opencode/opencode.jsonc", "jsonc"),
    ("copilot-cli", ".copilot/settings.json", "jsonc"),
    ("copilot-cli", ".copilot/config.json", "json"),
    ("copilot-cli", ".copilot/mcp-config.json", "jsonc"),
    ("copilot-cli", ".copilot/permissions-config.json", "json"),
    ("continue", ".continue/config.json", "json"),
    ("continue", ".continue/config.yaml", "yaml"),
    ("aider", ".aider.conf.yml", "yaml"),
    ("lm-studio", ".lmstudio/mcp.json", "json"),
    ("antigravity", ".gemini/config/mcp_config.json", "json"),
    ("antigravity", ".gemini/antigravity-cli/settings.json", "json"),
    ("openclaw", ".openclaw/openclaw.json", "json5"),
    ("openclaw", ".openclaw/exec-approvals.json", "json"),
    ("cline", ".cline/data/settings/providers.json", "json"),
]

EXTRA_WORKSPACE_CONFIGS = [
    ("opencode", "opencode.json", "jsonc"),
    ("opencode", "opencode.jsonc", "jsonc"),
    ("opencode", ".opencode/opencode.json", "jsonc"),
    ("opencode", ".opencode/opencode.jsonc", "jsonc"),
    ("copilot-cli", ".github/copilot/settings.json", "jsonc"),
    ("copilot-cli", ".github/copilot/settings.local.json", "jsonc"),
    ("copilot-cli", ".github/mcp.json", "jsonc"),
    ("aider", ".aider.conf.yml", "yaml"),
    ("antigravity", ".agents/mcp_config.json", "json"),
]

EXTRA_SKILLS = [
    ("opencode", ".config/opencode/skills"),
    ("opencode", ".opencode/skills"),
    ("copilot-cli", ".copilot/skills"),
    ("copilot-cli", ".github/skills"),
    ("antigravity", ".gemini/antigravity-cli/skills"),
    ("openclaw", ".openclaw/skills"),
]
EXTRA_AGENTS = [
    ("opencode", ".config/opencode/agents"),
    ("opencode", ".opencode/agents"),
    ("copilot-cli", ".copilot/agents"),
    ("copilot-cli", ".github/agents"),
]

# Paths already covered by the original collector (Cline/Roo/Kiro and editor
# profiles) are intentionally absent from the additive candidate lists above.
EXTRA_PLUGINS = [
    ("antigravity", ".gemini/config/plugins"),
    ("antigravity", ".gemini/antigravity-cli/plugins"),
    ("antigravity", ".agents/plugins"),
    ("copilot-cli", ".copilot/installed-plugins"),
]

EXTRA_SETTING_TYPES = {
    "opencode": {"share": {"manual", "auto", "disabled"}, "server.mdns": bool,
                 "experimental.portable_shell_scanner": bool},
    "copilot-cli": {
        "askUser": bool, "autoUpdate": bool,
        "autoUpdatesChannel": {"stable", "prerelease"},
        "disableAllHooks": bool, "experimental": bool,
        "customAgents.defaultLocalOnly": bool, "dynamicRetrieval.skills": bool,
        "permissions.disableBypassPermissionsMode": {"disable", "allow-auto-only"},
        "remote": {"on", "off"}, "remoteExport": bool,
        "sandbox.enabled": bool, "sandbox.allowBypass": bool,
        "sandbox.auth.git": bool, "sandbox.auth.gh": bool,
        "sandbox.userPolicy.network.allowLocalNetwork": bool,
        "sandbox.userPolicy.seatbelt.keychainAccess": bool,
    },
    "continue": {"allowAnonymousTelemetry": bool},
    "aider": {"yes-always": bool, "verify-ssl": bool, "auto-lint": bool,
              "auto-test": bool, "auto-commits": bool, "dirty-commits": bool,
              "analytics-disable": bool, "disable-playwright": bool,
              "suggest-shell-commands": bool, "gui": bool},
    "antigravity": {
        "toolPermission": {"request-review", "proceed-in-sandbox", "strict", "always-proceed"},
        "artifactReviewPolicy": {"asks-for-review", "agent-decides", "always-proceed"},
    },
    "openclaw": {
        "gateway.mode": {"local", "remote"},
        "gateway.bind": {"auto", "loopback", "lan", "tailnet", "custom"},
        "gateway.auth.mode": {"none", "token", "password", "trusted-proxy"},
        "gateway.tailscale.mode": {"off", "serve", "funnel"},
        "gateway.controlUi.enabled": bool,
        "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback": bool,
        "gateway.terminal.enabled": bool,
        "agents.defaults.sandbox.mode": {"off", "non-main", "all"},
        "agents.defaults.sandbox.workspaceAccess": {"none", "ro", "rw"},
        "agents.defaults.sandbox.browser.enabled": bool,
        "agents.defaults.sandbox.browser.allowHostControl": bool,
        "agents.defaults.sandbox.ssh.strictHostKeyChecking": bool,
        "browser.enabled": bool, "browser.evaluateEnabled": bool,
        "browser.noSandbox": bool, "browser.attachOnly": bool,
        "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork": bool,
        "browser.ssrfPolicy.allowPrivateNetwork": bool,
        "tools.exec.mode": {"deny", "allowlist", "ask", "auto", "full"},
        "tools.exec.host": {"auto", "sandbox", "gateway", "node"},
        "tools.exec.security": {"deny", "allowlist", "full"},
        "tools.exec.ask": {"off", "on-miss", "always"},
        "tools.exec.strictInlineEval": bool,
        "tools.elevated.enabled": bool,
        "plugins.enabled": bool,
    },
    "cline": {
        "toolAutoApprove": bool, "autoUpdateEnabled": bool, "telemetryOptOut": bool,
        "autoApprovalSettings.actions.readFiles": bool,
        "autoApprovalSettings.actions.editFiles": bool,
        "autoApprovalSettings.actions.executeSafeCommands": bool,
        "autoApprovalSettings.actions.useBrowser": bool,
        "autoApprovalSettings.actions.useMcp": bool,
    },
    "roo-code": {key: bool for key in (
        "autoApprovalEnabled", "alwaysAllowReadOnly", "alwaysAllowReadOnlyOutsideWorkspace",
        "alwaysAllowWrite", "alwaysAllowWriteOutsideWorkspace", "alwaysAllowWriteProtected",
        "alwaysAllowMcp", "alwaysAllowExecute", "alwaysAllowModeSwitch", "alwaysAllowSubtasks",
        "enableCheckpoints", "showRooIgnoredFiles")},
}

def _rule(rule_id, client, key, value, severity, category, title, summary, recommendation, *, requires=None, unless=None):
    item = {"id": rule_id, "client": client, "key": key, "value": value, "severity": severity,
            "category": category, "title": title, "summary": summary,
            "impact": "If this declaration applies, unintended agent actions can reach the resources permitted by this control. Runtime selection and stronger policy remain unverified.",
            "recommendation": recommendation, "references": SOURCE_REFERENCES[client]}
    if requires:
        item["requires"] = requires
    if unless:
        item["unless"] = unless
    return item


EXTRA_RULES = [
    _rule("PALMA-OPENCODE-001", "opencode", "permissionReview.allToolsAllow", True, "low", "execution",
          "OpenCode declares a blanket permission grant", "The V1 permission value permits every action without a prompt in this source.",
          "Replace the blanket grant with scoped rules and verify the active client version, agent, and configuration layers."),
    _rule("PALMA-OPENCODE-002", "opencode", "permissionReview.broadShellAllow", True, "low", "execution",
          "Review the broad OpenCode shell allowance", "A broad shell rule allows commands. More specific rules and other configuration layers can constrain that grant.",
          "Use narrow command allowances. Check rule order and agent overrides in OpenCode before running sensitive tasks.",
          unless=[{"key": "permissionReview.allToolsAllow", "value": True}]),
    _rule("PALMA-OPENCODE-003", "opencode", "permissionReview.broadExternalDirectoryAllow", True, "low", "filesystem",
          "OpenCode has a broad external-directory allowance", "A configured rule permits the external-directory boundary broadly; individual file or command permissions still apply.",
          "Limit external-directory grants to required paths and review the matching read, edit, and shell rules.",
          unless=[{"key": "permissionReview.allToolsAllow", "value": True}]),
    _rule("PALMA-OPENCODE-004", "opencode", "share", "auto", "high", "sharing",
          "Check the automatic sharing preference", "Automatic session sharing is selected. V1 implements this feature; V2 currently accepts the preference without implementing sharing.",
          "Check the installed version and use manual or disabled sharing when conversations contain sensitive information."),
    _rule("PALMA-OPENCODE-005", "opencode", "experimental.portable_shell_scanner", True, "low", "experimental",
          "An experimental shell scanner is selected", "The V2 portable shell permission scanner is enabled. This changes parsing behavior; it does not itself remove permission checks.",
          "Validate supported command parsing before enterprise use and document ownership of the experimental configuration."),
    _rule("PALMA-OPENCODE-006", "opencode", "configurationReview.mixedPermissionSchemas", True, "info", "hygiene",
          "OpenCode mixes permission schema generations", "Both V1 and V2 permission fields are present. Their action names and matching schemas differ.",
          "Keep the schema supported by the installed OpenCode version and remove obsolete declarations after checking the intended rules."),
    _rule("PALMA-COPILOT-002", "copilot-cli", "sandbox.userPolicy.seatbelt.keychainAccess", True, "medium", "credentials",
          "Copilot sandbox keychain access is configured", "The same source enables sandboxing and permits macOS keychain access from sandboxed commands.",
          "Remove keychain access unless required; prefer narrowly scoped credentials and verify the effective sandbox policy.",
          requires=[{"key": "sandbox.enabled", "value": True}]),
    _rule("PALMA-COPILOT-003", "copilot-cli", "experimental", True, "low", "experimental",
          "Copilot CLI experimental features are enabled", "The source opts into experimental CLI features. Their availability and behavior depend on the installed version.",
          "Assign an owner for experimental features and validate them before using sensitive repositories."),
    _rule("PALMA-COPILOT-004", "copilot-cli", "remote", "on", "high", "remote access",
          "Review Copilot session sync and remote access", "The source enables Copilot CLI's combined remote-access and session-sync preference; no active remote session was observed.",
          "Confirm this feature is appropriate for the account and repositories. Use remote=off where session data must remain local."),
    _rule("PALMA-COPILOT-005", "copilot-cli", "savedApprovals.allMcpTools", True, "low", "tool access",
          "A saved Copilot approval covers every tool on a server", "A saved location grants all MCP tools for a named server. The server identity is withheld and configuration matching is unverified.",
          "Review saved approvals in Copilot. Prefer individual tools and remove approvals for connections no longer used."),
    _rule("PALMA-COPILOT-006", "copilot-cli", "savedApprovals.fileWrites", True, "low", "filesystem",
          "Copilot retains a saved file-write approval", "A saved location permits file writes without the normal tool prompt. Directory permission checks can still apply.",
          "Review whether the location still needs standing write approval and remove obsolete saved permissions."),
    _rule("PALMA-CONTINUE-001", "continue", "models.requestOptions.verifySsl", False, "high", "network",
          "Continue disables TLS certificate verification", "A configured model explicitly disables TLS certificate verification for requests.",
          "Restore certificate verification. Configure a trusted CA bundle for private certificate authorities instead of bypassing validation."),
    _rule("PALMA-CONTINUE-002", "continue", "data.networkIncludesCode", True, "high", "sharing",
          "Continue can send code-bearing events to a data destination", "A network data destination uses the all-fields level, explicitly or through Continue's documented default.",
          "Review destination ownership and event selection. Choose noCode where appropriate, or remove unneeded data destinations."),
    _rule("PALMA-AIDER-001", "aider", "yes-always", True, "low", "execution",
          "Aider is configured to accept every confirmation", "The yes-always option removes ordinary confirmation opportunities in this source.",
          "Keep confirmations enabled for sensitive work and scope unattended runs to an independently isolated workspace."),
    _rule("PALMA-AIDER-002", "aider", "verify-ssl", False, "high", "network",
          "Aider disables TLS certificate verification", "The source explicitly disables SSL certificate verification for provider requests.",
          "Restore certificate verification and fix trust configuration for the required provider endpoint."),
    _rule("PALMA-AIDER-003", "aider", "load.configured", True, "critical", "execution",
          "Aider has a startup command file", "The source configures a file whose Aider commands load at startup. Its body has not been read or executed by this scan.",
          "Review the configured command file, restrict who can modify it, and remove the startup reference if it is no longer needed."),
    _rule("PALMA-ANTIGRAVITY-001", "antigravity", "toolPermission", "always-proceed", "low", "execution",
          "Antigravity is set to always proceed with tools", "The tool permission preference allows tools without routine approval prompts. Scoped permission rules may still constrain access.",
          "Use request-review or strict for sensitive work and verify sandbox and permission rules in the active client."),
    _rule("PALMA-ANTIGRAVITY-002", "antigravity", "permissionReview.unsandboxedWildcard", True, "low", "execution",
          "Antigravity broadly allows unsandboxed commands", "The unsandboxed command allowance covers every target without a same-source wildcard ask or deny rule.",
          "Replace the wildcard with narrowly reviewed exceptions and inspect all permission layers before enabling terminal automation."),
    _rule("PALMA-ANTIGRAVITY-003", "antigravity", "permissionReview.execute_urlWildcard", True, "critical", "browser access",
          "Antigravity has a broad browser-action allowance", "A configured execute_url wildcard permits browser actions across domains; narrower rules can still restrict particular targets.",
          "Limit browser interaction permissions to approved domains and use a dedicated browser profile for sensitive work."),
    _rule("PALMA-OPENCLAW-001", "openclaw", "gateway.auth.mode", "none", "high", "remote access",
          "OpenClaw gateway authentication is disabled", "The gateway source explicitly selects no authentication. This does not establish network reachability or a running gateway.",
          "Use gateway authentication and verify listener interfaces. Keep deliberate unauthenticated use confined to trusted local access."),
    _rule("PALMA-OPENCLAW-002", "openclaw", "gateway.bind", "lan", "high", "remote access",
          "OpenClaw declares an all-interface gateway listener", "The LAN bind mode targets all IPv4 interfaces. Gateway startup, authentication, firewall rules, and reachability are unverified.",
          "Prefer loopback or a required private interface. Verify authentication and host firewall restrictions before running the gateway."),
    _rule("PALMA-OPENCLAW-003", "openclaw", "gateway.tailscale.mode", "funnel", "high", "remote access",
          "OpenClaw declares a public Funnel route", "The configured Tailscale mode requests Funnel exposure. This is a saved preference, not proof of a published route.",
          "Review whether public access is necessary and verify gateway authentication, origin restrictions, and the actual Tailscale configuration."),
    _rule("PALMA-OPENCLAW-004", "openclaw", "tools.exec.mode", "full", "low", "execution",
          "OpenClaw requests full host execution", "The normalized host-execution mode omits ordinary policy prompts. Host-local approvals and strict inline-eval controls can still constrain commands.",
          "Choose ask or allowlist for routine work and review the corresponding host approvals document and any session overrides."),
    _rule("PALMA-OPENCLAW-005", "openclaw", "browser.noSandbox", True, "high", "browser access",
          "OpenClaw disables the browser sandbox", "The same source enables browser control and disables the browser's sandbox.",
          "Restore the browser sandbox where supported and verify the selected browser profile and host isolation.",
          requires=[{"key": "browser.enabled", "value": True}]),
    _rule("PALMA-OPENCLAW-006", "openclaw", "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork", True, "high", "browser access",
          "OpenClaw browser access extends to private networks", "The same source enables browser control and explicitly allows private-network destinations through its SSRF policy.",
          "Prefer specific allowed hostnames, isolate browser sessions, and review access to internal services.",
          requires=[{"key": "browser.enabled", "value": True}]),
    _rule("PALMA-OPENCLAW-007", "openclaw", "savedExecApprovals.askFallback", "full", "low", "execution",
          "Review the OpenClaw approval fallback", "A saved host policy adds no stricter security fallback when approval UI is unavailable. Other explicit restrictions remain relevant.",
          "Prefer deny when approval cannot be obtained and verify how this saved host policy combines with tools.exec settings."),
    _rule("PALMA-CLINE-001", "cline", "toolAutoApprove", True, "low", "execution",
          "Cline tool auto-approval is configured", "The current Cline global settings opt into tool auto-approval. The scan has not verified an active task or selected tools.",
          "Turn off broad auto-approval for sensitive work and review enabled tools and approved MCP connections."),
    _rule("PALMA-ROO-001", "roo-code", "alwaysAllowWriteOutsideWorkspace", True, "low", "filesystem",
          "Roo Code allows automatic writes outside the workspace", "The same source enables automatic approvals and permits writes beyond the current workspace.",
          "Limit write approvals to the project and review ignored or protected file behavior in the active extension.",
          requires=[{"key": "autoApprovalEnabled", "value": True}, {"key": "alwaysAllowWrite", "value": True}]),
]


def _get(data, key):
    if not isinstance(data, dict):
        return None
    if key in data:
        return data[key]
    value = data
    for component in key.split("."):
        if not isinstance(value, dict) or component not in value:
            return None
        value = value[component]
    return value


def _opaque(value):
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:12]


def _context(source):
    return source.get("context", "project" if source.get("scope") in {"workspace", "project"} else "base")


def _record(collector, source, key, value, *, context=None, extra=None, enabled="enabled"):
    details = {"key": key, "value": value, "context": context or _context(source),
               "interpretation": "configured"}
    if extra:
        details.update(extra)
    return collector.observe(source, "setting", key, details, enabled,
                             "extra:" + details["context"] + ":" + key)


def _invalid(collector, source):
    collector.gap(source, "a recognized additional-client configuration field has an unsupported type or value", "error")


_EXTRA_REFERENCE = re.compile(r"^(?:\{env:[A-Za-z_][A-Za-z0-9_]*\}|\{file:[^{}]+\}|\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\})$")


def _reference(value):
    if isinstance(value, str) and _EXTRA_REFERENCE.fullmatch(value.strip()):
        return "${env:PALMA_UNRESOLVED_REFERENCE}"
    return value


def _normalize_connection(entry, client, *, v2=False):
    """Normalize documented field aliases without resolving or running them."""
    if not isinstance(entry, dict):
        return entry
    result = dict(entry)
    if client == "opencode":
        if entry.get("type") == "local":
            result["type"] = "stdio"
            command = entry.get("command")
            if isinstance(command, list) and command and all(isinstance(arg, str) for arg in command):
                result["command"], result["args"] = command[0], command[1:]
        elif entry.get("type") == "remote":
            result["type"] = "http"
        if "environment" in entry:
            result["env"] = entry["environment"]
        # The V2 schema removed enabled. Preserve it as an unknown declaration
        # in the raw document, but never treat it as a V2 disable switch.
        if v2:
            result.pop("enabled", None)
    if client == "antigravity" and "serverUrl" in entry:
        result["url"] = entry["serverUrl"]
    for field in ("env", "headers", "http_headers"):
        if isinstance(result.get(field), dict):
            result[field] = {key: _reference(value) for key, value in result[field].items()}
    return result


def normalize_extra_data(client, data):
    """Return a shallow adapter view for standard MCP extraction.

    This is in-memory parser input, never output evidence. Call extract_extra
    with the original document after ordinary typed-setting/MCP collection.
    Imported Continue blocks are inventoried as unknown; they are not fetched.
    """
    if not isinstance(data, dict):
        return data
    result = dict(data)
    if client == "opencode" and isinstance(data.get("mcp"), dict):
        v2 = isinstance(data["mcp"].get("servers"), dict)
        entries = data["mcp"]["servers"] if v2 else data["mcp"]
        result["mcpServers"] = {key: _normalize_connection(entry, client, v2=v2)
                                for key, entry in entries.items()}
    elif client == "continue" and isinstance(data.get("mcpServers"), list):
        result["mcpServers"] = {
            "declared-" + str(index): _normalize_connection(entry, client)
            for index, entry in enumerate(data["mcpServers"], 1)
        }
    elif client == "antigravity" and isinstance(data.get("mcpServers"), dict):
        result["mcpServers"] = {key: _normalize_connection(entry, client)
                                for key, entry in data["mcpServers"].items()}
    return result


def _list(collector, source, data, key, *, context=None):
    entries = _get(data, key)
    if entries is None:
        return None
    if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
        _invalid(collector, source)
        return None
    value = {"entryCount": len(entries), "duplicateEntryCount": len(entries) - len(set(entries))}
    _record(collector, source, key, value, context=context)
    return entries


def _credentials(collector, source, values, *, key="additionalCredentialStorage", context=None):
    # The existing core helper understands placeholders and Bearer references.
    # Feed only documented credential fields into it, never arbitrary strings.
    from .collector import _credential_value
    literal = references = 0
    for value in values:
        if isinstance(value, dict):
            if isinstance(value.get("source"), str) and value["source"] in {"env", "file", "exec", "store"} and isinstance(value.get("id"), str):
                references += 1
            continue
        if isinstance(value, str) and value.lower().startswith("bearer "):
            value = value[7:].strip()
        found, reference_count = _credential_value(_reference(value))
        literal += found
        references += reference_count
    if literal or references:
        counts = {"literalCredentialCount": literal, "credentialReferenceCount": references}
        _record(collector, source, key, counts, context=context, extra=counts)


def _endpoint_summary(value):
    from .collector import _endpoint
    return _endpoint(value)


def _opencode_permissions(collector, source, value, *, version, context, enabled="enabled"):
    effects = {"allow", "ask", "deny"}
    summary = {"ruleCount": 0, "allowRuleCount": 0, "askRuleCount": 0, "denyRuleCount": 0,
               "broadShellAllow": False, "broadExternalDirectoryAllow": False,
               "allToolsAllow": False, "schema": version}
    if version == "v1":
        if isinstance(value, str) and value in effects:
            summary.update(ruleCount=1, allToolsAllow=value == "allow",
                           broadShellAllow=value == "allow", broadExternalDirectoryAllow=value == "allow")
            summary[value + "RuleCount"] = 1
        elif isinstance(value, dict):
            for action, rule in value.items():
                rules = [("*", rule)] if isinstance(rule, str) else list(rule.items()) if isinstance(rule, dict) else []
                if not rules or any(not isinstance(pattern, str) or not isinstance(effect, str) or effect not in effects for pattern, effect in rules):
                    _invalid(collector, source)
                    continue
                for pattern, effect in rules:
                    summary["ruleCount"] += 1
                    summary[effect + "RuleCount"] += 1
                    if pattern == "*" and action in {"*", "bash"}:
                        summary["broadShellAllow"] = effect == "allow"
                    if pattern == "*" and action in {"*", "external_directory"}:
                        summary["broadExternalDirectoryAllow"] = effect == "allow"
        else:
            _invalid(collector, source)
            return
    else:
        if not isinstance(value, list):
            _invalid(collector, source)
            return
        for rule in value:
            if (not isinstance(rule, dict) or not isinstance(rule.get("action"), str)
                    or not isinstance(rule.get("resource"), str) or not isinstance(rule.get("effect"), str)
                    or rule["effect"] not in effects):
                _invalid(collector, source)
                continue
            effect, action = rule["effect"], rule["action"]
            summary["ruleCount"] += 1
            summary[effect + "RuleCount"] += 1
            if rule["resource"] == "*":
                if action in {"*", "shell"}:
                    summary["broadShellAllow"] = effect == "allow"
                if action in {"*", "external_directory"}:
                    summary["broadExternalDirectoryAllow"] = effect == "allow"
    _record(collector, source, "permissionReview", summary, context=context, enabled=enabled)
    for key in ("broadShellAllow", "broadExternalDirectoryAllow", "allToolsAllow"):
        _record(collector, source, "permissionReview." + key, summary[key], context=context, enabled=enabled,
                extra={"semantics": "broad declarations; narrower rules and other layers may constrain access"})


def _opencode(collector, source, data):
    context = _context(source)
    start = len(collector.observations)
    if "permission" in data:
        _opencode_permissions(collector, source, data["permission"], version="v1", context=context + ":v1-permissions")
    if "permissions" in data:
        _opencode_permissions(collector, source, data["permissions"], version="v2", context=context + ":v2-permissions")
    if "permission" in data and "permissions" in data:
        for item in collector.observations[start:]:
            item["details"]["applicability"] = "mixed V1/V2 permission schema; select the supported client schema"
        _record(collector, source, "configurationReview.mixedPermissionSchemas", True)
    for field, version in (("agent", "v1"), ("agents", "v2")):
        agents = data.get(field)
        if agents is None:
            continue
        if not isinstance(agents, dict):
            _invalid(collector, source)
            continue
        for name, agent in sorted(agents.items(), key=lambda pair: str(pair[0])):
            if not isinstance(agent, dict):
                _invalid(collector, source)
                continue
            agent_id = "agent-" + _opaque(name)
            disabled_key = "disable" if version == "v1" else "disabled"
            enabled = "disabled" if agent.get(disabled_key) is True else "unknown"
            item = collector.observe(source, "agent", name,
                                     {"activation": "configured", "auditStatus": "not-assessed", "context": context,
                                      "itemId": agent_id, "schema": version, "declaration": collector.declaration(field, name)},
                                     enabled, "extra:" + field + ":" + agent_id)
            item["_content"] = content_digest(agent)
            key = "permission" if version == "v1" else "permissions"
            if key in agent:
                _opencode_permissions(collector, source, agent[key], version=version, context=context + ":" + version + ":" + agent_id, enabled=enabled)
    for field in ("plugin", "plugins"):
        plugins = data.get(field)
        if plugins is None:
            continue
        if not isinstance(plugins, list):
            _invalid(collector, source)
            continue
        for index, plugin in enumerate(plugins, 1):
            package = plugin.get("package") if isinstance(plugin, dict) else plugin
            if not isinstance(package, str):
                _invalid(collector, source)
                continue
            item_id = _opaque(package)
            collector.observe(source, "plugin", package,
                              {"activation": "configured", "auditStatus": "not-assessed", "context": context,
                               "declaration": field + "[" + str(index - 1) + "]", "itemId": item_id},
                              "unknown", "extra:" + field + ":" + str(index))
    server = data.get("server")
    if isinstance(server, dict):
        host = server.get("hostname")
        if isinstance(host, str):
            try:
                kind = "loopback" if ipaddress.ip_address(host.strip("[]")).is_loopback else "non-loopback"
            except ValueError:
                kind = "loopback" if host.lower() == "localhost" else "named-host"
            _record(collector, source, "server.hostnameScope", kind)
        cors = _list(collector, source, data, "server.cors")
        if cors is not None:
            _record(collector, source, "server.corsWildcard", "*" in cors)
    _list(collector, source, data, "instructions")


def _copilot(collector, source, data):
    if source.get("location", "").replace("\\", "/").endswith("/.copilot/config.json"):
        # Current Copilot stores internal state here; old values are not proof
        # of current preferences. Preserve history provenance for existing facts.
        for item in collector.observations:
            if item.get("sourceId") == source["id"]:
                item["details"]["context"] = "state"
                item["details"]["interpretation"] = "saved internal state; current application unverified"
                item["details"]["applicability"] = "legacy/internal Copilot state; current settings are stored separately"
        _list(collector, source, data, "trustedFolders", context="state")
        return
    for key in ("allowedUrls", "deniedUrls", "disabledMcpServers", "disabledSkills", "enabledMcpServers", "skillDirectories",
                "sandbox.userPolicy.deniedPaths"):
        values = _list(collector, source, data, key)
        if key == "allowedUrls" and values is not None:
            _record(collector, source, "allowedUrls.wildcard", "*" in values)
    locations = data.get("locations")
    if locations is None:
        return
    if not isinstance(locations, dict):
        _invalid(collector, source)
        return
    for path, saved in sorted(locations.items(), key=lambda pair: str(pair[0])):
        if not isinstance(saved, dict):
            _invalid(collector, source)
            continue
        context = _context(source) + ":saved-location-" + _opaque(path)
        _list(collector, source, saved, "allowed_directories", context=context)
        approvals = saved.get("tool_approvals", [])
        if not isinstance(approvals, list):
            _invalid(collector, source)
            continue
        counts = {"commandApprovalCount": 0, "writeApprovalCount": 0, "mcpApprovalCount": 0,
                  "allToolsOnServerApprovalCount": 0, "mcpSamplingApprovalCount": 0,
                  "extensionApprovalCount": 0, "otherKnownApprovalCount": 0}
        for approval in approvals:
            if not isinstance(approval, dict):
                _invalid(collector, source)
                continue
            kind = approval.get("kind")
            if kind == "commands":
                commands = approval.get("commandIdentifiers")
                if isinstance(commands, list) and all(isinstance(command, str) for command in commands):
                    counts["commandApprovalCount"] += len(commands)
                else:
                    _invalid(collector, source)
            elif kind == "write":
                counts["writeApprovalCount"] += 1
            elif kind == "mcp" and isinstance(approval.get("serverName"), str) and "toolName" in approval and (approval["toolName"] is None or isinstance(approval["toolName"], str)):
                counts["mcpApprovalCount"] += 1
                counts["allToolsOnServerApprovalCount"] += approval["toolName"] is None
            elif kind == "mcp-sampling" and isinstance(approval.get("serverName"), str):
                counts["mcpSamplingApprovalCount"] += 1
            elif kind in {"extension-management", "extension-permission-access"}:
                counts["extensionApprovalCount"] += 1
            elif kind in {"read", "memory", "custom-tool"}:
                counts["otherKnownApprovalCount"] += 1
        _record(collector, source, "savedApprovals", counts, context=context)
        _record(collector, source, "savedApprovals.allMcpTools", counts["allToolsOnServerApprovalCount"] > 0, context=context)
        _record(collector, source, "savedApprovals.fileWrites", counts["writeApprovalCount"] > 0, context=context)


def _continue(collector, source, data):
    models = data.get("models", [])
    if not isinstance(models, list):
        _invalid(collector, source)
        models = []
    for index, model in enumerate(models, 1):
        if not isinstance(model, dict):
            _invalid(collector, source)
            continue
        context = _context(source) + ":model-" + str(index)
        verify = _get(model, "requestOptions.verifySsl")
        if verify is not None:
            if type(verify) is bool:
                _record(collector, source, "models.requestOptions.verifySsl", verify, context=context)
            else:
                _invalid(collector, source)
        _credentials(collector, source, [_get(model, key) for key in
                     ("apiKey", "requestOptions.clientCertificate.passphrase")], context=context)
        if isinstance(model.get("apiBase"), str):
            _record(collector, source, "models.apiBase", _endpoint_summary(model["apiBase"]), context=context)
    destinations = data.get("data", [])
    if not isinstance(destinations, list):
        _invalid(collector, source)
        destinations = []
    for index, destination in enumerate(destinations, 1):
        if not isinstance(destination, dict):
            _invalid(collector, source)
            continue
        target = destination.get("destination")
        if not isinstance(target, str):
            _invalid(collector, source)
            continue
        try:
            scheme = urlsplit(target).scheme.lower()
        except ValueError:
            scheme = "unknown"
        context = _context(source) + ":data-destination-" + str(index)
        level = destination.get("level")
        valid_level = isinstance(level, str) and level in {"all", "noCode"}
        if level is not None and not valid_level:
            _invalid(collector, source)
        value = {"destinationType": "network" if scheme in {"http", "https"} else "local-file" if scheme == "file" else "unknown",
                 "level": level if valid_level else "unspecified" if level is None else "unsupported"}
        _record(collector, source, "data.destination", value, context=context)
        # Omitted level has the documented default 'all'; label that fact in
        # evidence rather than presenting it as an explicitly stored value.
        _record(collector, source, "data.networkIncludesCode", scheme in {"http", "https"} and (level is None or level == "all"),
                context=context, extra={"levelDefaultApplied": level is None})
        _credentials(collector, source, [destination.get("apiKey")], context=context)
    for key in ("models", "mcpServers", "rules", "prompts"):
        entries = data.get(key)
        if isinstance(entries, list):
            imported = sum(isinstance(entry, dict) and isinstance(entry.get("uses"), str) for entry in entries)
            if imported:
                _record(collector, source, key + ".importedBlocks", {"entryCount": imported, "resolution": "not-fetched"})
                collector.gap(source, "Continue imported blocks were inventoried but not fetched or resolved")


def _aider(collector, source, data):
    values = [data.get("openai-api-key"), data.get("anthropic-api-key")]
    api_keys = data.get("api-key", [])
    if isinstance(api_keys, str):
        api_keys = [api_keys]
    if isinstance(api_keys, list) and all(isinstance(value, str) for value in api_keys):
        values.extend(value.partition("=")[2] for value in api_keys if "=" in value)
    elif api_keys:
        _invalid(collector, source)
    _credentials(collector, source, values)
    for key in ("load", "lint-cmd", "test-cmd", "notifications-command"):
        value = data.get(key)
        if value is not None:
            if isinstance(value, str):
                _record(collector, source, key + ".configured", bool(value.strip()))
            elif key == "lint-cmd" and isinstance(value, list) and all(isinstance(item, str) for item in value):
                _record(collector, source, key + ".configured", bool(value))
            else:
                _invalid(collector, source)


def _antigravity(collector, source, data):
    rules = {}
    for effect in ("allow", "ask", "deny"):
        entries = _list(collector, source, data, "permissions." + effect)
        rules[effect] = set(entries or [])
    for action in ("command", "read_file", "write_file", "read_url", "execute_url", "mcp", "unsandboxed"):
        pattern = action + "(*)"
        allowed = pattern in rules["allow"]
        restricted = pattern in (rules["ask"] | rules["deny"])
        if action == "write_file" and "read_file(*)" in rules["deny"]:
            restricted = True
        if allowed or restricted:
            _record(collector, source, "permissionReview." + action + "Wildcard", allowed and not restricted)


def _openclaw(collector, source, data):
    _credentials(collector, source, [_get(data, key) for key in
                 ("gateway.auth.token", "gateway.auth.password", "gateway.remote.token", "gateway.remote.password", "socket.token")])
    includes = data.get("$include")
    if includes is not None:
        count = 1 if isinstance(includes, str) else len(includes) if isinstance(includes, list) and all(isinstance(item, str) for item in includes) else None
        if count is None:
            _invalid(collector, source)
        else:
            _record(collector, source, "configurationReview.includes", {"entryCount": count, "resolution": "not-resolved"})
            collector.gap(source, "OpenClaw configuration includes were inventoried but not resolved")
    for key in ("gateway.controlUi.allowedOrigins", "gateway.trustedProxies", "tools.allow", "tools.deny",
                "plugins.allow", "plugins.deny", "skills.allowBundled", "skills.load.extraDirs"):
        _list(collector, source, data, key)
    entries = _get(data, "plugins.entries")
    if isinstance(entries, dict):
        for name, plugin in sorted(entries.items(), key=lambda pair: str(pair[0])):
            if not isinstance(plugin, dict):
                _invalid(collector, source)
                continue
            item_id = _opaque(name)
            enabled = "disabled" if _get(data, "plugins.enabled") is False or plugin.get("enabled") is False else "enabled" if plugin.get("enabled") is True else "unknown"
            collector.observe(source, "plugin", name,
                              {"activation": "configured", "auditStatus": "not-assessed", "context": _context(source), "itemId": item_id, "declaration": collector.declaration("plugins.entries", name)},
                              enabled, "extra:plugin:" + item_id)
    if source.get("location", "").endswith("exec-approvals.json"):
        stores = [("defaults", data.get("defaults"))]
        if isinstance(data.get("agents"), dict):
            stores += [("agent-" + _opaque(name), value) for name, value in sorted(data["agents"].items())]
        for label, saved in stores:
            if not isinstance(saved, dict):
                continue
            context = _context(source) + ":saved-" + label
            for key, expected in {"security": {"deny", "allowlist", "full"}, "ask": {"off", "on-miss", "always"},
                                  "askFallback": {"deny", "allowlist", "full"}, "autoAllowSkills": bool}.items():
                value = saved.get(key)
                if value is None:
                    continue
                if (type(value) is bool if expected is bool else isinstance(value, str) and value in expected):
                    _record(collector, source, "savedExecApprovals." + key, value, context=context)
                else:
                    _invalid(collector, source)
            entries = saved.get("allowlist")
            if isinstance(entries, list):
                _record(collector, source, "savedExecApprovals.allowlist", {"entryCount": len(entries)}, context=context)


def extract_extra(collector, source, data):
    """Add safe metadata after the core's standard MCP/settings extraction."""
    if not isinstance(data, dict):
        return
    function = {"opencode": _opencode, "copilot-cli": _copilot, "continue": _continue,
                "aider": _aider, "antigravity": _antigravity, "openclaw": _openclaw}.get(source["client"])
    if function:
        function(collector, source, data)


def _editor_state_candidates(home, files):
    """Yield documented editor profile stores without exposing profile labels."""
    from .engine.filesystem import ReadGap
    for prefix in ("Library/Application Support", ".config", "AppData/Roaming"):
        for product, client in _EDITOR_STATE_PRODUCTS.items():
            user = home / prefix / product / "User"
            relative = (user / "globalStorage/state.vscdb").relative_to(home).as_posix()
            yield client, relative, relative, "base"
            try:
                profiles = files.children(user / "profiles")
            except ReadGap as error:
                if error.reason != "not_found":
                    safe = (user / "profiles").relative_to(home).as_posix()
                    yield client, safe, safe, "profile-gap"
                continue
            for profile in profiles:
                relative = (profile / "globalStorage/state.vscdb").relative_to(home).as_posix()
                safe = (user / "profiles" / ("profile-" + _opaque(profile.name)) /
                        "globalStorage/state.vscdb").relative_to(home).as_posix()
                yield client, relative, safe, "profile"


def _extension_state_values(client, value):
    """Project only verified boolean/enum preference keys from one exact row."""
    def unique_object(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    if not isinstance(value, (str, bytes)):
        raise ValueError("state JSON is not text")
    document = json.loads(value, object_pairs_hook=unique_object)
    if not isinstance(document, dict):
        raise ValueError("state JSON is not an object")
    filtered, invalid = {}, False
    for key, expected in EXTRA_SETTING_TYPES[client].items():
        # Cline's SDK/CLI settings share its client family, but are not the
        # extension's documented globalState schema.
        if client == "cline" and not key.startswith("autoApprovalSettings.actions."):
            continue
        current = _get(document, key)
        if current is None:
            continue
        if type(current) is bool if expected is bool else isinstance(current, str) and current in expected:
            # Flat, fixed keys are accepted by the ordinary typed extractor.
            filtered[key] = current
        else:
            invalid = True
    return filtered, invalid


def _read_extension_rows(raw, budget):
    """Query an in-memory copy; SQLite never opens the source path or its WAL."""
    from .engine.filesystem import ReadGap
    try:
        import sqlite3
    except ImportError as error:
        raise ReadGap("editor_state_sqlite_unavailable") from error
    if not hasattr(sqlite3.Connection, "deserialize"):
        raise ReadGap("editor_state_deserialize_unavailable")
    if not raw.startswith(b"SQLite format 3\0") or len(raw) < 100:
        raise ReadGap("editor_state_invalid_database", "invalid")
    # A closed WAL-mode database retains its format marker after checkpointing.
    # With no nonempty WAL, the main file is the available persisted snapshot.
    # Change only the in-memory copy so deserialize does not try opening a WAL.
    if raw[18:20] == b"\x02\x02":
        raw = raw[:18] + b"\x01\x01" + raw[20:]
    connection = sqlite3.connect(":memory:")
    interrupted = []
    try:
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA temp_store=MEMORY")
        if hasattr(connection, "enable_load_extension"):
            connection.enable_load_extension(False)
        connection.deserialize(raw)

        def authorize(action, table, column, database, trigger):
            if action == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ and database == "main" and trigger is None:
                if table == "ItemTable" and column in {"key", "value"}:
                    return sqlite3.SQLITE_OK
                if table in {"sqlite_master", "sqlite_schema"} and column in {"type", "sql", "name"}:
                    return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        def check_budget():
            try:
                budget.check()
            except ReadGap as error:
                interrupted.append(error)
                return 1
            return 0

        connection.set_authorizer(authorize)
        connection.set_progress_handler(check_budget, 1000)
        schema = connection.execute("SELECT type, sql FROM sqlite_master WHERE name = ?", ("ItemTable",)).fetchall()
        if (len(schema) != 1 or schema[0][0] != "table" or not isinstance(schema[0][1], str)
                or not re.match(r"\s*CREATE\s+TABLE\b", schema[0][1], re.I)):
            raise ReadGap("editor_state_unknown_schema", "unsupported")
        rows = connection.execute(
            "SELECT key, value FROM ItemTable WHERE key IN (?, ?, ?) LIMIT 4",
            tuple(_EDITOR_STATE_ROWS),
        ).fetchall()
        if len(rows) > len(_EDITOR_STATE_ROWS) or len({key for key, _ in rows}) != len(rows):
            raise ReadGap("editor_state_duplicate_extension_rows", "invalid")
        return sorted(rows, key=lambda row: row[0])
    except sqlite3.Error as error:
        if interrupted:
            raise interrupted[0]
        raise ReadGap("editor_state_invalid_database", "invalid") from error
    finally:
        connection.close()


def extra_state_documents(home, files=None):
    """Read only Cline/Roo preference fields from supported editor state stores.

    ``relative`` is private bridge input. Use ``location`` for evidence: named
    profiles are opaque there. No other extension row, conversation, instruction,
    credential store, or history is selected. Passing the collector's SafeFiles
    shares its explicit budgets and no-follow file protections. Returned data is
    already a projection of fixed typed fields, never the original JSON row.
    """
    from .engine.filesystem import Budget, ReadGap, SafeFiles
    home = Path(home).absolute()
    if files is None:
        from .engine.collection import CollectOptions
        options = CollectOptions(home=home, environ={}, discover_os_packages=False,
                                 max_file_bytes=64 * 1024 * 1024, max_total_bytes=128 * 1024 * 1024)
        files = SafeFiles([home], Budget(options, time.monotonic()))
    results = []
    for editor, relative, location, context in _editor_state_candidates(home, files):
        base = {"client": editor, "relative": relative, "location": location,
                "context": "profile" if context.startswith("profile") else "base", "data": {}}
        try:
            if context == "profile-gap":
                raise ReadGap("editor_profiles_not_readable")
            path = home / relative
            raw, opened = files.read(path)
            base["sizeBytes"] = opened.st_size
            if not stat.S_ISREG(opened.st_mode):
                raise ReadGap("editor_state_not_regular")
            current = files.info(path)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                    current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns):
                raise ReadGap("editor_state_changed_during_read")
            try:
                wal = files.info(path.with_name(path.name + "-wal"))
                if wal.st_size:
                    raise ReadGap("editor_state_uncheckpointed_wal")
            except ReadGap as error:
                if error.reason != "not_found":
                    raise
            rows = _read_extension_rows(raw, files.budget)
        except ReadGap as error:
            if error.reason != "not_found":
                results.append({**base, "status": "error" if error.status in {"invalid", "unreadable"} else "skipped",
                                "reason": error.reason})
            continue
        if not rows:
            results.append({**base, "status": "collected", "reason": "recognized_extension_rows_not_present"})
        for extension, value in rows:
            item = {**base, "client": _EDITOR_STATE_ROWS[extension], "extensionId": extension,
                    "location": location + "#" + extension}
            try:
                filtered, invalid = _extension_state_values(item["client"], value)
            except (ValueError, TypeError, UnicodeError, RecursionError):
                results.append({**item, "status": "error", "reason": "editor_state_invalid_extension_json"})
                continue
            results.append({**item, "data": filtered, "status": "error" if invalid else "collected",
                            "reason": "editor_state_unsupported_preference_type" if invalid else "saved_extension_preferences"})
    return results
