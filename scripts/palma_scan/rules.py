"""Original Palma governance policy with additional typed configuration checks."""
from collections import defaultdict
import hashlib
import json

REFERENCES = {
    "codex": ["https://developers.openai.com/codex/config-reference/", "https://developers.openai.com/codex/security/"],
    "claude-code": ["https://code.claude.com/docs/en/settings", "https://code.claude.com/docs/en/permissions", "https://code.claude.com/docs/en/sandboxing"],
    "claude-desktop": ["https://modelcontextprotocol.io/docs/develop/connect-local-servers"],
    "cursor": ["https://cursor.com/docs/context/mcp", "https://cursor.com/docs/cli/reference/permissions"],
    "vscode": ["https://code.visualstudio.com/docs/agents/run/approvals", "https://code.visualstudio.com/docs/agents/reference/mcp-configuration"],
    "gemini-cli": ["https://geminicli.com/docs/reference/configuration/", "https://geminicli.com/docs/tools/mcp-server/"],
    "windsurf": ["https://docs.windsurf.com/windsurf/cascade/mcp", "https://docs.windsurf.com/windsurf/terminal"],
    "shared": ["https://agentskills.io/specification"],
}
from .extra_clients import EXTRA_RULES, SOURCE_REFERENCES
from . import governance
REFERENCES.update(SOURCE_REFERENCES)

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding(rule_id, title, severity, category, observations, summary, impact, recommendation, *, evidence_type="configuration", confidence="high"):
    observations = sorted(observations, key=lambda item: item["id"])
    ids = [item["id"] for item in observations]
    identity = hashlib.sha256((rule_id + ":" + ":".join(ids)).encode()).hexdigest()[:16]
    evidence = []
    for item in observations:
        evidence.append(governance._evidence(item))
    references = sorted({url for item in observations for url in REFERENCES.get(item["client"], REFERENCES["shared"])})
    return {"id": "finding-" + identity, "ruleId": rule_id, "title": title, "severity": severity, "category": category, "confidence": confidence, "evidenceType": evidence_type, "summary": summary, "impact": impact, "recommendation": recommendation, "observationIds": ids, "evidence": evidence, "references": references}


def _active(item):
    details = item.get("details", {})
    return item.get("enabled") != "disabled" and not details.get("shadowedBySelectedProfile") and details.get("context") != "cached" and details.get("interpretation") != "inventory-only" and not details.get("applicability")


def _additional(snapshot: dict) -> list[dict]:
    """Additional client-specific predicates; original policy is evaluated separately."""
    findings = []
    observations = snapshot.get("observations", [])
    settings = defaultdict(dict)
    for item in observations:
        if item["kind"] == "setting" and item.get("details", {}).get("interpretation") != "inventory-only":
            details = item["details"]
            settings[(item["sourceId"], details.get("profileId", details.get("context", "base")))][details["key"]] = item

    for values in settings.values():
        if not values:
            continue
        client = next(iter(values.values()))["client"]

        def has(key, expected):
            value = values.get(key, {}).get("details", {}).get("value")
            return type(value) is type(expected) and value == expected

        def add(rule, title, severity, category, keys, summary, impact, recommendation):
            findings.append(_finding(rule, title, severity, category, [values[key] for key in keys], summary, impact, recommendation))

        if client == "codex" and has("default_permissions", ":danger-full-access"):
            add("unrestricted-folder-access", "Unrestricted folder access is configured", "low", "filesystem", ["default_permissions"],
                "Codex declares unrestricted folder access. Allowed agent actions can reach files beyond the working project without a separate folder-access prompt.",
                "Broad folder grants can expose unrelated files and PII to agent tools; review the scope even when this is an intentional preference.",
                "Prefer workspace-scoped access and grant additional directories only when needed. Review tool approval preferences alongside these grants.")
        if client == "claude-code" and has("permissions.defaultMode", "bypassPermissions") and has("permissions.disableBypassPermissionsMode", "disable"):
            add("PALMA-HYGIENE-005", "A bypass declaration is blocked in the same source", "info", "hygiene", ["permissions.defaultMode", "permissions.disableBypassPermissionsMode"],
                "The same source requests bypass mode and disables that mode. Both declarations remain visible for review.",
                "Contradictory settings make the intended approval policy harder to understand.",
                "Keep the blocking control and remove the obsolete bypass default after confirming the intended policy.")
        for key in ("github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions",):
            if client == "vscode" and has(key, True):
                add("PALMA-EXEC-004", "Broad tool approval is configured", "low", "execution", [key],
                    "This VS Code setting enables broad automatic approval or explicitly skips the Claude agent permission checks. A config file does not prove which harness is active.",
                    "A matching active agent may act on tool requests without the usual user approval boundary.",
                    "Turn off broad approval for routine work, use narrow tool allowances, and confirm the selected agent's effective approval and sandbox settings.")
        if client == "vscode" and has("chat.permissions.default", "autoApprove"):
            add("PALMA-EXEC-005", "An autonomous permission default is configured", "low", "execution", ["chat.permissions.default"],
                "VS Code declares a permission default that automatically approves tool use. Session choice, harness support, and organization policy can alter application.",
                "Unexpected agent actions may run with fewer user review opportunities when this default applies.",
                "Choose the standard permission default for sensitive work and use autonomous sessions only with appropriately scoped access.")
        for key in ("permissions.allow", "terminalAllowlist", "mcpAllowlist", "tools.allowed", "chat.tools.terminal.autoApprove"):
            item = values.get(key)
            summary = item["details"].get("value") if item else None
            if not isinstance(summary, dict) or summary.get("autoApprovalDisabled") or summary.get("broadApprovalBlocked"):
                continue
            broad = summary.get("broadApproval") or summary.get("broadShell") or summary.get("broadMcp")
            deny = values.get("permissions.deny", {}).get("details", {}).get("value", {})
            if broad and not (isinstance(deny, dict) and (deny.get("broadApproval") or (summary.get("broadShell") and deny.get("broadShell")))):
                add("PALMA-EXEC-006", "Review broad standing tool allowances", "low", "execution", [key],
                    "An allowlist includes an entire command or tool family. Deny rules, approval-required entries, higher scopes, and active auto-run settings may still constrain it.",
                    "Broad matching allowances can reduce opportunities to review unexpected actions if they apply to the current agent.",
                    "Replace broad entries with task-specific allowances and inspect the merged rule order in the client. An approval-required or deny entry must be interpreted using that client's semantics.")
        for key in ("sandbox_workspace_write.writable_roots", "permissions.additionalDirectories"):
            if key.startswith("sandbox_workspace_write.") and (has("sandbox_mode", "read-only") or has("sandbox_mode", "danger-full-access") or "default_permissions" in values):
                continue
            value = values.get(key, {}).get("details", {}).get("value", {})
            if isinstance(value, dict) and value.get("broadFilesystemRoot"):
                add("PALMA-FILES-001", "A broad filesystem root is declared", "low", "filesystem", [key],
                    "An additional-directory setting includes a home or filesystem root. The configured declaration is broader than a single project.",
                    "If the relevant permission setting applies, unrelated personal or enterprise files may fall within the agent's reachable scope.",
                    "Replace broad roots with the smallest working directories needed and verify read/write behavior and protected paths in the client.")
        for key in ("sandbox_workspace_write.network_access", "chat.agent.sandbox.allowNetwork"):
            if key.startswith("sandbox_workspace_write.") and (has("sandbox_mode", "read-only") or has("sandbox_mode", "danger-full-access") or "default_permissions" in values):
                continue
            if has(key, True):
                add("PALMA-NETWORK-001", "Review expanded command network access", "low", "network", [key],
                    "Command network access is explicitly allowed in this sandbox configuration. This alone neither grants tool approval nor proves an unrestricted endpoint.",
                    "Allowed commands may reach external services, so sensitive workflows need destination and data-sharing controls.",
                "Keep network access limited to required work and inspect any enforced destination allowlist. Review MCP, browser, and hosted tools separately from the command sandbox.")
        unused_workspace = [key for key in ("sandbox_workspace_write.network_access", "sandbox_workspace_write.writable_roots") if key in values]
        if client == "codex" and unused_workspace and (has("sandbox_mode", "read-only") or has("sandbox_mode", "danger-full-access")):
            add("PALMA-HYGIENE-006", "Workspace sandbox options do not match the declared mode", "info", "hygiene", ["sandbox_mode"] + unused_workspace,
                "Workspace-write options are retained alongside an explicit sandbox mode other than workspace-write. These options are not reported as active network or filesystem expansion.",
                "Inactive settings can obscure the intended policy, although they may be retained for another planned configuration.",
                "Keep only the options required for the intended mode, or document why the unused workspace-write declarations remain. Confirm the selected mode before changing behavior.")
        if client == "claude-code" and has("sandbox.enabled", True) and has("sandbox.network.allowAllUnixSockets", True):
            add("PALMA-NETWORK-003", "Sandbox access to Unix sockets is broad", "medium", "network", ["sandbox.enabled", "sandbox.network.allowAllUnixSockets"],
                "The same Claude Code source enables sandboxing and allows all Unix sockets. Live sockets, services, and effective host restrictions were not inspected.",
                "Available Unix sockets can expose local services and privileged interfaces beyond ordinary project files.",
                "Use a narrow allowlist of required sockets and review the privileges of the services behind them. Verify the active sandbox configuration.")
        if client == "gemini-cli" and has("security.folderTrust.enabled", False):
            add("PALMA-GOV-003", "Workspace trust checks are disabled", "medium", "governance", ["security.folderTrust.enabled"],
                "Gemini CLI's folder-trust mechanism is explicitly disabled in this source. Tool permissions and managed policy may still provide separate controls.",
                "Opening an unfamiliar workspace can have fewer trust-boundary checks before project-controlled configuration is considered.",
                "Restore folder trust for ordinary development and review project instructions, extensions, and MCP definitions before trusting unfamiliar repositories.")
        proxy_enabled = has("features.network_proxy", True) or has("features.network_proxy.enabled", True)
        proxy_flags = [key for key in ("features.network_proxy.dangerously_allow_all_unix_sockets", "features.network_proxy.dangerously_allow_non_loopback_proxy") if has(key, True)]
        if proxy_flags and proxy_enabled:
            add("PALMA-NETWORK-002", "Network proxy boundaries are relaxed", "medium", "network", proxy_flags,
                "A declared enabled Codex network proxy permits arbitrary Unix socket destinations or a listener beyond loopback. The scanner does not inspect live listeners.",
                "These options can widen local service access or expose the proxy to other hosts if the runtime uses them.",
                "Restore scoped Unix socket access and loopback binding unless explicitly needed. Verify the runtime listener, authentication, and surrounding firewall rules separately.")
        if has("shell_environment_policy.inherit", "all") and has("shell_environment_policy.ignore_default_excludes", True):
            add("PALMA-CREDS-003", "Review broad shell environment inheritance", "high", "credentials", ["shell_environment_policy.inherit", "shell_environment_policy.ignore_default_excludes"],
                "This source requests the full parent environment and disables the default sensitive-name exclusions. Additional filters may still apply; environment values were not inspected.",
                "Commands can potentially receive credentials or other sensitive environment variables when this combination applies.",
                "Prefer a minimal inherited environment, preserve the default exclusions, and inspect any explicit filters. Pass narrowly scoped credentials only to the tools that need them.")
        browser_keys = [key for key in values if (key.startswith("browser_use.") or key.startswith("computer_use.")) and has(key, "allow")]
        if browser_keys:
            add("PALMA-CAPABILITY-001", "Review browser and desktop access boundaries", "critical", "capabilities", browser_keys,
                "Browser or desktop capability settings, or permissive access-policy declarations, are present. 'Allow' and persistent-approval options do not themselves grant access or prove a running capability.",
                "Where enabled and approved, these tools can interact with pages, applications, or signed-in sessions; the reachable data depends on the product and chosen session.",
                "Review app and site scope, uploads, downloads, debugging access, and saved approvals. Use isolated browser sessions for untrusted content and keep sensitive apps outside the permitted scope.")
        if has("agents.overrides.browser_agent.enabled", True) and has("agents.browser.sessionMode", "existing"):
            keys = ["agents.overrides.browser_agent.enabled", "agents.browser.sessionMode"]
            add("PALMA-CAPABILITY-002", "Review browser session reuse and sensitive actions", "critical", "capabilities", keys,
                "The Gemini browser agent is declared enabled with an existing-session mode or reduced extra confirmation for selected sensitive actions. First-run consent and other policy checks may still apply.",
                "A reused browser session may expose additional context, while selected actions can have fewer confirmation steps. Signed-in access is not verified.",
                "Prefer isolated sessions and retain sensitive-action confirmation. Review file upload restrictions and browser-domain scope in the active agent.")
        if has("remoteControlAtStartup", True) and not has("disableRemoteControl", True):
            add("PALMA-CAPABILITY-003", "Remote session continuation is configured", "high", "capabilities", ["remoteControlAtStartup"],
                "Claude Code is configured to start Remote Control for supported local sessions. This does not imply public or unauthenticated access; the feature uses the owner's account.",
                "Remote continuation adds another way to operate a local agent and should fit the organization's account and endpoint policy.",
                "Confirm that remote continuation is approved, protect the linked account, and disable automatic startup where local-only interaction is required.")
        if has("enableAllProjectMcpServers", True):
            add("PALMA-MCP-003", "Project MCP startup approvals are broad", "low", "mcp", ["enableAllProjectMcpServers"],
                "Claude Code declares approval for all project MCP servers. This is server startup trust, not proof of bypassed tool-call permissions; project trust and policy still matter.",
                "An accepted project can supply additional executable integrations or remote connections that warrant provenance review.",
                "Prefer explicitly reviewed project MCP servers and inspect the project's .mcp.json before granting trust. Confirm applicable disabled-server and managed restrictions.")
        projects = values.get("projects.referenceInventory", {}).get("details", {}).get("value", {})
        if isinstance(projects, dict) and projects.get("missingWithinHomeCount", 0) > 0:
            add("PALMA-HYGIENE-004", "Some saved project locations are no longer present", "info", "hygiene", ["projects.referenceInventory"],
                "Claude's saved project references include paths inside the selected home that were not present when inspected. Out-of-scope, redirected, and inaccessible paths are not called stale.",
                "Historical project entries can add clutter or preserve obsolete trust choices. Missing locations may also be temporarily unavailable or intentionally retained.",
                "Review saved projects in the client and remove obsolete references after confirming their purpose. The scan does not alter settings or delete any files.")
        for rule in EXTRA_RULES:
            if rule["client"] != client or not has(rule["key"], rule["value"]):
                continue
            required = rule.get("requires", [])
            if not all(has(item["key"], item["value"]) for item in required):
                continue
            if any(has(item["key"], item["value"]) for item in rule.get("unless", [])):
                continue
            evidence_keys = list(dict.fromkeys([rule["key"]] + [item["key"] for item in required]))
            finding = _finding(rule["id"], rule["title"], rule["severity"], rule["category"], [values[key] for key in evidence_keys], rule["summary"], rule["impact"], rule["recommendation"])
            finding["references"] = rule["references"]
            findings.append(finding)

    buckets = defaultdict(list)
    for item in observations:
        details, kind = item["details"], item["kind"]
        if kind == "mcp":
            if details.get("autoApproval") == "all":
                buckets["mcp-trust"].append(item)
            if details.get("toolFamily") in {"filesystem", "agent"}:
                buckets["mcp-capability"].append(item)
            if details.get("unversionedPackage") is True:
                buckets["package-version"].append(item)
        elif kind == "agent" and (type(details.get("toolCount")) is not int or details["toolCount"] < 10):
            buckets["agents"].append(item)
        elif kind == "setting" and details.get("profileSelected") is False:
            buckets["inactive-profile"].append(item)

    for kind, items in sorted(buckets.items()):
        if kind == "mcp-trust":
            findings.append(_finding("PALMA-MCP-004", "MCP tool-call confirmations are disabled", "low", "mcp", items,
                "Connector trust preferences bypass tool-call confirmations when these declarations apply.",
                "The agent can invoke exposed tools without a separate approval. Review these grants alongside the connector's Critical access finding.",
                "Remove blanket trust where review is needed, narrow exposed tools, and confirm the intended permissions."))
        elif kind == "mcp-capability":
            findings.append(_finding("PALMA-CAPABILITY-004", "Connectors expose filesystem or agent-delegation capabilities", "low", "capabilities", items,
                "Integration metadata identifies filesystem access or delegation to another agent.",
                "These tools may reach local files and PII or pass context to another agent. Untrusted tool results can carry prompt injection.",
                "Review reachable directories, delegated tools, data destinations, and approval boundaries.", evidence_type="inventory"))
        elif kind == "package-version":
            findings.append(_finding("PALMA-GOV-002", "An MCP package lacks an exact version", "low", "governance", items,
                "A recognized package launcher declares an unpinned or moving package version.",
                "Later launches can obtain different code, increasing supply-chain exposure and making security review harder to reproduce.",
                "Pin a reviewed package version and establish an update review process."))
        elif kind == "agents":
            findings.append(_finding("PALMA-AGENT-001", "Local agent instructions need a review record", "low", "extensions", items,
                "Local agent definitions can contribute instructions and delegated workflows.",
                "Prompt injection or unsafe instructions can steer an agent into unintended tool use, PII exposure, or data leakage.",
                "Review instructions, declared tools, dependencies, and update sources; retain the reviewed version.", evidence_type="inventory"))
        elif kind == "inactive-profile":
            findings.append(_finding("PALMA-HYGIENE-001", "Inactive profile settings remain in configuration", "info", "hygiene", items,
                "Settings are retained in profiles that were not selected in the collected configuration.",
                "Old profiles can preserve confusing or obsolete permissions and may be selected again later.",
                "Remove unused profiles or document their intended purpose.", evidence_type="inventory"))

    # Same client/key across observed scopes is a review aid, never a precedence resolver.
    repeated = defaultdict(list)
    for item in observations:
        if item["kind"] == "setting" and _active(item) and item["details"].get("context") in {"base", "project"}:
            repeated[(item["client"], item["details"].get("accountAlias", "~"), item["details"]["key"])].append(item)
    for items in repeated.values():
        if len({item["sourceId"] for item in items}) < 2:
            continue
        values = {json.dumps(item["details"]["value"], sort_keys=True) for item in items}
        same = len(values) == 1
        findings.append(_finding("PALMA-HYGIENE-002" if same else "PALMA-HYGIENE-003", "A setting is repeated across configuration sources" if same else "Configuration sources disagree on a setting", "info" if same else "low", "hygiene", items,
            "The same typed value is declared in multiple observed sources. This may be intentional scope-specific configuration." if same else "Different typed values are declared in multiple observed sources. Their applicability depends on client precedence, selected workspace, managed policy, and session overrides.",
            "Repeated or conflicting declarations can make maintenance and troubleshooting harder; this does not establish which value is effective.",
            "Review the listed sources in the client's precedence order. Keep deliberate overrides and remove redundant or obsolete declarations only after confirming their purpose."))
    return sorted(findings, key=lambda item: (SEVERITY[item["severity"]], item["category"], item["title"], item["id"]))


def evaluate(snapshot: dict) -> list[dict]:
    """Show every matched policy, grouped by condition and ranked by severity."""
    findings = governance.evaluate(snapshot)
    groups = defaultdict(list)
    for finding in _additional(snapshot):
        groups[(finding["ruleId"], finding["title"], finding["severity"])].append(finding)
    observations = {item["id"]: item for item in snapshot.get("observations", [])}
    for matches in groups.values():
        first = matches[0]
        ids = sorted({identity for item in matches for identity in item["observationIds"]})
        grouped = _finding(first["ruleId"], first["title"], first["severity"], first["category"],
                           [observations[identity] for identity in ids], first["summary"], first["impact"],
                           first["recommendation"], evidence_type=first["evidenceType"], confidence=first["confidence"])
        grouped["references"] = sorted({url for item in matches for url in item["references"]})
        grouped["declarations"] = len(ids)
        findings.append(grouped)
    return sorted(findings, key=lambda item: (SEVERITY[item["severity"]], -item.get("declarations", 0), item["ruleId"], item["id"]))
