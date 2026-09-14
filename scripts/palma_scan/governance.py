"""Deterministic, local evaluation of Palma's AI exposure policy."""
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

from .engine.redaction import visible

RULES_VERSION = "2026-09-14.1"
INSTRUCTION_REVIEW_BYTES = 64 * 1024
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
UPGRADES = {"mcp-network-direct", "skills-local-unreviewed", "hooks-declared"}
LOW_PERMISSIONS = {"permissions-bypassed", "tools-auto-approved", "approval-prompts-disabled"}
# Connectors routed through a Palma-operated gateway are governed. The catalog expresses its
# exemption as `endpointOrigin notInParam gatewayOrigins`; this marker joins that list.
PALMA_GATEWAY = "palma-gateway"
# Inventory categories group every discovered setting by subject. These catalog
# categories make stronger assertions, so only actual switches/access grants
# qualify. Supporting controls such as confirmation, network restrictions, and
# keychain forwarding do not establish browser enablement or sandbox removal.
SETTING_POLICY_KEYS = {
    "sandbox": {
        "sandbox", "sandbox.enabled", "sandbox_mode", "sandboxMode",
        "tools.sandbox", "security.toolSandboxing", "chat.agent.sandbox.enabled",
        "agents.defaults.sandbox.mode", "permission_profile", "permissionProfile",
    },
    "browser": {
        "claudeInChromeEnabled", "experimental.browser.enabled",
        "features.browser_use", "features.browser_use_external", "features.browser_use_full_cdp_access",
        "browser_use.allow_global_persistent_approval", "browser_use.allow_history_access",
        "browser_use.default_origin_policy.persistent_approval",
        "agents.overrides.browser_agent.enabled", "workbench.browser.enableChatTools",
        "autoApprovalSettings.actions.useBrowser", "globalState.autoApprovalSettings.actions.useBrowser",
        "browser.enabled", "browser.evaluateEnabled", "agents.defaults.sandbox.browser.enabled",
        "agents.defaults.sandbox.browser.allowHostControl",
    },
    "computer": {
        "features.computer_use", "computer_use.allow_persistent_approval", "computer_use.default_app_access",
        "computerUse", "computerUse.enabled", "computerUseMcpState", "computerUseMcpState.enabled",
        "localAgentMode", "localAgentMode.enabled", "workWithApps", "workWithApps.enabled",
    },
}
PUBLIC_REFERENCES = {
    "mcp": ["https://modelcontextprotocol.io/specification/latest/basic/security_best_practices"],
    "skill": ["https://agentskills.io/specification"],
    "plugin": ["https://code.claude.com/docs/en/plugins"],
    "agent": ["https://code.claude.com/docs/en/sub-agents"],
    "setting": ["https://code.claude.com/docs/en/settings", "https://developers.openai.com/codex/config-reference/"],
    "hook": ["https://code.claude.com/docs/en/hooks"],
    "client": ["https://code.claude.com/docs/en/authentication"],
}


@lru_cache(maxsize=1)
def catalog():
    return json.loads(Path(__file__).with_name("palma_catalog.json").read_text(encoding="utf-8"))


def as_text(value):
    """Match the original catalog's PostgreSQL scalar comparison semantics."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return value if isinstance(value, str) else json.dumps(value)
    return json.dumps(value, separators=(",", ":"))


def matches(condition, attrs, params):
    value = attrs.get(condition["attr"])
    if "in" in condition:
        return as_text(value) in condition["in"]
    if "notIn" in condition:
        return (as_text(value) or "") not in condition["notIn"]
    if "isNull" in condition:
        return value is None
    if "has" in condition:
        return isinstance(value, list) and condition["has"] in value
    if "hasAny" in condition:
        return isinstance(value, list) and any(item in value for item in condition["hasAny"])
    if "lacks" in condition:
        return not (isinstance(value, list) and condition["lacks"] in value)
    if "min" in condition:
        return isinstance(value, int) and not isinstance(value, bool) and value >= condition["min"]
    if "notInParam" in condition:
        known = [item.lower() for item in params.get(condition["notInParam"], [])]
        return not known or (as_text(value) or "").lower() not in known
    raise ValueError("Unknown Palma policy condition.")


def _category(key):
    from .engine.adapters.settings import category
    return category(key)


def _setting_policy_category(key, details):
    """Qualify catalog assertions without changing collected inventory evidence.

    Native hook adapters emit concrete ``hook`` records, including disabled and
    cached handlers. A feature switch or opaque root object is not itself a
    handler. Historical per-event records retain their original catalog match.
    Apply this during evaluation as saved snapshots can retain broad categories.
    """
    label = details.get("category") or _category(key)
    if label in SETTING_POLICY_KEYS and key not in SETTING_POLICY_KEYS[label]:
        return "other"
    if label == "hooks":
        if not key.startswith("hooks.") or isinstance(details.get("value"), (bool, int, float, str)):
            return "other"
    return label


def _positive_count(value):
    return type(value) is int and value > 0


def _source_files(sources):
    """One component per physical location, even when several adapters read it."""
    unique = {}
    for source in sorted(sources, key=lambda item: item["id"]):
        unique.setdefault((source["client"], source["location"]), source)
    return list(unique.values())


def attributes(item):
    """Expose only policy attributes, never arbitrary config or commands."""
    details = item.get("details", {})
    kind = item["kind"]
    if kind == "client":
        return {key: details.get(key) for key in ("variant", "version", "installationState", "authModes")}
    if kind == "mcp":
        result = {key: details.get(key) for key in ("transport", "endpointOrigin", "packageName", "executable", "auth", "inlineCredentialPresent")}
        if details.get("governedBy") == PALMA_GATEWAY:
            result["endpointOrigin"] = PALMA_GATEWAY
        result["transport"] = result["transport"] or {"local": "stdio", "remote": "http"}.get(details.get("execution"), "unknown")
        result["inlineCredentialPresent"] = result["inlineCredentialPresent"] is True or _positive_count(details.get("literalCredentialCount"))
        result["capability"] = details.get("capability") or (details.get("toolFamily") if details.get("toolFamily") in {"computer", "browser"} else None)
        result["enabled"] = item.get("enabled", "unknown")
        return result
    if kind in {"skill", "plugin"}:
        result = {key: details.get(key) for key in ("origin", "digest", "artifactType", "version", "installationState")}
        if not result["origin"]:
            result["origin"] = "project" if details.get("context") == "project" else "user" if kind == "skill" and details.get("context") in {"base", "profile"} else "unknown"
        result["enabled"] = item.get("enabled", "unknown")
        return result
    if kind == "agent":
        return {"model": details.get("model"), "toolCount": details.get("toolCount"), "enabled": item.get("enabled", "unknown")}
    if kind == "setting":
        key = details.get("nativeKey", details.get("key", ""))
        value = details.get("value")
        return {"nativeKey": key, "category": _setting_policy_category(key, details),
                "value": value[:64] if isinstance(value, str) else value,
                "valueCollected": details.get("valueCollected", True), "effectiveState": details.get("effectiveState")}
    return {}


def _identity(item):
    details, kind = item.get("details", {}), item["kind"]
    if kind == "skill" and details.get("digest"):
        parts = (kind, details["digest"])
    elif kind == "client":
        parts = (kind, item["client"], details.get("variant"), details.get("version"))
    elif kind == "mcp" and details.get("endpointOrigin"):
        parts = (kind, details.get("transport"), details["endpointOrigin"], details.get("endpointPathHash"))
    elif kind == "mcp" and (details.get("packageName") or details.get("executable")):
        parts = (kind, "pkg" if details.get("packageName") else "exe", details.get("packageName") or details["executable"])
    elif kind == "mcp" and details.get("endpointIdentity"):
        parts = (kind, details["endpointIdentity"])
    elif kind == "plugin":
        parts = (kind, details.get("artifactType"), details.get("origin"), item["name"], details.get("version"))
    elif kind == "agent":
        parts = (kind, item["client"], item["name"], details.get("model"))
    elif kind == "setting":
        parts = (kind, item["client"], details.get("nativeKey", details.get("key")), details.get("valueType", type(details.get("value")).__name__), details.get("value"))
    else:
        parts = ("observation", item["id"])
    return json.dumps(parts, sort_keys=True, separators=(",", ":"))


# Evidence language describes the declaration that triggered the original policy.
# These summaries never claim a runtime session or a completed third-party audit.
SUMMARIES = {
    "mcp-local-unaudited": "{n} local connector declarations can launch code with the endpoint user's access. Review their ownership, tool permissions, monitoring, and governance.",
    "mcp-network-direct": "{n} remote connector declarations connect AI clients directly to services. Their tool access and data sharing need a governed policy and audit trail.",
    "mcp-inline-credential": "{n} connector declarations contain potential credential literals. Values are redacted; review the named configuration files for exposure.",
    "mcp-static-secret-auth": "{n} connectors declare authentication using a fixed header secret. Review ownership, scope, rotation, and storage.",
    "skills-local-unreviewed": "{n} locally installed skill declarations need an audit record. Their instructions and scripts can influence agent decisions, tool use, and data access.",
    "skills-unverifiable": "{n} skill declarations have no complete content digest. Their exact contents cannot be compared with a reviewed version.",
    "mcp-computer-use": "{n} connectors declare desktop control capabilities. These can reach the screen, keyboard, mouse, and applications available to the signed-in user.",
    "mcp-browser-automation": "{n} connectors declare browser automation. Review access to signed-in sessions, page data, form submissions, and script execution.",
    "browser-use-enabled": "{n} settings enable or trust browser capabilities. Govern access to signed-in sessions and require confirmation for sensitive actions.",
    "computer-use-enabled": "{n} settings enable or trust desktop capabilities. The agent can potentially act through the signed-in user's applications and operating-system permissions.",
    "hooks-declared": "{n} hook declarations can run custom logic on agent events. Review scripts and destinations for credential access, unintended actions, and potential data leakage.",
    "clients-config-only": "{n} AI client declarations have configuration present without a detected installation. Review whether the configuration is still needed.",
    "clients-api-key-auth": "{n} AI client declarations use API-key authentication. Review key ownership, scope, rotation, and offboarding controls.",
    "clients-outside-enterprise-identity": "{n} AI client declarations use vendor or cloud sign-in without an enterprise-identity declaration. Confirm that access follows your organization's identity and offboarding policy.",
    "plugins-cached-only": "{n} plugin packs are present in download caches without a detected installation. Remove obsolete versions and retain only the components you need.",
    "sandbox-disabled": "{n} settings disable a sandbox or declare unrestricted access. Review which files, network destinations, and host services agent commands can reach.",
    "permissions-bypassed": "{n} permission settings bypass or automatically grant tool approvals. Apply scoped permissions and approval policies before sensitive use.",
    "tools-auto-approved": "{n} settings automatically approve broad tool use. Unexpected or injected instructions can cross the usual human approval boundary.",
    "approval-prompts-disabled": "{n} Codex settings declare approval_policy=never. Review the permitted actions and restore approval checkpoints for sensitive work.",
}

IMPACTS = {
    "mcp-local-unaudited": "A local MCP server can reach files, credentials, and personally identifiable information (PII) with its host permissions. Malicious code or prompt-injected tool interactions can cause unauthorized actions or data leakage.",
    "mcp-network-direct": "Connector requests may send PII, source code, or other sensitive data to remote services. Untrusted tool output can carry prompt injection, while excessive tool permissions increase the impact of unintended calls.",
    "mcp-inline-credential": "If the value is a working credential, anyone who can read the file can use it as you: other processes, extensions and skills running under your account, and every backup, sync folder or dotfiles repository that copies the file. It keeps working until it is rotated.",
    "mcp-static-secret-auth": "The connector signs in with a fixed secret instead of a short-lived sign-in. If the secret is copied or leaks, it keeps granting access until someone rotates it.",
    "mcp-computer-use": "It can see your screen and use the keyboard and mouse as you, in any app you are signed in to. A page, document or message it reads can contain instructions that steer those actions, including sending data somewhere else.",
    "mcp-browser-automation": "It can open pages, fill in forms and click in sites where you are signed in, as you. A page it visits can contain instructions that steer it into unintended actions or into sending data elsewhere.",
    "browser-use-enabled": "The agent can browse and act in sites with your signed-in sessions. A page it reads can contain instructions that steer it into unintended actions or into sending data elsewhere, unless site access and sensitive actions require your approval.",
    "computer-use-enabled": "The agent can see your screen and use the keyboard and mouse as you, across your signed-in apps. Content it reads can contain instructions that steer those actions, including sending data elsewhere.",
    "skills-local-unreviewed": "Unreviewed skill instructions and scripts can contain prompt injection, mishandle PII, disclose secrets, or steer tools into data leakage. Review evidence should identify the installed version.",
    "hooks-declared": "Hooks can execute custom logic automatically, access PII and credentials, transmit data, or inject instructions into an agent workflow. A compromised hook or writable script creates a path to data leakage.",
}


def _evidence(item):
    details = item.get("details", {})
    value = {key: details[key] for key in (
        "transport", "execution", "endpointScope", "auth", "inlineCredentialPresent", "literalCredentialCount",
        "capability", "capabilityEvidence", "origin", "digest", "installationState", "toolCount",
        "category", "valueCollected", "effectiveState", "context", "activation", "profileSelected", "applicability",
        "shadowedBySelectedProfile", "typeCounts", "event", "value") if key in details}
    value["observedState"] = item.get("enabled", "unknown")
    return {"sourceId": item["sourceId"], "location": item["location"],
            "key": details.get("nativeKey", details.get("key", item["name"])), "value": value}


# Names come from scanned files. Inside a sentence they lose quotation marks, control and
# invisible direction characters, so a name cannot close its quotation or reorder the text.
_UNSAFE_PROSE = re.compile(r'[\x00-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\u201c\u201d"]')
PROSE_NAME_LIMIT = 60
PROSE_LOCATION_LIMIT = 512


def _join(parts):
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def _prose_name(name):
    """A declared name as it may appear in a summary, or None for a path or web address."""
    text = " ".join(visible(_UNSAFE_PROSE.sub("", str(name))).split())
    if not text or re.search(r"[\\/]|://", text):
        return None  # Shown with its evidence, never inside a sentence.
    return text if len(text) <= PROSE_NAME_LIMIT else text[:PROSE_NAME_LIMIT - 1] + "\u2026"


def _names(items, limit=3):
    # Quoted, so a name such as "browser" never reads as part of the sentence.
    names = sorted({item["name"] for item in items}, key=str.casefold)
    listed = [f"\u201c{name}\u201d" for name in list(dict.fromkeys(filter(None, map(_prose_name, names))))[:limit]]
    rest = len(names) - len(listed)
    if not listed:
        return f"{rest:,} {'connector' if rest == 1 else 'connectors'}"
    return _join(listed + ([f"{rest:,} more"] if rest > 0 else []))


def _files(items, limit=2):
    """The files a summary names; merged copies count, and very long paths are only counted."""
    # The least nested file first: normally the main checkout rather than a copy.
    files = sorted({location for item in items for location in [item["location"], *item.get("details", {}).get("locations", [])]},
                   key=lambda location: (location.count("/"), len(location), location))
    unlisted = sum(max(0, item.get("details", {}).get("locationCount", 0) - len(item.get("details", {}).get("locations", []))) for item in items)
    named = [location for location in files if len(location) <= PROSE_LOCATION_LIMIT][:limit]
    rest = len(files) + unlisted - len(named)
    if not named:
        return f"{rest:,} {'file' if rest == 1 else 'files'}"
    return _join(named + ([f"{rest:,} other {'file' if rest == 1 else 'files'}"] if rest > 0 else []))


def _finding(spec, items, *, extra_sources=(), severity=None, summary=None, text=None, impact=None, recommendation=None, rating_reason=None):
    """One finding. ``summary`` is a template with {n}; ``text`` is a finished sentence that
    names declarations, so nothing in a name is ever treated as a template."""
    items = sorted(items, key=lambda item: item["id"])
    extra_sources = sorted(extra_sources, key=lambda item: item["id"])
    ids = [item["id"] for item in items]
    identity = hashlib.sha256((spec["id"] + ":" + ":".join(ids + [item["id"] for item in extra_sources])).encode()).hexdigest()[:16]
    count = len(items) + len(extra_sources)
    sentence = summary or SUMMARIES.get(spec["id"], spec.get("headline", "{n} declarations require review."))
    sentence = sentence.replace("{n}", f"{count:,}").replace("{where}", "on this machine")
    if text is not None:
        sentence = text
    elif count == 1:
        for plural, singular in catalog()["singularPhrases"]:
            sentence = sentence.replace(plural, singular)
        for plural, singular in (
            ("connector declarations can", "connector declaration can"),
            ("connector declarations connect", "connector declaration connects"),
            ("connector declarations contain", "connector declaration contains"),
            ("connectors declare", "connector declares"),
            ("skill declarations need", "skill declaration needs"),
            ("skill declarations have", "skill declaration has"),
            ("skill declarations are", "skill declaration is"),
            ("settings enable", "setting enables"), ("settings disable", "setting disables"),
            ("settings automatically", "setting automatically"),
            ("settings declare", "setting declares"),
            ("hook declarations can", "hook declaration can"),
            ("client declarations have", "client declaration has"),
            ("client declarations use", "client declaration uses"),
            ("plugin packs are", "plugin pack is"),
            ("configuration records contain", "configuration record contains"),
            ("permission settings bypass", "permission setting bypasses"),
            ("automatically approve", "automatically approves"),
            ("components exceed", "component exceeds"),
            ("configuration files contain", "configuration file contains"),
        ):
            sentence = sentence.replace(plural, singular)
    severity = severity or spec["severity"]
    area = spec.get("area", "hygiene")
    category = {"access": "mcp", "content": "extensions", "permissions": "execution", "discovery": "configuration"}.get(area, area)
    if "credential" in spec["id"]:
        category = "credentials"
    if spec["id"] == "hooks-declared":
        category = "automation"
    evidence = [_evidence(item) for item in items]
    for source in extra_sources:
        facts = {key: source[key] for key in ("reason", "artifactRole", "componentKind", "packageState", "classification", "issueKind", "sizeBytes", "limitBytes", "reviewThresholdBytes") if key in source}
        evidence.append({"sourceId": source["id"], "location": source["location"], "key": source.get("componentKind", "configuration"), "value": facts})
    return {"id": "finding-" + identity, "ruleId": spec["id"], "title": spec["title"],
            "severity": severity, "baselineSeverity": spec["severity"],
            "ratingReason": rating_reason or ("Palma classifies permission bypass and unrestricted folder grants as Low for visibility and governance review." if severity == "low" and (spec["id"] in LOW_PERMISSIONS or spec["id"] == "sandbox-disabled") else "Palma's standalone governance policy elevates this exposure to Critical." if severity != spec["severity"] else "Palma governance policy prioritizes this observed configuration pattern and its potential impact."),
            "category": category, "confidence": "high", "evidenceType": "inventory" if spec.get("kind") in {"skill", "plugin", "agent", "client"} else "configuration",
            "summary": sentence, "impact": impact or IMPACTS.get(spec["id"], catalog()["areas"]["guidance"][area]["why"]),
            "recommendation": recommendation or spec["action"], "observationIds": ids, "evidence": evidence,
            "declarations": count, "distinct": len({_identity(item) for item in items}) + len(extra_sources),
            "clients": sorted({item["client"] for item in items} | {source["client"] for source in extra_sources}),
            "references": PUBLIC_REFERENCES.get(spec.get("kind"), PUBLIC_REFERENCES["setting"])}


def _skill_findings(spec, items):
    """Local skills keep Critical priority; version-controlled project skills keep High.

    A skill committed to the project's repository has change history and can go through
    code review, unlike a copied or downloaded folder. Its installed version still needs
    a review record, so the catalog's High rating applies rather than the Critical upgrade.
    """
    recommendation = "Review the named skill contents, scripts, dependencies, and update source. Remove unused skills and record the approved version; Palma can distribute reviewed skills across a team."
    versioned = [item for item in items if item.get("details", {}).get("provenance") == "version-controlled"]
    local = [item for item in items if item.get("details", {}).get("provenance") != "version-controlled"]
    findings = []
    if local:
        findings.append(_finding(spec, local, severity="critical", recommendation=recommendation))
    if versioned:
        findings.append(_finding({**spec, "title": "Project skills in version control need a review record"}, versioned, severity="high",
            summary="{n} project skill declarations are inside the project's git repository and not excluded by its .gitignore, so their changes can be reviewed like code. The installed version has no recorded review.",
            recommendation="Review the skill instructions and scripts through the repository's code review, and record the reviewed version before sensitive use.",
            rating_reason="Version-controlled project skills keep the catalog's High priority: their changes can be reviewed like code, but the installed version still needs a review record."))
    return findings


def evaluate(snapshot, params=None):
    """Preserve all original matches; cached/disabled evidence stays visible.

    params supports the original catalog's pure fixture comparison only. The CLI
    has no gateway/enrollment option and native collection does not export URLs.
    """
    params = dict(params or {})
    params["gatewayOrigins"] = [*params.get("gatewayOrigins", []), PALMA_GATEWAY]
    observations = snapshot.get("observations", [])
    sources = snapshot.get("sources", [])
    malformed = {source["id"] for source in sources if source.get("issueKind") == "unsupported-mcp-shape"}
    # The sign-in secret itself is written in the file. Older snapshots only record that some
    # credential is.
    inline = {item["id"] for item in observations if item["kind"] == "mcp"
              and item.get("details", {}).get("authSecretInline", attributes(item)["inlineCredentialPresent"]) is True}
    result = []
    for spec in catalog()["rules"]:
        items = [item for item in observations if item["kind"] == spec["kind"]
                 and all(matches(condition, attributes(item), params) for condition in spec["conditions"])]
        if spec["id"] == "mcp-unknown-transport":
            items = [item for item in items if item["sourceId"] not in malformed]
        if spec["id"] == "hooks-declared":
            items += [item for item in observations if item["kind"] == "hook"]
        if spec["id"] == "mcp-static-secret-auth":
            # One root cause is reported once: a fixed secret written into the file is the
            # Critical credential finding, not also a separate High one.
            items = [item for item in items if item["id"] not in inline]
        if not items:
            continue
        severity = "low" if spec["id"] in LOW_PERMISSIONS else "critical" if spec["id"] in UPGRADES else spec["severity"]
        if spec["id"] == "sandbox-disabled" and all(attributes(item).get("value") == "danger-full-access" for item in items):
            severity = "low"
            spec = {**spec, "title": "Unrestricted folder and command access is configured"}
        if spec["id"] == "skills-local-unreviewed":
            result.extend(_skill_findings(spec, items))
            continue
        summary = None
        if spec["id"] == "mcp-inline-credential":
            summary = f"{_names(items)} {'keeps' if len({item['name'] for item in items}) == 1 else 'keep'} a potential credential in plain text in {_files(items)}. The value is withheld from this report."
        elif spec["id"] == "mcp-static-secret-auth":
            summary = f"{_names(items)} {'signs' if len({item['name'] for item in items}) == 1 else 'sign'} in with a fixed secret supplied through configuration, declared in {_files(items)}."
        elif spec["id"] in {"mcp-computer-use", "mcp-browser-automation"}:
            reach = "the screen, keyboard and mouse" if spec["id"] == "mcp-computer-use" else "a web browser"
            summary = f"{_names(items)} can control {reach} as you. Declared in {_files(items)}."
        result.append(_finding(spec, items, severity=severity, text=summary))

    credentials = [item for item in observations if item["kind"] != "mcp" and _positive_count(item.get("details", {}).get("literalCredentialCount"))]
    if credentials:
        result.append(_finding({"id": "config-inline-credential", "kind": "setting", "area": "access", "severity": "critical",
            "title": "Potential credentials stored in configuration files", "action": "Replace literal secrets with supported secret references or credential storage. Review exposure and rotate affected credentials."}, credentials,
            text=f"Potential credentials are stored in plain text in {_files(credentials)}. Values are withheld from this report.",
            impact="If these values are working credentials, anyone who can read the files can use them as you: other processes, extensions and skills running under your account, and every backup, sync folder or repository that copies them. They keep working until they are rotated."))
    packaged_skills = [item for item in observations if item["kind"] == "skill" and attributes(item).get("origin") == "plugin"]
    if packaged_skills:
        result.append(_finding({"id": "skills-plugin-unreviewed", "kind": "skill", "area": "content", "severity": "critical",
            "title": "Plugin skills need a recorded security review", "action": "Review the installed skill instructions and scripts, verify their source and version, and retain an audit record before sensitive use."}, packaged_skills,
            summary="{n} skill declarations are supplied by local plugin packs. Installation or marketplace distribution alone does not establish a security review for the version present.",
            impact="Plugin skills can carry prompt injection or executable components that mishandle PII, access credentials, and cause data leakage. Review the exact installed version and its dependencies."))
    oversized = [source for source in sources if source.get("reason") == "size_limit" and source.get("componentKind") in {"skill", "agent", "plugin", "hook"}]
    source_map = {source["id"]: source for source in sources}
    for item in observations:
        size = item.get("details", {}).get("manifestSizeBytes")
        if item["kind"] in {"skill", "agent"} and type(size) is int and size > INSTRUCTION_REVIEW_BYTES and item["sourceId"] in source_map:
            oversized.append({**source_map[item["sourceId"]], "sizeBytes": size, "componentKind": item["kind"], "reviewThresholdBytes": INSTRUCTION_REVIEW_BYTES})
    oversized = _source_files(oversized)
    if oversized:
        result.append(_finding({"id": "artifacts-oversized", "kind": "skill", "area": "content", "severity": "high",
            "title": "Oversized skills and plugin components can waste tokens and agent usage",
            "action": "Review the listed files and packs. Split long instructions, load references only when needed, remove generated or duplicate content, and delete unused versions."}, [], extra_sources=oversized,
            summary="{n} skill or plugin components exceed a content-size review threshold. Loading large instructions or repeated content can consume context, increase token costs, and waste agent usage.",
            impact="Excessive content can crowd out task context, increase processing cost and latency, and make security review harder. File size signals potential overhead; it does not measure tokens actually consumed."))
    unsupported = _source_files([source for source in sources if source["id"] in malformed])
    if unsupported:
        result.append(_finding({"id": "mcp-unsupported-shape", "kind": "mcp", "area": "hygiene", "severity": "low",
            "title": "Unsupported connector configuration needs repair or removal",
            "action": "Check the named file against the client's supported MCP schema. Correct malformed entries, or remove obsolete and unused configurations; then rescan."}, [], extra_sources=unsupported,
            summary="{n} MCP configuration files contain unsupported declaration shapes. These entries may be ignored or fail to load, leaving unusable configuration behind.",
            impact="Invalid entries create maintenance noise and can hide intended connector settings. The shape issue alone does not establish working connector access."))
    copies = {}
    for item in observations:
        details = item.get("details", {})
        digest = details.get("digest")
        if item["kind"] == "skill" and isinstance(digest, str) and digest:
            copies.setdefault((item["client"], item["name"], digest), []).append(item)
    repeated = [item for group in copies.values() if len({entry["location"] for entry in group}) > 1 for item in group]
    if repeated:
        result.append(_finding({"id": "skills-duplicate-content", "kind": "skill", "area": "hygiene", "severity": "low",
            "title": "Duplicate skill content appears in multiple locations",
            "action": "Review the listed copies and retain the locations needed by each client or project. Consolidate obsolete copies and use one reviewed update source."}, repeated,
            summary="{n} skill declarations repeat the same named content and digest within a client. Review whether each copy is needed and whether an agent can load duplicate instructions.",
            impact="Repeated skills can create update drift and unnecessary maintenance. Loading multiple copies may waste context and tokens; separate project installations can also be intentional."))
    return sorted(result, key=lambda item: (ORDER[item["severity"]], -item["declarations"], item["ruleId"]))
