"""Vendor-specific transport/auth extraction; configured servers are never started."""
import hashlib
import ipaddress
import re
from pathlib import PureWindowsPath
from urllib.parse import urlsplit

from ..redaction import PLACEHOLDER, SECRET_KEY, path_credentials, url_credentials

PACKAGE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*(?:@[a-z0-9][a-z0-9._+-]*)?$")


def transport_for(family, entry):
    explicit = entry.get("type")
    mapping = {"stdio": "stdio", "http": "http", "streamableHttp": "http", "streamable-http": "http",
               "sse": "sse", "websocket": "websocket", "ws": "websocket", "sdk": "sdk"}
    if explicit is not None:
        if not isinstance(explicit, str):
            return "unknown", "unknown"
        return mapping.get(explicit, "unknown"), "declared" if explicit in mapping else "unknown"
    if family == "gemini-cli" and isinstance(entry.get("httpUrl"), str):
        return "http", "inferred"
    if isinstance(entry.get("command"), str):
        return "stdio", "inferred"
    if family in {"gemini-cli", "cline"} and isinstance(entry.get("url"), str):
        return "sse", "inferred"
    if any(isinstance(entry.get(key), str) for key in ("url", "serverUrl", "httpUrl")):
        return "http", "inferred"
    return "unknown", "unknown"


def endpoint(entry):
    value = next((entry[key] for key in ("httpUrl", "url", "serverUrl") if isinstance(entry.get(key), str)), None)
    if not value:
        return None, None, False
    try:
        parsed = urlsplit(value)
        # A labeled credential segment (/access_token/<value>) would make even an
        # unsalted digest a guessable fingerprint of the secret: export no hash then.
        path_hash = None if path_credentials(parsed.path) else hashlib.sha256(
            parsed.path.encode("utf-8", errors="replace")).hexdigest()
        if parsed.scheme in {"unix", "pipe"}:
            return None, path_hash, False
        if parsed.scheme not in {"https", "http", "wss", "ws"} or not parsed.hostname or PLACEHOLDER.search(parsed.netloc):
            return None, path_hash, True
        host = canonical_host(parsed.hostname)
        if not host or "\\" in value or any(ord(character) < 32 for character in value):
            return None, path_hash, True
        port = parsed.port
        default = 443 if parsed.scheme in {"https", "wss"} else 80
        suffix = ":" + str(port) if port is not None and port != default else ""
        origin = parsed.scheme + "://" + host + suffix
        return (origin, path_hash, False) if len(origin) <= 512 else (None, path_hash, True)
    except (ValueError, UnicodeError):
        return None, None, True


def canonical_host(host):
    """Match WHATWG origins for ASCII DNS/IP; ambiguous IDNA stays unknown."""
    try:
        address = ipaddress.ip_address(host)
        if "%" in host:
            return None
        return "[" + address.compressed + "]" if address.version == 6 else str(address)
    except ValueError:
        pass
    if not re.fullmatch(r"[a-zA-Z0-9._-]+", host):
        return None
    last = host.rstrip(".").rsplit(".", 1)[-1]
    if last.isdigit() or re.fullmatch(r"0[xX][a-fA-F0-9]+", last):
        return None  # WHATWG treats legacy numeric IPv4 forms specially.
    return host.lower()


def command_metadata(entry):
    command = entry.get("command")
    if not isinstance(command, str) or not command:
        return None, None
    executable = PureWindowsPath(command).name
    if not re.fullmatch(r"[A-Za-z0-9._+-]{1,100}", executable):
        executable = "[custom executable]"
    args = entry.get("args")
    package = None
    if executable in {"npx", "npx.cmd", "uvx", "uvx.exe", "bunx", "pnpx"} and isinstance(args, list):
        for arg in args[:20]:
            if isinstance(arg, str) and not arg.startswith("-"):
                package = arg if PACKAGE.fullmatch(arg) and not SECRET_KEY.search(arg) else None
                break
    return executable, package


def auth_metadata(entry):
    headers = entry.get("headers", entry.get("http_headers", {}))
    headers = headers if isinstance(headers, dict) else {}
    credential_headers = {key: value for key, value in headers.items() if SECRET_KEY.search(key) or key.lower() in {"cookie", "x-auth"}}
    inline = any(isinstance(value, str) and value and not PLACEHOLDER.search(value) for value in credential_headers.values())
    inline |= any(isinstance(entry.get(key), str) and bool(url_credentials(entry[key])) for key in ("url", "httpUrl", "serverUrl"))
    env = entry.get("env", {})
    if isinstance(env, dict):
        inline |= any(SECRET_KEY.search(key) and isinstance(value, str) and bool(value) and not PLACEHOLDER.search(value) for key, value in env.items())
    if isinstance(entry.get("oauth"), dict) or entry.get("authProviderType") == "dynamic_discovery":
        return "oauth_declared", bool(inline)
    authorization = next((value for key, value in headers.items() if key.lower() == "authorization"), None)
    if isinstance(authorization, str) and authorization.lower().startswith("bearer "):
        return "bearer_header", bool(inline)
    if credential_headers:
        return "static_header", bool(inline)
    env_auth = isinstance(env, dict) and any(SECRET_KEY.search(key) for key in env)
    if env_auth or any(entry.get(key) for key in ("env_vars", "env_http_headers", "bearer_token_env_var", "headersHelper")):
        return "environment_reference", bool(inline)
    return "unknown", bool(inline)


def collect_mcps(builder, candidate, source, entries, parent_id=None):
    if not isinstance(entries, dict):
        builder.gap(candidate, "unknown_schema", "unsupported")
        return
    builder.mcp_documents.append((candidate, source, entries, parent_id))
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            builder.gap(candidate, "unknown_schema", "unsupported")
            continue
        nested = entry.get("transport")
        if candidate.family == "cline" and isinstance(nested, dict):
            entry = {**entry, **nested}
        transport, evidence = transport_for(candidate.family, entry)
        origin, path_hash, endpoint_gap = endpoint(entry)
        if transport == "unknown" or endpoint_gap or malformed_fields(entry):
            builder.gap(candidate, "unknown_schema", "unsupported")
        executable, package = command_metadata(entry)
        auth, inline = auth_metadata(entry)
        enabled = "disabled" if entry.get("disabled") is True or entry.get("enabled") is False else "unknown"
        if entry.get("disabled") is False or entry.get("enabled") is True:
            enabled = "enabled"
        builder.emit(candidate, source, "mcp", name, discriminator=(name, parent_id),
                     transport=transport, transportEvidence=evidence, endpointOrigin=origin,
                     endpointPathHash=path_hash, executable=executable, packageName=package,
                     auth=auth, inlineCredentialPresent=inline, enabled=enabled, parentId=parent_id)


def malformed_fields(entry):
    fields = {"type": str, "url": str, "httpUrl": str, "serverUrl": str, "command": str,
              "args": list, "headers": dict, "http_headers": dict, "env": dict,
              "enabled": bool, "disabled": bool, "transport": dict}
    return any(key in entry and not isinstance(entry[key], expected) for key, expected in fields.items())
