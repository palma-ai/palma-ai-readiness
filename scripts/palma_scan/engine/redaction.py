"""Export only bounded metadata, with discovered credential values scrubbed."""
import re
from urllib.parse import unquote, unquote_plus, urlsplit

SECRET_KEY = re.compile(r"token|secret|password|authorization|api[-_]?key|credential", re.I)
KNOWN_SECRET = re.compile(
    r"(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}"
    r"|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
)
PLACEHOLDER = re.compile(r"\$\{[^}]+\}|\$[A-Z][A-Z0-9_]*|%[A-Z][A-Z0-9_]*%")
OPTION_MAPS = {"env", "headers", "http_headers"}
DECLARATION_MAPS = {"mcpServers", "mcp_servers", "servers", "plugins", "projects", "profiles", "model_providers"}
BOOLEAN_VALUES = {"0", "1", "true", "false"}
PUBLIC_ENV_VALUES = {
    "NODE_ENV": {"development", "production", "test"},
    "CI": BOOLEAN_VALUES, "DEBUG": BOOLEAN_VALUES, "NO_COLOR": BOOLEAN_VALUES,
    "FORCE_COLOR": BOOLEAN_VALUES | {"2", "3"},
    "PYTHONUNBUFFERED": {"0", "1"}, "PYTHONDONTWRITEBYTECODE": {"0", "1"},
    "LOG_LEVEL": {"trace", "debug", "info", "warn", "warning", "error", "fatal", "critical", "off", "silent"},
    "BROWSER_USE_TINYSKY_ENABLED": BOOLEAN_VALUES,
}
PUBLIC_HEADER_VALUES = {
    "accept": {"application/json", "text/event-stream", "application/json, text/event-stream", "*/*"},
    "content-type": {"application/json", "application/json; charset=utf-8"},
}
DOTTED_VERSION = re.compile(r"[0-9]{1,8}(?:\.[0-9]{1,8}){1,5}")
# Sensitivity of a learned value. DECLARED: the value sits under a credential-named
# key, in URL userinfo/credential fields or a credential argument. INFERRED: the value
# is private only because its env/header key is not a recognized public option.
DECLARED, INFERRED = "declared", "inferred"
MIN_DECLARED_SECRET_LENGTH = 8
MIN_INFERRED_SECRET_LENGTH = 20
URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
# Lower-case slugs with short segments are identifiers (model names, regions, project
# ids, feature flags), never credentials: `claude-sonnet-4-5-20250929`, `us-east-1`.
IDENTIFIER_SLUG = re.compile(r"[a-z0-9]{1,16}(?:[._-][a-z0-9]{1,16})*")


def plausible_secret(value: str, level) -> bool:
    """Whether a learned value can be scrubbed from exported text without corrupting it.

    Every learned value is removed from every exported name, version, executable and
    location by plain substring replacement, so a short or ordinary value ("1",
    "prod", "1000", a version, a model slug) destroys unrelated inventory text: an
    env entry ``CLAUDE_CODE_ENABLE_TELEMETRY: "1"`` once rewrote ``2.1.197`` as
    ``2.[redacted].[redacted]97``. A credential that is this short or this ordinary
    is not a leak risk in a name or version, so the floor costs no protection.
    """
    if not value or PLACEHOLDER.fullmatch(value) or any(character.isspace() for character in value):
        return False
    if value.lower() in BOOLEAN_VALUES or DOTTED_VERSION.fullmatch(value):
        return False
    if level == DECLARED:
        return len(value) >= MIN_DECLARED_SECRET_LENGTH and not (value.isdigit() and len(value) < 16)
    return (len(value) >= MIN_INFERRED_SECRET_LENGTH and not URL_SCHEME.match(value)
            and not IDENTIFIER_SLUG.fullmatch(value))


def _sensitivity(current, key=None):
    """Combine an inherited sensitivity with the key that introduces a value."""
    if current is True or current == DECLARED or (key is not None and SECRET_KEY.search(key)):
        return DECLARED
    return current or False


def public_option_value(container, key, value):
    """Exempt only recognized public options with constrained public values."""
    if not isinstance(value, str):
        return False
    if container == "env":
        key = key.upper()
        if key == "BROWSER_USE_CODEX_APP_VERSION":
            return bool(DOTTED_VERSION.fullmatch(value))
        return value in PUBLIC_ENV_VALUES.get(key, ())
    return value.lower() in PUBLIC_HEADER_VALUES.get(key.lower(), ())


def utf16_length(value: str) -> int:
    return sum(2 if ord(character) > 0xFFFF else 1 for character in value)


def path_credentials(path: str) -> set[str]:
    """Credentials in labeled path segments such as /access_token/<value>."""
    credentials = set()
    segments = path.split("/")
    for previous, item in zip(segments, segments[1:]):
        if item and SECRET_KEY.search(unquote(previous)):
            credentials.update((item, unquote(item)))
    return {item for item in credentials if item and not PLACEHOLDER.fullmatch(item)}


def url_credentials(value: str) -> set[str]:
    """Recognizable credentials in URL userinfo, query or labeled path segments."""
    credentials = set()
    try:
        parts = urlsplit(value)
        for item in (parts.username, parts.password):
            if item:
                credentials.update((item, unquote(item)))
        credentials.update(query_credentials(parts.query))
        credentials.update(path_credentials(parts.path))
    except ValueError:
        pass
    return {item for item in credentials if item and not PLACEHOLDER.fullmatch(item)}


def query_credentials(query: str) -> set[str]:
    # The source byte limit bounds this loop. Iterate without allocating an
    # unbounded list of pairs or silently abandoning later sensitive fields.
    credentials, start = set(), 0
    while start <= len(query):
        end = query.find("&", start)
        field = query[start:end] if end >= 0 else query[start:]
        key, _, item = field.partition("=")
        if item and SECRET_KEY.search(unquote_plus(key)):
            credentials.update((item, unquote_plus(item)))
        if end < 0:
            break
        start = end + 1
    return credentials


class Redactor:
    def __init__(self):
        self.secrets: set[str] = set()

    def learn(self, data: object, sensitive=False, depth: int = 0):
        """Learn credential values. ``sensitive`` is False, DECLARED (or True) or INFERRED."""
        if depth > 30:
            return
        if isinstance(data, dict):
            for key, value in data.items():
                private = _sensitivity(sensitive, key)
                if key in OPTION_MAPS and isinstance(value, dict):
                    self._learn_options(value, key, private, depth + 1)
                elif key in DECLARATION_MAPS and isinstance(value, dict):
                    self._learn_declarations(value, private, depth + 1)
                else:
                    self.learn(value, private or (INFERRED if key in OPTION_MAPS else False), depth + 1)
                if key in {"url", "httpUrl", "serverUrl"} and isinstance(value, str):
                    self._learn_url(value)
                if key == "args" and isinstance(value, list):
                    self._learn_args(value)
        elif isinstance(data, list):
            for item in data:
                self.learn(item, sensitive, depth + 1)
        elif sensitive and isinstance(data, str):
            level = _sensitivity(sensitive)
            for value in (data, data.removeprefix("Bearer ").removeprefix("Basic ")):
                self._remember(value, level)

    def _remember(self, value, level):
        if plausible_secret(value, level):
            self.secrets.add(value)
        elif level == INFERRED and URL_SCHEME.match(value):
            # An inferred URL is an endpoint, not a secret, but its embedded credentials are.
            self.secrets.update(item for item in url_credentials(value) if plausible_secret(item, DECLARED))

    def _learn_options(self, entries, container, sensitive, depth):
        if depth > 30:
            return
        for key, value in entries.items():
            private = _sensitivity(sensitive, key)
            if not private and not public_option_value(container, key, value):
                private = INFERRED
            self.learn({key: value}, private, depth)

    def _learn_declarations(self, entries, sensitive, depth):
        if depth > 30:
            return
        for name, entry in entries.items():
            # These keys identify servers/plugins/projects, not credential fields.
            if isinstance(entry, dict) or (isinstance(entry, list) and all(isinstance(item, dict) for item in entry)):
                self.learn(entry, sensitive, depth + 1)
            else:
                # Malformed entries retain credential, URL and argument learning.
                self.learn({name: entry}, sensitive, depth)

    def _learn_args(self, args):
        previous_private = False
        for item in args:
            if not isinstance(item, str):
                previous_private = False
                continue
            key, separator, value = item.partition("=")
            if separator and SECRET_KEY.search(key):
                self.learn(value, DECLARED)
            if previous_private:
                self.learn(item, DECLARED)
            previous_private = item.startswith("-") and bool(SECRET_KEY.search(item)) and not separator

    def _learn_url(self, value: str):
        self.secrets.update(item for item in url_credentials(value) if plausible_secret(item, DECLARED))

    def text(self, value: object, maximum: int = 256) -> str:
        text = str(value)
        for secret in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(secret, "[redacted]")
        text = KNOWN_SECRET.sub("[redacted]", text)
        text = "".join(c if ord(c) >= 32 and ord(c) != 127 and not 0xD800 <= ord(c) <= 0xDFFF else " " for c in text)
        result, units = [], 0
        for character in text.strip():
            units += 2 if ord(character) > 0xFFFF else 1
            if units > maximum:
                break
            result.append(character)
        return "".join(result) or "[unnamed]"

    def scrub_observation(self, observation: dict):
        limits = {"name": 256, "nativeKey": 256, "version": 100, "model": 100,
                  "executable": 100, "packageName": 200}
        for field, maximum in limits.items():
            if observation.get(field) is not None:
                observation[field] = self.text(observation[field], maximum)
        origin = observation.get("endpointOrigin")
        if origin is not None and self.text(origin, 512) != origin:
            observation["endpointOrigin"] = None
        if "toolNames" in observation:
            observation["toolNames"] = [self.text(item, 100) for item in observation["toolNames"]]


# Ordinary words, default service accounts and client names occur in unrelated paths
# and labels. An account with such a name is still removed from its home paths, but
# its bare name is not rewritten elsewhere: that would corrupt unrelated text.
GENERIC_ACCOUNT_NAMES = frozenset({
    "admin", "administrator", "agent", "agents", "app", "apps", "build", "ci", "claude", "cline",
    "code", "codex", "config", "continue", "copilot", "cursor", "data", "default", "desktop", "dev",
    "developer", "docker", "documents", "downloads", "ec2-user", "gemini", "git", "github", "guest",
    "home", "kiro", "library", "local", "mcp", "node", "ollama", "opencode", "plugins", "project",
    "projects", "public", "python", "root", "runner", "server", "servers", "settings", "shared",
    "skills", "src", "system", "test", "tests", "ubuntu", "user", "users", "vagrant", "windsurf",
    "work", "workspace",
})
MIN_ACCOUNT_NAME_LENGTH = 3
# Keys that hold opaque identifiers, never paths or names.
_IDENTIFIER_KEYS = frozenset({"id", "sourceId", "parentId", "contextId", "profileId", "observationIds"})
# Keys whose strings are locations or messages. The account name is removed only from
# these and from absolute paths: client ids, setting keys and values are fixed
# vocabulary that a login name such as "vscode" or "sandbox" must not rewrite.
_TEXT_KEYS = frozenset({"location", "locations", "declaration", "configuredLocations", "reason", "reasons", "limitations"})
_ABSOLUTE_PATH = re.compile(r"~?[\\/]|[A-Za-z]:[\\/]")
# The snapshot validator's field limit; an alias or token can be longer than what it replaces.
MAX_SCRUBBED_LENGTH = 10_000


def _distinctive(name):
    return (isinstance(name, str) and len(name) >= MIN_ACCOUNT_NAME_LENGTH
            and name.casefold() not in GENERIC_ACCOUNT_NAMES and not name.isdigit())


def _alternation(words):
    return "(?:" + "|".join(map(re.escape, sorted(words, key=len, reverse=True))) + ")"


def _lookup(table, text):
    """The replacement for a case-insensitive match; Unicode case mapping can change length."""
    value = table.get(text.lower())
    if value is None:
        value = next(item for key, item in table.items() if re.fullmatch(re.escape(key), text, re.IGNORECASE))
    return value


class IdentityScrubber:
    """Remove account home directories and the account name from exported text.

    ``accounts`` is a list of ``{"root": path, "alias": "~" | "user-N", "names": [...]}``.
    A home path becomes its alias wherever it appears, not only as a prefix: caches,
    temporary folders and session state often embed one. An account name is replaced
    as a whole token, also in the dash-separated form tools use to encode a folder
    (``/tmp/x/-Users-first-last-project``), but only in locations, messages and absolute
    paths, and only when distinctive enough not to corrupt ordinary text.
    """

    def __init__(self, accounts):
        self.aliases, self.tokens, homes = {}, {}, {}
        for account in accounts:
            alias = account["alias"]
            root = str(account.get("root") or "").rstrip("/\\")
            variants = {root, root.replace("\\", "/")}
            if root.startswith("/Users/"):
                variants.add("/System/Volumes/Data" + root)  # macOS firmlinked form
            for variant in variants:
                split = max(variant.rfind("/"), variant.rfind("\\")) + 1
                if 0 < split < len(variant):
                    self.aliases.setdefault(variant.lower(), alias)
                    homes.setdefault(variant[:split].lower(), set()).add(variant[split:].lower())
            token = "[account]" if alias == "~" else "[" + alias + "]"
            for name in account.get("names", ()):
                if _distinctive(name):
                    for form in {name, re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")}:
                        if _distinctive(form):
                            self.tokens.setdefault(form.lower(), token)
        # One pattern per folder that holds homes, not one pass per account; a longer folder
        # comes first, so a home inside another home keeps its own alias.
        self.paths = [(parent, re.compile(re.escape(parent) + _alternation(names) + r"(?![A-Za-z0-9._-])", re.IGNORECASE))
                      for parent, names in sorted(homes.items(), key=lambda item: -len(item[0]))]
        self.names = (re.compile(r"(?<![A-Za-z0-9])" + _alternation(self.tokens) + r"(?![A-Za-z0-9])", re.IGNORECASE)
                      if self.tokens else None)

    def text(self, value, names=True):
        if not isinstance(value, str):
            return value
        original, lowered = len(value), value.lower()
        for parent, pattern in self.paths:
            if parent in lowered:
                value = pattern.sub(lambda match: _lookup(self.aliases, match.group(0)), value)
        if names and self.names:
            value = self.names.sub(lambda match: _lookup(self.tokens, match.group(0)), value)
        return value[:MAX_SCRUBBED_LENGTH] if len(value) > max(original, MAX_SCRUBBED_LENGTH) else value

    def scrub(self, value, key=None):
        """Return ``value`` with every nested string scrubbed; identifiers are kept."""
        if key in _IDENTIFIER_KEYS:
            return value
        if isinstance(value, str):
            return self.text(value, names=key in _TEXT_KEYS or bool(_ABSOLUTE_PATH.match(value)))
        if isinstance(value, list):
            return [self.scrub(item, key) for item in value]
        if isinstance(value, dict):
            return {name: self.scrub(item, name) for name, item in value.items()}
        return value

    def scrub_snapshot(self, snapshot):
        for field in ("sources", "observations", "coverage"):
            if field in snapshot:
                snapshot[field] = self.scrub(snapshot[field])
        return snapshot
