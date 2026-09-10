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
