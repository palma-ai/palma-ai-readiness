"""Build a referentially complete report with bounded source/observation slots."""
from datetime import datetime, timezone

from .filesystem import ReadGap
from .identity import fingerprint
from .parsing import ParseError, parse_document

NAMES = {"claude-code": "Claude Code", "claude-desktop": "Claude Desktop", "codex": "Codex",
         "cursor": "Cursor", "gemini-cli": "Gemini CLI", "kiro": "Kiro", "vscode": "VS Code",
         "windsurf": "Windsurf", "cline": "Cline", "roo-code": "Roo Code", "unknown": "Unknown"}
VARIANTS = {"claude-code": "cli", "claude-desktop": "desktop", "gemini-cli": "cli",
            "vscode": "ide", "windsurf": "ide", "roo-code": "extension"}


def iso_time(timestamp=None):
    value = datetime.now(timezone.utc) if timestamp is None else datetime.fromtimestamp(timestamp, timezone.utc)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ReportBuilder:
    def __init__(self, files, redactor, options, namespace):
        self.files, self.redactor, self.options, self.namespace = files, redactor, options, namespace
        self.sources: dict[str, dict] = {}
        self.observations: dict[str, dict] = {}
        self.clients: dict[str, dict] = {}
        self.variant_evidence: dict[str, set[str]] = {}
        self.limit_reason = None
        self.documents: dict[str, dict] = {}
        self.candidates = {}
        self.mcp_documents = []
        self.component_parents = {}
        self.manifests_seen = 0

    def context_id(self, candidate):
        return fingerprint(self.namespace, candidate.family, candidate.context)

    def source(self, candidate):
        identity = fingerprint(self.namespace, candidate.family, candidate.scope, str(candidate.path.absolute()), candidate.role, candidate.context)
        if identity in self.sources:
            return self.sources[identity]
        if len(self.sources) >= self.options.max_sources - 1:
            self.limit_reason = "count_limit"
            raise ReadGap("count_limit")
        source = {"id": identity, "family": candidate.family, "scope": candidate.scope,
                  "location": candidate.location, "format": candidate.format, "status": "collected",
                  "reason": "none", "sizeBytes": None, "modifiedAt": None}
        self.sources[identity] = source
        self.candidates[identity] = candidate
        return source

    def discard_since(self, known):
        """Forget every source and gap registered after `known`; return what was dropped.

        Used when a probe had to read a file to learn whether it belongs to a
        supported client at all: an unrelated application must leave neither a
        source row nor a path fingerprint in the report. Callers re-emit any
        collection-limit gap on their parent so exhaustion stays visible.
        """
        dropped = [self.sources.pop(identity) for identity in list(self.sources) if identity not in known]
        for source in dropped:
            self.documents.pop(source["id"], None)
        return dropped

    def probe_document(self, candidate):
        """Read and parse a document WITHOUT teaching the redactor or caching it.

        For identity probes whose outcome decides whether the file is ours at all.
        Returns (known_sources_before, source, data); call `adopt_document` once the
        identity is accepted, or `discard_since(known)` to leave no trace.
        """
        known = set(self.sources)
        source, raw = self.read(candidate)
        if raw is None:
            return known, source, None
        try:
            return known, source, parse_document(raw, candidate.format)
        except ParseError:
            source.update(status="invalid", reason="parse_error")
            return known, source, None

    def adopt_document(self, source, data):
        """Accept a probed document into the report exactly as `document()` would have."""
        self.redactor.learn(data)
        self.documents[source["id"]] = data

    def checkpoint(self):
        """Registry state before one candidate runs; see `rollback`."""
        return set(self.sources), set(self.observations), len(self.mcp_documents)

    def rollback(self, checkpoint):
        """Discard every source, document and observation registered since `checkpoint`.

        An adapter that fails part-way leaves nothing behind: no probe-only source
        naming an unrelated application, and no partial evidence that looks complete.
        """
        sources, observations, mcp_documents = checkpoint
        for identity in [identity for identity in self.sources if identity not in sources]:
            del self.sources[identity]
            self.documents.pop(identity, None)
            self.candidates.pop(identity, None)
            self.component_parents.pop(identity, None)
        for identity in [identity for identity in self.observations if identity not in observations]:
            del self.observations[identity]
        self.clients = {context: client for context, client in self.clients.items() if client["id"] in self.observations}
        del self.mcp_documents[mcp_documents:]

    def gap(self, candidate, reason, status="skipped"):
        identity = fingerprint(self.namespace, "gap", candidate.family, str(candidate.path), reason)
        if identity in self.sources:
            return
        if len(self.sources) >= self.options.max_sources - 1:
            self.limit_reason = "count_limit"
            return
        source = dict(self._gap_source(identity, reason), family=candidate.family, scope=candidate.scope,
                      location=candidate.location + ":coverage", status=status)
        self.sources[identity] = source
        self.candidates[identity] = candidate

    def _gap_source(self, identity, reason):
        return {"id": identity, "family": "unknown", "scope": "user", "location": "collection:coverage",
                "format": "unknown", "status": "skipped", "reason": reason, "sizeBytes": None, "modifiedAt": None}

    def finish(self):
        if self.limit_reason:
            identity = fingerprint(self.namespace, "collection-limit")
            self.sources[identity] = self._gap_source(identity, self.limit_reason)
        for observation in self.observations.values():
            self.redactor.scrub_observation(observation)
        for source in self.sources.values():
            source["location"] = self.redactor.text(source["location"], 512)

    def read(self, candidate):
        source = self.source(candidate)
        try:
            raw, info = self.files.read(candidate.path)
            self.file_metadata(candidate, source, info)
            return source, raw
        except ReadGap as error:
            source.update(status=error.status, reason=error.reason)
            return source, None

    def file_metadata(self, candidate, source, info):
        try:
            source["modifiedAt"] = iso_time(info.st_mtime)
        except (ValueError, OSError, OverflowError):
            self.gap(candidate, "unknown_schema", "unsupported")
        if 0 <= info.st_size <= 1_000_000_000:
            source["sizeBytes"] = info.st_size
        else:
            self.gap(candidate, "size_limit")

    def document(self, candidate):
        source = self.source(candidate)
        if source["id"] in self.documents:
            return source, self.documents[source["id"]]
        source, raw = self.read(candidate)
        if raw is None:
            return source, None
        try:
            data = parse_document(raw, candidate.format)
            self.redactor.learn(data)
            self.documents[source["id"]] = data
            return source, data
        except ParseError:
            source.update(status="invalid", reason="parse_error")
            return source, None

    def directory(self, candidate):
        source = self.source(candidate)
        try:
            return source, self.files.children(candidate.path)
        except ReadGap as error:
            source.update(status=error.status, reason=error.reason)
            return source, None

    def ensure_client(self, candidate, source, installed=False, version=None):
        context = self.context_id(candidate)
        variant = self.client_variant(candidate, context)
        if context in self.clients:
            client = self.clients[context]
            client["variant"] = variant
            if installed:
                client.update(installationState="installed", version=version)
            return client
        if len(self.observations) >= self.options.max_observations:
            self.limit_reason = "count_limit"
            raise ReadGap("count_limit")
        client = {"id": fingerprint(context, "client"), "contextId": context, "sourceId": source["id"],
                  "kind": "client", "name": NAMES.get(candidate.family, candidate.family), "family": candidate.family,
                  "variant": variant, "version": version,
                  "installationState": "installed" if installed else "config_only",
                  "authModes": ["unknown"], "authEvidence": "unknown"}
        self.clients[context] = client
        self.observations[client["id"]] = client
        return client

    def client_variant(self, candidate, context):
        variant = candidate.variant if candidate.variant != "unknown" else VARIANTS.get(candidate.family, "unknown")
        if candidate.family == "cursor" and candidate.path.name in {"cli-config.json", "cli.json"}:
            variant = "cli"
        evidence = self.variant_evidence.setdefault(context, set())
        if variant != "unknown":
            evidence.add(variant)
        return next(iter(evidence)) if len(evidence) == 1 else "unknown"

    def emit(self, candidate, source, kind, name, discriminator=None, **fields):
        if kind in {"skill", "agent", "plugin"}:
            self.manifests_seen += 1
            if self.manifests_seen > self.options.max_manifests:
                self.gap(candidate, "manifest_limit")
                return None
        context = self.context_id(candidate)
        identity = fingerprint(context, source["id"], kind, discriminator if discriminator is not None else name)
        if identity in self.observations:
            return self.observations[identity]
        slots = 1 + int(context not in self.clients)
        if len(self.observations) + slots > self.options.max_observations:
            self.limit_reason = "count_limit"
            return None
        self.ensure_client(candidate, source)
        observation = {"id": identity, "contextId": context, "sourceId": source["id"],
                       "kind": kind, "name": name, **fields}
        self.observations[identity] = observation
        return observation
