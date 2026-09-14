"""Small local artifact contract and counts; no endpoint or account identity."""
from collections import Counter
import json
import math
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit

SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
KINDS = ("client", "mcp", "skill", "plugin", "agent", "setting", "hook")


DEFAULT_BOOKING_URL = "https://calendar.app.google/qVE3L8fGgmQWv3Hx7"


def booking_link(value):
    if value is None or value == DEFAULT_BOOKING_URL:
        return DEFAULT_BOOKING_URL
    try:
        parts = urlsplit(value)
        # A "Talk to Palma" link must lead to Palma, not to a look-alike sign-in page.
        if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
                or parts.fragment or any(c.isspace() or ord(c) < 32 for c in value)
                or "\\" in value or len(value) > 2048
                or not (parts.hostname == "palma.ai" or parts.hostname.endswith(".palma.ai"))):
            raise ValueError
        _ = parts.port
    except ValueError:
        raise ValueError("Use the published Palma calendar URL or an HTTPS link on palma.ai without credentials or a fragment.") from None
    return value


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys are not supported.")
        result[key] = value
    return result


def _bounded(value, depth=0):
    if depth > 18:
        raise ValueError("Snapshot nesting exceeds the local artifact limit.")
    if isinstance(value, str) and len(value) > 10000:
        raise ValueError("Snapshot contains an oversized text field.")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Snapshot numbers must be finite.")
    if isinstance(value, (list, dict)):
        for item in (value.values() if isinstance(value, dict) else value):
            _bounded(item, depth + 1)


def _records(snapshot, key, required):
    entries = snapshot.get(key)
    if not isinstance(entries, list):
        raise ValueError(f"Snapshot {key} must be a list.")
    ids = set()
    for entry in entries:
        if not isinstance(entry, dict) or not required.issubset(entry):
            raise ValueError(f"Snapshot has an incomplete {key} record.")
        for field in required:
            if not isinstance(entry[field], str) or not entry[field]:
                raise ValueError(f"Snapshot {key}.{field} must be a nonempty string.")
        if entry["id"] in ids:
            raise ValueError(f"Snapshot {key} IDs must be unique.")
        ids.add(entry["id"])
    return entries, ids


def validate(snapshot):
    if not isinstance(snapshot, dict) or snapshot.get("schemaVersion") != "2.0":
        raise ValueError("Expected a Palma local snapshot with schemaVersion 2.0.")
    allowed = {"schemaVersion", "collector", "mode", "startedAt", "completedAt", "status",
               "scope", "sources", "observations", "coverage", "findings"}
    if set(snapshot) - allowed:
        raise ValueError("Snapshot contains fields outside the independent local format.")
    _bounded(snapshot)
    if snapshot.get("mode") not in {"endpoint", "declared"}:
        raise ValueError("Snapshot mode must be endpoint or declared.")
    if snapshot.get("status") not in {"complete", "partial"}:
        raise ValueError("Snapshot status must be complete or partial.")
    for field in ("collector", "scope", "coverage"):
        if not isinstance(snapshot.get(field), dict):
            raise ValueError(f"Snapshot {field} must be an object.")
    if not isinstance(snapshot["coverage"].get("limitations"), list) or not all(
            isinstance(item, str) for item in snapshot["coverage"]["limitations"]):
        raise ValueError("Snapshot coverage.limitations must be a list of text.")
    inspected = snapshot["coverage"].get("sourcesInspected", 0)
    if type(inspected) is not int or inspected < 0:
        raise ValueError("Snapshot coverage.sourcesInspected must be a non-negative integer.")
    if snapshot["scope"].get("type") not in {"machine", "current-user", "copied-home", "declared"}:
        raise ValueError("Snapshot has an unsupported scope type.")
    if snapshot["mode"] == "declared" and (snapshot["status"] != "partial" or snapshot["scope"]["type"] != "declared"):
        raise ValueError("A declared inventory must retain partial status and declared scope.")
    if snapshot["mode"] == "endpoint" and snapshot["scope"]["type"] == "declared":
        raise ValueError("A declared inventory cannot be labeled as an endpoint scan.")
    sources, source_ids = _records(snapshot, "sources", {"id", "client", "scope", "location", "status"})
    observations, observation_ids = _records(snapshot, "observations", {"id", "kind", "client", "name", "sourceId", "location", "enabled"})
    for source in sources:
        if source["status"] not in {"collected", "missing", "skipped", "error"}:
            raise ValueError("Snapshot has an unsupported source status.")
    for observation in observations:
        if (observation["sourceId"] not in source_ids or observation["kind"] not in KINDS
                or observation["enabled"] not in {"enabled", "disabled", "unknown"}
                or not isinstance(observation.get("details"), dict)):
            raise ValueError("Snapshot has an invalid observation or evidence link.")
        if observation["kind"] == "setting":
            details = observation["details"]
            if not isinstance(details.get("key"), str) or not details["key"] or "value" not in details:
                raise ValueError("Setting evidence must contain a setting key and value.")
    findings, _ = _records(snapshot, "findings", {"id", "ruleId", "title", "severity", "category", "confidence", "evidenceType", "summary", "impact", "recommendation"})
    for finding in findings:
        if (finding["severity"] not in SEVERITIES or finding["confidence"] not in {"high", "medium", "low"}
                or finding["evidenceType"] not in {"configuration", "inventory", "declared"}):
            raise ValueError("Snapshot has invalid finding labels.")
        refs = finding.get("observationIds")
        evidence = finding.get("evidence")
        if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in observation_ids for ref in refs):
            raise ValueError("Finding references an unknown observation.")
        if not isinstance(evidence, list) or any(not isinstance(item, dict) or item.get("sourceId") not in source_ids for item in evidence):
            raise ValueError("Finding references an unknown evidence source.")
        if snapshot["mode"] == "declared" and finding["evidenceType"] != "declared":
            raise ValueError("Declared findings must be labeled as declared evidence.")
    return snapshot


def read_snapshot(path):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Snapshot input must be a regular file, not a link or special file.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Snapshot input must be a regular file.")
        data = stream.read(MAX_SNAPSHOT_BYTES + 1)
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot input exceeds the 64 MB local artifact limit.")
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("Snapshot is not valid bounded UTF-8 JSON.") from None
    return validate(result)


def summarize(snapshot):
    counts = Counter(item["kind"] for item in snapshot["observations"])
    counts["client"] = len({item["client"].casefold() for item in snapshot["observations"] if item["kind"] == "client"})
    severity = Counter(item["severity"] for item in snapshot["findings"])
    coverage = Counter(item["status"] for item in snapshot["sources"])
    inspected = snapshot["coverage"].get("sourcesInspected")
    coverage["collected"] = inspected if type(inspected) is int else coverage["collected"]
    return {"schemaVersion": "2.0", "mode": snapshot["mode"], "status": snapshot["status"],
            "scope": snapshot["scope"]["type"],
            "counts": {kind: counts[kind] for kind in KINDS},
            "findings": {level: severity[level] for level in SEVERITIES},
            "coverage": {state: coverage[state] for state in ("collected", "skipped", "error")},
            "limitationCount": len(snapshot["coverage"]["limitations"]),
            # Rule text only, in report order: an assistant can present priorities without
            # reading scanned names or locations.
            "priorities": [{key: finding.get(key) for key in ("severity", "title", "ruleId", "declarations", "applies", "clients", "recommendation")}
                           for finding in snapshot["findings"]]}


def json_text(data):
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
